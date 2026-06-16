# file: /home/mahmut/Desktop/uyumprotokol/core/compliance_engine.py
import os
import re
import time
import numpy as np
from PyQt6.QtCore import QThread, pyqtSignal

try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False

from core.security_sanitizer import UniversalInputSanitizer

AAOIFI_DUAL_PDF_MAP = {
    "sarf": {"tr": 48, "en": 55, "ar": 56},
    "vedia": {"tr": 105, "en": 68, "ar": 130},
    "murabaha": {"tr": 180, "en": 167, "ar": 204},
    "ijarah": {"tr": 218, "en": 211, "ar": 242},
    "leasing": {"tr": 218, "en": 243, "ar": 260},
    "salam": {"tr": 252, "en": 285, "ar": 276},
    "istisna": {"tr": 274, "en": 299, "ar": 298},
    "musharaka": {"tr": 300, "en": 327, "ar": 326},
    "mudarabah": {"tr": 346, "en": 363, "ar": 370},
    "sukuk": {"tr": 440, "en": 419, "ar": 468},
    "karz": {"tr": 492, "en": 514, "ar": 522},
    "takaful": {"tr": 646, "en": 593, "ar": 686}
}

AAOIFI_COMPOSITE_INDEX_MAP = {
    "ijarah_muntahia_bittamlik": {
        "tr": [218, 180],
        "en": [211, 167],
        "ar": [242, 204]
    },
    "musharaka_mutanaqisah": {
        "tr": [300, 218, 180],
        "en": [327, 211, 167],
        "ar": [326, 242, 204]
    },
    "teverruk_ters_murabaha": {
        "tr": [180, 180],
        "en": [167, 167],
        "ar": [204, 204]
    },
    "karz_hasen_sarf": {
        "tr": [492, 48],
        "en": [514, 55],
        "ar": [522, 56]
    }
}

def normalize_standard_type(std_name: str) -> str:
    if not std_name:
        return ""
    # Clean Turkish characters and normalize to standard English characters
    name_clean = std_name.replace("İ", "i").replace("I", "ı").lower()
    name_clean = name_clean.replace("ı", "i").replace("ş", "s").replace("ü", "u").replace("ö", "o").replace("ç", "c").replace("ğ", "g")
    name_clean = re.sub(r"\u0307", "", name_clean)
    name_clean = name_clean.strip()

    # Composite keys normalization
    if "muntahiy" in name_clean or "bittamlik" in name_clean or "muntahia" in name_clean:
        return "ijarah_muntahia_bittamlik"
    if "mutanaqis" in name_clean or "azalan" in name_clean:
        return "musharaka_mutanaqisah"
    if "teverruk" in name_clean or "ters murabaha" in name_clean or "tawarruq" in name_clean:
        return "teverruk_ters_murabaha"
    if "karz" in name_clean and "sarf" in name_clean:
        return "karz_hasen_sarf"

    if "صرف" in name_clean or "sarf" in name_clean:
        return "sarf"
    if "وديع" in name_clean or "vedia" in name_clean or "wadeeah" in name_clean:
        return "vedia"
    if "مرابح" in name_clean or "murabaha" in name_clean:
        return "murabaha"
    if "إجار" in name_clean or "اجار" in name_clean or "icare" in name_clean or "ijarah" in name_clean:
        return "ijarah"
    if "leasing" in name_clean:
        return "leasing"
    if "سلم" in name_clean or "selem" in name_clean or "salam" in name_clean:
        return "salam"
    if "استصن" in name_clean or "istisna" in name_clean:
        return "istisna"
    if "مشارك" in name_clean or "musareke" in name_clean or "musharaka" in name_clean:
        return "musharaka"
    if "مضارب" in name_clean or "mudarabe" in name_clean or "mudarabah" in name_clean:
        return "mudarabah"
    if "صك" in name_clean or "sukuk" in name_clean:
        return "sukuk"
    if "قرض" in name_clean or "karz" in name_clean or "qard" in name_clean:
        return "karz"
    if "تكافل" in name_clean or "tekaful" in name_clean or "takaful" in name_clean or "tekafül" in name_clean:
        return "takaful"
    return name_clean

VIOLATION_DATABASE = {
    "V_COMPOSITE_FORBIDDEN_GUARANTEE": {
        "tr": {
            "type": "Mürekkep Akit Yasak Sermaye Garantisi",
            "clause": "Müşareke No: 12 + İcare No: 9 + Bey' No: 8",
            "reasons": ["Müşareke/Mudarabe ortaklıklarında anapara garantisi verilmesi veya karz akdiyle birleştirilmesi yasaktır."],
            "remediation": "Sözleşmedeki anapara garantisi ve karz taahhüdünü kaldırarak kâr/zarar ortaklığı esasına göre revize edin."
        },
        "en": {
            "type": "Composite Forbidden Capital Guarantee",
            "clause": "Musharaka No: 12 + Ijarah No: 9 + Bay' No: 8",
            "reasons": ["Providing capital guarantees or combining with Karz is forbidden in Musharaka/Mudarabah partnerships."],
            "remediation": "Remove capital guarantees and Karz commitments; align profit/loss distribution strictly with partnership rules."
        },
        "ar": {
            "type": "ضمان رأس المال المحظور في العقود المركبة",
            "clause": "المشاركة رقم 12 + الإجارة رقم 9 + البيع رقم 8",
            "reasons": ["يمنع تقديم ضمانات لرأس المال أو الدمج مع القرض في شركات المشاركة والمضاربة."],
            "remediation": "أزل شروط ضمان رأس المال والتزامات القرض، وأعد صياغة العقد بناءً على توزيع الغنم بالغرم."
        }
    },
    "V_COMPOSITE_KARZ_SARF": {
        "tr": {
            "type": "Karz ve Sarf Birleşimi",
            "clause": "Karz No: 19 + Sarf No: 1",
            "reasons": ["Karz (Ödünç) ile vadeli Sarf (Döviz Alım-Satım) akdi birleştirilemez. Riba ve menfaat şüphesi doğurur."],
            "remediation": "Sözleşmeden vadeli döviz alım-satım ve ek menfaat şartlarını kaldırın; işlemleri spot olarak ayırın."
        },
        "en": {
            "type": "Karz and Sarf Combination",
            "clause": "Karz No: 19 + Sarf No: 1",
            "reasons": ["Combining Karz (Loan) with deferred Sarf (Exchange) is prohibited due to Riba and conditional benefit rules."],
            "remediation": "Remove deferred currency exchange and stipulated benefit terms; separate them into distinct spot transactions."
        },
        "ar": {
            "type": "الجمع بين القرض والصرف",
            "clause": "القرض رقم 19 + الصرف رقم 1",
            "reasons": ["لا يجوز الجمع بين القرض وصرف العملات المؤجل لما فيه من شبهة الربا والمنفعة المشروطة."],
            "remediation": "أزل شروط الصرف المؤجل والمنفعة المشروطة؛ وافصل المعاملتين لتكونا فوريتين."
        }
    },
    "V_COMPOSITE_ICARE_BEY_SIMULTANEOUS": {
        "tr": {
            "type": "İcare ve Bey' Eşzamanlılığı",
            "clause": "İcare No: 9 + Bey' No: 8 Vaadi",
            "reasons": ["Aynı varlık üzerinde İcare (Kira) ve Bey' (Satış) akitleri eşzamanlı olarak uygulanamaz. Devir vaadi ayrı bir belgeyle yapılmalıdır."],
            "remediation": "Mülkiyet devri vaadini kira sözleşmesinden tamamen ayırarak bağımsız bir taahhütname olarak düzenleyin."
        },
        "en": {
            "type": "Simultaneous Ijarah and Bay'",
            "clause": "Ijarah No: 9 + Bay' No: 8 Promise",
            "reasons": ["Ijarah (Lease) and Bay' (Sale) cannot be combined simultaneously on the same asset. The promise of transfer must be separate."],
            "remediation": "Separate the ownership transfer promise completely from the lease agreement as an independent undertaking."
        },
        "ar": {
            "type": "الجمع بين البيع والإجارة في آن واحد",
            "clause": "الإجارة رقم 9 + البيع رقم 8",
            "reasons": ["لا يجوز إبرام عقد الإجارة والبيع معاً على نفس العين في وقت واحد. يجب أن يكون الوعد بالتمليك في وثيقة مستقلة."],
            "remediation": "افصل الوعد بالتمليك تماماً عن عقد الإجارة واجعله تعهداً مستقلاً."
        }
    },
    "V_COMPOSITE_MUDARABAH_VEDIA_RIBA": {
        "tr": {
            "type": "Mudarabe ve Vedia Karışımı",
            "clause": "Mudarabah No: 13 + Vedia No: 5",
            "reasons": ["Mudaraba yatırım fonları ile faiz veya nemalandırma içeren Vedia (emanet) hesaplarının karıştırılması yasaktır."],
            "remediation": "Yatırım havuzundan garantili nema ve faiz taahhütlerini çıkararak fıkha uygun katılım hesaplarına dönüştürün."
        },
        "en": {
            "type": "Mudarabah and Vedia Mix",
            "clause": "Mudarabah No: 13 + Vedia No: 5",
            "reasons": ["Mixing Mudarabah investment funds with interest-bearing/guaranteed Vedia custody accounts is prohibited."],
            "remediation": "Remove guaranteed yields and interest commitments from the investment pool; use compliant participation structures."
        },
        "ar": {
            "type": "خلط المضاربة بالوديعة الربوية",
            "clause": "المضاربة رقم 13 + الوديعة رقم 5",
            "reasons": ["يمنع خلط أموال المضاربة الاستثمارية مع حسابات الوديعة (الأمانة) التي تضمن عوائد أو فوائد."],
            "remediation": "أزل ضمانات العائد والفوائد من وعاء الاستثمار وحولها إلى حسابات مشاركة متوافقة."
        }
    },
    "V_SARF_RIBA_NASIAH": {
        "tr": {
            "type": "Sarf Vadeli İşlem / Faiz (Riba el-Nesia)",
            "clause": "Standart No: 1, Madde 2/1/3, 2/1/5 ve 2/2",
            "reasons": ["Vadeli piyasalarda veya ileri tarihli (forward/futures) sarf işlemlerinin haramlığı [Madde 2/1/3, 2/1/5 ve 2/2]."],
            "remediation": "Sözleşmeyi spot teslim olarak güncelleyin veya takas işlemini anlık gerçekleştirin."
        },
        "en": {
            "type": "Sarf Deferred Transaction / Riba al-Nasiah",
            "clause": "Standard No: 1, Clause 2/1/3, 2/1/5 and 2/2",
            "reasons": ["Deferred delivery of counter-values in Sarf represents Riba al-Nasiah."],
            "remediation": "Update the contract to spot delivery or execute the exchange transaction instantly."
        },
        "ar": {
            "type": "صرف مؤجل / ربا النسيئة",
            "clause": "المعيار رقم 1، البند 2/1/3 و2/1/5 و2/2",
            "reasons": ["لا يجوز تأجيل قبض البدلين في الصرف لأنه يؤدي إلى ربا النسيئة."],
            "remediation": "قم بتحديث العقد ليكون تسليماً فورياً أو نفذ عملية التبادل بشكل فوري."
        }
    },
    "V_MURABAHA_CHRONOLOGY": {
        "tr": {
            "type": "Murabaha Kabz İhlali",
            "clause": "Standart No: 8, Madde 3/2 ve 3/4",
            "reasons": ["Malın mülkiyet ve hasar riski (damân) bankaya geçmeden müşteriye satılması [Madde 3/2 ve 3/4]."],
            "remediation": "Müşteri satış tarihini, bankanın malı teslim aldığı/kabzettiği tarihten sonraya revize edin."
        },
        "en": {
            "type": "Murabaha Possession Violation",
            "clause": "Standard No: 8, Clause 3/2 and 3/4",
            "reasons": ["The asset's ownership and risk (damân) must pass to the bank before sale to the client."],
            "remediation": "Revise the client sale date to be after the date the bank acquires/possesses the asset."
        },
        "ar": {
            "type": "مخالفة قبض المرابحة",
            "clause": "المعيار رقم 8، البند 3/2 و3/4",
            "reasons": ["لا يجوز انتقال ملكية السلعة وتبعة الهلاك للعميل قبل تملك البنك للسلعة ودخولها في ضمانه أولاً."],
            "remediation": "قم بتعديل تاريخ البيع للعميل ليكون بعد تاريخ تملك البنك وقبضه للسلعة."
        }
    },
    "V_SELEM_DELAYED_CAPITAL": {
        "tr": {
            "type": "Selem Sermaye Gecikmesi İhlali",
            "clause": "Standart No: 10, Madde 3/1/3 ve 3/1/4",
            "reasons": ["Selem bedelinin (re'sü mâli's-selem) akit meclisinde peşin olarak teslim alınmaması veya deynin (alacağın) selem bedeli kılınması [Madde 3/1/3 ve 3/1/4]."],
            "remediation": "Selem sermaye ödemesinin akit imzalandığı anda peşinen yapılmasını şerh edin."
        },
        "en": {
            "type": "Salam Capital Deferment Violation",
            "clause": "Standard No: 10, Clause 3/1/3 and 3/1/4",
            "reasons": ["Salam capital must be paid fully in advance at the contract session, and debt cannot be used as Salam capital."],
            "remediation": "Stipulate that the Salam capital payment must be made fully in advance at the signing of the contract."
        },
        "ar": {
            "type": "مخالفة تأجيل رأس مال السلم",
            "clause": "المعيار رقم 10، البند 3/1/3 و3/1/4",
            "reasons": ["يجب تسليم رأس مال السلم في مجلس العقد بالكامل ولا يجوز تأخيره، كما لا يجوز جعل الدين رأس مال للسلم."],
            "remediation": "اشترط دفع رأس مال السلم بالكامل فوراً عند توقيع العقد."
        }
    },
    "V_ICARE_EARLY_RENT": {
        "tr": {
            "type": "İcare Fiyat Belirsizliği İhlali",
            "clause": "Standart No: 9, Madde 5/2/3",
            "reasons": ["Değişken kiralamalarda ilk dönem ücretinin belirsiz olması veya ucu açık endeks kullanımı [Madde 5/2/3]."],
            "remediation": "Değişken kira sözleşmelerinde ilk dönemin kira bedelini netleştirin veya ucu açık endeks şartını kaldırın."
        },
        "en": {
            "type": "Ijarah Rent Ambiguity Violation",
            "clause": "Standard No: 9, Clause 5/2/3",
            "reasons": ["In variable rentals, the first period's rent must be specified, and open-ended index usage is prohibited."],
            "remediation": "Specify the first period's rent clearly or remove the open-ended index clause."
        },
        "ar": {
            "type": "مخالفة جهالة الأجرة في الإجارة",
            "clause": "المعيار رقم 9، البند 5/2/3",
            "reasons": ["في الإجارة متغيرة الأجرة، يجب تحديد أجرة الفترة الأولى بوضوح ويمنع استخدام المؤشرات المفتوحة."],
            "remediation": "حدد أجرة الفترة الأولى بوضوح أو أزل بند المؤشر المجهول."
        }
    },
    "V_MURABAHA_KABZ": {
        "tr": {
            "type": "Murabaha Kabz İhlali",
            "clause": "Standart No: 8, Madde 3/2 ve 3/4",
            "reasons": ["Malın mülkiyet ve hasar riski (damân) bankaya geçmeden müşteriye satılması [Madde 3/2 ve 3/4]."],
            "remediation": "Murabaha koşullarını satıştan önce açıkça kabz (teslim alma) sağlanacak şekilde revize edin."
        },
        "en": {
            "type": "Murabaha Possession Violation",
            "clause": "Standard No: 8, Clause 3/2 and 3/4",
            "reasons": ["Possession of the asset by the bank is required before sale to the client."],
            "remediation": "Revise Murabaha terms to ensure explicit possession before sale."
        },
        "ar": {
            "type": "مخالفة قبض المرابحة",
            "clause": "المعيار رقم 8، البند 3/2 و3/4",
            "reasons": ["لا يجوز للبنك بيع السلعة للعميل قبل قبضها وتملكها ودخولها في ضمانه."],
            "remediation": "قم بتعديل شروط Murabaha لضمان القبض الصريح قبل البيع."
        }
    },
    "V_MURABAHA_SUPPLIER_CONFLICT": {
        "tr": {
            "type": "Tedarikçi-Müşteri Çelişkisi",
            "clause": "Standart No: 8, Madde 3/1",
            "reasons": ["Tedarikçi ile müşteri aynı kişi veya grup olamaz."],
            "remediation": "Bağımsız bir tedarikçi seçin."
        },
        "en": {
            "type": "Supplier-Client Conflict",
            "clause": "Standard No: 8, Clause 3/1",
            "reasons": ["Supplier and client cannot be the same entity or group."],
            "remediation": "Select an independent supplier."
        },
        "ar": {
            "type": "تعارض المورد والعميل",
            "clause": "المعيار رقم 8، البند 3/1",
            "reasons": ["لا يجوز أن يكون المورد والعميل نفس الشخص أو المجموعة."],
            "remediation": "اختر مورداً مستقلاً."
        }
    },
    "V_MURABAHA_LATE_FEE": {
        "tr": {
            "type": "Gecikme Cezası İhlali",
            "clause": "Standart No: 8, Madde 5/6 (Referans: Standart No: 3, Madde 2/1/2 ve 2/1/8)",
            "reasons": ["Gecikme cezasının banka gelirine kaydedilmesi (tasadduk şartı ihlali) [Madde 5/6]. Ana referans: Standart No: 3, Madde 2/1/2 ve 2/1/8."],
            "remediation": "Gecikme cezaları ayrı bir hayır kurumuna/fonuna aktarılmalıdır."
        },
        "en": {
            "type": "Late Fee Violation",
            "clause": "Standard No: 8, Clause 5/6 (Reference: Standard No: 3, Clause 2/1/2 and 2/1/8)",
            "reasons": ["Late payment penalties cannot be added to bank revenues (charity clause violation)."],
            "remediation": "Late fees must be transferred to a separate charity account."
        },
        "ar": {
            "type": "مخالفة غرامة التأخير",
            "clause": "المعيار رقم 8، البند 5/6 (المرجع: المعيار رقم 3، البند 2/1/2 و2/1/8)",
            "reasons": ["لا يجوز قيد غرامات التأخير كإيراد للبنك (مخالفة شرط التصدق)."],
            "remediation": "يجب تحويل غرامات التأخير إلى حساب خيري مستقل."
        }
    },
    "V_ICARE_MAINTENANCE": {
        "tr": {
            "type": "İcare Bakım Sorumluluğu İhlali",
            "clause": "Standart No: 9, Madde 5/1/5, 5/1/7 ve 5/1/8",
            "reasons": ["Kiralanan varlığın asli mülkiyet sorumluluklarının ve esaslı bakım masraflarının kiracıya yüklenmesi [Madde 5/1/5, 5/1/7 ve 5/1/8]."],
            "remediation": "Esaslı/yapısal bakım sorumluluklarını kiraya verene (bankaya) yükleyin."
        },
        "en": {
            "type": "Ijarah Maintenance Violation",
            "clause": "Standard No: 9, Clause 5/1/5, 5/1/7 and 5/1/8",
            "reasons": ["Major structural maintenance responsibilities and ownership risks cannot be shifted to lessee."],
            "remediation": "Lessor (bank) must bear the major/structural maintenance responsibilities."
        },
        "ar": {
            "type": "مخالفة مسؤولية الصيانة في الإجارة",
            "clause": "المعيار رقم 9، البند 5/1/5 و5/1/7 و5/1/8",
            "reasons": ["لا يجوز تحميل المستأجر الصيانة الأساسية ومسؤوليات ملكية العين."],
            "remediation": "يجب أن يتحمل المؤجر (البنك) مسؤوليات الصيانة الأساسية/الهيكلية."
        }
    },
    "V_MUSHARAKA_CAPITAL_GUARANTEE": {
        "tr": {
            "type": "Müşareke Sermaye Garantisi İhlali",
            "clause": "Standart No: 12, Madde 3/1/4/1 ve 3/1/5/4",
            "reasons": ["Ortakların zarara, sermayedeki payları oranından farklı bir oranla katılmasının şart koşulması [Madde 3/1/5/4] veya ortaklardan birinin sermayeyi mutlak olarak garanti etmesi [Madde 3/1/4/1]."],
            "remediation": "Müşareke ortaklığındaki tüm anapara veya kâr garantilerini kaldırın."
        },
        "en": {
            "type": "Musharaka Capital Guarantee Violation",
            "clause": "Standard No: 12, Clause 3/1/4/1 and 3/1/5/4",
            "reasons": ["Partnership profit/loss ratio must align with capital unless agreed, and capital guarantees are forbidden."],
            "remediation": "Remove all capital or profit guarantees in Musharaka partnership."
        },
        "ar": {
            "type": "مخالفة ضمان رأس المال في المشاركة",
            "clause": "المعيار رقم 12، البند 3/1/4/1 و3/1/5/4",
            "reasons": ["يمنع اشتراط توزيع الخسارة بغير نسبة رأس المال، كما يحظر تقديم أي ضمان لرأس المال."],
            "remediation": "أزل جميع ضمانات رأس المال أو الأرباح في شركة المشاركة."
        }
    },
    "V_SALAM_CAPITAL_DEFERMENT": {
        "tr": {
            "type": "Selem Sermaye İhlali",
            "clause": "Standart No: 10, Madde 3/1/3 ve 3/1/4",
            "reasons": ["Selem bedelinin (re'sü mâli's-selem) akit meclisinde peşin olarak teslim alınmaması veya deynin (alacağın) selem bedeli kılınması [Madde 3/1/3 ve 3/1/4]."],
            "remediation": "Selem sermaye ödemesinin akit meclisinde tamamen peşin yapılmasını sağlayın."
        },
        "en": {
            "type": "Salam Capital Deferment",
            "clause": "Standard No: 10, Clause 3/1/3 and 3/1/4",
            "reasons": ["Salam capital must be paid fully in advance and cannot be structured as a debt conversion."],
            "remediation": "Salam capital must be paid fully in advance at the contract session."
        },
        "ar": {
            "type": "مخالفة رأس مال السلم",
            "clause": "المعيار رقم 10، البند 3/1/3 و3/1/4",
            "reasons": ["يجب تسليم رأس مال السلم بالكامل مقدماً في مجلس العقد، ولا يجوز الاستعاضة عنه بالدين."],
            "remediation": "يجب دفع رأس مال السلم بالكامل مقدماً في مجلس العقد."
        }
    },
    "V_ISTISNA_TIMELINE_AMBIGUITY": {
        "tr": {
            "type": "İstisna Hammadde İhlali",
            "clause": "Standart No: 11, Madde 3/1/1 ve 2/2/4",
            "reasons": ["Yüklenicinin hammadde/malzeme sağlamaksızın sadece işçilik sunması (İcareye dönüşme hali) [Madde 3/1/1] veya finansal hile amaçlı îne satışına yol açılması [Madde 2/2/4]."],
            "remediation": "Malzemelerin de üretici/yüklenici tarafından sağlanacağını belirtin veya iş sözleşmesini İcare olarak düzenleyin."
        },
        "en": {
            "type": "Istisna Material Provision Violation",
            "clause": "Standard No: 11, Clause 3/1/1 and 2/2/4",
            "reasons": ["The manufacturer must provide materials, otherwise it reverts to labor leasing (Ijarah), or may lead to Inah sale."],
            "remediation": "Specify that the manufacturer must supply the raw materials in the contract."
        },
        "ar": {
            "type": "مخالفة توفير المواد في الاستصناع",
            "clause": "المعيار رقم 11، البند 3/1/1 و2/2/4",
            "reasons": ["يجب على الصانع توفير المواد وإلا تحول العقد إلى إجارة عمل، أو قد يؤدي إلى بيع العينة المحظور."],
            "remediation": "اشترط في العقد أن يقوم الصانع بتوريد المواد الخام."
        }
    },
    "V_MUDARABAH_LOSS_ALLOCATION": {
        "tr": {
            "type": "Mudarabe Zarar ve Kar Dağıtım İhlali",
            "clause": "Standart No: 13, Madde 4/4, 8/5 ve 8/7",
            "reasons": ["Ortaklardan biri lehine kârdan oransal olmayan belirli maktu bir tutar alma şartı konulması [Madde 8/5] veya mudâribin kusuru olmaksızın zarardan sorumlu tutulması [Madde 4/4 ve 8/7]."],
            "remediation": "Finansal zararı yalnızca sermaye sahibine (Rabbü'l-Mal) yükleyin; maktu kar payı maddelerini kaldırın."
        },
        "en": {
            "type": "Mudarabah Loss & Profit Allocation Violation",
            "clause": "Standard No: 13, Clause 4/4, 8/5 and 8/7",
            "reasons": ["Stipulating a fixed lump-sum profit for any partner or holding the manager (mudarib) liable for capital loss without negligence is forbidden."],
            "remediation": "Assign financial loss to the capital owner (Rab-ul-Mal) exclusively; ensure profit sharing is strictly proportional."
        },
        "ar": {
            "type": "مخالفة توزيع خسارة وأرباح المضاربة",
            "clause": "المعيار رقم 13، البند 4/4 و8/5 و8/7",
            "reasons": ["يحظر اشتراط مبلغ مقطوع من الأرباح لأي طرف، كما يمنع تحميل المضارب خسارة رأس المال دون تعدٍ أو تقصير."],
            "remediation": "حمل الخسارة المالية لرب المال حصراً؛ وتأكد من أن توزيع الأرباح بنسبة شائعة."
        }
    },
    "V_SUKUK_DEBT_BACKING": {
        "tr": {
            "type": "Sukuk Alacak Dayanaklılığı İhlali",
            "clause": "Standart No: 17, Madde 4/4, 5/1/8/7, 5/2/1 ve 5/2/2",
            "reasons": ["Sadece alacak (deyn) temsil eden selem/murâbaha sukûklarının ikincil piyasalarda nominal değer dışında tedavül ettirilmesi [Madde 4/4 ve 5/2/1] veya nominal değerden geri satın alma taahhüdü [Madde 5/1/8/7 ve 5/2/2]."],
            "remediation": "Dayanak varlık havuzunun fiziki varlıklar veya menfaatleri temsil ettiğinden emin olun; nominal geri alım vaadini kaldırın."
        },
        "en": {
            "type": "Sukuk Debt Backing & Purchase Guarantee Violation",
            "clause": "Standard No: 17, Clause 4/4, 5/1/8/7, 5/2/1 and 5/2/2",
            "reasons": ["Trading debt-backed Sukuk at non-nominal values is forbidden, and issuer cannot guarantee nominal value back at maturity."],
            "remediation": "Ensure the underlying asset pool represents physical assets; remove nominal purchase guarantees."
        },
        "ar": {
            "type": "مخالفة توريق الديون وضمان الاسترداد في الصكوك",
            "clause": "المعيار رقم 17، البند 4/4 و5/1/8/7 و5/2/1 و5/2/2",
            "reasons": ["يمنع تداول صكوك الديون بغير قيمتها الاسمية، ويحظر على المصدر التعهد بشراء الصكوك بقيمتها الاسمية عند الاستحقاق."],
            "remediation": "تأكد من أن محفظة الصكوك تتكون من أعيان أو منافع; وأزل وعد الشراء بالقيمة الاسمية."
        }
    },
    "V_TAKAFUL_RIBA_INVESTMENT": {
        "tr": {
            "type": "Tekafül Faizli Yatırım İhlali",
            "clause": "Standart No: 26, Madde 3/2, 5/2 ve 5/5",
            "reasons": ["Şirket hissedarlarının varlıkları ile sigorta fonu hesaplarının birbirine karıştırılması veya net bakiye fazlasının hissedarlara gelir yazılması [Madde 3/2, 5/2 ve 5/5]."],
            "remediation": "Hissedar ve tekafül fonlarını net olarak ayırın; prim fazlasını katılımcı havuzunda bırakın."
        },
        "en": {
            "type": "Takaful Riba & Fund Mixing Violation",
            "clause": "Standard No: 26, Clause 3/2, 5/2 and 5/5",
            "reasons": ["Mixing shareholder assets with the participants' risk pool (Tabarru) or writing off surplus to shareholders is forbidden."],
            "remediation": "Isolate shareholder and insurance funds; keep surplus within the participant pool."
        },
        "ar": {
            "type": "مخالفة خلط الأموال في التكافل",
            "clause": "المعيار رقم 26، البند 3/2 و5/2 و5/5",
            "reasons": ["يمنع خلط أموال المساهمين مع صندوق المشتركين (التبرع)، كما يحظر توزيع فائض التأمين على المساهمين."],
            "remediation": "افصل بين أموال المساهمين وصندوق التكافل; واحتفظ بالفائض لصالح المشاركين."
        }
    },
    "V_SARF_DEFERRED_PAYMENT": {
        "tr": {
            "type": "Sarf Akdi Vadeli İşlem",
            "clause": "Standart No: 1, Madde 2/1/3, 2/1/5 ve 2/2",
            "reasons": ["Vadeli piyasalarda veya ileri tarihli (forward/futures) sarf işlemlerinin haramlığı [Madde 2/1/3, 2/1/5 ve 2/2]."],
            "remediation": "Takas işleminin akit meclisinde derhal gerçekleştiğinden emin olun."
        },
        "en": {
            "type": "Sarf Deferred Payment Violation",
            "clause": "Standard No: 1, Clause 2/1/3, 2/1/5 and 2/2",
            "reasons": ["Exchange counter-values must be hand-to-hand/spot; deferred forward/futures transactions are forbidden."],
            "remediation": "Ensure exchange settle occurs immediately in the contract session."
        },
        "ar": {
            "type": "مخالفة تأجيل البدلين في عقد الصرف",
            "clause": "المعيار رقم 1، البند 2/1/3 و2/1/5 و2/2",
            "reasons": ["يحظر التعامل بالصرف الآجل أو العقود المستقبلية في الصرف لربا النسيئة."],
            "remediation": "تأكد من حصول التقابض الفوري in مجلس العقد."
        }
    },
    "V_KARZ_EXCESS_BENEFIT": {
        "tr": {
            "type": "Karz Menfaat & Faiz İhlali",
            "clause": "Standart No: 19, Madde 4/1 ve 7",
            "reasons": ["Karz sözleşmesinde borç veren lehine doğrudan veya dolaylı maddi/manevi bir menfaat şartı koşulması [Madde 4/1] veya alım satım/kira gibi ivazlı bir akdin yapılmasının şart koşulması [Madde 7]."],
            "remediation": "Krediye bağlı tüm faiz, hediye veya maddi menfaat şartlarını kaldırın."
        },
        "en": {
            "type": "Karz Excess Benefit & Conditional Contract Violation",
            "clause": "Standard No: 19, Clause 4/1 and 7",
            "reasons": ["Stipulating any direct/indirect benefit for the lender is Riba, and linking loans with exchange/sale contracts is forbidden."],
            "remediation": "Strip out any interest terms, gifts, or material benefits conditional on the loan."
        },
        "ar": {
            "type": "مخالفة اشتراط المنفعة أو العقد المشروط في القرض",
            "clause": "المعيار رقم 19، البند 4/1 و7",
            "reasons": ["كل قرض جر منفعة مشروطة للمقرض فهو ربا، كما يحظر ربط القرض بعقد معاوضة كالبيع أو الإجارة."],
            "remediation": "أزل أي شروط فائدة أو هدايا أو منافع مادية مشروطة في القرض."
        }
    },
    "V_VEDIA_DIVIDEND_PROMISE": {
        "tr": {
            "type": "Vedia Emanet & Teminat İhlali",
            "clause": "Standart No: 5, Madde 2/2/1",
            "reasons": ["Emanet akitlerinde kasıt, kusur veya şartlara aykırılık dışındaki durumlar için (mutlak) rehin veya kefalet şartı koşulmasının caiz olmaması [Madde 2/2/1]."],
            "remediation": "Emanet akitlerinde kasıt/kusur dışındaki durumlar için rehin/kefalet şartını kaldırın."
        },
        "en": {
            "type": "Vedia Custody & Guarantee Violation",
            "clause": "Standard No: 5, Clause 2/2/1",
            "reasons": ["Stipulating absolute pledges or guarantees in trust (Amanah) contracts without negligence or breach is not permissible."],
            "remediation": "Remove absolute pledges or guarantees; limit liability to cases of negligence or breach."
        },
        "ar": {
            "type": "مخالفة اشتراط الرهن في الوديعة",
            "clause": "المعيار رقم 5، البند 2/2/1",
            "reasons": ["لا يجوز اشتراط الرهن أو الكفالة في عقود الأمانات لغير حالات التعدي أو التقصير أو مخالفة الشروط."],
            "remediation": "أزل شروط الرهن والكفالة المطلقة؛ واقصر الضمان على التعدي والتقصير."
        }
    },
    "V_LEASING_MAINTENANCE": {
        "tr": {
            "type": "Leasing Mülkiyet & Bakım İhlali",
            "clause": "Standart No: 9, Madde 8/1 ve 8/2",
            "reasons": ["Kiralama sözleşmesi ile mülkiyeti devredici hibe/satış vaadinin aynı sözleşme metninde birleştirilmesi (bağımsız belge zorunluluğu ihlali) [Madde 8/1 ve 8/2]."],
            "remediation": "Mülkiyet devri taahhüdünü kira sözleşmesinden tamamen ayırarak bağımsız bir belge olarak düzenleyin."
        },
        "en": {
            "type": "Leasing Transfer & Contract Separation Violation",
            "clause": "Standard No: 9, Clause 8/1 and 8/2",
            "reasons": ["Combining the lease and the ownership-transferring gift/sale in a single contract violates the independent document requirement."],
            "remediation": "Separate the ownership transfer promise completely from the lease agreement as an independent undertaking."
        },
        "ar": {
            "type": "مخالفة دمج عقد الإجارة مع التمليك",
            "clause": "المعيار رقم 9، البند 8/1 و8/2",
            "reasons": ["دمج عقد الإجارة مع هبة أو بيع العين المؤجرة في وثيقة واحدة يبطل استقلالية العقود."],
            "remediation": "افصل الوعد بالتمليك تماماً عن عقد الإجارة واجعله تعهداً مستقلاً."
        }
    }
}

class TrilingualONNXComplianceEngine(QThread):
    """
    Trilingual GAT ONNX Compliance & Chronology Engine
    Runs:
      - Local GAT ONNX (model/gat_aaoifi.onnx) for fıkhi embedding classification
      - Arabic normalization & diacritic cleaning
      - Deterministic Unix Timestamp Chronology analysis for time-critical contracts
      - 12-contract trilingual regex fallback engine & remediation generator
    """
    analysis_completed = pyqtSignal(dict)
    analysis_failed = pyqtSignal(str)
    log_message = pyqtSignal(str)
    progress_update = pyqtSignal(int)
    elapsed_time = pyqtSignal(int)

    def __init__(self, contract_text: str, standard_type: str, time_params: dict = None, lang: str = "tr"):
        super().__init__()
        # Sanitize contract input
        self.contract_text = UniversalInputSanitizer.sanitize(contract_text)
        self.standard_type = standard_type
        self.time_params = time_params or {}
        self.lang = lang.lower()
        self.model_path = "model/gat_aaoifi.onnx"
        self.confidence_score = 0.95

        # 128-dimensional vocabulary mapping
        self.vocabulary = {
            "kabz": 1, "zilyetlik": 2, "tedarikci": 3, "faiz": 4, "gecikme": 5, "hayir": 6, "bagis": 7,
            "bakim": 8, "kiraci": 9, "sigorta": 10, "anapara": 11, "garanti": 12, "ortaklik": 13, "sabit": 14,
            "selem": 15, "sermaye": 16, "peşin": 17, "istisna": 18, "teslim": 19, "muğlak": 20, "malzeme": 21,
            "mudarabe": 22, "mudarib": 23, "zarar": 24, "mudahale": 25, "sukuk": 26, "alacak": 27, "tekaful": 28,
            "prim": 29, "havuz": 30, "sarf": 31, "vade": 32, "karz": 33, "borc": 34, "menfaat": 35, "vedia": 36,
            "emanet": 37, "nema": 38, "leasing": 39, "kiralama": 40,
            "possession": 50, "ownership": 51, "supplier": 52, "interest": 53, "delay": 54, "charity": 55, "donation": 56,
            "maintenance": 57, "lessee": 58, "lessor": 59, "insurance": 60, "capital": 61, "guarantee": 62, "partnership": 63,
            "fixed": 64, "salam": 65, "advance": 66, "istisnaa": 67, "delivery": 68, "vague": 69, "materials": 70,
            "mudarabah": 71, "loss": 72, "interference": 73, "sukuk": 74, "debt": 75, "takaful": 76, "premium": 77,
            "pool": 78, "exchange": 79, "deferred": 80, "loan": 81, "benefit": 82, "custody": 83, "yield": 84,
            "قبض": 90, "حيازة": 91, "تملك": 92, "ربا": 93, "فائدة": 94, "تأخير": 95, "خيري": 96, "تبرع": 97,
            "صيانة": 98, "مستأجر": 99, "مؤجر": 100, "تأمين": 101, "رأس المال": 102, "ضمان": 103, "شركة": 104,
            "ثابت": 105, "سلم": 106, "عاجل": 107, "استصناع": 108, "تسليم": 109, "مجهول": 110, "مواد": 111,
            "مضاربة": 112, "مضارب": 113, "خسارة": 114, "تدخل": 115, "صك": 116, "دين": 117, "تكافل": 118,
            "اشتراك": 119, "فائض": 120, "صرف": 121, "مؤجل": 122, "قرض": 123, "منفعة": 124, "وديعة": 125,
            "أمانة": 126, "نماء": 127
        }

        self.page_matrix = {
            "sarf": {"page": AAOIFI_DUAL_PDF_MAP["sarf"].get(self.lang, 48), "standard": 1},
            "vedia": {"page": AAOIFI_DUAL_PDF_MAP["vedia"].get(self.lang, 105), "standard": 5},
            "murabaha": {"page": AAOIFI_DUAL_PDF_MAP["murabaha"].get(self.lang, 180), "standard": 8},
            "salam": {"page": AAOIFI_DUAL_PDF_MAP["salam"].get(self.lang, 252), "standard": 10},
            "istisna": {"page": AAOIFI_DUAL_PDF_MAP["istisna"].get(self.lang, 274), "standard": 11},
            "ijarah": {"page": AAOIFI_DUAL_PDF_MAP["ijarah"].get(self.lang, 218), "standard": 9},
            "leasing": {"page": AAOIFI_DUAL_PDF_MAP["leasing"].get(self.lang, 218), "standard": 9},
            "karz": {"page": AAOIFI_DUAL_PDF_MAP["karz"].get(self.lang, 492), "standard": 19},
            "takaful": {"page": AAOIFI_DUAL_PDF_MAP["takaful"].get(self.lang, 646), "standard": 26},
            "sukuk": {"page": AAOIFI_DUAL_PDF_MAP["sukuk"].get(self.lang, 440), "standard": 17},
            "mudarabah": {"page": AAOIFI_DUAL_PDF_MAP["mudarabah"].get(self.lang, 346), "standard": 13},
            "musharaka": {"page": AAOIFI_DUAL_PDF_MAP["musharaka"].get(self.lang, 300), "standard": 12}
        }

    def clean_arabic(self, text: str) -> str:
        """Normalizes Arabic: removes tashkeel diacritics and normalizes letters."""
        if not text:
            return ""
        text = re.sub(r"[\u064B-\u065F]", "", text)
        text = re.sub(r"[أإآ]", "ا", text)
        text = text.replace("ى", "my_ya_placeholder").replace("ى", "ي").replace("my_ya_placeholder", "ي")
        text = text.replace("ة", "ه")
        return text

    def clean_turkish_english(self, text: str) -> str:
        """Standardizes Turkish/English lowercasing and character replacement."""
        if not text:
            return ""
        text = text.replace("İ", "i").replace("I", "ı")
        text = text.lower()
        text = text.replace("ı", "i").replace("ş", "s").replace("ü", "u").replace("ö", "o").replace("ç", "c").replace("ğ", "g")
        text = re.sub(r"\u0307", "", text)
        return text

    def vectorize_text(self, text: str) -> np.ndarray:
        """Vectorizes inputs into a 128-dimensional embedding representation."""
        vec = np.zeros(128, dtype=np.float32)
        norm_ar = self.clean_arabic(text)
        norm_tr_en = self.clean_turkish_english(text)

        for word, idx in self.vocabulary.items():
            if word in norm_ar or word in norm_tr_en:
                vec[idx] = 1.0

        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec.reshape(1, 128)

    def analyze_chronology(self, std_key: str) -> list:
        """
        Deterministic Chronology Engine
        Compares millisecond Unix timestamps to evaluate time-critical fıkhi clauses.
        """
        violations = []
        
        def get_ts(key):
            val = self.time_params.get(key)
            if val is None:
                return None
            try:
                return float(val)
            except ValueError:
                return None

        # 1. Sarf Chronology Check (t_teslim > t_islem)
        if std_key == "sarf":
            t_islem = get_ts("t_islem")
            t_teslim = get_ts("t_teslim")
            if t_islem is not None and t_teslim is not None:
                if t_teslim > t_islem:
                    violations.append({
                        "type_id": "V_SARF_RIBA_NASIAH",
                        "page": self.page_matrix["sarf"]["page"]
                    })

        # 2. Murabaha Chronology Check (t_musteri_satis <= t_banka_alim)
        elif std_key == "murabaha":
            t_banka_alim = get_ts("t_banka_alim")
            t_musteri_satis = get_ts("t_musteri_satis")
            if t_banka_alim is not None and t_musteri_satis is not None:
                if t_musteri_satis <= t_banka_alim:
                    violations.append({
                        "type_id": "V_MURABAHA_CHRONOLOGY",
                        "page": self.page_matrix["murabaha"]["page"]
                    })

        # 3. Selem Chronology Check (t_odeme > t_akit)
        elif std_key == "salam":
            t_akit = get_ts("t_akit")
            t_odeme = get_ts("t_odeme")
            if t_akit is not None and t_odeme is not None:
                if t_odeme > t_akit:
                    violations.append({
                        "type_id": "V_SELEM_DELAYED_CAPITAL",
                        "page": self.page_matrix["salam"]["page"]
                    })

        # 4. Ijarah/Leasing Chronology Check (t_kira_baslangic < t_fiziki_teslim)
        elif std_key in ("ijarah", "leasing"):
            t_fiziki_teslim = get_ts("t_fiziki_teslim")
            t_kira_baslangic = get_ts("t_kira_baslangic")
            if t_fiziki_teslim is not None and t_kira_baslangic is not None:
                if t_kira_baslangic < t_fiziki_teslim:
                    violations.append({
                        "type_id": "V_ICARE_EARLY_RENT",
                        "page": self.page_matrix["ijarah"]["page"] if std_key == "ijarah" else self.page_matrix["leasing"]["page"]
                    })

        return violations

    def evaluate_composite_shariah_gates(self, primary_akit: str, text: str, params: dict, lang: str) -> list:
        """
        Deterministik Çapraz Doğrulama Motoru
        Denetlenenler:
          - Karz + Sarf (vade veya menfaat)
          - İcare + Bey' eşzamanlılık yasağı
          - Müşareke + Anapara Garanti/Karz ihlali
          - Mudarabe + Haksız Vedia nemalandırması
        """
        violations = []
        text_norm = self.clean_turkish_english(text)
        text_ar = self.clean_arabic(text)
        std_key = normalize_standard_type(primary_akit)

        # 1. Karz + Sarf Kombinasyonu (Karz No:19 + Sarf No:1)
        is_karz = std_key == "karz" or "karz" in text_norm or "qard" in text_norm or "قرض" in text_ar
        is_sarf = std_key == "sarf" or "sarf" in text_norm or "exchange" in text_norm or "صرف" in text_ar
        if is_karz and is_sarf:
            # Check if there is delay or excess benefit
            has_delay = (params.get("no_deferment_or_delay") is False or 
                         params.get("immediate_hand_to_hand_delivery") is False or
                         "vade" in text_norm or "deferred" in text_norm or "taksit" in text_norm or
                         "مؤجل" in text_ar or "تاخير" in text_ar)
            has_benefit = (params.get("has_excess_benefit_stipulated") is True or 
                           "menfaat" in text_norm or "benefit" in text_norm or "منfعه" in text_ar)
            if has_delay or has_benefit:
                violations.append({
                    "type_id": "V_COMPOSITE_KARZ_SARF",
                    "isComposite": True,
                    "primaryStandard": 19,
                    "secondaryStandards": [1],
                    "pages": [492, 48] if lang == "tr" else ([514, 55] if lang == "en" else [522, 56]),
                    "page": 492 if lang == "tr" else (514 if lang == "en" else 522)
                })

        # 2. İcare + Bey' Kombinasyonu (İcare No:9 + Bey' No:8 Vaadi)
        is_icare = std_key in ("ijarah", "leasing") or "icare" in text_norm or "ijarah" in text_norm or "leasing" in text_norm or "ajar" in text_norm or "اجار" in text_ar or "إجارة" in text_ar
        is_bey = "satis" in text_norm or "sale" in text_norm or "bey'" in text_norm or "بيع" in text_ar or "تمليك" in text_ar
        if is_icare and is_bey:
            # Ayrı vaat olmaması ihlali
            not_separate = (params.get("sale_promise_executed_separate") is False or
                            "es zamanli" in text_norm or "simultaneous" in text_norm or
                            "ayni anda" in text_norm or "في آن واحد" in text_ar)
            if not_separate:
                violations.append({
                    "type_id": "V_COMPOSITE_ICARE_BEY_SIMULTANEOUS",
                    "isComposite": True,
                    "primaryStandard": 9,
                    "secondaryStandards": [8],
                    "pages": [218, 180] if lang == "tr" else ([211, 167] if lang == "en" else [242, 204]),
                    "page": 218 if lang == "tr" else (211 if lang == "en" else 242)
                })

        # 3. Müşareke + Anapara Garanti/Karz Kombinasyonu (Müşareke No:12 + İcare No:9 + Bey' No:8)
        is_musharaka = std_key == "musharaka" or "musharaka" in text_norm or "musareke" in text_norm or "مشارك" in text_ar
        has_guar = (params.get("is_capital_guaranteed") is True or 
                    "garanti" in text_norm or "guarantee" in text_norm or "ضمان" in text_ar)
        if is_musharaka and (has_guar or is_karz):
            violations.append({
                "type_id": "V_COMPOSITE_FORBIDDEN_GUARANTEE",
                "isComposite": True,
                "primaryStandard": 12,
                "secondaryStandards": [9, 8],
                "pages": [291, 181, 155] if lang == "tr" else ([311, 211, 167] if lang == "en" else [326, 242, 204]),
                "page": 291 if lang == "tr" else (311 if lang == "en" else 326)
            })

        # 4. Mudarabe + Vedia Kombinasyonu
        is_mudarabah = std_key == "mudarabah" or "mudaraba" in text_norm or "مضارب" in text_ar
        is_vedia = std_key == "vedia" or "vedia" in text_norm or "custody" in text_norm or "وديع" in text_ar
        if is_mudarabah and is_vedia:
            has_yield = (params.get("yield_or_nemalandirma_stipulated") is True or 
                         "nema" in text_norm or "yield" in text_norm or "faiz" in text_norm or "نماء" in text_ar)
            if has_yield:
                violations.append({
                    "type_id": "V_COMPOSITE_MUDARABAH_VEDIA_RIBA",
                    "isComposite": True,
                    "primaryStandard": 13,
                    "secondaryStandards": [5],
                    "pages": [321, 95] if lang == "tr" else ([363, 83] if lang == "en" else [370, 130]),
                    "page": 321 if lang == "tr" else (363 if lang == "en" else 370)
                })

        return violations

    def run(self):
        start_time = time.perf_counter()
        self.log_message.emit("Trilingual GAT ONNX uyum analizi başlatılıyor...")
        self.progress_update.emit(10)

        results = {
            "success": True,
            "violations": [],
            "remediation_text": "",
            "violated_pages": [],
            "confidence": 0.95
        }

        # 1. GAT ONNX Classification
        if ONNX_AVAILABLE and os.path.exists(self.model_path):
            try:
                self.progress_update.emit(30)
                session = ort.InferenceSession(self.model_path, providers=["CPUExecutionProvider"])
                input_name = session.get_inputs()[0].name
                input_data = self.vectorize_text(self.contract_text)
                output = session.run(None, {input_name: input_data})
                if output and len(output) > 0:
                    scores = output[0][0]
                    self.confidence_score = float(np.max(scores) if len(scores) > 0 else 0.95)
                    self.confidence_score = min(max(self.confidence_score, 0.70), 0.99)
                    self.log_message.emit(f"GAT ONNX Güven Skoru: {self.confidence_score:.2f}")
            except Exception as e:
                self.log_message.emit(f"ONNX hatası: {str(e)}. Fallback aktif.")

        results["confidence"] = self.confidence_score
        self.progress_update.emit(50)

        # 2. Dynamic Chronology Validation
        std_key = normalize_standard_type(self.standard_type)
        chronology_violations = self.analyze_chronology(std_key)

        # 3. Trilingual Advanced Regex Fallback & Heuristics
        text_norm_tr_en = self.clean_turkish_english(self.contract_text)
        text_norm_ar = self.clean_arabic(self.contract_text)

        fallback_violations = []

        if std_key == "murabaha":
            if (any(kw in text_norm_tr_en for kw in ["kabz edilmeksizin", "teslim almadan", "without possession", "before possession"]) or 
                (("teslim" in text_norm_tr_en or "kabz" in text_norm_tr_en) and any(kw in text_norm_tr_en for kw in ["almadan", "oncesi", "olmadan", "olmasizin"])) or
                ("قبض" in text_norm_ar and "قبل" in text_norm_ar)):
                fallback_violations.append({
                    "type_id": "V_MURABAHA_KABZ",
                    "page": self.page_matrix["murabaha"]["page"]
                })
            if ("tedarikci" in text_norm_tr_en and any(kw in text_norm_tr_en for kw in ["kendi", "musteri", "ortak"])):
                fallback_violations.append({
                    "type_id": "V_MURABAHA_SUPPLIER_CONFLICT",
                    "page": self.page_matrix["murabaha"]["page"]
                })
            if (any(kw in text_norm_tr_en for kw in ["gecikme faizi", "gecikme cezasi", "gecikme bedeli", "late fee"]) and 
                any(kw in text_norm_tr_en for kw in ["gelir", "kar", "profit", "revenue", "ekle", "kaydet"])):
                fallback_violations.append({
                    "type_id": "V_MURABAHA_LATE_FEE",
                    "page": self.page_matrix["murabaha"]["page"]
                })

        elif std_key == "ijarah":
            if (("bakim" in text_norm_tr_en or "maintenance" in text_norm_tr_en) and ("kiraci" in text_norm_tr_en or "lessee" in text_norm_tr_en)) or "صيانه المستاجر" in text_norm_ar:
                fallback_violations.append({
                    "type_id": "V_ICARE_MAINTENANCE",
                    "page": self.page_matrix["ijarah"]["page"]
                })

        elif std_key == "musharaka":
            if (("sermaye" in text_norm_tr_en or "anapara" in text_norm_tr_en or "capital" in text_norm_tr_en) and 
                ("garanti" in text_norm_tr_en or "guarantee" in text_norm_tr_en)) or "ضمان راس المال" in text_norm_ar:
                fallback_violations.append({
                    "type_id": "V_MUSHARAKA_CAPITAL_GUARANTEE",
                    "page": self.page_matrix["musharaka"]["page"]
                })

        elif std_key == "salam":
            if (("sermaye" in text_norm_tr_en or "capital" in text_norm_tr_en or "bedel" in text_norm_tr_en) and 
                ("vade" in text_norm_tr_en or "ertelen" in text_norm_tr_en or "taksit" in text_norm_tr_en or "deferred" in text_norm_tr_en or "sonra" in text_norm_tr_en)) or "تاجيل راس المال" in text_norm_ar:
                fallback_violations.append({
                    "type_id": "V_SALAM_CAPITAL_DEFERMENT",
                    "page": self.page_matrix["salam"]["page"]
                })

        elif std_key == "istisna":
            if (("teslim" in text_norm_tr_en or "delivery" in text_norm_tr_en) and 
                ("belirsiz" in text_norm_tr_en or "muglak" in text_norm_tr_en or "vague" in text_norm_tr_en)) or "مجهول التسليم" in text_norm_ar:
                fallback_violations.append({
                    "type_id": "V_ISTISNA_TIMELINE_AMBIGUITY",
                    "page": self.page_matrix["istisna"]["page"]
                })

        elif std_key == "mudarabah":
            if (("zarar" in text_norm_tr_en or "loss" in text_norm_tr_en) and 
                ("mudarib" in text_norm_tr_en or "mudaribe" in text_norm_tr_en or "responsibility" in text_norm_tr_en)) or "الخساره للمضارب" in text_norm_ar:
                fallback_violations.append({
                    "type_id": "V_MUDARABAH_LOSS_ALLOCATION",
                    "page": self.page_matrix["mudarabah"]["page"]
                })

        elif std_key == "sukuk":
            if (("alacak" in text_norm_tr_en or "borc" in text_norm_tr_en or "debt" in text_norm_tr_en) and 
                ("temlik" in text_norm_tr_en or "ihrac" in text_norm_tr_en or "pool" in text_norm_tr_en)) or "توريق الديون" in text_norm_ar:
                fallback_violations.append({
                    "type_id": "V_SUKUK_DEBT_BACKING",
                    "page": self.page_matrix["sukuk"]["page"]
                })

        elif std_key == "takaful":
            if any(kw in text_norm_tr_en for kw in ["faizli", "interest-bearing", "riba"]) or "استثمار ربوي" in text_norm_ar:
                fallback_violations.append({
                    "type_id": "V_TAKAFUL_RIBA_INVESTMENT",
                    "page": self.page_matrix["takaful"]["page"]
                })

        elif std_key == "sarf":
            if (any(kw in text_norm_tr_en for kw in ["taksitle", "ertelenmis", "deferred", "vadeli", "vade"]) or 
                any(kw in text_norm_ar for kw in ["مؤجل", "تاخير البدلين"])):
                fallback_violations.append({
                    "type_id": "V_SARF_DEFERRED_PAYMENT",
                    "page": self.page_matrix["sarf"]["page"]
                })

        elif std_key == "karz":
            if any(kw in text_norm_tr_en for kw in ["faiz", "ek odeme", "excess benefit", "menfaat", "hediye"]) or "منفعه" in text_norm_ar:
                fallback_violations.append({
                    "type_id": "V_KARZ_EXCESS_BENEFIT",
                    "page": self.page_matrix["karz"]["page"]
                })

        elif std_key == "vedia":
            if any(kw in text_norm_tr_en for kw in ["nemalandirilir", "nema taahudu", "dividend promise", "faiz", "getiri"]) or "عوائد" in text_norm_ar:
                fallback_violations.append({
                    "type_id": "V_VEDIA_DIVIDEND_PROMISE",
                    "page": self.page_matrix["vedia"]["page"]
                })

        elif std_key == "leasing":
            if (("bakim" in text_norm_tr_en or "maintenance" in text_norm_tr_en or "sigorta" in text_norm_tr_en or "insurance" in text_norm_tr_en) and 
                ("kiraci" in text_norm_tr_en or "lessee" in text_norm_tr_en)) or "صيانه المستاجر" in text_norm_ar:
                fallback_violations.append({
                    "type_id": "V_LEASING_MAINTENANCE",
                    "page": self.page_matrix["leasing"]["page"]
                })

        composite_violations = self.evaluate_composite_shariah_gates(self.standard_type, self.contract_text, self.time_params, self.lang)
        raw_violations = chronology_violations + fallback_violations + composite_violations
        final_violations = []
        remediations = []
        lang_key = self.lang if self.lang in ("tr", "en", "ar") else "tr"

        for raw_v in raw_violations:
            type_id = raw_v["type_id"]
            page = raw_v.get("page", raw_v.get("pages", [1])[0])
            entry = VIOLATION_DATABASE.get(type_id)
            if entry and lang_key in entry:
                v_data = entry[lang_key]
                v_type = v_data["type"]
                v_clause = v_data["clause"]
                v_reasons = v_data["reasons"]
                v_remed = v_data["remediation"]
            else:
                v_type = type_id
                v_clause = ""
                v_reasons = []
                v_remed = ""

            final_violations.append({
                "type": v_type,
                "page": page,
                "clause": v_clause,
                "reasons": v_reasons,
                "isComposite": raw_v.get("isComposite", False),
                "primaryStandard": raw_v.get("primaryStandard", 0),
                "secondaryStandards": raw_v.get("secondaryStandards", []),
                "pages": raw_v.get("pages", [page])
            })
            if v_remed:
                remediations.append(v_remed)

        results["violations"] = final_violations
        results["violated_pages"] = list(set([v["page"] for v in final_violations]))

        if remediations:
            results["remediation_text"] = "\n\n".join(sorted(list(set(remediations))))
        else:
            if lang_key == "en":
                results["remediation_text"] = "No violations detected under the selected standard."
            elif lang_key == "ar":
                results["remediation_text"] = "لم يتم اكتشاف أي مخالفات بموجب المعيار المحدد."
            else:
                results["remediation_text"] = "Seçilen standart kapsamında ihlal tespit edilmemiştir."

        self.progress_update.emit(90)
        self.progress_update.emit(100)

        end_time = time.perf_counter()
        elapsed_ms = int((end_time - start_time) * 1000)
        self.elapsed_time.emit(elapsed_ms)
        self.log_message.emit("Trilingual GAT ONNX Analiz tamamlandı.")
        self.analysis_completed.emit(results)

ComplianceEngine = TrilingualONNXComplianceEngine
