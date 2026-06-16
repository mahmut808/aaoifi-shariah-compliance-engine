# file: /home/mahmut/Desktop/uyumprotokol/app_main.py
import os
import sys
import time
import re
import argparse
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QGridLayout, QVBoxLayout, QHBoxLayout,
    QLabel, QTextEdit, QPushButton, QComboBox, QFrame, QScrollArea, QProgressBar,
    QFileDialog, QMessageBox, QDateTimeEdit
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal, QTimer, QDateTime

from PyQt6.QtGui import (
    QFont, QIcon, QPixmap, QPainter, QPainterPath, QColor, QLinearGradient, QBrush, QPen
)

from ui.heatmap import ComplianceHeatmap
from ui.pdf_viewer import PdfViewerWidget
from core.compliance_engine import ComplianceEngine
from core.security_sanitizer import UniversalInputSanitizer

# ==========================================
# Clickable Risk Card Widget
# ==========================================
class ClickableRiskCard(QFrame):
    clicked = pyqtSignal(int)

    def __init__(self, violation, idx, lang="tr", parent=None):
        super().__init__(parent)
        self.violation = violation
        self.idx = idx
        self.lang = lang.lower()
        self.page = violation['page']
        self.setObjectName(f"risk_card_{idx}")
        self.init_ui()

    def init_ui(self):
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.set_selected(False)
        
        card_layout = QVBoxLayout(self)
        card_layout.setContentsMargins(10, 10, 10, 10)
        card_layout.setSpacing(4)
        
        confidence = self.violation.get('confidence', 0.95)
        title_text = f"⚠️ {self.violation['type']} ({confidence*100:.0f}%)"
        title = QLabel(title_text)
        title.setStyleSheet("color: #ef4444; font-weight: bold; font-size: 13px; background: transparent;")
        card_layout.addWidget(title)
        
        if self.lang == "en":
            clause_prefix = "Clause"
            unknown_text = "Unknown"
        elif self.lang == "ar":
            clause_prefix = "البند"
            unknown_text = "غير معروف"
        else:
            clause_prefix = "Madde"
            unknown_text = "Bilinmiyor"

        clause_lbl = QLabel(f"{clause_prefix}: {self.violation.get('clause', unknown_text)}")
        clause_lbl.setStyleSheet("color: #f87171; font-size: 12px; font-weight: bold; background: transparent;")
        card_layout.addWidget(clause_lbl)
        
        for reason in self.violation['reasons']:
            r_lbl = QLabel(reason)
            r_lbl.setWordWrap(True)
            r_lbl.setStyleSheet("color: #94a3b8; font-size: 12px; background: transparent;")
            card_layout.addWidget(r_lbl)

        # If composite, add a horizontal layout for the pages
        if self.violation.get('isComposite', False) and len(self.violation.get('pages', [])) > 1:
            pages_layout = QHBoxLayout()
            pages_layout.setSpacing(4)
            for idx, p in enumerate(self.violation['pages']):
                if self.lang == "en":
                    btn_txt = f"Page {p}"
                    btn_txt += " (Primary)" if idx == 0 else " (Secondary)"
                elif self.lang == "ar":
                    btn_txt = f"صفحة {p}"
                    btn_txt += " (رئيسي)" if idx == 0 else " (ثانوي)"
                else:
                    btn_txt = f"Sayfa {p}"
                    btn_txt += " (Birincil)" if idx == 0 else " (İkincil)"
                
                btn = QPushButton(btn_txt)
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #1e293b;
                        color: #f8fafc;
                        border: 1px solid #475569;
                        border-radius: 4px;
                        padding: 3px 6px;
                        font-size: 11px;
                    }
                    QPushButton:hover {
                        background-color: #ef4444;
                        border-color: #ef4444;
                    }
                """)
                # Capture current page value in default argument
                btn.clicked.connect(lambda checked, page_val=p, is_sec=(idx > 0): self.on_page_btn_clicked(page_val, is_sec))
                pages_layout.addWidget(btn)
            card_layout.addLayout(pages_layout)

    def on_page_btn_clicked(self, page_val, is_secondary):
        parent_window = self.window()
        if is_secondary and hasattr(parent_window, "pdf_view") and hasattr(parent_window.pdf_view, "smooth_scroll_to_page"):
            parent_window.pdf_view.smooth_scroll_to_page(page_val)
            # update label indicator
            if hasattr(parent_window, "lbl_page_indicator") and hasattr(parent_window, "TRANSLATIONS"):
                tr = parent_window.TRANSLATIONS[self.lang]
                total_p = 1398 if self.lang == "tr" else (1264 if self.lang == "en" else 1388)
                parent_window.lbl_page_indicator.setText(f"{tr['page_ind']} {page_val} / {total_p}")
        else:
            self.clicked.emit(page_val)

    def set_selected(self, selected=True):
        if selected:
            self.setStyleSheet("""
                QFrame {
                    background-color: #1e293b;
                    border: 2px solid #ef4444;
                    border-radius: 6px;
                    margin-bottom: 3px;
                }
            """)
        else:
            self.setStyleSheet("""
                QFrame {
                    background-color: #111a2e;
                    border: 1px solid #991b1b;
                    border-radius: 6px;
                    margin-bottom: 3px;
                }
                QFrame:hover {
                    background-color: #1a263f;
                    border-color: #ef4444;
                }
            """)

    def mousePressEvent(self, event):
        self.clicked.emit(self.page)
        super().mousePressEvent(event)

# ==========================================
# Drag & Drop File Loader Widget
# ==========================================
class DragDropFrame(QFrame):
    fileDropped = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Sunken)
        self.setObjectName("DragDropFrame")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 20, 15, 20)
        layout.setSpacing(8)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.lbl_text = QLabel("Sözleşmenizi Yükleyin\nSürükle Bırak")
        self.lbl_text.setStyleSheet("font-size: 13px; font-weight: bold; color: #f8fafc; background: transparent;")
        self.lbl_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.lbl_text)

        self.setStyleSheet("""
            QFrame#DragDropFrame {
                background-color: #0f172a;
                border: 1px dashed #334155;
                border-radius: 8px;
            }
            QFrame#DragDropFrame:hover {
                background-color: #1e293b;
                border: 1px dashed #475569;
            }
        """)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            self.setStyleSheet("""
                QFrame#DragDropFrame {
                    background-color: #1e293b;
                    border: 2px dashed #475569;
                }
            """)
            event.acceptProposedAction()

    def dragLeaveEvent(self, event):
        self.setStyleSheet("""
            QFrame#DragDropFrame {
                background-color: #0f172a;
                border: 1px dashed #334155;
                border-radius: 8px;
            }
        """)

    def dropEvent(self, event):
        self.setStyleSheet("""
            QFrame#DragDropFrame {
                background-color: #0f172a;
                border: 1px dashed #334155;
                border-radius: 8px;
            }
        """)
        parent_window = self.window()
        current_lang = "tr"
        if hasattr(parent_window, "current_lang"):
            current_lang = parent_window.current_lang

        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if os.path.exists(file_path):
                ext = os.path.splitext(file_path)[1].lower()
                if ext in ('.pdf', '.md', '.txt', '.docx'):
                    self.fileDropped.emit(file_path)
                else:
                    if current_lang == "en":
                        title = "Error"
                        msg = f"Extension error: '{ext}' is not accepted.\nYou can only upload files with .pdf, .md, .txt, .docx extensions."
                    elif current_lang == "ar":
                        title = "خطأ"
                        msg = f"خطأ في الامتداد: '{ext}' غير مقبول.\nيمكنك فقط تحميل الملفات ذات الامتدادات .pdf، .md، .txt، .docx."
                    else:
                        title = "Hata"
                        msg = f"Uzantı hatası: '{ext}' kabul edilmiyor.\nYalnızca .pdf, .md, .txt, .docx uzantılı dosyalar yükleyebilirsiniz."
                    QMessageBox.critical(self, title, msg)
                break

    def mousePressEvent(self, event):
        parent_window = self.window()
        current_lang = "tr"
        if hasattr(parent_window, "current_lang"):
            current_lang = parent_window.current_lang

        if current_lang == "en":
            dialog_title = "Select Contract File"
            file_filter = "Supported Files (*.pdf *.md *.txt *.docx)"
        elif current_lang == "ar":
            dialog_title = "اختر ملف العقد"
            file_filter = "الملفات المدعومة (*.pdf *.md *.txt *.docx)"
        else:
            dialog_title = "Sözleşme Dosyası Seçin"
            file_filter = "Desteklenen Dosyalar (*.pdf *.md *.txt *.docx)"

        file_path, _ = QFileDialog.getOpenFileName(
            self, dialog_title, "", file_filter
        )
        if file_path:
            ext = os.path.splitext(file_path)[1].lower()
            if ext in ('.pdf', '.md', '.txt', '.docx'):
                self.fileDropped.emit(file_path)
            else:
                if current_lang == "en":
                    title = "Error"
                    msg = f"Extension error: '{ext}' is not accepted.\nYou can only upload files with .pdf, .md, .txt, .docx extensions."
                elif current_lang == "ar":
                    title = "خطأ"
                    msg = f"خطأ في الامتداد: '{ext}' غير مقبول.\nيمكنك فقط تحميل الملفات ذات الامتدادات .pdf، .md، .txt، .docx."
                else:
                    title = "Hata"
                    msg = f"Uzantı hatası: '{ext}' kabul edilmiyor.\nYalnızca .pdf, .md, .txt, .docx uzantılı dosyalar yükleyebilirsiniz."
                QMessageBox.critical(self, title, msg)


# ==========================================
# Main QMainWindow Application Body
# ==========================================
class UyumProtokoluApp(QMainWindow):
    STANDARD_RANGES_TR = {
        "Sarf (Standart No: 1)": (48, 77),
        "Vedia (Standart No: 5)": (105, 134),
        "Murabaha (Standart No: 8)": (180, 217),
        "İcare (Standart No: 9)": (218, 251),
        "Leasing (Standart No: 9)": (218, 251),
        "Selem (Standart No: 10)": (252, 273),
        "İstisna (Standart No: 11)": (274, 299),
        "Müşareke (Standart No: 12)": (300, 345),
        "Mudarabe (Standart No: 13)": (346, 373),
        "Sukuk (Standart No: 17)": (440, 491),
        "Karz (Standart No: 19)": (492, 512),
        "Tekafül (Standart No: 26)": (646, 735)
    }

    STANDARD_RANGES_EN = {
        "Sarf (Standard No: 1)": (55, 82),
        "Vedia (Standard No: 5)": (68, 166),
        "Murabaha (Standard No: 8)": (167, 210),
        "Ijarah (Standard No: 9)": (211, 242),
        "Leasing (Standard No: 9)": (243, 284),
        "Salam (Standard No: 10)": (285, 298),
        "Istisna (Standard No: 11)": (299, 326),
        "Musharaka (Standard No: 12)": (327, 362),
        "Mudarabah (Standard No: 13)": (363, 418),
        "Sukuk (Standard No: 17)": (419, 484),
        "Karz (Standard No: 19)": (514, 592),
        "Takaful (Standard No: 26)": (593, 680)
    }

    STANDARD_RANGES_AR = {
        "الصرف (معيار رقم 1)": (56, 77),
        "الوديعة (معيار رقم 5)": (130, 155),
        "المرابحة (معيار رقم 8)": (204, 241),
        "الإجارة (معيار رقم 9)": (242, 259),
        "الـLeasing (معيار رقم 9)": (260, 275),
        "السلم (معيار رقم 10)": (276, 297),
        "الاستصناع (معيار رقم 11)": (298, 325),
        "المشاركة (معيار رقم 12)": (326, 369),
        "المضاربة (معيار رقم 13)": (370, 381),
        "الصكوك (معيار رقم 17)": (468, 481),
        "القرض (معيار رقم 19)": (522, 545),
        "التكافل (معيار رقم 26)": (686, 699)
    }

    TRANSLATIONS = {
        "tr": {
            "title": "Uyum Protokolü: GAT ONNX Masaüstü UX",
            "left_title": "Parametreler & Girdi",
            "lbl_select_std": "AAOIFI Standardı Seçimi:",
            "lbl_contract_text": "Sözleşme Metni:",
            "btn_analyze": "Uyum Analizini Çalıştır",
            "lbl_report": "İhlal Raporu:",
            "lbl_remed_title": "Fıkhi Düzeltme Maddesi:",
            "btn_copy_remediation": "Düzeltme Metnini Kopyala",
            "btn_jump": "İlgili Maddeye Git",
            "right_title": "Bulgular & Düzeltme",
            "drag_text": "Sözleşmenizi Yükleyin\nSürükle Bırak",
            "page_ind": "AAOIFI Kitap Sayfası:",
            "heatmap_title": "Uyum Isı Haritası",
            "ready": "PDF Yüklendi. Analiz için hazır.",
            "success": "Analiz Süresi: {elapsed} ms | Durum: Başarılı",
            "pdf_error": "HATA: Standartlar kitabı PDF bulunamadı."
        },
        "en": {
            "title": "Compliance Protocol: GAT ONNX Desktop UX",
            "left_title": "Parameters & Input",
            "lbl_select_std": "AAOIFI Standard Selection:",
            "lbl_contract_text": "Contract Text:",
            "btn_analyze": "Run Compliance Analysis",
            "lbl_report": "Violation Report:",
            "lbl_remed_title": "Shariah Remediation Clause:",
            "btn_copy_remediation": "Copy Remediation Text",
            "btn_jump": "Go to Page/Clause",
            "right_title": "Findings & Remediation",
            "drag_text": "Upload Contract\nDrag & Drop",
            "page_ind": "AAOIFI Book Page:",
            "heatmap_title": "Compliance Heatmap Grid",
            "ready": "PDF Loaded. Ready for analysis.",
            "success": "Analysis Duration: {elapsed} ms | Status: Success",
            "pdf_error": "ERROR: Standards book PDF not found."
        },
        "ar": {
            "title": "بروتوكول التوافق: واجهة GAT ONNX",
            "left_title": "المعلمات والمدخلات",
            "lbl_select_std": "اختيار معيار أيوفي:",
            "lbl_contract_text": "نص العقد:",
            "btn_analyze": "تشغيل تحليل التوافق",
            "lbl_report": "تقرير الانتهاكات المكتشفة:",
            "lbl_remed_title": "بند المعالجة الفقهية المقترح:",
            "btn_copy_remediation": "نسخ بند المعالجة",
            "btn_jump": "الانتقال إلى البند/الصفحة",
            "right_title": "النتائج والمعالجة",
            "drag_text": "تحميل العقد\nسحب وإفلات",
            "page_ind": "صفحة كتاب أيوفي:",
            "heatmap_title": "خريطة التمثيل الحراري للتوافق",
            "ready": "تم تحميل ملف PDF. جاهز للتحليل.",
            "success": "مدة التحليل: {elapsed} ملي ثانية | الحالة: نجاح",
            "pdf_error": "خطأ: لم يتم العثور على ملف PDF الخاص بكتاب المعايير."
        }
    }

    def __init__(self):
        super().__init__()
        self.current_lang = "tr"
        self.STANDARD_RANGES = self.STANDARD_RANGES_TR
        self.setWindowTitle("Uyum Protokolü: GAT ONNX Masaüstü UX")
        
        # Fixed resolution
        self.setFixedSize(1440, 850)
        
        self.pdf_file_path = "Faizsiz Finans Standartları AAOIFI (Güncellenmiş Versiyon).pdf"
        self.active_violations = []
        self.compliance_thread = None
        self.selected_violation_page = None
        self.risk_cards = []

        self.init_ui()
        self.load_defaults()

    def init_ui(self):
        app_font = QFont("Inter", 12)
        self.setFont(app_font)

        central_widget = QWidget(self)
        central_widget.setObjectName("centralWidget")
        self.setCentralWidget(central_widget)

        main_grid = QGridLayout(central_widget)
        main_grid.setContentsMargins(15, 15, 15, 15)
        main_grid.setSpacing(15)

        self.setStyleSheet("""
            QMainWindow { background-color: #0b1120; }
            QFrame { background-color: #111827; border: 1px solid #1f2937; border-radius: 8px; }
            QLabel { color: #f8fafc; font-family: 'Inter', sans-serif; font-size: 14px; }
            QTextEdit { background-color: #1e293b; border: 1px solid #334155; color: #f1f5f9; font-size: 14px; border-radius: 6px; padding: 6px; }
            QTextEdit:focus { border: 1px solid #3b82f6; }
            QComboBox { background-color: #1e293b; border: 1px solid #334155; color: #f8fafc; padding: 6px; border-radius: 6px; font-weight: bold; }
            QPushButton { background-color: #2563eb; color: #ffffff; font-weight: bold; border-radius: 6px; padding: 8px 12px; border: 1px solid #3b82f6; }
            QPushButton:hover { background-color: #1d4ed8; }
            QProgressBar { border: 1px solid #334155; background-color: #1e293b; text-align: center; color: #ffffff; font-weight: bold; border-radius: 6px; }
            QProgressBar::chunk { background-color: #2563eb; border-radius: 5px; }

            /* QFileDialog override styling to ensure readability on light themes */
            QFileDialog { background-color: #ffffff; color: #000000; }
            QFileDialog QLabel { color: #000000; font-family: 'Inter', sans-serif; }
            QFileDialog QLineEdit { background-color: #ffffff; color: #000000; border: 1px solid #cbd5e1; }
            QFileDialog QComboBox { background-color: #ffffff; color: #000000; border: 1px solid #cbd5e1; padding: 2px; }
            QFileDialog QComboBox QAbstractItemView { background-color: #ffffff; color: #000000; }
            QFileDialog QTreeView { background-color: #ffffff; color: #000000; border: 1px solid #cbd5e1; }
            QFileDialog QTreeView::item { color: #000000; }
            QFileDialog QTreeView::item:hover { background-color: #e2e8f0; }
            QFileDialog QTreeView::item:selected { background-color: #3b82f6; color: #ffffff; }
            QFileDialog QListView { background-color: #ffffff; color: #000000; border: 1px solid #cbd5e1; }
            QFileDialog QListView::item { color: #000000; }
            QFileDialog QListView::item:hover { background-color: #e2e8f0; }
            QFileDialog QListView::item:selected { background-color: #3b82f6; color: #ffffff; }
            QFileDialog QPushButton { background-color: #e2e8f0; color: #0f172a; border: 1px solid #cbd5e1; font-weight: bold; padding: 6px 12px; }
            QFileDialog QPushButton:hover { background-color: #cbd5e1; }
            QFileDialog QHeaderView::section { background-color: #f1f5f9; color: #0f172a; border: 1px solid #e2e8f0; }
            QFileDialog QToolButton { background-color: #e2e8f0; color: #0f172a; border: 1px solid #cbd5e1; }
            QFileDialog QToolButton:hover { background-color: #cbd5e1; }
        """)

        # LEFT PANEL
        left_panel = QFrame()
        left_panel.setFixedWidth(340)
        left_panel.setMaximumHeight(820)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(12, 12, 12, 12)
        left_layout.setSpacing(8)

        left_layout.addWidget(QLabel("Dil / Language / اللغة:"))
        self.combo_lang = QComboBox()
        self.combo_lang.addItem("Türkçe (TR)", "tr")
        self.combo_lang.addItem("English (EN)", "en")
        self.combo_lang.addItem("العربية (AR)", "ar")
        self.combo_lang.currentIndexChanged.connect(self.on_language_changed)
        left_layout.addWidget(self.combo_lang)

        self.left_title = QLabel("Parametreler & Girdi")
        self.left_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #3b82f6;")
        left_layout.addWidget(self.left_title)

        self.lbl_select_std = QLabel("AAOIFI Standardı Seçimi:")
        left_layout.addWidget(self.lbl_select_std)

        self.combo_standard = QComboBox()
        self.combo_standard.currentIndexChanged.connect(self.on_standard_changed)
        left_layout.addWidget(self.combo_standard)

        self.drag_drop = DragDropFrame()
        self.drag_drop.fileDropped.connect(self.on_file_loaded)
        left_layout.addWidget(self.drag_drop)

        self.lbl_contract_text = QLabel("Sözleşme Metni:")
        left_layout.addWidget(self.lbl_contract_text)
        
        self.txt_contract = QTextEdit()
        left_layout.addWidget(self.txt_contract)

        # Dynamic Chronology Parameter Selectors
        self.time_params_frame = QFrame()
        self.time_params_frame.setStyleSheet("background-color: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 5px;")
        time_layout = QGridLayout(self.time_params_frame)
        time_layout.setContentsMargins(6, 6, 6, 6)
        time_layout.setSpacing(6)
        
        self.lbl_time1 = QLabel("Zaman 1:")
        self.dt_time1 = QDateTimeEdit()
        self.dt_time1.setCalendarPopup(True)
        self.dt_time1.setDateTime(QDateTime.currentDateTime())
        self.dt_time1.setStyleSheet("background-color: #0f172a; color: #f8fafc; border: 1px solid #475569; border-radius: 4px; padding: 3px;")
        
        self.lbl_time2 = QLabel("Zaman 2:")
        self.dt_time2 = QDateTimeEdit()
        self.dt_time2.setCalendarPopup(True)
        self.dt_time2.setDateTime(QDateTime.currentDateTime().addSecs(3600))
        self.dt_time2.setStyleSheet("background-color: #0f172a; color: #f8fafc; border: 1px solid #475569; border-radius: 4px; padding: 3px;")
        
        time_layout.addWidget(self.lbl_time1, 0, 0)
        time_layout.addWidget(self.dt_time1, 0, 1)
        time_layout.addWidget(self.lbl_time2, 1, 0)
        time_layout.addWidget(self.dt_time2, 1, 1)
        
        left_layout.addWidget(self.time_params_frame)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        left_layout.addWidget(self.progress_bar)

        self.lbl_telemetry = QLabel("Süre: 0 ms | Durum: Hazır")
        self.lbl_telemetry.setStyleSheet("color: #94a3b8; font-size: 12px; font-weight: bold;")
        left_layout.addWidget(self.lbl_telemetry)

        self.btn_analyze = QPushButton("Uyum Analizini Çalıştır")
        self.btn_analyze.clicked.connect(self.run_compliance_analysis)
        left_layout.addWidget(self.btn_analyze)

        # CENTER PANEL
        center_widget = QWidget()
        center_layout = QVBoxLayout(center_widget)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(10)

        self.lbl_page_indicator = QLabel("AAOIFI Kitap Sayfası: 1 / 1398")
        self.lbl_page_indicator.setStyleSheet("color: #94a3b8; font-size: 14px; font-weight: bold; background-color: #0c1324; padding: 4px; border-radius: 4px;")
        center_layout.addWidget(self.lbl_page_indicator)

        self.pdf_view = PdfViewerWidget()
        center_layout.addWidget(self.pdf_view, stretch=3)

        self.heatmap = ComplianceHeatmap()
        self.heatmap.pageSelected.connect(self.sync_pdf_view)
        center_layout.addWidget(self.heatmap, stretch=1)

        # RIGHT PANEL
        right_panel = QFrame()
        right_panel.setFixedWidth(340)
        right_panel.setMaximumHeight(820)
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(12, 12, 12, 12)
        right_layout.setSpacing(8)

        self.right_title = QLabel("Bulgular & Düzeltme")
        self.right_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #ef4444;")
        right_layout.addWidget(self.right_title)

        self.lbl_report = QLabel("İhlal Raporu:")
        right_layout.addWidget(self.lbl_report)

        self.scroll_findings = QScrollArea()
        self.scroll_findings.setWidgetResizable(True)
        self.scroll_findings.setStyleSheet("background-color: #0b1120; border: 1px solid #334155; border-radius: 6px;")
        self.findings_container = QWidget()
        self.findings_container.setStyleSheet("background-color: #0b1120;")
        self.findings_layout = QVBoxLayout(self.findings_container)
        self.findings_layout.setContentsMargins(5, 5, 5, 5)
        self.findings_layout.setSpacing(5)
        self.findings_layout.addStretch()
        self.scroll_findings.setWidget(self.findings_container)
        right_layout.addWidget(self.scroll_findings, stretch=2)

        self.lbl_remed_title = QLabel("Fıkhi Düzeltme Maddesi:")
        right_layout.addWidget(self.lbl_remed_title)

        self.txt_remediation = QTextEdit()
        self.txt_remediation.setReadOnly(True)
        self.txt_remediation.setStyleSheet("background-color: #1e293b; color: #f59e0b; border: 1px solid #334155;")
        right_layout.addWidget(self.txt_remediation, stretch=2)

        self.btn_copy_remediation = QPushButton("Düzeltme Metnini Kopyala")
        self.btn_copy_remediation.setStyleSheet("""
            QPushButton {
                background-color: #1e293b;
                color: #f8fafc;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 8px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2d3748;
                border-color: #4a5568;
            }
        """)
        self.btn_copy_remediation.clicked.connect(self.copy_remediation_text)
        right_layout.addWidget(self.btn_copy_remediation)

        self.btn_jump = QPushButton("İlgili Maddeye Git")
        self.btn_jump.setEnabled(False)
        self.btn_jump.clicked.connect(self.go_to_selected_violation_page)
        right_layout.addWidget(self.btn_jump)

        main_grid.addWidget(left_panel, 0, 0)
        main_grid.addWidget(center_widget, 0, 1)
        main_grid.addWidget(right_panel, 0, 2)

    def load_defaults(self):
        self.repopulate_standards()
        if os.path.exists(self.pdf_view.pdf_path):
            self.lbl_telemetry.setText(self.TRANSLATIONS[self.current_lang]["ready"])
        else:
            self.lbl_telemetry.setText(self.TRANSLATIONS[self.current_lang]["pdf_error"])
        self.on_standard_changed(0)

    def repopulate_standards(self):
        self.combo_standard.blockSignals(True)
        self.combo_standard.clear()
        for key in self.STANDARD_RANGES.keys():
            self.combo_standard.addItem(key)
        self.combo_standard.blockSignals(False)

    def on_language_changed(self, idx: int):
        self.current_lang = self.combo_lang.itemData(idx)
        
        # Apply Right-to-Left layout support for Arabic
        if self.current_lang == "ar":
            self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        else:
            self.setLayoutDirection(Qt.LayoutDirection.LeftToRight)

        if self.current_lang == "ar":
            self.STANDARD_RANGES = self.STANDARD_RANGES_AR
        elif self.current_lang == "en":
            self.STANDARD_RANGES = self.STANDARD_RANGES_EN
        else:
            self.STANDARD_RANGES = self.STANDARD_RANGES_TR

        self.repopulate_standards()
        
        tr = self.TRANSLATIONS[self.current_lang]
        self.setWindowTitle(tr["title"])
        self.left_title.setText(tr["left_title"])
        self.lbl_select_std.setText(tr["lbl_select_std"])
        self.lbl_contract_text.setText(tr["lbl_contract_text"])
        self.btn_analyze.setText(tr["btn_analyze"])
        self.right_title.setText(tr["right_title"])
        self.lbl_report.setText(tr["lbl_report"])
        self.lbl_remed_title.setText(tr["lbl_remed_title"])
        self.btn_copy_remediation.setText(tr["btn_copy_remediation"])
        self.btn_jump.setText(tr["btn_jump"])
        self.drag_drop.lbl_text.setText(tr["drag_text"])
        self.heatmap.title_label.setText(tr["heatmap_title"])

        self.on_standard_changed(0)

    def on_standard_changed(self, index: int):
        if index < 0 or index >= self.combo_standard.count():
            return
        std_name = self.combo_standard.itemText(index)
        start_p, end_p = self.STANDARD_RANGES[std_name]
        
        total_p = 1398 if self.current_lang == "tr" else (1264 if self.current_lang == "en" else 1388)
        self.heatmap.set_range(start_p, end_p, total_p)
        
        self.pdf_view.switch_pdf_and_navigate(std_name, self.current_lang)
        
        tr = self.TRANSLATIONS[self.current_lang]
        self.lbl_page_indicator.setText(f"{tr['page_ind']} {start_p} / {total_p}")
        
        self.txt_contract.clear()
        self.progress_bar.setValue(0)
        self.lbl_telemetry.setText(f"{std_name.split(' (')[0]}")
        self.clear_findings_layout()
        self.txt_remediation.clear()
        self.btn_jump.setEnabled(False)
        self.selected_violation_page = None

        # Dynamically configure chronology parameters view based on contract type
        std_lower = std_name.lower()
        if "sarf" in std_lower or "صرف" in std_lower:
            self.time_params_frame.show()
            if self.current_lang == "en":
                self.lbl_time1.setText("Transaction Time (t_islem):")
                self.lbl_time2.setText("Delivery Time (t_teslim):")
            elif self.current_lang == "ar":
                self.lbl_time1.setText("وقت المعاملة (t_islem):")
                self.lbl_time2.setText("وقت التسليم (t_teslim):")
            else:
                self.lbl_time1.setText("İşlem Zamanı (t_islem):")
                self.lbl_time2.setText("Teslim Zamanı (t_teslim):")
        elif "murabaha" in std_lower or "مرابح" in std_lower:
            self.time_params_frame.show()
            if self.current_lang == "en":
                self.lbl_time1.setText("Bank Purchase (t_banka_alim):")
                self.lbl_time2.setText("Client Sale (t_musteri_satis):")
            elif self.current_lang == "ar":
                self.lbl_time1.setText("شراء البنك (t_banka_alim):")
                self.lbl_time2.setText("بيع العميل (t_musteri_satis):")
            else:
                self.lbl_time1.setText("Banka Alım (t_banka_alim):")
                self.lbl_time2.setText("Müşteri Satış (t_musteri_satis):")
        elif "selem" in std_lower or "salam" in std_lower or "سلم" in std_lower:
            self.time_params_frame.show()
            if self.current_lang == "en":
                self.lbl_time1.setText("Contract Time (t_akit):")
                self.lbl_time2.setText("Payment Time (t_odeme):")
            elif self.current_lang == "ar":
                self.lbl_time1.setText("وقت العقد (t_akit):")
                self.lbl_time2.setText("وقت الدفع (t_odeme):")
            else:
                self.lbl_time1.setText("Akit Zamanı (t_akit):")
                self.lbl_time2.setText("Ödeme Zamanı (t_odeme):")
        elif "icare" in std_lower or "ijarah" in std_lower or "leasing" in std_lower or "إجار" in std_lower or "اجار" in std_lower:
            self.time_params_frame.show()
            if self.current_lang == "en":
                self.lbl_time1.setText("Physical Delivery (t_fiziki_teslim):")
                self.lbl_time2.setText("Rent Start (t_kira_baslangic):")
            elif self.current_lang == "ar":
                self.lbl_time1.setText("التسليم الفعلي (t_fiziki_teslim):")
                self.lbl_time2.setText("بدء الإيجار (t_kira_baslangic):")
            else:
                self.lbl_time1.setText("Fiziki Teslim (t_fiziki_teslim):")
                self.lbl_time2.setText("Kira Başlangıç (t_kira_baslangic):")
        else:
            self.time_params_frame.hide()

    def on_file_loaded(self, path: str):
        try:
            # First validate file extension and signature header
            UniversalInputSanitizer.validate_file_extension_and_header(path)
            
            validated_path = UniversalInputSanitizer.sanitize_path(path)
            if validated_path.lower().endswith(".pdf"):
                import fitz
                doc = fitz.open(validated_path)
                text_parts = []
                for i, page in enumerate(doc):
                    text_parts.append(f"=== PAGE {i+1} ===\n")
                    text_parts.append(page.get_text())
                raw_text = "\n".join(text_parts)
            elif validated_path.lower().endswith(".docx"):
                import docx
                doc = docx.Document(validated_path)
                text_parts = []
                for paragraph in doc.paragraphs:
                    text_parts.append(paragraph.text)
                raw_text = "\n".join(text_parts)
            else:
                with open(validated_path, "r", encoding="utf-8") as f:
                    raw_text = f.read()

            sanitized_text = UniversalInputSanitizer.sanitize(raw_text)
            self.txt_contract.setPlainText(sanitized_text)
            
            if self.current_lang == "en":
                self.lbl_telemetry.setText(f"File Loaded: {os.path.basename(validated_path)}")
            elif self.current_lang == "ar":
                self.lbl_telemetry.setText(f"تم تحميل الملف: {os.path.basename(validated_path)}")
            else:
                self.lbl_telemetry.setText(f"Dosya Yüklendi: {os.path.basename(validated_path)}")
        except Exception as e:
            if self.current_lang == "en":
                self.lbl_telemetry.setText(f"Error: {str(e)}")
            elif self.current_lang == "ar":
                self.lbl_telemetry.setText(f"خطأ: {str(e)}")
            else:
                self.lbl_telemetry.setText(f"Hata: {str(e)}")

    def run_compliance_analysis(self):
        contract_text = self.txt_contract.toPlainText()
        if not contract_text.strip():
            if self.current_lang == "en":
                self.lbl_telemetry.setText("Contract text is empty!")
            elif self.current_lang == "ar":
                self.lbl_telemetry.setText("نص العقد فارغ!")
            else:
                self.lbl_telemetry.setText("Sözleşme metni boş!")
            return

        self.btn_analyze.setEnabled(False)
        self.clear_findings_layout()
        self.heatmap.clear_heatmap()
        self.txt_remediation.clear()
        self.btn_jump.setEnabled(False)
        self.selected_violation_page = None

        std_name = self.combo_standard.currentText()
        
        # Build chronology parameters map
        time_params = {}
        std_lower = std_name.lower()
        if "sarf" in std_lower or "صرف" in std_lower:
            time_params["t_islem"] = self.dt_time1.dateTime().toMSecsSinceEpoch() / 1000.0
            time_params["t_teslim"] = self.dt_time2.dateTime().toMSecsSinceEpoch() / 1000.0
        elif "murabaha" in std_lower or "مرابح" in std_lower:
            time_params["t_banka_alim"] = self.dt_time1.dateTime().toMSecsSinceEpoch() / 1000.0
            time_params["t_musteri_satis"] = self.dt_time2.dateTime().toMSecsSinceEpoch() / 1000.0
        elif "selem" in std_lower or "salam" in std_lower or "سلم" in std_lower:
            time_params["t_akit"] = self.dt_time1.dateTime().toMSecsSinceEpoch() / 1000.0
            time_params["t_odeme"] = self.dt_time2.dateTime().toMSecsSinceEpoch() / 1000.0
        elif "icare" in std_lower or "ijarah" in std_lower or "leasing" in std_lower or "إجار" in std_lower or "اجار" in std_lower:
            time_params["t_fiziki_teslim"] = self.dt_time1.dateTime().toMSecsSinceEpoch() / 1000.0
            time_params["t_kira_baslangic"] = self.dt_time2.dateTime().toMSecsSinceEpoch() / 1000.0
            
        self.compliance_thread = ComplianceEngine(contract_text, std_name, time_params, lang=self.current_lang)
        self.compliance_thread.log_message.connect(lambda msg: self.lbl_telemetry.setText(msg))
        self.compliance_thread.progress_update.connect(self.progress_bar.setValue)
        self.compliance_thread.elapsed_time.connect(self.on_telemetry_time_received)
        self.compliance_thread.analysis_completed.connect(self.on_analysis_completed)
        self.compliance_thread.analysis_failed.connect(self.on_analysis_failed)
        self.compliance_thread.start()

    def on_telemetry_time_received(self, elapsed_ms: int):
        success_msg = self.TRANSLATIONS[self.current_lang]["success"].format(elapsed=elapsed_ms)
        self.lbl_telemetry.setText(success_msg)

    def on_analysis_completed(self, results):
        self.btn_analyze.setEnabled(True)
        self.txt_remediation.setPlainText(results["remediation_text"])
        
        # Heatmap support for composite violations
        composite_violations = [v for v in results.get("violations", []) if v.get("isComposite", False)]
        if composite_violations:
            self.heatmap.mark_multiple_composite_violations(composite_violations, severity="error")
        else:
            self.heatmap.set_violation_pages(results["violated_pages"], severity="error")

        self.active_violations = results["violations"]

        self.clear_findings_layout()
        self.risk_cards = []

        confidence = results.get("confidence", 0.95)
        
        if not self.active_violations:
            if self.current_lang == "en":
                lbl_text = "Compliant"
            elif self.current_lang == "ar":
                lbl_text = "متوافق"
            else:
                lbl_text = "Fıkhi Uyumlu"
            lbl = QLabel(lbl_text)
            lbl.setStyleSheet("color: #10b981; font-weight: bold; font-size: 13px; padding: 5px;")
            self.findings_layout.insertWidget(0, lbl)
            return

        for idx, violation in enumerate(self.active_violations):
            violation["confidence"] = confidence
            card = ClickableRiskCard(violation, idx, lang=self.current_lang)
            card.clicked.connect(self.on_risk_card_clicked)
            self.risk_cards.append(card)
            self.findings_layout.insertWidget(idx, card)
            
        self.btn_jump.setEnabled(True)
        
        if results["violated_pages"]:
            first_page = results["violated_pages"][0]
            self.selected_violation_page = first_page
            self.sync_pdf_view(first_page)
            if self.risk_cards:
                self.risk_cards[0].set_selected(True)
        else:
            std_name = self.combo_standard.currentText()
            self.sync_pdf_view(self.STANDARD_RANGES[std_name][0])

    def on_analysis_failed(self, err_msg: str):
        self.btn_analyze.setEnabled(True)
        if self.current_lang == "en":
            self.lbl_telemetry.setText(f"Error: {err_msg}")
        elif self.current_lang == "ar":
            self.lbl_telemetry.setText(f"خطأ: {err_msg}")
        else:
            self.lbl_telemetry.setText(f"Hata: {err_msg}")

    def on_risk_card_clicked(self, page_num: int):
        self.selected_violation_page = page_num
        self.sync_pdf_view(page_num)
        sender_card = self.sender()
        for card in self.risk_cards:
            card.set_selected(card == sender_card)

    def sync_pdf_view(self, page_num: int):
        self.pdf_view.jump_to_page(page_num)
        tr = self.TRANSLATIONS[self.current_lang]
        total_p = 1398 if self.current_lang == "tr" else (1264 if self.current_lang == "en" else 1388)
        self.lbl_page_indicator.setText(f"{tr['page_ind']} {page_num} / {total_p}")

    def go_to_selected_violation_page(self):
        if self.selected_violation_page:
            self.sync_pdf_view(self.selected_violation_page)

    def copy_remediation_text(self):
        remed = self.txt_remediation.toPlainText()
        if remed:
            QApplication.clipboard().setText(remed)
            
            # Save original text and style to restore later
            orig_text = self.btn_copy_remediation.text()
            orig_style = self.btn_copy_remediation.styleSheet()
            
            if self.current_lang == "en":
                copied_text = "✓ Copied!"
                self.lbl_telemetry.setText("Text Copied")
            elif self.current_lang == "ar":
                copied_text = "✓ تم النسخ!"
                self.lbl_telemetry.setText("تم نسخ النص")
            else:
                copied_text = "✓ Kopyalandı!"
                self.lbl_telemetry.setText("Metin Kopyalandı")
                
            self.btn_copy_remediation.setText(copied_text)
            self.btn_copy_remediation.setStyleSheet("""
                QPushButton {
                    background-color: #10b981; 
                    color: #ffffff; 
                    border: 1px solid #10b981; 
                    border-radius: 6px;
                    padding: 8px 12px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #059669;
                    border-color: #059669;
                }
            """)
            
            QTimer.singleShot(1500, lambda: self.restore_copy_button(orig_text, orig_style))

    def restore_copy_button(self, orig_text, orig_style):
        current_text = self.TRANSLATIONS[self.current_lang]["btn_copy_remediation"]
        self.btn_copy_remediation.setText(current_text)
        self.btn_copy_remediation.setStyleSheet(orig_style)

    def clear_findings_layout(self):
        for i in reversed(range(self.findings_layout.count())):
            item = self.findings_layout.itemAt(i)
            if item and item.widget():
                item.widget().deleteLater()
        self.risk_cards.clear()

    def closeEvent(self, event):
        if self.compliance_thread and self.compliance_thread.isRunning():
            self.compliance_thread.terminate()
            self.compliance_thread.wait()
        event.accept()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Uyum Protokolu Compliance GUI")
    parser.add_argument("--contract_text", type=str, default="")
    parser.add_argument("--standard", type=str, default="")
    parser.add_argument("--lang", type=str, default="tr")
    parser.add_argument("--t1", type=float, default=None)
    parser.add_argument("--t2", type=float, default=None)
    args, unknown = parser.parse_known_args()

    app = QApplication(sys.argv)
    window = UyumProtokoluApp()

    # Pre-populate if CLI args are passed
    if args.lang in ["tr", "en", "ar"]:
        idx = window.combo_lang.findData(args.lang)
        if idx >= 0:
            window.combo_lang.setCurrentIndex(idx)
    
    if args.contract_text:
        window.txt_contract.setPlainText(args.contract_text)

    if args.standard:
        # Match by name substring
        for i in range(window.combo_standard.count()):
            txt = window.combo_standard.itemText(i)
            if args.standard.lower() in txt.lower():
                window.combo_standard.setCurrentIndex(i)
                break

    if args.t1 is not None:
        window.dt_time1.setDateTime(QDateTime.fromMSecsSinceEpoch(int(args.t1 * 1000)))
    if args.t2 is not None:
        window.dt_time2.setDateTime(QDateTime.fromMSecsSinceEpoch(int(args.t2 * 1000)))

    window.show()

    if args.contract_text:
        # Trigger run instantly if contract text was passed
        QTimer.singleShot(500, window.run_compliance_analysis)

    sys.exit(app.exec())
