# file: /home/mahmut/Desktop/uyumprotokol/ui/pdf_viewer.py
import os
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineSettings
from PyQt6.QtCore import QUrl, QTimer

class PdfViewerWidget(QWebEngineView):
    def __init__(self, corpus_path="aaoifi.pdf"):
        super().__init__()
        
        # Configure WebEngine Settings with OWASP ASVS Hardening
        settings = self.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.PdfViewerEnabled, True)
        # OWASP Desktop Security Hardening: local content shouldn't fetch remote resources
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, False)
        # Allow local files to load (needed for pdf.js loading local PDF)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, True)
        # OWASP Hardening: Disable scripts from accessing clipboard directly
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanAccessClipboard, False)
        
        # Dynamically locate the healthy, uncorrupted version of the AAOIFI standard PDF
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Candidate names for the healthy file and fallback
        candidates = []
        try:
            for f in os.listdir(base_dir):
                if f.lower().endswith(".pdf") and "faizsiz" in f.lower():
                    candidates.append(os.path.join(base_dir, f))
        except Exception:
            pass
            
        candidates.extend([
            os.path.join(base_dir, "Faizsiz Finans Standartları AAOIFI (Güncellenmiş Versiyon).pdf"),
            os.path.join(base_dir, "Faizsiz Finans Standartları AAOIFI (Güncellenmiş Versiyon).pdf"),
            os.path.join(base_dir, "aaoifi.pdf")
        ])
        
        selected_pdf = None
        for path in candidates:
            if os.path.exists(path):
                selected_pdf = path
                if "faizsiz" in path.lower():
                    break
                    
        self.pdf_path = selected_pdf if selected_pdf else os.path.join(base_dir, "aaoifi.pdf")
        self.load_pdf(self.pdf_path)
        
    def load_pdf(self, path: str):
        if not os.path.exists(path):
            print(f"❌ Hata: PDF dosyası bulunamadı: {path}")
            self.setHtml(f"""
                <div style="
                    background-color: #fef2f2;
                    color: #991b1b;
                    padding: 30px;
                    border: 1px solid #fee2e2;
                    border-radius: 8px;
                    font-family: 'Inter', sans-serif;
                    text-align: center;
                    margin-top: 50px;
                ">
                    <h3 style="margin-top: 0;">PDF Dosyası Bulunamadı</h3>
                    <p>Lütfen <b>{os.path.basename(path)}</b> dosyasının proje kök dizininde olduğunu doğrulayın.</p>
                </div>
            """)
            return False
            
        self.pdf_path = path
        url = QUrl.fromLocalFile(self.pdf_path)
        self.setUrl(url)
        print(f"✓ PDF Yükleniyor: {self.pdf_path}")
        return True

    def switch_pdf_and_navigate(self, akit_turu: str, lang: str):
        """
        Dynamically loads the appropriate PDF file based on the language (lang)
        and navigates to the target page index of the selected instrument (akit_turu).
        """
        from core.security_sanitizer import UniversalInputSanitizer
        from core.compliance_engine import AAOIFI_DUAL_PDF_MAP, AAOIFI_COMPOSITE_INDEX_MAP, normalize_standard_type

        # 1. Normalize instrument to look up in mapping
        key = normalize_standard_type(akit_turu)

        # 2. Determine target page
        target_page = 1
        if key and key in AAOIFI_COMPOSITE_INDEX_MAP:
            target_page = AAOIFI_COMPOSITE_INDEX_MAP[key].get(lang.lower(), [1])[0]
        elif key and key in AAOIFI_DUAL_PDF_MAP:
            target_page = AAOIFI_DUAL_PDF_MAP[key].get(lang.lower(), 1)

        # 3. Determine the whitelisted target PDF file path
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        if lang.lower() == "tr":
            pdf_file = "Faizsiz Finans Standartları AAOIFI (Güncellenmiş Versiyon).pdf"
            # Fallback check
            full_path = os.path.join(base_dir, pdf_file)
            if not os.path.exists(full_path):
                # Try with different spelling of u
                pdf_file = "Faizsiz Finans Standartları AAOIFI (Güncellenmiş Versiyon).pdf"
                full_path = os.path.join(base_dir, pdf_file)
                if not os.path.exists(full_path):
                    pdf_file = "aaoifi.pdf"
        elif lang.lower() == "en":
            pdf_file = "Shariaa-Standards-ENG.pdf"
        elif lang.lower() == "ar":
            pdf_file = "723607313-معايير-الأيوفي-الشرعية-النسخة-العربية-2017.pdf"
        else:
            pdf_file = "aaoifi.pdf"

        target_pdf_path = os.path.join(base_dir, pdf_file)

        # 4. Strict Security validation using UniversalInputSanitizer whitelists
        try:
            target_pdf_path = UniversalInputSanitizer.validate_safe_pdf_path(target_pdf_path)
        except Exception as e:
            print(f"❌ Security Sanitizer Violation: {str(e)}")
            return False

        # 5. Load & navigate
        if self.pdf_path != target_pdf_path:
            self.pdf_path = target_pdf_path
            # Store target page to jump after URL is loaded
            self.target_url = QUrl.fromLocalFile(self.pdf_path)
            self.target_url.setFragment(f"page={target_page}")
            self.setUrl(self.target_url)
            print(f"✓ PDF Changed and Loaded: {self.pdf_path} (Page {target_page})")
        else:
            self.jump_to_page(target_page)
        return True

    def smooth_scroll_to_page(self, page_number: int):
        """
        Executes JavaScript to smoothly scroll to the target page index.
        Supports both pdf.js/Chromium PDF viewer and custom HTML viewports.
        """
        js_code = f"""
        (function() {{
            if (typeof PDFViewerApplication !== 'undefined' && PDFViewerApplication.pdfViewer) {{
                PDFViewerApplication.pdfViewer.scrollPageIntoView({{ pageNumber: {page_number}, destArray: null, allowNegativePosition: true }});
            }} else {{
                var totalHeight = document.documentElement.scrollHeight || document.body.scrollHeight;
                var targetTop = totalHeight * ({page_number} / 1398.0);
                window.scrollTo({{ top: targetTop, behavior: 'smooth' }});
            }}
        }})();
        """
        self.page().runJavaScript(js_code)
        print(f"✓ Smooth scrolling to page {page_number} via JS executed.")

    def jump_to_page(self, page_number):
        """Navigates to the specified page number of the PDF via URL fragment."""
        if not os.path.exists(self.pdf_path):
            return
            
        # Store the target URL with fragment
        self.target_url = QUrl.fromLocalFile(self.pdf_path)
        self.target_url.setFragment(f"page={page_number}")
        
        # Load about:blank first to clear out the previous document scroll history
        self.setUrl(QUrl("about:blank"))
        
        # Schedule loading the actual PDF with the fragment after 50ms
        QTimer.singleShot(50, self._load_target_pdf)
        print(f"✓ PDF Sayfasına Atlanıyor: Sayfa {page_number}")

    def _load_target_pdf(self):
        if hasattr(self, "target_url"):
            self.setUrl(self.target_url)

    def pageNavigator(self):
        class NavigatorProxy:
            def __init__(self, parent_widget):
                self.parent = parent_widget
            def jumpTo(self, page_num):
                self.parent.jump_to_page(page_num)
        return NavigatorProxy(self)
