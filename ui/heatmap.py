# file: /home/mahmut/Desktop/uyumprotokol/ui/heatmap.py
from PyQt6.QtWidgets import QWidget, QGridLayout, QPushButton, QVBoxLayout, QLabel, QScrollArea
from PyQt6.QtCore import pyqtSignal, Qt

class ComplianceHeatmap(QWidget):
    """
    Dynamic Compliance Heatmap Widget
    Renders a 13-column grid of AAOIFI PDF pages.
    Colors:
      - Normal: Sleek dark blue
      - Warning: Gold
      - Critical Violation: Crimson Red
    Toggling triggers page navigation in the PDF viewer.
    """
    pageSelected = pyqtSignal(int)

    def __init__(self, start_page: int = 150, end_page: int = 214):
        super().__init__()
        self.start_page = start_page
        self.end_page = end_page
        self.total_pages_limit = 1398
        self.violated_pages = {}  # maps page_num -> severity level ('error' or 'warning')
        self.buttons = {}
        
        self.init_ui()

    def init_ui(self):
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(5)

        # Title Label
        self.title_label = QLabel("Uyum Isı Haritası")
        self.title_label.setStyleSheet("color: #94a3b8; font-weight: bold; font-size: 12px; padding-left: 5px;")
        self.main_layout.addWidget(self.title_label)

        # Scroll Area for Grid Container
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFixedHeight(160)
        self.scroll_area.setStyleSheet("""
            QScrollArea {
                background-color: #0c1324;
                border: 1px solid #1e293b;
                border-radius: 8px;
            }
            QScrollBar:vertical {
                border: none;
                background: #0c1324;
                width: 6px;
            }
            QScrollBar::handle:vertical {
                background: #1d4ed8;
                border-radius: 3px;
            }
        """)

        self.grid_container = QWidget()
        self.grid_container.setStyleSheet("background-color: #0c1324;")
        self.grid_layout = QGridLayout(self.grid_container)
        self.grid_layout.setSpacing(5)
        self.grid_layout.setContentsMargins(10, 10, 10, 10)

        self.build_grid()
        self.scroll_area.setWidget(self.grid_container)
        self.main_layout.addWidget(self.scroll_area)

    def build_grid(self):
        # Clear existing buttons from layout
        for btn in self.buttons.values():
            self.grid_layout.removeWidget(btn)
            btn.deleteLater()
        self.buttons.clear()

        # Dynamic Grid Layout configuration - 13 columns as requested
        columns = 13
        total_pages = self.end_page - self.start_page + 1
        
        # Scale cell resolution based on active document limits
        if self.total_pages_limit == 1264:
            btn_w, btn_h = 38, 28
        elif self.total_pages_limit == 1000:
            btn_w, btn_h = 40, 28
        else: # TR (1398) or default
            btn_w, btn_h = 36, 28

        for idx in range(total_pages):
            page = self.start_page + idx
            row = idx // columns
            col = idx % columns

            btn = QPushButton(str(page))
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setFixedSize(btn_w, btn_h)
            btn.clicked.connect(lambda checked, p=page: self.pageSelected.emit(p))
            btn.setToolTip(f"Sayfa / Page {page}")
            
            self.buttons[page] = btn
            self.grid_layout.addWidget(btn, row, col)
            
        self.apply_button_styles()

    def set_range(self, start_page: int, end_page: int, total_pages_limit: int = 1398):
        self.start_page = start_page
        self.end_page = end_page
        self.total_pages_limit = total_pages_limit
        self.violated_pages.clear()
        self.build_grid()

    def apply_button_styles(self):
        for page, btn in self.buttons.items():
            if page in self.violated_pages:
                severity = self.violated_pages[page]
                if severity == "error":
                    # Critical Violation Style (Red)
                    btn.setStyleSheet("""
                        QPushButton {
                            background-color: #ef4444;
                            color: #ffffff;
                            border: 1px solid #b91c1c;
                            border-radius: 4px;
                            font-size: 11px;
                            font-weight: bold;
                        }
                        QPushButton:hover {
                            background-color: #f87171;
                        }
                    """)
                else:
                    # Warning Style (Gold)
                    btn.setStyleSheet("""
                        QPushButton {
                            background-color: #f59e0b;
                            color: #ffffff;
                            border: 1px solid #d97706;
                            border-radius: 4px;
                            font-size: 11px;
                            font-weight: bold;
                        }
                        QPushButton:hover {
                            background-color: #fbbf24;
                        }
                    """)
            else:
                # Normal styled page button
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #111a2e;
                        color: #64748b;
                        border: 1px solid #1e293b;
                        border-radius: 4px;
                        font-size: 11px;
                    }
                    QPushButton:hover {
                        background-color: #1d4ed8;
                        color: #ffffff;
                        border-color: #3b82f6;
                    }
                """)

    def set_violation_pages(self, violated_pages_list, severity="error"):
        """Highlights specified pages immediately with target severity."""
        for p in violated_pages_list:
            self.violated_pages[p] = severity
        self.apply_button_styles()

    def mark_multiple_composite_violations(self, composite_violations, severity="error"):
        """
        Calculates a dynamic page range enclosing all composite primary and secondary pages,
        rebuilds the grid, and highlights them concurrently.
        """
        all_pages = []
        for cv in composite_violations:
            all_pages.extend(cv.get("pages", []))
        if not all_pages:
            return
        
        min_p = min(all_pages)
        max_p = max(all_pages)
        
        # Expand slightly for context
        start = max(1, min_p - 5)
        end = min(self.total_pages_limit, max_p + 5)
        
        self.set_range(start, end, self.total_pages_limit)
        self.set_violation_pages(all_pages, severity)

    def clear_heatmap(self):
        self.violated_pages.clear()
        self.apply_button_styles()
