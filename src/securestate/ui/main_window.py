from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
)

from securestate.platform_info import identify_platform
from securestate.assessments.windows_firewall import (
    assess_windows_firewall,
)


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("SecureState Lab")
        self.resize(1250, 780)
        self.setMinimumSize(1000, 650)

        self.navigation_buttons = []
        self.system_info_labels = {}

        self.create_interface()

    def create_interface(self):
        central = QWidget()
        self.setCentralWidget(central)

        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(245)

        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(18, 25, 18, 20)
        side_layout.setSpacing(12)

        brand = QLabel("SECURESTATE")
        brand.setObjectName("brand")

        brand_subtitle = QLabel("LAB")
        brand_subtitle.setObjectName("brand_subtitle")

        side_layout.addWidget(brand)
        side_layout.addWidget(brand_subtitle)
        side_layout.addSpacing(30)

        navigation_items = [
            "Dashboard",
            "System Discovery",
            "Security Assessment",
            "Vulnerability Intelligence",
            "Remediation",
            "Verification",
            "Reports",
        ]

        for index, name in enumerate(navigation_items):
            button = QPushButton(name)
            button.setObjectName("nav_button")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(
                lambda checked=False, page=index:
                self.show_page(page)
            )

            self.navigation_buttons.append(button)
            side_layout.addWidget(button)

        side_layout.addStretch()

        status = QLabel("RESEARCH PROTOTYPE\nEarly development")
        status.setObjectName("lab_status")
        side_layout.addWidget(status)

        content = QWidget()
        content.setObjectName("content")

        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(32, 28, 32, 25)
        content_layout.setSpacing(22)

        self.page_title = QLabel("Dashboard")
        self.page_title.setObjectName("page_title")

        self.page_subtitle = QLabel(
            "Monitor system security assessments and verification."
        )
        self.page_subtitle.setObjectName("page_subtitle")

        content_layout.addWidget(self.page_title)
        content_layout.addWidget(self.page_subtitle)

        self.pages = QStackedWidget()
        self.pages.addWidget(self.create_dashboard())
        self.pages.addWidget(self.create_system_discovery())
        self.pages.addWidget(self.create_security_assessment())

        page_data = [
            (
                "Vulnerability Intelligence",
                "Investigate known vulnerabilities and patch information.",
            ),
            (
                "Remediation",
                "Review and approve controlled security corrections.",
            ),
            (
                "Verification",
                "Independently verify corrective actions.",
            ),
            (
                "Reports",
                "Review assessment evidence and generate reports.",
            ),
        ]

        for name, description in page_data:
            self.pages.addWidget(
                self.create_placeholder_page(name, description)
            )

        content_layout.addWidget(self.pages)

        self.statusBar().showMessage(
            "Ready | No assessment has been run."
        )

        root.addWidget(sidebar)
        root.addWidget(content, 1)

        self.setStyleSheet("""
            QMainWindow {
                background: #f4f6fa;
            }

            #sidebar {
                background: #111827;
            }

            #brand {
                color: white;
                font-size: 23px;
                font-weight: bold;
            }

            #brand_subtitle {
                color: #60a5fa;
                font-size: 13px;
                font-weight: bold;
            }

            #nav_button {
                background: transparent;
                color: #cbd5e1;
                border: none;
                border-radius: 7px;
                text-align: left;
                padding: 13px 12px;
                font-size: 13px;
            }

            #nav_button:hover {
                background: #253247;
                color: white;
            }

            #nav_button:checked {
                background: #2563eb;
                color: white;
                font-weight: bold;
            }

            #lab_status {
                color: #94a3b8;
                font-size: 11px;
                padding: 12px;
                border-top: 1px solid #334155;
            }

            #content {
                background: #f4f6fa;
            }

            #page_title {
                color: #111827;
                font-size: 27px;
                font-weight: bold;
            }

            #page_subtitle {
                color: #64748b;
                font-size: 13px;
            }

            #section_card {
                background: white;
                border: 1px solid #e2e8f0;
                border-radius: 10px;
            }

            #card_title {
                color: #334155;
                font-size: 14px;
                font-weight: bold;
            }

            #card_value {
                color: #111827;
                font-size: 25px;
                font-weight: bold;
            }

            #muted_text {
                color: #64748b;
                font-size: 12px;
            }

            #system_value {
                color: #111827;
                font-size: 13px;
            }

            QPushButton#action_button {
                background: #2563eb;
                color: white;
                border: none;
                border-radius: 7px;
                padding: 12px 18px;
                font-weight: bold;
            }

            QPushButton#action_button:hover {
                background: #1d4ed8;
            }

            QStatusBar {
                background: white;
                color: #64748b;
            }
        """)

        self.show_page(0)

    def create_dashboard(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(20)

        introduction = QLabel(
            "Welcome to SecureState Lab\n"
            "Your operating system security assessment workspace."
        )
        introduction.setObjectName("muted_text")
        layout.addWidget(introduction)

        cards = QHBoxLayout()
        cards.setSpacing(15)

        for title, value, detail in [
            ("Systems Discovered", "0", "No systems registered"),
            ("Assessments", "0", "No assessments performed"),
            ("Findings", "0", "No findings recorded"),
            ("Verified Fixes", "0", "No fixes verified"),
        ]:
            card = QFrame()
            card.setObjectName("section_card")

            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(18, 18, 18, 18)

            title_label = QLabel(title)
            title_label.setObjectName("card_title")

            value_label = QLabel(value)
            value_label.setObjectName("card_value")

            detail_label = QLabel(detail)
            detail_label.setObjectName("muted_text")

            card_layout.addWidget(title_label)
            card_layout.addWidget(value_label)
            card_layout.addWidget(detail_label)

            cards.addWidget(card)

        layout.addLayout(cards)

        activity = QFrame()
        activity.setObjectName("section_card")

        activity_layout = QVBoxLayout(activity)
        activity_layout.setContentsMargins(22, 20, 22, 20)

        activity_title = QLabel("Recent Activity")
        activity_title.setObjectName("card_title")

        activity_description = QLabel(
            "No assessment activity yet.\n\n"
            "Assessment results will appear here as they are generated."
        )
        activity_description.setObjectName("muted_text")

        activity_layout.addWidget(activity_title)
        activity_layout.addWidget(activity_description)

        layout.addWidget(activity)
        layout.addStretch()

        return page

    def create_system_discovery(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(20)

        description = QLabel(
            "Identify the operating system and collect system information."
        )
        description.setObjectName("muted_text")
        layout.addWidget(description)

        card = QFrame()
        card.setObjectName("section_card")

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(25, 25, 25, 25)
        card_layout.setSpacing(18)

        heading = QLabel("System Information")
        heading.setObjectName("card_title")
        card_layout.addWidget(heading)

        fields = [
            ("operating_system", "Operating System"),
            ("os_release", "OS Release"),
            ("os_version", "OS Version"),
            ("architecture", "Architecture"),
            ("processor", "Processor"),
            ("hostname", "Hostname"),
            ("python_version", "Python Version"),
            ("current_user", "Current User"),
            ("assessment_time_utc", "Last Discovery (UTC)"),
        ]

        self.system_info_labels = {}
        grid = QGridLayout()
        grid.setHorizontalSpacing(25)
        grid.setVerticalSpacing(16)

        for row, (key, title) in enumerate(fields):
            label = QLabel(title)
            label.setObjectName("muted_text")

            value = QLabel("Not discovered")
            value.setObjectName("system_value")
            value.setWordWrap(True)
            value.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )

            self.system_info_labels[key] = value
            grid.addWidget(label, row, 0)
            grid.addWidget(value, row, 1)

        card_layout.addLayout(grid)
        layout.addWidget(card)

        button = QPushButton("Refresh System Information")
        button.setObjectName("action_button")
        button.clicked.connect(self.refresh_system_information)

        layout.addWidget(button)
        layout.addStretch()

        self.refresh_system_information()

        return page

    def refresh_system_information(self):
        information = identify_platform()

        for key, value in information.items():
            label = self.system_info_labels.get(key)

            if label is not None:
                label.setText(str(value))

        self.statusBar().showMessage(
            "System information refreshed successfully."
        )

    def create_security_assessment(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(18)

        description = QLabel(
            "Inspect selected Windows security controls."
        )
        description.setObjectName("muted_text")
        layout.addWidget(description)

        card = QFrame()
        card.setObjectName("section_card")

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 20, 20, 20)
        card_layout.setSpacing(15)

        heading = QLabel("Windows Defender Firewall")
        heading.setObjectName("card_title")

        details = QLabel(
            "Inspect Domain, Private and Public firewall profiles."
        )
        details.setObjectName("muted_text")

        self.firewall_button = QPushButton(
            "Run Firewall Assessment"
        )
        self.firewall_button.setObjectName("action_button")
        self.firewall_button.clicked.connect(
            self.run_firewall_assessment
        )

        self.firewall_summary = QLabel(
            "No firewall assessment has been performed."
        )
        self.firewall_summary.setObjectName("muted_text")
        self.firewall_summary.setWordWrap(True)

        self.firewall_table = QTableWidget(0, 4)
        self.firewall_table.setHorizontalHeaderLabels([
            "Security Control",
            "Status",
            "Evidence",
            "Recommendation",
        ])

        self.firewall_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.firewall_table.horizontalHeader().setStretchLastSection(
            True
        )
        self.firewall_table.setWordWrap(True)
        self.firewall_table.setMinimumHeight(280)

        card_layout.addWidget(heading)
        card_layout.addWidget(details)
        card_layout.addWidget(self.firewall_button)
        card_layout.addWidget(self.firewall_summary)
        card_layout.addWidget(self.firewall_table)

        layout.addWidget(card)
        layout.addStretch()

        return page

    def run_firewall_assessment(self):
        self.firewall_button.setEnabled(False)
        self.firewall_button.setText("Assessing Firewall...")

        try:
            results = assess_windows_firewall()

            self.firewall_table.setRowCount(len(results))

            counts = {
                "PASS": 0,
                "FAIL": 0,
                "UNKNOWN": 0,
                "NOT_APPLICABLE": 0,
            }

            for row, result in enumerate(results):
                status = result.status.value
                counts[status] = counts.get(status, 0) + 1

                values = [
                    result.control,
                    status,
                    result.evidence,
                    result.recommendation,
                ]

                for column, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    item.setToolTip(str(value))

                    self.firewall_table.setItem(
                        row,
                        column,
                        item,
                    )

            self.firewall_summary.setText(
                "Assessment completed | "
                f"PASS: {counts['PASS']} | "
                f"FAIL: {counts['FAIL']} | "
                f"UNKNOWN: {counts['UNKNOWN']} | "
                f"NOT APPLICABLE: {counts['NOT_APPLICABLE']}"
            )

            self.statusBar().showMessage(
                "Windows firewall assessment completed."
            )

        except Exception as error:
            self.firewall_summary.setText(
                f"Assessment error: {error}"
            )

            self.statusBar().showMessage(
                "Firewall assessment encountered an error."
            )

        finally:
            self.firewall_button.setEnabled(True)
            self.firewall_button.setText(
                "Run Firewall Assessment"
            )

    def create_placeholder_page(self, title, description):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.setContentsMargins(0, 25, 0, 0)

        card = QFrame()
        card.setObjectName("section_card")

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(25, 25, 25, 25)
        card_layout.setSpacing(15)

        heading = QLabel(title)
        heading.setObjectName("card_title")

        description_label = QLabel(description)
        description_label.setObjectName("muted_text")
        description_label.setWordWrap(True)

        development = QLabel(
            "This module has not been implemented yet."
        )
        development.setObjectName("muted_text")

        card_layout.addWidget(heading)
        card_layout.addWidget(description_label)
        card_layout.addWidget(development)

        layout.addWidget(card)

        return page

    def show_page(self, index):
        self.pages.setCurrentIndex(index)

        self.page_title.setText(
            self.navigation_buttons[index].text()
        )

        subtitles = [
            "Monitor system security assessments and verification.",
            "Discover and inspect operating system information.",
            "Evaluate selected operating system security controls.",
            "Investigate known vulnerabilities and patch information.",
            "Review and approve controlled security corrections.",
            "Independently verify corrective actions.",
            "Review assessment evidence and generate reports.",
        ]

        self.page_subtitle.setText(subtitles[index])

        for button_index, button in enumerate(
            self.navigation_buttons
        ):
            button.setChecked(button_index == index)
