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
    QScrollArea,
)

from securestate.platform_info import identify_platform
from securestate.assessments.host_firewall import assess_host_firewall
from securestate.discovery import collect_system_inventory
from securestate.assessments.security_configuration import assess_security_configuration
from securestate.assessments.windows_firewall import (
    assess_windows_firewall,
)
from securestate.vulnerability_intelligence import (
    assess_package_vulnerabilities,
    screen_windows_products_against_kev,
    enrich_windows_kev_matches_with_nvd,
    assess_windows_products_with_nvd,
)


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("SecureState Lab")
        self.resize(1250, 780)
        self.setMinimumSize(1000, 650)

        self.navigation_buttons = []
        self.system_info_labels = {}
        self.last_inventory = None
        self.last_vulnerability_results = None

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
            if name == "Vulnerability Intelligence":
                self.pages.addWidget(self.create_vulnerability_page())
            else:
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

        inventory_button = QPushButton("Run Full System Inventory")
        inventory_button.setObjectName("action_button")
        inventory_button.clicked.connect(self.run_full_inventory)
        layout.addWidget(inventory_button)

        self.inventory_summary = QLabel(
            "Full inventory has not been collected."
        )
        self.inventory_summary.setObjectName("muted_text")
        self.inventory_summary.setWordWrap(True)
        layout.addWidget(self.inventory_summary)

        self.inventory_table = QTableWidget(0, 4)
        self.inventory_table.setHorizontalHeaderLabels(
            ["Category", "Name / Identifier", "Version / State", "Details"]
        )
        self.inventory_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.inventory_table.horizontalHeader().setStretchLastSection(True)
        self.inventory_table.setWordWrap(True)
        self.inventory_table.setMinimumHeight(260)
        layout.addWidget(self.inventory_table)
        layout.addStretch()

        self.refresh_system_information()

        return page

    def run_full_inventory(self):
        try:
            inventory = collect_system_inventory()
            self.last_inventory = inventory
            rows = []

            for item in inventory.get("software", []):
                rows.append(("Software", item.get("name", ""), item.get("version", ""), item.get("publisher", item.get("manager", ""))))
            for item in inventory.get("updates", []):
                rows.append(("Update", item.get("id", item.get("package", "")), item.get("installed_on", item.get("candidate", "")), item.get("description", "")))
            for item in inventory.get("users", []):
                rows.append(("User", item.get("name", ""), item.get("enabled", item.get("uid", "")), item.get("primary_group", item.get("shell", ""))))
            for item in inventory.get("administrators_group_members", []):
                rows.append(("Local administrator", item.get("name", ""), item.get("object_class", ""), f"SID: {item.get('sid', '')}; Source: {item.get('principal_source', '')}"))
            for item in inventory.get("privileged_group_members", []):
                rows.append(("Linux privileged group", item.get("name", ""), item.get("group", ""), f"GID: {item.get('gid', '')}"))
            for item in inventory.get("services", []):
                rows.append(("Service", item.get("name", item.get("unit", "")), item.get("status", item.get("active", "")), item.get("display_name", item.get("description", ""))))
            for item in inventory.get("listening_ports", []):
                details = item.get("LocalAddress", item.get("protocol", ""))
                if item.get("process_name") or item.get("process_id") is not None:
                    details += f"; Process: {item.get('process_name') or 'Unknown'} (PID {item.get('process_id', 'Unknown')})"
                if item.get("process_path"):
                    details += f"; Path: {item['process_path']}"
                rows.append(("Listening port", item.get("LocalPort", item.get("local_endpoint", "")), item.get("state", ""), details))

            self.inventory_table.setRowCount(min(len(rows), 500))
            for row_index, values in enumerate(rows[:500]):
                for column, value in enumerate(values):
                    cell = QTableWidgetItem(str(value))
                    cell.setToolTip(str(value))
                    self.inventory_table.setItem(row_index, column, cell)

            counts = {
                "software": len(inventory.get("software", [])),
                "updates": len(inventory.get("updates", [])),
                "users": len(inventory.get("users", [])),
                "administrators_group_members": len(inventory.get("administrators_group_members", [])),
                "privileged_group_members": len(inventory.get("privileged_group_members", [])),
                "services": len(inventory.get("services", [])),
                "listening_ports": len(inventory.get("listening_ports", [])),
            }
            errors = inventory.get("collection_errors", [])
            self.inventory_summary.setText(
                "Inventory completed | "
                + " | ".join(f"{key.replace('_', ' ').title()}: {value}" for key, value in counts.items())
                + f" | Collection errors: {len(errors)}"
                + (" | " + "; ".join(f"{e['section']}: {e['error']}" for e in errors) if errors else "")
                + (" | Display limited to 500 rows." if len(rows) > 500 else "")
            )
            self.statusBar().showMessage("System inventory collection completed.")
        except Exception as error:
            self.inventory_summary.setText(f"Inventory error: {error}")
            self.statusBar().showMessage("System inventory collection failed.")

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
            "Inspect real firewall and security configuration on this host."
        )
        description.setObjectName("muted_text")
        layout.addWidget(description)

        card = QFrame()
        card.setObjectName("section_card")

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 20, 20, 20)
        card_layout.setSpacing(15)

        heading = QLabel("Host Firewall Assessment")
        heading.setObjectName("card_title")

        details = QLabel(
            "Windows: Domain, Private and Public profiles. Linux: UFW, firewalld or nftables inspection."
        )
        details.setObjectName("muted_text")

        self.firewall_button = QPushButton(
            "Run Host Firewall Assessment"
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
        self.firewall_table.setMinimumHeight(190)
        self.firewall_table.setMaximumHeight(260)
        self.firewall_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.firewall_table.verticalHeader().setVisible(False)

        card_layout.addWidget(heading)
        card_layout.addWidget(details)
        card_layout.addWidget(self.firewall_button)
        card_layout.addWidget(self.firewall_summary)
        card_layout.addWidget(self.firewall_table)

        self.configuration_button = QPushButton("Run Security Configuration Assessment")
        self.configuration_button.setObjectName("action_button")
        self.configuration_button.clicked.connect(self.run_configuration_assessment)

        self.configuration_summary = QLabel(
            "Collect system inventory before running configuration assessment."
        )
        self.configuration_summary.setObjectName("muted_text")
        self.configuration_summary.setWordWrap(True)

        self.configuration_table = QTableWidget(0, 5)
        self.configuration_table.setHorizontalHeaderLabels([
            "Check ID", "Control", "Status", "Evidence", "Recommendation"
        ])
        self.configuration_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.configuration_table.horizontalHeader().setStretchLastSection(True)
        self.configuration_table.setWordWrap(True)
        self.configuration_table.setMinimumHeight(210)
        self.configuration_table.setMaximumHeight(320)
        self.configuration_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.configuration_table.verticalHeader().setVisible(False)

        card_layout.addWidget(self.configuration_button)
        card_layout.addWidget(self.configuration_summary)
        card_layout.addWidget(self.configuration_table)

        layout.addWidget(card)
        layout.addStretch()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setWidget(page)
        return scroll

    def run_firewall_assessment(self):
        self.firewall_button.setEnabled(False)
        self.firewall_button.setText("Assessing Firewall...")

        try:
            results = assess_host_firewall()

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
                "Host firewall assessment completed."
            )

        except Exception as error:
            self.firewall_summary.setText(
                f"Assessment error: {error}"
            )

            self.statusBar().showMessage(
                "Host firewall assessment encountered an error."
            )

        finally:
            self.firewall_button.setEnabled(True)
            self.firewall_button.setText(
                "Run Firewall Assessment"
            )

    def run_configuration_assessment(self):
        if not self.last_inventory:
            self.configuration_summary.setText(
                "No inventory available. Open System Discovery and run Full System Inventory first."
            )
            return

        self.configuration_button.setEnabled(False)
        self.configuration_button.setText("Assessing Configuration...")
        try:
            results = assess_security_configuration(self.last_inventory)
            self.configuration_table.setRowCount(len(results))

            counts = {"PASS": 0, "FAIL": 0, "UNKNOWN": 0, "NOT_APPLICABLE": 0}
            for row, result in enumerate(results):
                status = result.status.value
                counts[status] = counts.get(status, 0) + 1
                values = [
                    result.check_id, result.control, status,
                    result.evidence, result.recommendation,
                ]
                for column, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    item.setToolTip(str(value))
                    self.configuration_table.setItem(row, column, item)

            self.configuration_summary.setText(
                "Assessment completed | "
                + " | ".join(f"{key}: {value}" for key, value in counts.items())
                + " | Read-only checks; UNKNOWN means more evidence is required."
            )
            self.statusBar().showMessage("Security configuration assessment completed.")
        except Exception as error:
            self.configuration_summary.setText(f"Assessment error: {error}")
            self.statusBar().showMessage("Security configuration assessment failed.")
        finally:
            self.configuration_button.setEnabled(True)
            self.configuration_button.setText("Run Security Configuration Assessment")

    def create_vulnerability_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(16)

        description = QLabel(
            "Query installed package versions against OSV and enrich matching CVEs with CISA Known Exploited Vulnerabilities data."
        )
        description.setObjectName("muted_text")
        description.setWordWrap(True)
        layout.addWidget(description)

        self.vulnerability_button = QPushButton("Run Package Vulnerability Assessment")
        self.vulnerability_button.setObjectName("action_button")
        self.vulnerability_button.clicked.connect(self.run_vulnerability_assessment)
        layout.addWidget(self.vulnerability_button)

        self.windows_product_button = QPushButton("Screen Windows Products Against CISA KEV")
        self.windows_product_button.setObjectName("action_button")
        self.windows_product_button.clicked.connect(self.run_windows_product_screening)
        layout.addWidget(self.windows_product_button)

        self.windows_product_summary = QLabel(
            "Windows product screening is a separate catalogue check; it does not confirm version applicability."
        )
        self.windows_product_summary.setObjectName("muted_text")
        self.windows_product_summary.setWordWrap(True)
        layout.addWidget(self.windows_product_summary)

        self.windows_product_table = QTableWidget(0, 7)
        self.windows_product_table.setHorizontalHeaderLabels([
            "Installed Product", "Version", "Publisher", "CVE",
            "KEV Product", "Classification", "Validation Note",
        ])
        self.windows_product_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.windows_product_table.horizontalHeader().setStretchLastSection(True)
        self.windows_product_table.setWordWrap(True)
        self.windows_product_table.setMinimumHeight(220)
        layout.addWidget(self.windows_product_table)

        self.nvd_button = QPushButton("Assess All Windows Products with NVD CPE/CVE")
        self.nvd_button.setObjectName("action_button")
        self.nvd_button.clicked.connect(self.run_nvd_enrichment)
        layout.addWidget(self.nvd_button)

        self.nvd_summary = QLabel(
            "Assess all inventoried Windows applications against NVD CPE records, independently of KEV name matches."
        )
        self.nvd_summary.setObjectName("muted_text")
        self.nvd_summary.setWordWrap(True)
        layout.addWidget(self.nvd_summary)

        self.nvd_table = QTableWidget(0, 6)
        self.nvd_table.setHorizontalHeaderLabels([
            "Installed Product", "Version", "CVE", "NVD Status",
            "Vulnerability Status", "Description",
        ])
        self.nvd_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.nvd_table.horizontalHeader().setStretchLastSection(True)
        self.nvd_table.setWordWrap(True)
        self.nvd_table.setMinimumHeight(220)
        layout.addWidget(self.nvd_table)

        self.vulnerability_summary = QLabel(
            "Collect Full System Inventory before running vulnerability intelligence."
        )
        self.vulnerability_summary.setObjectName("muted_text")
        self.vulnerability_summary.setWordWrap(True)
        layout.addWidget(self.vulnerability_summary)

        self.vulnerability_table = QTableWidget(0, 7)
        self.vulnerability_table.setHorizontalHeaderLabels([
            "Package", "Installed Version", "Vulnerability ID",
            "Classification", "CISA KEV", "Sources", "Summary",
        ])
        self.vulnerability_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.vulnerability_table.horizontalHeader().setStretchLastSection(True)
        self.vulnerability_table.setWordWrap(True)
        self.vulnerability_table.setMinimumHeight(300)
        self.vulnerability_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        layout.addWidget(self.vulnerability_table, 1)

        note = QLabel(
            "A package/version match is a candidate finding, not proof of exploitability. "
            "Validate vendor advisories, distribution backports, installed build details and runtime exposure."
        )
        note.setObjectName("muted_text")
        note.setWordWrap(True)
        layout.addWidget(note)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(page)
        return scroll

    def run_nvd_enrichment(self):
        if not self.last_inventory:
            self.nvd_summary.setText("Run Full System Inventory first.")
            return
        if self.last_inventory.get("system", {}).get("operating_system", "") != "Windows":
            self.nvd_summary.setText("NVD product enrichment currently requires Windows product inventory.")
            return
        self.nvd_button.setEnabled(False)
        self.nvd_button.setText("Querying NVD...")
        self.nvd_summary.setText("Searching NVD CPE records for all inventoried Windows products. This may take time.")
        try:
            result = assess_windows_products_with_nvd(self.last_inventory.get('software', []))
            rows = []
            for product in result.get("matches", []):
                candidates = product.get("nvd_candidates", [])
                if not candidates:
                    rows.append((
                        product.get("product", ""),
                        product.get("installed_version", ""),
                        "",
                        product.get("nvd_status", ""),
                        "",
                        "",
                    ))
                for candidate in candidates:
                    rows.append((
                        product.get("product", ""),
                        product.get("installed_version", ""),
                        candidate.get("cve_id", ""),
                        product.get("nvd_status", ""),
                        candidate.get("vuln_status", ""),
                        candidate.get("description", ""),
                    ))
            self.nvd_table.setRowCount(len(rows))
            for row, values in enumerate(rows):
                for column, value in enumerate(values):
                    cell = QTableWidgetItem(str(value))
                    cell.setToolTip(str(value))
                    self.nvd_table.setItem(row, column, cell)

            errors = result.get("source_errors", [])
            self.nvd_summary.setText(
                f"Status: {result.get('status')} | Products queried: {result.get('products_queried', 0)}"
                f" | Exact CPE candidates: {result.get('cpe_candidates', 0)}"
                f" | CVE candidates: {result.get('cve_candidates', 0)}"
                f" | Source errors: {len(errors)}"
                + (" | " + "; ".join(item.get("error", "") for item in errors) if errors else "")
                + " | All NVD results require manual version/configuration validation."
            )
            self.statusBar().showMessage("NVD CPE/CVE enrichment completed.")
        except Exception as error:
            self.nvd_summary.setText(f"NVD enrichment error: {error}")
        finally:
            self.nvd_button.setEnabled(True)
            self.nvd_button.setText("Assess All Windows Products with NVD CPE/CVE")

    def run_vulnerability_assessment(self):
        if not self.last_inventory:
            self.vulnerability_summary.setText(
                "No inventory available. Open System Discovery and run Full System Inventory first."
            )
            return

        self.vulnerability_button.setEnabled(False)
        self.vulnerability_button.setText("Querying Vulnerability Sources...")
        self.vulnerability_summary.setText("Querying OSV and CISA KEV. This may take a short while.")
        try:
            software = self.last_inventory.get("software", [])
            result = assess_package_vulnerabilities(software)
            self.last_vulnerability_results = result
            findings = result.get("findings", [])
            self.vulnerability_table.setRowCount(len(findings))
            for row, finding in enumerate(findings):
                values = [
                    finding.get("package", ""),
                    finding.get("version", ""),
                    ", ".join(finding.get("cve_ids", [])) or finding.get("vulnerability_id", ""),
                    finding.get("classification", ""),
                    "YES" if finding.get("known_exploited") else "No",
                    ", ".join(finding.get("sources", [])),
                    finding.get("summary", ""),
                ]
                for column, value in enumerate(values):
                    cell = QTableWidgetItem(str(value))
                    cell.setToolTip(str(value))
                    self.vulnerability_table.setItem(row, column, cell)

            errors = result.get("source_errors", [])
            kev_status = result.get("kev_correlation_status", "UNKNOWN")
            kev_count = result.get("kev_catalogue_entries")
            if kev_status == "EVALUATED":
                kev_text = f"CISA KEV catalogue entries: {kev_count}"
            elif kev_status == "NOT_EVALUATED_NO_SUPPORTED_PACKAGES":
                kev_text = "CISA KEV correlation: not evaluated"
            else:
                kev_text = "CISA KEV catalogue: unavailable"
            unsupported_reasons = {}
            for item in result.get("unsupported_details", []):
                reason = item.get("reason", "unknown")
                unsupported_reasons[reason] = unsupported_reasons.get(reason, 0) + 1
            reason_text = ", ".join(
                f"{key}: {value}" for key, value in sorted(unsupported_reasons.items())
            ) or "none"
            self.vulnerability_summary.setText(
                f"Assessment completed | Packages queried: {result.get('queried_packages', 0)}"
                f" | Unsupported inventory records: {result.get('unsupported_records', 0)} ({reason_text})"
                f" | Candidate findings: {len(findings)}"
                f" | KEV-linked findings: {sum(1 for item in findings if item.get('known_exploited'))}"
                f" | {kev_text}"
                f" | Source errors: {len(errors)}"
                + (" | " + "; ".join(f"{item['source']}: {item['error']}" for item in errors) if errors else "")
            )
            self.statusBar().showMessage("Vulnerability intelligence query completed.")
        except Exception as error:
            self.vulnerability_summary.setText(f"Vulnerability intelligence error: {error}")
            self.statusBar().showMessage("Vulnerability intelligence query failed.")
        finally:
            self.vulnerability_button.setEnabled(True)
            self.vulnerability_button.setText("Run Package Vulnerability Assessment")

    def run_windows_product_screening(self):
        if not self.last_inventory:
            self.windows_product_summary.setText(
                "No inventory available. Run Full System Inventory first."
            )
            return

        system_name = self.last_inventory.get("system", {}).get("operating_system", "")
        if system_name != "Windows":
            self.windows_product_summary.setText(
                "This screening currently supports Windows registry software inventory only."
            )
            return

        self.windows_product_button.setEnabled(False)
        self.windows_product_button.setText("Screening Windows Products...")
        try:
            result = screen_windows_products_against_kev(
                self.last_inventory.get("software", [])
            )
            matches = result.get("matches", [])
            self.windows_product_table.setRowCount(len(matches))
            for row, match in enumerate(matches):
                values = [
                    match.get("product", ""),
                    match.get("installed_version", ""),
                    match.get("publisher", ""),
                    match.get("cve_id", ""),
                    match.get("catalogue_product", ""),
                    match.get("classification", ""),
                    match.get("assessment_note", ""),
                ]
                for column, value in enumerate(values):
                    cell = QTableWidgetItem(str(value))
                    cell.setToolTip(str(value))
                    self.windows_product_table.setItem(row, column, cell)

            errors = result.get("source_errors", [])
            self.windows_product_summary.setText(
                f"Status: {result.get('status')} | Products screened: {result.get('products_screened', 0)}"
                f" | Exact catalogue matches: {len(matches)}"
                f" | Unsupported records: {result.get('unsupported_records', 0)}"
                f" | CISA KEV catalogue entries: {result.get('kev_catalogue_entries', 'Unavailable')}"
                f" | Source errors: {len(errors)}"
                + (" | " + "; ".join(item["error"] for item in errors) if errors else "")
            )
            self.statusBar().showMessage("Windows product catalogue screening completed.")
        except Exception as error:
            self.windows_product_summary.setText(f"Windows product screening error: {error}")
        finally:
            self.windows_product_button.setEnabled(True)
            self.windows_product_button.setText("Screen Windows Products Against CISA KEV")

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
