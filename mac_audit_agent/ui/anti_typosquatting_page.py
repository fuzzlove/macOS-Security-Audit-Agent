from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal, Slot, QStandardPaths
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFormLayout, QHeaderView,
    QLabel, QLineEdit, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QTextBrowser,
    QVBoxLayout, QWidget)

from mac_audit_agent.anti_typosquatting.models import AssetType, GenerationConfiguration, PackageEcosystem, ProtectedAsset
from mac_audit_agent.anti_typosquatting.reporting import export_html, export_professional
from mac_audit_agent.professional_report import PROFESSIONAL_REPORT_FILTER, selected_report_path
from mac_audit_agent.anti_typosquatting.service import AntiTyposquattingService
from mac_audit_agent.ui.button_factory import create_toolbar_button
from mac_audit_agent.ui.responsive_actions import ResponsiveActionRow
from mac_audit_agent.ui.severity_styles import apply_severity_to_table_item

ANTI_TYPOSQUATTING_DESCRIPTION = (
    "Package & Domain Impersonation helps developers, administrators, defenders, incident responders, and security testers protect "
    "software supply chains and public identities. It generates explainable domain and package-name variants that an "
    "attacker might register or publish to impersonate a trusted website, dependency, product, publisher, or update "
    "channel. Coverage includes common typing mistakes, adjacent-key errors, missing or repeated characters, transposed "
    "letters, separator and package-normalization collisions, namespace confusion, misleading prefixes or suffixes, "
    "internationalized names, and Unicode visual confusables. Teams can compare these candidates with authorized registry "
    "metadata, investigate existing lookalikes, watch for later registration or publication, and prioritize appropriate "
    "defensive registrations with their registrar, registry, legal, brand-protection, and fraud teams. Finding and "
    "defensively addressing a high-risk unregistered variant before an attacker uses it can reduce phishing, dependency "
    "confusion, credential theft, fraudulent support sites, malicious update delivery, and brand impersonation.\n\n"
    "This capability should be an integral SDLC control: define protected product, organization, domain, publisher, and "
    "package identities during design; scan proposed names before launch; check manifests and dependency changes during "
    "development and code review; gate CI/CD releases on approved package coordinates and publisher ownership; monitor "
    "lookalikes after deployment; and feed confirmed abuse into incident response, takedown, fraud prevention, and lessons "
    "learned. Similarity is an investigation lead—not proof of malicious intent, ownership, availability, or legal rights. "
    "MSAA generates candidates locally; optional live checks require consent, disclose only the selected names to allowlisted "
    "metadata providers, never visit candidate websites, and never download or install candidate packages."
)

TYPO_SQUATTING_EXAMPLES = (
    "Illustrative lookalike patterns (do not visit or install):\n"
    "• microsoftt.co — repeated-letter brand/domain variation\n"
    "• npmm — extra-letter package-name variation resembling npm\n"
    "• python4 — misleading version-suffix package variation resembling python\n"
    "These names are educational examples only. Similarity does not establish ownership, availability, or malicious intent."
)


class _Signals(QObject):
    completed = Signal(object)
    failed = Signal(str)


class _AnalysisWorker(QRunnable):
    def __init__(self, asset, configuration):
        super().__init__()
        self.asset, self.configuration = asset, configuration
        self.signals = _Signals()
        self.cancelled = False

    @Slot()
    def run(self):
        if self.cancelled:
            return
        try:
            result = AntiTyposquattingService().analyze(self.asset, self.configuration)
        except Exception as exc:  # contained at the worker boundary
            self.signals.failed.emit(str(exc))
            return
        if not self.cancelled:
            self.signals.completed.emit(result)


class _LookupWorker(QRunnable):
    def __init__(self, run):
        super().__init__(); self.run = run; self.signals = _Signals(); self.cancelled = False
    @Slot()
    def run(self):
        try:
            from mac_audit_agent.anti_typosquatting.models import AssetType, PackageEcosystem
            from mac_audit_agent.anti_typosquatting.providers import CratesIoProvider, GoModuleProvider, MavenCentralProvider, NpmProvider, NuGetProvider, PackagistProvider, PyPIProvider, RDAPProvider, RubyGemsProvider
            asset = self.run.asset
            mapping={PackageEcosystem.NPM:NpmProvider,PackageEcosystem.PYPI:PyPIProvider,PackageEcosystem.CRATES_IO:CratesIoProvider,PackageEcosystem.RUBYGEMS:RubyGemsProvider,PackageEcosystem.NUGET:NuGetProvider,PackageEcosystem.MAVEN_CENTRAL:MavenCentralProvider,PackageEcosystem.GO_MODULE:GoModuleProvider,PackageEcosystem.PACKAGIST:PackagistProvider}
            provider = RDAPProvider() if asset.asset_type == AssetType.DOMAIN else mapping[asset.ecosystem]()
            for candidate in self.run.candidates[:10]:
                if self.cancelled: return
                result = provider.lookup(candidate.ascii_name or candidate.normalized_name, private=True) if asset.ecosystem == PackageEcosystem.GO_MODULE else provider.lookup(candidate.ascii_name or candidate.normalized_name)
                candidate.lookup_status = result.status.value
                candidate.lookup_evidence = {"provider": result.provider, "message": result.message, **result.evidence}
                if result.status.value in {"No Registration Data Found", "Not Currently Published"} and candidate.risk_band in {"critical", "high"}:
                    candidate.registration_guidance = "Priority defensive-registration candidate: an authorized owner should verify rights and actual availability with the registrar or registry before purchase or publication."
                elif result.status.value in {"Registered", "Published"}:
                    candidate.registration_guidance = "Already registered or published: verify ownership and preserve evidence; do not attempt purchase or allege abuse from similarity alone."
        except Exception as exc:
            self.signals.failed.emit(str(exc)); return
        if not self.cancelled: self.signals.completed.emit(self.run)


class AntiTyposquattingPage(QWidget):
    """Local-first analysis page; registry interaction requires a separate consent workflow."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("antiTyposquattingPage")
        self._run = None
        self._worker = None
        self._pool = QThreadPool.globalInstance()
        layout = QVBoxLayout(self)
        explanation = QLabel(ANTI_TYPOSQUATTING_DESCRIPTION)
        explanation.setWordWrap(True)
        explanation.setAccessibleName("Package and Domain Impersonation explanation")
        layout.addWidget(explanation)
        self.examples = QLabel(TYPO_SQUATTING_EXAMPLES)
        self.examples.setObjectName("antiTyposquattingExamples")
        self.examples.setAccessibleName("Illustrative typosquatting examples")
        self.examples.setWordWrap(True)
        self.examples.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByKeyboard | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.examples.setStyleSheet("padding: 8px; border: 1px solid #667085; border-radius: 6px;")
        layout.addWidget(self.examples)
        form = QFormLayout()
        self.asset_type = QComboBox(); self.asset_type.addItems(["Internet Domain", "Software Package"])
        self.asset_type.setAccessibleName("Asset Type"); self.asset_type.setToolTip("Choose whether the protected asset is an Internet domain or a software package name.")
        self.name = QLineEdit(); self.name.setPlaceholderText("examplebrand.test"); self.name.setAccessibleName("Canonical Name")
        self.name.setToolTip("Enter a bare domain or registry-valid package name that you own or are authorized to protect.")
        self.ecosystem = QComboBox(); self.ecosystem.addItems(["npm Registry", "Python Package Index (PyPI)", "crates.io", "RubyGems.org", "NuGet.org", "Maven Central", "Go Modules", "Composer and Packagist"])
        self.ecosystem.setAccessibleName("Package Ecosystem"); self.ecosystem.setToolTip("Select the package registry whose naming and normalization rules apply.")
        self.locale = QComboBox(); self.locale.addItems(["United States English QWERTY", "United Kingdom English QWERTY", "French AZERTY", "German QWERTZ", "Spanish QWERTY", "Italian QWERTY", "Brazilian Portuguese QWERTY", "Polish QWERTY", "Turkish QWERTY", "Generic QWERTY fallback"])
        self.locale.setAccessibleName("Region and Keyboard Layout")
        self.typing_profile = QComboBox(); self.typing_profile.addItems(["Standard Desktop Keyboard", "Mobile or Touchscreen Input", "Fast Typing", "Novice or Unfamiliar User", "Reduced-Dexterity Input", "Visual-Confusable Review", "Phonetic or Non-Native Spelling Review"])
        self.typing_profile.setAccessibleName("Typing and Accessibility Profile"); self.typing_profile.setToolTip("Model an input behavior without inferring demographic traits or location.")
        self.offline = QCheckBox("Generate Offline Only"); self.offline.setChecked(True); self.offline.setAccessibleName("Generate Offline Only")
        self.offline.setToolTip("Keep canonical and generated names local and perform no registry network requests.")
        self.namespace_part = QLineEdit(); self.namespace_part.setAccessibleName("Publisher Namespace Component")
        self.package_part = QLineEdit(); self.package_part.setAccessibleName("Package Identifier Component")
        self.namespace_label = QLabel("Group Identifier or Vendor"); self.package_label = QLabel("Artifact Identifier or Package")
        self.go_privacy = QLabel("Go module paths may disclose private organization and repository names. Public lookup is prohibited for paths matching private-module policy unless separately authorized."); self.go_privacy.setWordWrap(True)
        form.addRow("Asset Type", self.asset_type); form.addRow("Canonical Name", self.name); form.addRow("Package Ecosystem", self.ecosystem); form.addRow(self.namespace_label, self.namespace_part); form.addRow(self.package_label, self.package_part); form.addRow("Regions and Keyboard Layouts", self.locale); form.addRow("Typing and Accessibility Profiles", self.typing_profile); form.addRow("", self.offline)
        layout.addWidget(self.go_privacy)
        layout.addLayout(form)
        self.options = {}
        for label, key, checked in [
            ("Common Human Typographical Errors", "human", True), ("Regional Keyboard Errors", "keyboard", True),
            ("Phonetic and Linguistic Errors", "phonetic", True), ("Unicode Visual Confusables", "unicode", True),
            ("Internationalized Domain Variants", "idn", True), ("Domain Extension Confusion", "tld", True),
            ("Brand and Service Word Additions", "service", True), ("Package Namespace and Separator Confusion", "package", True),
            ("Include Plausible Two-Error Variants", "two_error", False)]:
            control = QCheckBox(label); control.setChecked(checked); control.setAccessibleName(label); control.setToolTip("Enable or disable the bounded %s candidate category." % label.lower()); layout.addWidget(control); self.options[key] = control
        self.asset_type.currentIndexChanged.connect(lambda index: self.ecosystem.setVisible(index == 1))
        self.ecosystem.currentIndexChanged.connect(self._ecosystem_changed)
        self.ecosystem.setVisible(False)
        self._ecosystem_changed()
        buttons = ResponsiveActionRow()
        self.generate_button = self._button("Generate Likely Typographical Variants", "Generate a bounded deterministic candidate set locally.", self.generate)
        self.lookup_button = self._button("Check Registration and Publication Status", "Request consent before sending selected names to allowlisted registry providers.", self.lookup)
        self.watch_button = self._button("Add Selected Variants to Protection Watchlist", "Add selected candidates to the local defensive watchlist.", self.watchlist)
        self.export_button = self._button("Export Analysis Results", "Export an escaped local HTML report containing explanations and limitations.", self.export_results)
        self.clear_button = self._button("Clear Analysis Results", "Clear the displayed analysis without modifying registrations or packages.", self.clear_results)
        for button in (self.generate_button, self.lookup_button, self.watch_button, self.export_button, self.clear_button): buttons.add_button(button)
        layout.addWidget(buttons)
        self.table = QTableWidget(0, 10); self.table.setHorizontalHeaderLabels(["Candidate", "Risk Band", "Attacker-use Assumption %", "Name Closeness %", "Human Typo %", "Impersonation %", "Defensive Registration %", "Investigation %", "Lookup Status", "Registration Guidance"])
        self.table.setAccessibleName("Package and Domain Impersonation analysis results"); self.table.setSortingEnabled(True)
        self.table.setWordWrap(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(9, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 190); self.table.setColumnWidth(1, 100)
        for column in range(2, 8): self.table.setColumnWidth(column, 112)
        self.table.setColumnWidth(8, 170)
        self.table.itemSelectionChanged.connect(self._show_details)
        layout.addWidget(self.table)
        self.details = QTextBrowser(); self.details.setAccessibleName("Candidate Details"); layout.addWidget(self.details)

    def _button(self, label, tooltip, callback):
        button = create_toolbar_button(label, accessible_name=label, tooltip=tooltip, on_click=callback)
        button.setText(label)
        button.setMaximumWidth(16777215)
        return button

    def _asset(self):
        if self.asset_type.currentIndex() == 0:
            return ProtectedAsset(AssetType.DOMAIN, self.name.text().strip())
        ecosystems=list(PackageEcosystem); ecosystem=ecosystems[self.ecosystem.currentIndex()]
        canonical=self.name.text().strip()
        if ecosystem == PackageEcosystem.MAVEN_CENTRAL and self.namespace_part.text().strip() and self.package_part.text().strip(): canonical=self.namespace_part.text().strip()+":"+self.package_part.text().strip()
        if ecosystem == PackageEcosystem.PACKAGIST and self.namespace_part.text().strip() and self.package_part.text().strip(): canonical=self.namespace_part.text().strip()+"/"+self.package_part.text().strip()
        return ProtectedAsset(AssetType.PACKAGE, canonical, ecosystem)

    def _ecosystem_changed(self):
        ecosystem=list(PackageEcosystem)[self.ecosystem.currentIndex()]
        structured=ecosystem in {PackageEcosystem.MAVEN_CENTRAL,PackageEcosystem.PACKAGIST}
        for widget in (self.namespace_part,self.package_part,self.namespace_label,self.package_label): widget.setVisible(structured)
        self.namespace_label.setText("Group Identifier" if ecosystem==PackageEcosystem.MAVEN_CENTRAL else "Vendor")
        self.package_label.setText("Artifact Identifier" if ecosystem==PackageEcosystem.MAVEN_CENTRAL else "Package")
        self.go_privacy.setVisible(ecosystem==PackageEcosystem.GO_MODULE)

    def _locale_id(self):
        return ["en-US-qwerty", "en-GB-qwerty", "fr-FR-azerty", "de-DE-qwertz", "es-ES-qwerty", "it-IT-qwerty", "pt-BR-qwerty", "pl-PL-qwerty", "tr-TR-qwerty", "generic-qwerty"][self.locale.currentIndex()]

    @Slot()
    def generate(self):
        self.generate_button.setEnabled(False); self.generate_button.setText("Generating Analysis…")
        profile_ids = ("desktop", "mobile", "fast", "novice", "reduced-dexterity", "visual-review", "phonetic-review")
        config = GenerationConfiguration(locales=(self._locale_id(),), typing_profiles=(profile_ids[self.typing_profile.currentIndex()],), include_human_typos=self.options["human"].isChecked(), include_keyboard=self.options["keyboard"].isChecked(), include_phonetic=self.options["phonetic"].isChecked(), include_unicode=self.options["unicode"].isChecked() or self.options["idn"].isChecked(), include_tld_confusion=self.options["tld"].isChecked(), include_service_words=self.options["service"].isChecked(), include_package_confusion=self.options["package"].isChecked(), include_two_error=self.options["two_error"].isChecked(), offline_only=True)
        self._worker = _AnalysisWorker(self._asset(), config)
        self._worker.signals.completed.connect(self._complete); self._worker.signals.failed.connect(self._failed); self._pool.start(self._worker)

    @Slot(object)
    def _complete(self, run):
        self._run = run; self.table.setSortingEnabled(False); self.table.setRowCount(len(run.candidates))
        for row, candidate in enumerate(run.candidates):
            values = [candidate.display_name, candidate.risk_band.upper(), candidate.attacker_use_assumption.total, candidate.name_closeness.total, candidate.human_typo.total, candidate.impersonation.total, candidate.defensive_registration.total, candidate.investigation.total, candidate.lookup_status, candidate.registration_guidance]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if 2 <= column <= 7: item.setData(Qt.DisplayRole, int(value))
                self.table.setItem(row, column, item)
            apply_severity_to_table_item(self.table.item(row, 1), candidate.risk_band, candidate.attacker_use_assumption.total, "risk_score", reasons=[reason.explanation for reason in candidate.reasons], text=candidate.risk_band.upper())
        self.table.setSortingEnabled(True); self.generate_button.setEnabled(True); self.generate_button.setText("Generate Likely Typographical Variants")

    @Slot(str)
    def _failed(self, message):
        self.generate_button.setEnabled(True); self.generate_button.setText("Generate Likely Typographical Variants")
        self.lookup_button.setEnabled(True); self.lookup_button.setText("Check Registration and Publication Status")
        QMessageBox.warning(self, "Operation Could Not Complete", message)

    def lookup(self):
        if not self._run: QMessageBox.information(self, "Nothing to Check", "Generate an analysis first."); return
        answer = QMessageBox.question(self, "Live Lookup Consent", "Up to ten candidate names will be sent to allowlisted RDAP or package registry services. No website will be opened and no package will be downloaded. Results may be incomplete or rate limited. Continue?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes: return
        self.lookup_button.setEnabled(False); self.lookup_button.setText("Checking Registry Status…")
        self._worker = _LookupWorker(self._run); self._worker.signals.completed.connect(self._lookup_complete); self._worker.signals.failed.connect(self._failed); self._pool.start(self._worker)

    @Slot(object)
    def _lookup_complete(self, run):
        self.lookup_button.setEnabled(True); self.lookup_button.setText("Check Registration and Publication Status"); self._complete(run)

    def watchlist(self):
        if not self._run: QMessageBox.information(self, "Nothing to Add", "Generate an analysis first."); return
        selected_rows = sorted({index.row() for index in self.table.selectedIndexes()})
        selected_names = {self.table.item(row, 0).text() for row in selected_rows}
        selected = [item for item in self._run.candidates if item.display_name in selected_names]
        if not selected: QMessageBox.information(self, "Select Variants", "Select one or more result rows first."); return
        from mac_audit_agent.anti_typosquatting.persistence import AntiTyposquattingStore
        from mac_audit_agent.version import APP_VERSION
        root = Path(QStandardPaths.writableLocation(QStandardPaths.AppDataLocation))
        store = AntiTyposquattingStore(root / "anti_typosquatting.sqlite3"); store.save_run(self._run, APP_VERSION)
        count = store.add_watchlist(self._run, selected)
        QMessageBox.information(self, "Protection Watchlist Updated", "%d selected variant(s) were added to the local watchlist. No domain was registered and no package was published." % count)

    def export_results(self):
        if not self._run: QMessageBox.information(self, "Nothing to Export", "Generate an analysis first."); return
        path, selected = QFileDialog.getSaveFileName(self, "Export Analysis Results", "anti_typosquatting_analysis.html", PROFESSIONAL_REPORT_FILTER)
        if path:
            destination = selected_report_path(path, selected)
            export_html(self._run, destination) if destination.suffix.lower() == ".html" else export_professional(self._run, destination)

    def clear_results(self):
        self._run = None; self.table.setRowCount(0); self.details.clear()

    def _show_details(self):
        if not self._run or not self.table.currentItem(): return
        name = self.table.item(self.table.currentRow(), 0).text()
        candidate = next((item for item in self._run.candidates if item.display_name == name), None)
        if candidate:
            self.details.setPlainText("Canonical asset: %s\nCandidate: %s\nRisk band: %s\nAttacker-use assumption: %d%%\nName closeness: %d%%\nRegistration guidance: %s\nCode points: %s\nScripts: %s\nConfusable skeleton: %s\nRules: %s\nReasons: %s\nConfidence limitation: this is a deterministic opportunity assumption, not evidence of attacker intent, ownership, availability, or abuse." % (candidate.canonical_asset, candidate.display_name, candidate.risk_band.upper(), candidate.attacker_use_assumption.total, candidate.name_closeness.total, candidate.registration_guidance, ", ".join(candidate.unicode_code_points) or "ASCII only", ", ".join(candidate.unicode_scripts), candidate.confusable_skeleton, ", ".join(r.rule_id for r in candidate.reasons), " ".join(r.explanation for r in candidate.reasons)))

    def closeEvent(self, event):
        if self._worker: self._worker.cancelled = True
        super().closeEvent(event)
