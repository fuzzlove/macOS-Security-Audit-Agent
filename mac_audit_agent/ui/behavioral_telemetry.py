from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor, QBrush
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDateTimeEdit,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.telemetry.manager import TelemetryManager, manager_for
from mac_audit_agent.telemetry.models import ActivityDimension, AnomalyDisposition
from mac_audit_agent.telemetry.policies import PROFILE_POLICIES
from mac_audit_agent.telemetry.workstation_profiles import workstation_profile
from mac_audit_agent.ui.responsive_actions import ResponsiveActionRow
from mac_audit_agent.ui.telemetry_chart import TelemetryChart, TelemetryChartPoint


_DIMENSION_LABELS = {
    "OVERALL": "Overall Activity",
    **{dimension.value: dimension.value.replace("_ACTIVITY", "").replace("_", " ").title() for dimension in ActivityDimension},
}

_SEVERITY_COLORS = {
    "critical": QColor("#B42318"),
    "high": QColor("#C2413A"),
    "medium": QColor("#D97706"),
    "low": QColor("#4F7CAC"),
    "info": QColor("#637083"),
}


class BehavioralTelemetryPanel(QWidget):
    """Coverage-aware operator view over the shared behavioral telemetry service."""

    investigation_requested = Signal(str)
    evidence_requested = Signal(str)

    def __init__(self, database: Any, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.db = database
        self.manager: TelemetryManager = manager_for(database)
        self.repository = self.manager.repository
        self._anomalies: list[dict[str, Any]] = []
        self._selected_anomaly_id = ""
        self._build_ui()
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(10_000)
        self._refresh_timer.timeout.connect(self.refresh)
        self._refresh_timer.start()
        self.refresh()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(10)

        controls = ResponsiveActionRow(self)
        profile_label = QLabel("Workstation role")
        profile_label.setToolTip("Declares the intended workstation role used alongside local host and user baselines.")
        self.workstation_profile_combo = QComboBox()
        self.workstation_profile_combo.addItems(list(PROFILE_POLICIES))
        self.workstation_profile_combo.setCurrentText(self.manager.policy.profile)
        self.workstation_profile_combo.setToolTip(workstation_profile(self.manager.policy.profile).description)
        self.range_combo = QComboBox()
        for label, hours in (("Last Hour", 1), ("6 Hours", 6), ("24 Hours", 24), ("7 Days", 168), ("30 Days", 720), ("Custom", -1)):
            self.range_combo.addItem(label, hours)
        self.range_combo.setCurrentIndex(2)
        self.range_combo.currentIndexChanged.connect(self._range_changed)
        self.dimension_combo = QComboBox()
        for value, label in _DIMENSION_LABELS.items():
            self.dimension_combo.addItem(label, value)
        self.dimension_combo.currentIndexChanged.connect(self.refresh)
        self.start_edit = QDateTimeEdit(datetime.now().astimezone() - timedelta(hours=24))
        self.start_edit.setCalendarPopup(True)
        self.start_edit.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.end_edit = QDateTimeEdit(datetime.now().astimezone())
        self.end_edit.setCalendarPopup(True)
        self.end_edit.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.start_edit.setVisible(False)
        self.end_edit.setVisible(False)
        self.start_edit.dateTimeChanged.connect(self.refresh)
        self.end_edit.dateTimeChanged.connect(self.refresh)
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh)
        rebuild_button = QPushButton("Rebuild Behavioral Baseline")
        rebuild_button.clicked.connect(self._rebuild_baseline)
        controls.add_buttons(
            [
                profile_label,
                self.workstation_profile_combo,
                self.range_combo,
                self.dimension_combo,
                self.start_edit,
                self.end_edit,
                refresh_button,
                rebuild_button,
            ]
        )
        self.workstation_profile_combo.currentTextChanged.connect(self._workstation_profile_changed)
        outer.addWidget(controls)

        summary_frame = QFrame()
        summary_frame.setProperty("themeCard", True)
        summary_grid = QGridLayout(summary_frame)
        summary_grid.setContentsMargins(12, 10, 12, 10)
        summary_grid.setSpacing(8)
        self.summary_labels: dict[str, QLabel] = {}
        definitions = (
            ("state", "Current State"),
            ("confidence", "Baseline Confidence"),
            ("score", "Current Activity Score"),
            ("range", "Normal Range"),
            ("anomalies", "Anomalies Today"),
            ("high_risk", "High-Risk Anomalies"),
            ("age", "Baseline Age"),
            ("coverage", "Telemetry Coverage"),
            ("profile", "Workstation Role"),
        )
        for index, (key, title) in enumerate(definitions):
            card = QFrame()
            card.setProperty("metricCard", True)
            card.setMinimumHeight(78)
            card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            layout = QVBoxLayout(card)
            layout.setContentsMargins(10, 8, 10, 8)
            heading = QLabel(title)
            heading.setProperty("textRole", "muted")
            value = QLabel("—")
            value.setProperty("textRole", "metric")
            value.setWordWrap(True)
            layout.addWidget(heading)
            layout.addWidget(value)
            summary_grid.addWidget(card, index // 4, index % 4)
            self.summary_labels[key] = value
        outer.addWidget(summary_frame)

        chart_frame = QFrame()
        chart_frame.setProperty("themeCard", True)
        chart_layout = QVBoxLayout(chart_frame)
        chart_heading = QLabel("Activity vs Normal Baseline")
        chart_heading.setProperty("textRole", "cardTitle")
        chart_layout.addWidget(chart_heading)
        self.chart = TelemetryChart()
        self.chart.anomaly_selected.connect(self.select_anomaly)
        chart_layout.addWidget(self.chart)
        outer.addWidget(chart_frame)

        splitter = QSplitter(Qt.Horizontal)
        activity_frame = QFrame()
        activity_frame.setProperty("themeCard", True)
        activity_layout = QVBoxLayout(activity_frame)
        self.activity_summary = QLabel("Behavior Summary — no telemetry has been aggregated yet.")
        self.activity_summary.setWordWrap(True)
        self.activity_summary.setProperty("textRole", "cardTitle")
        activity_layout.addWidget(self.activity_summary)
        self.dimension_table = QTableWidget(0, 4)
        self.dimension_table.setHorizontalHeaderLabels(("Dimension", "Observed", "Coverage", "Assessment"))
        self.dimension_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.dimension_table.setSelectionMode(QAbstractItemView.NoSelection)
        self.dimension_table.verticalHeader().setVisible(False)
        self.dimension_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.dimension_table.horizontalHeader().setStretchLastSection(True)
        activity_layout.addWidget(self.dimension_table)
        splitter.addWidget(activity_frame)

        detail_frame = QFrame()
        detail_frame.setProperty("themeCard", True)
        detail_layout = QVBoxLayout(detail_frame)
        detail_title = QLabel("Why MSAA flagged this")
        detail_title.setProperty("textRole", "cardTitle")
        detail_layout.addWidget(detail_title)
        self.explanation = QTextEdit()
        self.explanation.setReadOnly(True)
        self.explanation.setPlaceholderText("Select an anomaly to review its calculation, context, coverage, and evidence references.")
        detail_layout.addWidget(self.explanation)
        actions = ResponsiveActionRow(self)
        for label, disposition in (
            ("Expected Behavior", AnomalyDisposition.EXPECTED.value),
            ("Investigate", AnomalyDisposition.INVESTIGATE.value),
            ("False Positive", AnomalyDisposition.FALSE_POSITIVE.value),
            ("Suspicious", AnomalyDisposition.SUSPICIOUS.value),
            ("Confirmed Incident", AnomalyDisposition.CONFIRMED.value),
        ):
            button = QPushButton(label)
            button.clicked.connect(lambda _checked=False, value=disposition: self._set_disposition(value))
            actions.add_button(button)
        self.open_evidence_button = QPushButton("Open Related Evidence")
        self.open_evidence_button.clicked.connect(self._open_evidence)
        actions.add_button(self.open_evidence_button)
        detail_layout.addWidget(actions)
        splitter.addWidget(detail_frame)
        splitter.setSizes([650, 520])
        outer.addWidget(splitter)

        timeline_title = QLabel("Behavior Timeline")
        timeline_title.setProperty("textRole", "cardTitle")
        outer.addWidget(timeline_title)
        self.timeline = QTableWidget(0, 6)
        self.timeline.setHorizontalHeaderLabels(("Time", "Category", "Score", "Severity", "Confidence", "Primary reasons"))
        self.timeline.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.timeline.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.timeline.setSelectionMode(QAbstractItemView.SingleSelection)
        self.timeline.setAlternatingRowColors(True)
        self.timeline.verticalHeader().setVisible(False)
        self.timeline.horizontalHeader().setStretchLastSection(True)
        self.timeline.itemSelectionChanged.connect(self._timeline_selected)
        outer.addWidget(self.timeline)

    def _range_changed(self) -> None:
        custom = int(self.range_combo.currentData()) < 0
        self.start_edit.setVisible(custom)
        self.end_edit.setVisible(custom)
        self.refresh()

    def _window(self) -> tuple[datetime, datetime, str]:
        hours = int(self.range_combo.currentData())
        if hours < 0:
            start = self.start_edit.dateTime().toPython()
            end = self.end_edit.dateTime().toPython()
            if start.tzinfo is None:
                start = start.astimezone()
            if end.tzinfo is None:
                end = end.astimezone()
            return start.astimezone(timezone.utc), end.astimezone(timezone.utc), "Custom"
        end = datetime.now(timezone.utc)
        return end - timedelta(hours=hours), end, self.range_combo.currentText()

    def refresh(self) -> None:
        start, end, window_label = self._window()
        if start >= end:
            self.chart.set_series([], empty_message="The custom start time must be earlier than the end time.")
            return
        buckets = self.repository.list_buckets(since=start.isoformat(), until=end.isoformat(), user_ref="", limit=50_000)
        anomalies = self.repository.list_anomalies(since=start.isoformat(), limit=5000)
        self._anomalies = anomalies
        selected_dimension = str(self.dimension_combo.currentData())
        points = self._chart_points(buckets, anomalies, selected_dimension)
        age_days = self._baseline_age_days()
        empty = (
            f"MSAA is establishing the behavioral baseline. {age_days} day{'s' if age_days != 1 else ''} of aggregated telemetry collected. "
            "Behavioral analytics confidence is currently limited."
        )
        self.chart.set_series(points, empty_message=empty)
        self._update_summary(buckets, anomalies, points, window_label, age_days)
        self._populate_dimensions(buckets)
        self._populate_timeline(anomalies)

    def _chart_points(self, buckets, anomalies: list[dict[str, Any]], selected_dimension: str) -> list[TelemetryChartPoint]:
        anomaly_by_time: dict[str, dict[str, Any]] = {}
        for item in anomalies:
            if selected_dimension != "OVERALL" and item.get("dimension") != selected_dimension:
                continue
            stamp = str(item.get("timestamp", ""))
            if stamp not in anomaly_by_time or int(item.get("anomaly_score", 0)) > int(anomaly_by_time[stamp].get("anomaly_score", 0)):
                anomaly_by_time[stamp] = item
        output: list[TelemetryChartPoint] = []
        for bucket in buckets:
            baselines = self.repository.baselines_for(
                host_ref=bucket.host_ref,
                user_ref="",
                time_cohort=bucket.time_cohort,
                context_cohort=bucket.context_cohort,
            )
            observed = self._observed(bucket, selected_dimension)
            selected = [baseline for feature, baseline in baselines.items() if self._feature_dimension(feature, selected_dimension)]
            expected = sum(item.median_value for item in selected) if selected else None
            low = sum(item.normal_low for item in selected) if selected else None
            high = sum(item.normal_high for item in selected) if selected else None
            anomaly = anomaly_by_time.get(bucket.bucket_end, {})
            output.append(TelemetryChartPoint(
                timestamp=bucket.bucket_end,
                observed=observed,
                expected=expected,
                normal_low=low,
                normal_high=high,
                anomaly_score=int(anomaly.get("anomaly_score", 0) or 0),
                anomaly_id=str(anomaly.get("anomaly_id", "")),
            ))
        return output

    @staticmethod
    def _observed(bucket, selected_dimension: str) -> float | None:
        if selected_dimension == "OVERALL":
            values = [value for value in bucket.dimension_values.values() if value is not None]
            return sum(float(value) for value in values) if values else None
        if bucket.coverage.get(selected_dimension) in {"UNKNOWN", "UNAVAILABLE"}:
            return None
        value = bucket.dimension_values.get(selected_dimension)
        return None if value is None else float(value)

    @staticmethod
    def _feature_dimension(feature: str, selected_dimension: str) -> bool:
        if feature.startswith("risk_"):
            return False
        if selected_dimension == "OVERALL":
            return True
        tokens = {
            ActivityDimension.PROCESS.value: ("process", "unsigned"),
            ActivityDimension.APPLICATION.value: ("application",),
            ActivityDimension.NETWORK.value: ("network", "destination", "remote_port"),
            ActivityDimension.DNS.value: ("dns", "domain", "resolver"),
            ActivityDimension.FILESYSTEM.value: ("file", "rename", "deletion"),
            ActivityDimension.PERSISTENCE.value: ("persistence", "launch", "login_item"),
            ActivityDimension.AUTHENTICATION.value: ("authentication", "administrator", "login", "unlock"),
            ActivityDimension.PRIVILEGE.value: ("privileged", "sudo", "root"),
            ActivityDimension.SECURITY_CONFIGURATION.value: ("security_setting", "firewall", "gatekeeper", "filevault"),
            ActivityDimension.SOFTWARE.value: ("software", "installation", "package"),
            ActivityDimension.EXTERNAL_DEVICE.value: ("external_device", "usb", "volume"),
            ActivityDimension.SENSOR.value: ("sensor", "security_tool", "telemetry"),
        }.get(selected_dimension, ())
        return any(token in feature for token in tokens)

    def _baseline_age_days(self) -> int:
        row = self.repository.connection.execute("SELECT MIN(bucket_start) AS first_seen FROM telemetry_buckets").fetchone()
        if not row or not row["first_seen"]:
            return 0
        try:
            first = datetime.fromisoformat(str(row["first_seen"]).replace("Z", "+00:00"))
            if first.tzinfo is None:
                first = first.replace(tzinfo=timezone.utc)
            return max(0, (datetime.now(timezone.utc) - first.astimezone(timezone.utc)).days)
        except ValueError:
            return 0

    def _update_summary(self, buckets, anomalies, points: list[TelemetryChartPoint], window_label: str, age_days: int) -> None:
        latest = points[-1] if points else None
        serious = [item for item in anomalies if int(item.get("anomaly_score", 0)) >= 60]
        high_deviation = [item for item in anomalies if int(item.get("anomaly_score", 0)) >= 80]
        high = [item for item in anomalies if str(item.get("security_severity", "")).lower() in {"high", "critical"}]
        health = self.manager.health()
        coverage_values = {value for bucket in buckets for value in bucket.coverage.values()}
        covered_dimensions = {dimension for bucket in buckets for dimension in bucket.coverage}
        selected_dimension = str(self.dimension_combo.currentData())
        if not coverage_values:
            coverage = "UNKNOWN"
        elif coverage_values.intersection({"UNKNOWN", "UNAVAILABLE", "REDUCED"}):
            coverage = "PARTIAL"
        elif selected_dimension == "OVERALL" and len(covered_dimensions) < len(ActivityDimension):
            coverage = "PARTIAL"
        elif selected_dimension != "OVERALL" and selected_dimension not in covered_dimensions:
            coverage = "UNKNOWN"
        else:
            coverage = "COMPLETE"
        baselines = [
            item for item in self.repository.list_baselines(user_ref="", limit=5000)
            if self._feature_dimension(str(item.get("feature_name", "")), selected_dimension)
        ]
        confidence_value = sum(float(item["confidence"]) for item in baselines) / len(baselines) if baselines else 0.0
        if selected_dimension == "OVERALL" and covered_dimensions:
            confidence_value *= min(1.0, len(covered_dimensions) / len(ActivityDimension))
        confidence = "HIGH" if confidence_value >= 0.75 else "MEDIUM" if confidence_value >= 0.4 else "LOW"
        state = "DEGRADED" if health.get("analysis_availability") == "DEGRADED" else "HIGH DEVIATION" if high_deviation else "UNUSUAL" if serious else "NORMAL" if buckets else "LEARNING"
        latest_anomaly = max((int(item.get("anomaly_score", 0)) for item in anomalies), default=0)
        if latest and latest.observed is not None and latest.normal_high is not None:
            activity_index = min(100, round(latest.observed / max(1.0, latest.normal_high) * 30))
        else:
            activity_index = 0
        score = max(activity_index, latest_anomaly)
        self.summary_labels["state"].setText(state)
        self.summary_labels["confidence"].setText(f"{confidence} ({confidence_value:.0%})")
        self.summary_labels["score"].setText(f"{score}/100")
        self.summary_labels["range"].setText(
            f"{latest.normal_low:.0f}–{latest.normal_high:.0f}" if latest and latest.normal_low is not None and latest.normal_high is not None else "ESTABLISHING"
        )
        today = datetime.now(timezone.utc).date()
        today_anomalies = [item for item in anomalies if self._date(item.get("timestamp")) == today]
        self.summary_labels["anomalies"].setText(str(len(today_anomalies)))
        self.summary_labels["high_risk"].setText(str(len(high)))
        self.summary_labels["age"].setText(f"{age_days} day{'s' if age_days != 1 else ''}")
        self.summary_labels["coverage"].setText(coverage)
        self.summary_labels["profile"].setText(self.manager.policy.profile)
        self.activity_summary.setText(
            f"Behavior Summary — {window_label}\nActivity level: {state.title()} · "
            f"{len(anomalies)} notable anomal{'ies' if len(anomalies) != 1 else 'y'} · "
            f"{len(high)} high-risk · Coverage: {coverage.title()} · Role: {self.manager.policy.profile}"
        )

    def _workstation_profile_changed(self, name: str) -> None:
        selected = self.manager.set_workstation_profile(name, actor="local_operator")
        profile = workstation_profile(selected)
        self.workstation_profile_combo.setToolTip(
            f"{profile.description}\nExpected: {', '.join(profile.expected_activity)}. "
            "Role deviations are unusual observations, not automatic malware verdicts."
        )
        self.refresh()

    @staticmethod
    def _date(value: Any):
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return parsed.astimezone(timezone.utc).date()
        except ValueError:
            return None

    def _populate_dimensions(self, buckets) -> None:
        totals: dict[str, float] = {}
        coverage: dict[str, set[str]] = {}
        for bucket in buckets:
            for dimension, value in bucket.dimension_values.items():
                if value is not None:
                    totals[dimension] = totals.get(dimension, 0.0) + float(value)
            for dimension, state in bucket.coverage.items():
                coverage.setdefault(dimension, set()).add(state)
        dimensions = list(ActivityDimension)
        self.dimension_table.setRowCount(len(dimensions))
        for row, dimension in enumerate(dimensions):
            states = coverage.get(dimension.value, set())
            availability = "UNAVAILABLE" if "UNAVAILABLE" in states else "UNKNOWN" if not states or "UNKNOWN" in states else "REDUCED" if "REDUCED" in states else "VALID"
            observed = "UNKNOWN" if availability in {"UNKNOWN", "UNAVAILABLE"} else f"{totals.get(dimension.value, 0):,.0f}"
            assessment = "Analytics unavailable" if availability == "UNAVAILABLE" else "Insufficient telemetry" if availability == "UNKNOWN" else "Partial telemetry" if availability == "REDUCED" else "Observed"
            for column, value in enumerate((_DIMENSION_LABELS[dimension.value], observed, availability, assessment)):
                item = QTableWidgetItem(value)
                if availability in {"UNKNOWN", "UNAVAILABLE", "REDUCED"} and column == 2:
                    item.setForeground(QBrush(_SEVERITY_COLORS["medium"]))
                self.dimension_table.setItem(row, column, item)
        self.dimension_table.resizeRowsToContents()

    def _populate_timeline(self, anomalies: list[dict[str, Any]]) -> None:
        self.timeline.setRowCount(len(anomalies))
        for row, anomaly in enumerate(anomalies):
            values = (
                str(anomaly.get("timestamp", ""))[:19].replace("T", " "),
                _DIMENSION_LABELS.get(str(anomaly.get("dimension", "")), str(anomaly.get("dimension", ""))),
                str(anomaly.get("anomaly_score", 0)),
                str(anomaly.get("security_severity", "info")).upper(),
                f"{float(anomaly.get('detection_confidence', 0)):.0%}",
                ", ".join(anomaly.get("reason_codes", [])[:4]),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.UserRole, anomaly.get("anomaly_id", ""))
                if column == 3:
                    item.setForeground(QBrush(_SEVERITY_COLORS.get(str(anomaly.get("security_severity", "info")).lower(), _SEVERITY_COLORS["info"])))
                self.timeline.setItem(row, column, item)
        self.timeline.resizeRowsToContents()

    def _timeline_selected(self) -> None:
        row = self.timeline.currentRow()
        if row < 0:
            return
        item = self.timeline.item(row, 0)
        if item is not None:
            self.select_anomaly(str(item.data(Qt.UserRole) or ""))

    def select_anomaly(self, anomaly_id: str) -> None:
        anomaly = next((item for item in self._anomalies if item.get("anomaly_id") == anomaly_id), None)
        if anomaly is None:
            return
        self._selected_anomaly_id = anomaly_id
        reasons = "\n".join(f"• {reason}" for reason in anomaly.get("reasons", [])) or "• No explanatory signals were retained."
        entities = ", ".join(f"{key}: {value}" for key, value in anomaly.get("related_entities", {}).items()) or "None recorded"
        canonical_context = self._canonical_context(anomaly)
        coverage = ", ".join(f"{key}: {value}" for key, value in anomaly.get("sensor_coverage", {}).items()) or "Unknown"
        self.explanation.setPlainText(
            f"Anomaly score: {anomaly.get('anomaly_score', 0)}/100\n"
            f"Security severity: {str(anomaly.get('security_severity', 'info')).upper()}\n"
            f"Detection confidence: {float(anomaly.get('detection_confidence', 0)):.0%}\n"
            f"Observed: {anomaly.get('observed_value', 'unknown')}\n"
            f"Comparable normal range: {anomaly.get('normal_low', 'unknown')}–{anomaly.get('normal_high', 'unknown')}\n"
            f"Baseline version: {anomaly.get('baseline_version', 0)}\n"
            f"Policy: {anomaly.get('active_behavior_policy', 'unknown')}\n\n"
            f"Reasons:\n{reasons}\n\n"
            f"Related entities: {entities}\nCanonical process/evidence context: {canonical_context}\nTelemetry coverage: {coverage}\n"
            f"Disposition: {anomaly.get('disposition', 'NEW')}\n\n"
            f"Recommendation: {anomaly.get('recommendation', '')}\n\n"
            "Unusual behavior is a reason to investigate, not proof of malicious intent."
        )

    def _canonical_context(self, anomaly: dict[str, Any]) -> str:
        references = [str(item) for item in anomaly.get("evidence_refs", [])[:20] if str(item)]
        if not references:
            return "No canonical references were retained."
        placeholders = ",".join("?" for _ in references)
        try:
            rows = self.db.conn.execute(
                f"SELECT event_type,process_name,related_process,related_path,related_network_endpoint FROM background_monitor_events WHERE event_id IN ({placeholders}) ORDER BY timestamp ASC LIMIT 20",
                references,
            ).fetchall()
        except Exception:
            return "Canonical evidence is temporarily unavailable; references remain preserved."
        summaries: list[str] = []
        for row in rows:
            process = str(row["related_process"] or row["process_name"] or "unknown process")
            path = str(row["related_path"] or "")
            endpoint = str(row["related_network_endpoint"] or "")
            details = ", ".join(value for value in (process, path, endpoint) if value)
            summaries.append(f"{row['event_type']}: {details}")
        return "; ".join(summaries[:6]) if summaries else "Open the preserved references in Flight Recorder."

    def _set_disposition(self, disposition: str) -> None:
        if not self._selected_anomaly_id:
            QMessageBox.information(self, "Select an Anomaly", "Select an anomaly before recording an operator disposition.")
            return
        self.repository.update_anomaly_disposition(self._selected_anomaly_id, disposition, actor="local_operator")
        if disposition == AnomalyDisposition.INVESTIGATE.value:
            self.investigation_requested.emit(self._selected_anomaly_id)
        self.refresh()
        self.select_anomaly(self._selected_anomaly_id)

    def _open_evidence(self) -> None:
        anomaly = next((item for item in self._anomalies if item.get("anomaly_id") == self._selected_anomaly_id), None)
        if anomaly is None:
            QMessageBox.information(self, "Select an Anomaly", "Select an anomaly with related canonical evidence first.")
            return
        reference = str(anomaly.get("incident_id") or (anomaly.get("evidence_refs") or [""])[0])
        self.evidence_requested.emit(reference)

    def _rebuild_baseline(self) -> None:
        previous = self.repository.latest_baseline_version()
        result = QMessageBox.warning(
            self,
            "Rebuild Behavioral Baseline",
            "This creates a new version boundary and recalculates expected behavior from eligible aggregates. "
            "Previous version metadata and all historical security anomalies are retained. Continue?",
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if result != QMessageBox.Yes:
            return
        outcome = self.manager.rebuild_baseline(actor="local_operator", reason=f"manual rebuild after baseline v{previous}")
        QMessageBox.information(self, "Baseline Rebuilt", f"Created baseline v{outcome['version']} with {outcome['baseline_count']} feature cohorts.")
        self.refresh()


__all__ = ["BehavioralTelemetryPanel"]
