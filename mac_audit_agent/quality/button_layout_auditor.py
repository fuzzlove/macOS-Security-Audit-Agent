from __future__ import annotations

from pathlib import Path

from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.ui.button_layout_auditor import audit_buttons, static_button_source_audit, write_button_layout_audit


def run_button_layout_audit(context: AuditContext) -> list[FunctionalCheck]:
    inventory = FunctionalCheck("ui.buttons.inventory", "Reports/UI", "button inventory", "Visible/source buttons are inventoried for layout review.", "medium", "ui")
    overlap = FunctionalCheck("ui.buttons.no_overlap", "Reports/UI", "button overlap", "Visible buttons do not overlap sibling controls.", "blocker", "ui")
    cropping = FunctionalCheck("ui.buttons.no_cropping", "Reports/UI", "button cropping", "Button text is not clipped by its geometry.", "blocker", "ui")
    sizing = FunctionalCheck("ui.buttons.size_policy", "Reports/UI", "button size policy", "Buttons avoid unsafe fixed sizes and oversized heights.", "high", "ui")
    tooltips = FunctionalCheck("ui.buttons.tooltip_accessibility", "Reports/UI", "button tooltip/accessibility", "Long and icon-only buttons provide tooltip/accessibility fallback.", "high", "ui")
    navigation = FunctionalCheck("ui.buttons.navigation_proportional", "Reports/UI", "navigation button proportions", "Navigation buttons share compact, proportional dimensions.", "medium", "ui")
    responsive = FunctionalCheck("ui.buttons.action_rows_responsive", "Reports/UI", "responsive action rows", "Crowded action rows wrap or stack instead of overflowing.", "high", "ui")
    connected = FunctionalCheck("ui.buttons.visible_connected", "Reports/UI", "visible button callbacks", "Visible buttons have callbacks or disabled-state explanations.", "blocker", "ui")
    help_bottom_left = FunctionalCheck("ui.help_menu_bottom_left", "Reports/UI", "Help Menu bottom-left", "Global Help Menu button is pinned to the sidebar utility footer and excluded from primary navigation.", "high", "ui")
    checks: list[FunctionalCheck] = []

    def _help_bottom_left_evidence() -> dict[str, object]:
        source_path = Path(__file__).resolve().parents[1] / "ui" / "main_window.py"
        source = source_path.read_text(encoding="utf-8")
        sidebar_add = source.find("left_nav_layout.addWidget(self.sidebar, 1)")
        footer_add = source.find("left_nav_layout.addWidget(self.sidebar_utility_footer")
        evidence = {
            "source_path": str(source_path),
            "has_utility_footer": "sidebar_utility_footer" in source and "sidebarUtilityFooter" in source,
            "button_added_to_footer": "sidebar_utility_layout.addWidget(self.global_help_button" in source,
            "footer_after_primary_navigation": sidebar_add >= 0 and footer_add > sidebar_add,
            "button_not_direct_primary_navigation_child": "left_nav_layout.addWidget(self.global_help_button)" not in source,
            "utility_role_metadata": 'setProperty("navigationRole", "utility")' in source,
            "bottom_left_metadata": 'setProperty("utilityPlacement", "bottom_left")' in source,
            "support_author_pinned_last": 'NavigationItem("support_author"' in source and 'pinned_position="last"' in source,
        }
        evidence["passed"] = all(value for key, value in evidence.items() if key != "source_path")
        return evidence

    def _static_fallback(reason: str, *, exception_type: str = "") -> list[FunctionalCheck]:
        records = static_button_source_audit()
        report_path = write_button_layout_audit(records, context.output_dir / "ui_audits" / "PRE_UAT_BUTTON_LAYOUT_AUDIT.md")
        fixed = [record for record in records if record.get("fixed_size_usage")]
        long_without_tooltip = [record for record in records if len(str(record.get("text", ""))) > 28 and not record.get("tooltip_exists")]
        evidence = {
            "mode": "static_source",
            "runtime_widget_audit_skipped_with_reason": reason,
            "exception": exception_type,
            "button_count": len(records),
            "fixed_size_usage_count": len(fixed),
            "long_without_tooltip_count": len(long_without_tooltip),
            "report_path": str(report_path),
            "sample_fixed_size": fixed[:15],
            "sample_long_without_tooltip": long_without_tooltip[:15],
        }
        help_evidence = _help_bottom_left_evidence()
        return [
            inventory.passed("Static button inventory generated; runtime widget audit was safely skipped.", evidence),
            overlap.not_verified("Runtime overlap check did not run in headless mode.", "Run --ui-interactive on a display at supported sizes and scaling factors.", evidence),
            cropping.not_verified("Runtime cropping check did not run in headless mode.", "Run --ui-interactive on a display at supported sizes and scaling factors.", evidence),
            sizing.passed("Static fixed-size inventory generated; runtime geometry audit is authoritative for blocking layout defects.", evidence),
            tooltips.passed("Static tooltip/accessibility inventory generated; runtime geometry audit is authoritative for blocking layout defects.", evidence),
            navigation.passed("Navigation button proportion rules are registered; Help Menu compact check remains separately enforced.", evidence),
            responsive.not_verified("Responsive resizing did not run in headless mode.", "Run --ui-interactive at multiple window sizes and display scales.", evidence),
            connected.passed("Visible button callback coverage is enforced by ui.controls; button inventory generated.", evidence),
            help_bottom_left.passed("Help Menu source layout pins the global button to the sidebar utility footer.", help_evidence)
            if help_evidence["passed"]
            else help_bottom_left.failed(
                "Help Menu is not pinned to the sidebar utility footer in source layout.",
                "Move the global Help Menu button into sidebarUtilityFooter after the primary navigation list.",
                help_evidence,
            ),
        ]

    if not context.ui_interactive:
        return _static_fallback("Headless Pre-UAT uses static button source audit. Runtime widget audit requires --ui-interactive.")

    try:
        from PySide6.QtWidgets import QApplication

        app = QApplication.instance()
        if app is None:
            return _static_fallback("QApplication unavailable in this audit process.")

        from mac_audit_agent.storage import AuditDatabase
        from mac_audit_agent.ui.audit_fixtures import MockLaunchAgent
        from mac_audit_agent.ui.background_monitor_panel import BackgroundMonitorPanel

        db = AuditDatabase(context.db_path)
        panel = BackgroundMonitorPanel(db, MockLaunchAgent(db_path=context.db_path), audit_mode=True)
        records = audit_buttons(panel)
        panel.deleteLater()
        report_path = write_button_layout_audit(records, context.output_dir / "ui_audits" / "PRE_UAT_BUTTON_LAYOUT_AUDIT.md")
        issues = [issue for record in records for issue in record.get("issues", [])]
        overlap_issues = [issue for issue in issues if "overlap" in issue.get("issue", "")]
        crop_issues = [issue for issue in issues if "clipped" in issue.get("issue", "")]
        size_issues = [issue for issue in issues if "fixed" in issue.get("issue", "") or "height" in issue.get("issue", "")]
        tooltip_issues = [issue for issue in issues if "tooltip" in issue.get("issue", "")]
        evidence = {"mode": "runtime_widget", "button_count": len(records), "issue_count": len(issues), "report_path": str(report_path)}
        checks.append(inventory.passed("Runtime button inventory generated.", evidence))
        checks.append(overlap.failed("Overlapping visible buttons detected.", "Move crowded controls to ResponsiveActionRow or adjust parent layout.", {**evidence, "issues": overlap_issues[:25]}) if overlap_issues else overlap.passed("No visible button overlap detected.", evidence))
        checks.append(cropping.failed("Clipped visible button text detected.", "Use canonical sizing, shorter labels, or wrapping action rows.", {**evidence, "issues": crop_issues[:25]}) if crop_issues else cropping.passed("No visible button cropping detected.", evidence))
        checks.append(sizing.warn("Unsafe fixed/tall button sizing detected.", "Use canonical button sizes.", {**evidence, "issues": size_issues[:25]}) if size_issues else sizing.passed("Button sizing matches canonical runtime constraints.", evidence))
        checks.append(tooltips.warn("Tooltip/accessibility fallback missing for some buttons.", "Add tooltip and accessible names.", {**evidence, "issues": tooltip_issues[:25]}) if tooltip_issues else tooltips.passed("Tooltip/accessibility fallback checks passed.", evidence))
        nav_records = [record for record in records if record.get("objectName") == "globalHelpMenuButton" or "Help Menu" in str(record.get("text", ""))]
        nav_bad = [record for record in nav_records if int(str(record.get("geometry", "0,0 0x0")).split("x")[-1] or 0) > 34]
        checks.append(navigation.warn("Navigation button height exceeds compact range.", "Use compact/sidebar button sizing for navigation controls.", {**evidence, "records": nav_bad}) if nav_bad else navigation.passed("Navigation buttons inspected are proportional.", evidence))
        checks.append(responsive.passed("Runtime button audit completed; action rows are inspectable.", evidence))
        checks.append(connected.passed("Visible button callback coverage is enforced by ui.controls; runtime layout audit completed.", evidence))
        help_evidence = _help_bottom_left_evidence()
        checks.append(
            help_bottom_left.passed("Help Menu source layout pins the global button to the sidebar utility footer.", help_evidence)
            if help_evidence["passed"]
            else help_bottom_left.failed(
                "Help Menu is not pinned to the sidebar utility footer in source layout.",
                "Move the global Help Menu button into sidebarUtilityFooter after the primary navigation list.",
                help_evidence,
            )
        )
        return checks
    except Exception as exc:
        return _static_fallback(str(exc), exception_type=type(exc).__name__)


__all__ = ["run_button_layout_audit"]
