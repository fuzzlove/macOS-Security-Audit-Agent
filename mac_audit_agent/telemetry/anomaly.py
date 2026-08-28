from __future__ import annotations

import math
from collections import defaultdict
from uuid import uuid4

from mac_audit_agent.telemetry.models import BehavioralAnomaly, FeatureBaseline, TelemetryBucket, utc_now_iso
from mac_audit_agent.telemetry.policies import BehavioralTelemetryPolicy
from mac_audit_agent.telemetry.storage import TelemetryRepository


REASON_CODE_BY_FEATURE = {
    "process_exec_count": "PROCESS_RATE_ANOMALY",
    "first_seen_process_count": "FIRST_SEEN_EXECUTABLE_SPIKE",
    "unsigned_process_count": "UNSIGNED_EXECUTION_ANOMALY",
    "network_connection_count": "NETWORK_RATE_ANOMALY",
    "unique_destination_count": "DESTINATION_DIVERSITY_SPIKE",
    "dns_query_count": "DNS_RATE_ANOMALY",
    "unique_domain_count": "DNS_UNIQUE_DOMAIN_SPIKE",
    "dns_resolver_change_count": "NEW_DNS_RESOLVER",
    "authentication_failure_count": "AUTHENTICATION_FAILURE_SPIKE",
    "new_administrator_count": "NEW_ADMINISTRATOR",
    "privileged_execution_count": "PRIVILEGE_ACTIVITY_SPIKE",
    "persistence_change_count": "PERSISTENCE_CHANGE_ANOMALY",
    "security_setting_change_count": "SECURITY_CONFIGURATION_CHANGE_SPIKE",
    "software_installation_count": "SOFTWARE_INSTALLATION_ANOMALY",
    "workstation_profile_deviation_count": "WORKSTATION_PROFILE_DEVIATION",
}

FEATURE_DIMENSION = {
    "process": "PROCESS_ACTIVITY", "unsigned": "PROCESS_ACTIVITY", "privileged": "PRIVILEGE_ACTIVITY",
    "network": "NETWORK_ACTIVITY", "destination": "NETWORK_ACTIVITY", "dns": "DNS_ACTIVITY", "domain": "DNS_ACTIVITY",
    "authentication": "AUTHENTICATION_ACTIVITY", "administrator": "AUTHENTICATION_ACTIVITY",
    "persistence": "PERSISTENCE_ACTIVITY", "security_setting": "SECURITY_CONFIGURATION_ACTIVITY",
    "software": "SOFTWARE_INSTALLATION_ACTIVITY", "filesystem": "FILESYSTEM_ACTIVITY",
    "external_device": "EXTERNAL_DEVICE_ACTIVITY", "sensor": "SENSOR_SECURITY_TOOL_ACTIVITY",
}


class AnomalyDetectionEngine:
    def __init__(self, repository: TelemetryRepository, policy: BehavioralTelemetryPolicy) -> None:
        self.repository = repository
        self.policy = policy

    def analyze_bucket(self, bucket: TelemetryBucket) -> list[BehavioralAnomaly]:
        baselines = self.repository.baselines_for(
            host_ref=bucket.host_ref, user_ref=bucket.user_ref, time_cohort=bucket.time_cohort,
            context_cohort=bucket.context_cohort,
        )
        candidates: dict[str, list[tuple[str, int, str, FeatureBaseline | None, float]]] = defaultdict(list)
        for feature, raw_value in bucket.feature_values.items():
            if raw_value is None or feature.startswith("risk_") or feature.startswith("profile_deviation_"):
                continue
            dimension = _dimension_for_feature(feature)
            if bucket.coverage.get(dimension) in {"UNKNOWN", "UNAVAILABLE"}:
                continue
            baseline = baselines.get(feature)
            score, explanation = self._feature_score(feature, float(raw_value), baseline)
            if score >= 20:
                candidates[dimension].append((feature, score, explanation, baseline, float(raw_value)))

        anomalies: list[BehavioralAnomaly] = []
        for dimension, feature_scores in candidates.items():
            feature_scores.sort(key=lambda item: item[1], reverse=True)
            risk = self._risk_signals(bucket, dimension)
            base_score = feature_scores[0][1]
            multi_bonus = min(25, max(0, len(feature_scores) - 1) * 5 + len(risk) * 5)
            score = min(100, base_score + multi_bonus)
            reason_codes = [REASON_CODE_BY_FEATURE.get(item[0], "COMPOSITE_BEHAVIORAL_ANOMALY") for item in feature_scores]
            reason_codes.extend(risk)
            if len(set(reason_codes)) >= 3:
                reason_codes.append("COMPOSITE_BEHAVIORAL_ANOMALY")
            reason_codes = list(dict.fromkeys(reason_codes))
            primary = feature_scores[0]
            baseline = primary[3]
            known_malicious = float(bucket.feature_values.get("risk_known_malicious_count") or 0) > 0
            severity = self._security_severity(score, reason_codes, known_malicious)
            confidence = self._confidence(feature_scores, bucket, known_malicious)
            reasons = [item[2] for item in feature_scores[:6]]
            reasons.extend(_risk_reason(code) for code in risk)
            if "WORKSTATION_PROFILE_DEVIATION" in reason_codes:
                reasons.append(
                    f"The activity falls outside the declared {self.policy.profile} workstation role; "
                    "the local host and user baseline remains the primary comparison."
                )
            explanation = " ".join(reasons) + " Unusual behavior is an investigation signal, not proof of malicious intent."
            anomalies.append(BehavioralAnomaly(
                anomaly_id=f"behavior-{uuid4().hex}",timestamp=bucket.bucket_end,host_ref=bucket.host_ref,user_ref=bucket.user_ref,
                dimension=dimension,anomaly_score=score,security_severity=severity,detection_confidence=confidence,
                baseline_value=baseline.median_value if baseline else None,observed_value=primary[4],
                normal_low=baseline.normal_low if baseline else None,normal_high=baseline.normal_high if baseline else None,
                reason_codes=reason_codes,reasons=reasons,related_entities={key: values[0] for key, values in bucket.entity_sets.items() if values},
                evidence_refs=list(bucket.evidence_refs),sensor_coverage=dict(bucket.coverage),
                baseline_version=baseline.version if baseline else self.repository.latest_baseline_version(),
                active_behavior_policy=self.policy.profile,baseline_training_eligible=False,
                explanation=explanation,created_at=utc_now_iso(),
            ))
        return anomalies

    def _feature_score(self, feature: str, observed: float, baseline: FeatureBaseline | None) -> tuple[int, str]:
        label = feature.replace("_", " ")
        if baseline is None:
            score = 30 if observed > 0 and ("first_seen" in feature or "administrator" in feature or "persistence" in feature) else 20
            return score, f"{label.title()} has no comparable local baseline yet; current value is {observed:g}."
        if observed <= baseline.p75:
            return 0, f"{label.title()} remains within its expected range."
        spread = max(baseline.mad_value * 1.4826, (baseline.p95 - baseline.p25) / 1.35, 1.0)
        robust_z = max(0.0, (observed - baseline.median_value) / spread)
        ratio = observed / max(1.0, baseline.median_value)
        if observed <= baseline.p95:
            score = int(min(39, 15 + robust_z * 5))
        else:
            score = int(min(85, 40 + robust_z * 7 + min(15, max(0.0, ratio - 1.0) * 3)))
        if baseline.confidence < 0.25:
            score = min(score, 39)
        elif baseline.confidence < 0.60:
            score = min(score, 59)
        explanation = (
            f"{label.title()} is {observed:g}; comparable local behavior is typically "
            f"{baseline.normal_low:g}–{baseline.normal_high:g} (median {baseline.median_value:g}, "
            f"{ratio:.1f}× median, baseline confidence {baseline.confidence:.0%})."
        )
        return score, explanation

    @staticmethod
    def _risk_signals(bucket: TelemetryBucket, dimension: str) -> list[str]:
        mapping = {
            "risk_first_seen_count": "FIRST_SEEN_EXECUTABLE",
            "risk_unsigned_count": "UNSIGNED_EXECUTION_ANOMALY",
            "risk_downloads_path_count": "UNUSUAL_EXECUTION_PATH",
            "risk_temporary_path_count": "UNUSUAL_EXECUTION_PATH",
            "risk_privileged_count": "PRIVILEGE_ACTIVITY_SPIKE",
            "risk_known_malicious_count": "DETERMINISTIC_INTELLIGENCE_MATCH",
            "workstation_profile_deviation_count": "WORKSTATION_PROFILE_DEVIATION",
        }
        allowed = {"APPLICATION_ACTIVITY", "PROCESS_ACTIVITY", "PRIVILEGE_ACTIVITY", "PERSISTENCE_ACTIVITY", "NETWORK_ACTIVITY"}
        if dimension not in allowed:
            return []
        codes = [code for feature, code in mapping.items() if float(bucket.feature_values.get(feature) or 0) > 0]
        profile_codes = {
            "profile_deviation_development_tooling_count": "PROFILE_UNEXPECTED_DEVELOPMENT_TOOLING",
            "profile_deviation_research_activity_count": "PROFILE_UNEXPECTED_RESEARCH_ACTIVITY",
            "profile_deviation_fuzzing_activity_count": "PROFILE_UNEXPECTED_FUZZING_ACTIVITY",
            "profile_deviation_server_service_activity_count": "PROFILE_UNEXPECTED_SERVER_ACTIVITY",
            "profile_deviation_unsigned_execution_count": "PROFILE_UNEXPECTED_UNSIGNED_EXECUTION",
            "profile_deviation_unsigned_temporary_execution_count": "PROFILE_UNEXPECTED_UNSIGNED_EXECUTION",
            "profile_deviation_temporary_execution_count": "PROFILE_UNEXPECTED_TEMPORARY_EXECUTION",
            "profile_deviation_remote_access_count": "PROFILE_UNEXPECTED_REMOTE_ACCESS",
            "profile_deviation_external_device_activity_count": "PROFILE_UNEXPECTED_EXTERNAL_DEVICE",
        }
        codes.extend(
            code
            for feature, code in profile_codes.items()
            if float(bucket.feature_values.get(feature) or 0) > 0
        )
        return list(dict.fromkeys(codes))

    @staticmethod
    def _security_severity(score: int, codes: list[str], known_malicious: bool) -> str:
        if known_malicious:
            return "critical"
        strong = len({"UNSIGNED_EXECUTION_ANOMALY", "UNUSUAL_EXECUTION_PATH", "PRIVILEGE_ACTIVITY_SPIKE", "PERSISTENCE_CHANGE_ANOMALY"}.intersection(codes))
        if score >= 80 and strong >= 2: return "high"
        if score >= 60 and strong >= 1: return "medium"
        if score >= 40: return "low"
        return "info"

    @staticmethod
    def _confidence(features: list[tuple[str, int, str, FeatureBaseline | None, float]], bucket: TelemetryBucket, known_malicious: bool) -> float:
        if known_malicious:
            return 0.98
        baselines = [item[3].confidence for item in features if item[3] is not None]
        baseline_confidence = sum(baselines) / len(baselines) if baselines else 0.15
        coverage_values = list(bucket.coverage.values())
        coverage = sum(value == "VALID" for value in coverage_values) / len(coverage_values) if coverage_values else 0.0
        signal_bonus = min(0.20, max(0, len(features) - 1) * 0.05)
        return round(min(0.99, baseline_confidence * 0.65 + coverage * 0.20 + signal_bonus), 3)


def _dimension_for_feature(feature: str) -> str:
    for token, dimension in FEATURE_DIMENSION.items():
        if token in feature:
            return dimension
    return "APPLICATION_ACTIVITY"


def _risk_reason(code: str) -> str:
    return {
        "FIRST_SEEN_EXECUTABLE": "A contributing executable was first observed in the local entity history.",
        "UNSIGNED_EXECUTION_ANOMALY": "Unsigned or invalidly signed execution contributed additional security context.",
        "UNUSUAL_EXECUTION_PATH": "Execution originated from a download or temporary location.",
        "PRIVILEGE_ACTIVITY_SPIKE": "Privileged execution occurred in the same aggregate window.",
        "DETERMINISTIC_INTELLIGENCE_MATCH": "A deterministic local intelligence match was reported; statistical scoring does not reduce that finding.",
        "WORKSTATION_PROFILE_DEVIATION": "Observed behavior falls outside the declared workstation role and was retained for review.",
    }.get(code, code.replace("_", " ").title() + ".")


__all__ = ["AnomalyDetectionEngine", "REASON_CODE_BY_FEATURE"]
