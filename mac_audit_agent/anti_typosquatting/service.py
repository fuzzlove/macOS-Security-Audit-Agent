from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from .configuration import DATA_VERSIONS
from .engine import candidate_id, generate, normalize
from .models import AnalysisRun, AssetType, Candidate, GenerationConfiguration, PackageEcosystem, ProtectedAsset, ScoreBreakdown
from .normalization import code_points, confusable_skeleton, domain_ascii, normalize_pypi, parse_npm, scripts, visible_text
from .scoring import assumption_scores, score


class AntiTyposquattingService:
    def analyze(self, asset: ProtectedAsset, configuration: Optional[GenerationConfiguration] = None) -> AnalysisRun:
        config = configuration or GenerationConfiguration()
        self.validate_asset(asset)
        values = generate(asset, config)
        candidates = []
        kind = "domain" if asset.asset_type == AssetType.DOMAIN else asset.ecosystem.value
        for display, reasons, operations in values:
            normalized = normalize(display, kind)
            parsed = None
            if asset.asset_type == AssetType.PACKAGE and asset.ecosystem:
                from .namespaces import adapter_for
                parsed = adapter_for(asset.ecosystem).parse_identifier(display)
            try:
                ascii_name = domain_ascii(display) if kind == "domain" else normalized
                state = "valid"
            except ValueError:
                ascii_name, state = "", "invalid"
            human, impersonation, defensive, investigation = score(reasons)
            closeness, attacker_assumption, risk_band = assumption_scores(asset.canonical_name, display, human, impersonation, reasons)
            guidance = (
                "High-priority assumption: check authoritative registration and ownership data. If no registration data is found, an authorized brand owner should verify availability and rights with its registrar before considering defensive registration."
                if risk_band in {"critical", "high"}
                else "Review alongside higher-risk variants; monitor or register only when business value, rights, and authoritative availability checks justify it."
            )
            candidate = Candidate(
                candidate_id=candidate_id(asset.canonical_name, normalized),
                canonical_asset=asset.canonical_name,
                display_name=visible_text(display),
                normalized_name=normalized,
                ascii_name=ascii_name,
                asset_type=asset.asset_type.value,
                ecosystem=asset.ecosystem.value if asset.ecosystem else "",
                identifier_components={item.name: item.value for item in parsed.components} if parsed else {},
                identifier_projections=list(parsed.projections) if parsed else [],
                categories=sorted({reason.category for reason in reasons}),
                reasons=reasons,
                edit_operations=sorted(set(operations)),
                locale_profiles=sorted({reason.locale for reason in reasons}),
                unicode_scripts=scripts(display),
                unicode_code_points=code_points(display),
                confusable_skeleton=confusable_skeleton(display),
                human_typo=human,
                impersonation=impersonation,
                namespace_confusion=ScoreBreakdown(min(100, sum(30 for reason in reasons if reason.category in {"namespace_confusion", "normalization_collision", "projection_confusion"})), {reason.rule_id: 30 for reason in reasons if reason.category in {"namespace_confusion", "normalization_collision", "projection_confusion"}}),
                visual_impersonation=ScoreBreakdown(impersonation.total, dict(impersonation.contributions)),
                name_closeness=closeness,
                attacker_use_assumption=attacker_assumption,
                risk_band=risk_band,
                supply_chain_reachability=ScoreBreakdown(0, {"not_observed_locally": 0}),
                ownership_confidence=ScoreBreakdown(0, {"ownership_not_verified": 0}),
                defensive_registration=defensive,
                investigation=investigation,
                validation_state=state,
                registration_guidance=guidance,
            )
            candidates.append(candidate)
        candidates.sort(key=lambda item: (-item.attacker_use_assumption.total, -item.name_closeness.total, item.normalized_name))
        candidates = candidates[: max(1, min(config.result_limit, config.post_dedup_limit))]
        return AnalysisRun(
            schema_version="1.0",
            run_id=str(uuid4()),
            asset=asset,
            configuration=config,
            candidates=candidates,
            data_versions=dict(DATA_VERSIONS),
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    @staticmethod
    def validate_asset(asset: ProtectedAsset) -> None:
        name = asset.canonical_name.strip()
        if not name or len(name) > 253:
            raise ValueError("Canonical name is empty or exceeds the supported length.")
        if asset.asset_type == AssetType.DOMAIN:
            domain_ascii(name)
        elif asset.ecosystem == PackageEcosystem.NPM:
            parse_npm(name)
        elif asset.ecosystem:
            from .namespaces import adapter_for
            adapter_for(asset.ecosystem).parse_identifier(name)
        else:
            raise ValueError("Software packages require npm or PyPI ecosystem selection.")
