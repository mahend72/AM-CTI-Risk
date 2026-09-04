"""STIX/ATT&CK data validation layer (restructuring brief §15).

Findings are always *recorded*, never used to silently drop data - the
risk engine still runs against every entity even when this layer reports
ERROR-severity issues. See docs/LEGACY_BEHAVIOUR.md for the defects this
layer is designed to surface (it does not fix any of them).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from am_assurance.core.models import ValidationIssue

if TYPE_CHECKING:
    from am_assurance.core.config import ScoringConfig
    from am_assurance.cti.attack_index import AttackIndex
    from am_assurance.cti.relationship_index import RelationshipIndex


def validate_bundle(
    attack_index: "AttackIndex",
    relationship_index: "RelationshipIndex",
    scoring_config: "ScoringConfig",
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []

    issues.extend(_check_malformed_technique_ids(attack_index, scoring_config))
    issues.extend(_check_duplicate_technique_mappings(scoring_config))
    issues.extend(_check_missing_names(attack_index))
    issues.extend(_check_missing_mitre_attack_reference(attack_index))
    issues.extend(_check_dangling_relationships(attack_index, relationship_index))
    issues.extend(_static_legacy_findings())

    return issues


def _check_malformed_technique_ids(attack_index, scoring_config) -> list[ValidationIssue]:
    valid_ids = attack_index.all_technique_ids()
    issues = []
    for bucket, technique_ids in scoring_config.severity_buckets.items():
        for tid in technique_ids:
            if tid not in valid_ids:
                issues.append(
                    ValidationIssue(
                        severity="ERROR",
                        record=f"configs/scoring.yaml:severity_buckets[{bucket}]",
                        reason=(
                            "Malformed or unknown technique identifier: matches no "
                            "attack-pattern external_id in the loaded STIX bundle."
                        ),
                        original_value=tid,
                        suggested_action=(
                            "Confirm with the original author whether this is a typo "
                            "(see docs/LEGACY_BEHAVIOUR.md §2 / METHODOLOGY_DECISIONS.md D-2). "
                            "Do not auto-correct - the entry is permanently inert and does "
                            "not affect any current score."
                        ),
                    )
                )
    return issues


def _check_duplicate_technique_mappings(scoring_config) -> list[ValidationIssue]:
    seen: dict[str, list[int]] = {}
    for bucket, technique_ids in scoring_config.severity_buckets.items():
        for tid in technique_ids:
            seen.setdefault(tid, []).append(bucket)

    issues = []
    for tid, buckets in seen.items():
        if len(buckets) > 1:
            issues.append(
                ValidationIssue(
                    severity="INFO",
                    record=f"severity_buckets:{tid}",
                    reason=(
                        "Technique appears in multiple severity buckets; "
                        "find_severity averages across all matching buckets by design "
                        "(see docs/METHODOLOGY.md 'Factor: Severity'). Not a defect."
                    ),
                    original_value=sorted(buckets),
                    suggested_action=None,
                )
            )
    return issues


def _check_missing_names(attack_index) -> list[ValidationIssue]:
    issues = []
    for obj in attack_index.objects_by_type.get("attack-pattern", []):
        if not obj.get("name"):
            issues.append(
                ValidationIssue(
                    severity="ERROR",
                    record=obj.get("id", "<unknown>"),
                    reason="attack-pattern object has no 'name' field.",
                    original_value=None,
                    suggested_action="Investigate upstream STIX bundle integrity.",
                )
            )
    return issues


def _check_missing_mitre_attack_reference(attack_index) -> list[ValidationIssue]:
    issues = []
    for obj in attack_index.objects_by_type.get("attack-pattern", []):
        refs = obj.get("external_references", [])
        if not any(r.get("source_name") == "mitre-attack" for r in refs):
            issues.append(
                ValidationIssue(
                    severity="WARNING",
                    record=obj.get("id", "<unknown>"),
                    reason=(
                        "attack-pattern has no 'mitre-attack' external reference; any "
                        "relationship targeting it cannot be scored and will be recorded "
                        "as unscored evidence (see docs/METHODOLOGY_DECISIONS.md D-5)."
                    ),
                    original_value=obj.get("name"),
                    suggested_action=(
                        "None required for scoring - the assessor handles this "
                        "defensively. Investigate upstream data only if this technique "
                        "was expected to be scorable."
                    ),
                )
            )
    return issues


def _check_dangling_relationships(attack_index, relationship_index) -> list[ValidationIssue]:
    issues = []
    for rel in relationship_index.all_relationships():
        if rel.get("source_ref") not in attack_index.objects_by_id:
            issues.append(
                ValidationIssue(
                    severity="WARNING",
                    record=rel.get("id", "<unknown>"),
                    reason="relationship source_ref does not resolve to any object in the bundle.",
                    original_value=rel.get("source_ref"),
                    suggested_action="Ignored by the assessor (cannot originate from a missing entity).",
                )
            )
        if rel.get("target_ref") not in attack_index.objects_by_id:
            issues.append(
                ValidationIssue(
                    severity="WARNING",
                    record=rel.get("id", "<unknown>"),
                    reason="relationship target_ref does not resolve to any object in the bundle.",
                    original_value=rel.get("target_ref"),
                    suggested_action="Ignored by the assessor (cannot target a missing object).",
                )
            )
    return issues


def _static_legacy_findings() -> list[ValidationIssue]:
    """Findings that are properties of the legacy source itself, not of the
    currently-loaded bundle - always emitted for auditability."""

    return [
        ValidationIssue(
            severity="INFO",
            record="Code/find_severity.py.txt:data1 (legacy)",
            reason=(
                "Original dict literal contained duplicate keys 34 and 10. Python "
                "silently collapsed each to its last-written value at runtime. The "
                "collapsed (13-key) table is what the legacy code actually executed "
                "against and is preserved exactly in configs/scoring.yaml. "
                "See docs/LEGACY_BEHAVIOUR.md §1 / METHODOLOGY_DECISIONS.md D-1."
            ),
            original_value="duplicate keys: 34 (x2), 10 (x3)",
            suggested_action="Documented; no action required; preserved intentionally.",
        ),
        ValidationIssue(
            severity="INFO",
            record="risk/impact.py (corrected)",
            reason=(
                "Legacy impact_level() raised UnboundLocalError at max_val in "
                "{10, 50, 80}. Corrected by making lower bounds inclusive, matching "
                "find_severity's already-consistent boundary convention over the "
                "same cut-points. Verified to change zero of 93 pre-existing "
                "results. See docs/METHODOLOGY_DECISIONS.md D-4."
            ),
            original_value="max_val in {10, 50, 80} -> UnboundLocalError",
            suggested_action="Documented; correction applied; no result impact.",
        ),
    ]
