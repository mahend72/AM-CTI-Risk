"""Run summary: counts by entity type / risk level, warning totals."""

from __future__ import annotations

from collections import Counter
from typing import Any

from am_assurance.assurance.assurance_record import AssuranceRecord


def build_summary(records: list[AssuranceRecord]) -> dict[str, Any]:
    by_entity_type = Counter(r.entity_type for r in records)
    by_risk_level = Counter(r.risk_level for r in records)
    warnings_total = sum(len(r.warnings) for r in records)

    return {
        "total_entities_assessed": len(records),
        "entities_by_type": dict(by_entity_type),
        "entities_by_risk_level": dict(by_risk_level),
        "total_warnings": warnings_total,
        "legacy_validated_count": sum(1 for r in records if r.legacy_validated),
        "non_legacy_validated_count": sum(1 for r in records if not r.legacy_validated),
    }
