"""Evidence extraction: turns an EntityAssessment's related techniques into
the flat evidence list an AssuranceRecord exposes (restructuring brief §8).

This module answers "what did the risk engine look at", not "how risky is
it" - it never computes or alters a score.
"""

from __future__ import annotations

from typing import Any

from am_assurance.core.models import EntityAssessment

SOURCE_FRAMEWORK = "MITRE ATT&CK for ICS"


def build_evidence(assessment: EntityAssessment) -> list[dict[str, Any]]:
    evidence = []
    for tech in assessment.related_techniques:
        evidence.append(
            {
                "technique_id": tech.technique_code,
                "technique_name": tech.technique_name,
                "source": SOURCE_FRAMEWORK,
                "relation_id": tech.relation_id,
                "base_score": tech.base_score,
                "severity_level": tech.severity_level,
                "warning": tech.warning,
            }
        )
    return evidence


def related_technique_ids(assessment: EntityAssessment) -> list[str]:
    return [t.technique_code for t in assessment.related_techniques if t.technique_code]
