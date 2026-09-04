"""Mitigation cross-referencing (assurance context only - not a score).

The legacy methodology never linked a malware/intrusion-set assessment
directly to the course-of-action entries that mitigate it - a
course-of-action only ever points at attack-patterns (`mitigates`
relationships), and malware/intrusion-sets only ever point at
attack-patterns too (`uses` relationships) - see
docs/CURRENT_IMPLEMENTATION_AUDIT.md §4. This module performs a
best-effort, presentational join through shared technique IDs so an
AssuranceRecord can show "what might mitigate this" as supporting
evidence. It is explicitly NOT part of the original scoring and is never
fed back into severity/frequency/likelihood/impact/risk_level.
"""

from __future__ import annotations

from typing import Any

from am_assurance.assurance.evidence import related_technique_ids
from am_assurance.core.models import EntityAssessment


def find_mitigations(
    assessment: EntityAssessment,
    course_of_action_assessments: list[EntityAssessment],
) -> list[dict[str, Any]]:
    if assessment.entity.entity_type == "course-of-action":
        return []

    target_techniques = set(related_technique_ids(assessment))
    if not target_techniques:
        return []

    mitigations = []
    for coa in course_of_action_assessments:
        coa_techniques = set(related_technique_ids(coa))
        shared = sorted(target_techniques & coa_techniques)
        if shared:
            mitigations.append(
                {
                    "course_of_action_id": coa.entity.stix_id,
                    "course_of_action_name": coa.entity.name,
                    "shared_technique_ids": shared,
                }
            )
    return mitigations
