"""AssuranceRecord: the "why did the framework reach this conclusion"
counterpart to the risk engine's "how risky is this" (restructuring brief
§7). Every field here is either a pass-through of an already-computed
risk-engine value, or supporting evidence/provenance around it - nothing
here computes a new score.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from am_assurance.assurance.controls import find_mitigations
from am_assurance.assurance.evidence import SOURCE_FRAMEWORK, build_evidence
from am_assurance.assurance.provenance import Provenance
from am_assurance.core.config import AssuranceConfig
from am_assurance.core.models import EntityAssessment


@dataclass(frozen=True)
class AssuranceRecord:
    assessment_id: str
    entity_id: str
    entity_name: str
    entity_type: str
    source_framework: str
    related_techniques: list[str]
    raw_evidence: list[dict[str, Any]]
    severity: int
    frequency: int
    likelihood: str
    timeliness: int
    combined_score: float
    impact_level: str
    risk_level: str
    mitigations: list[dict[str, Any]]
    warnings: list[str]
    provenance: dict[str, Any]
    configuration_version: str
    data_version: str
    legacy_validated: bool
    as_of: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "entity_id": self.entity_id,
            "entity_name": self.entity_name,
            "entity_type": self.entity_type,
            "source_framework": self.source_framework,
            "related_techniques": self.related_techniques,
            "raw_evidence": self.raw_evidence,
            "severity": self.severity,
            "frequency": self.frequency,
            "likelihood": self.likelihood,
            "timeliness": self.timeliness,
            "combined_score": self.combined_score,
            "impact_level": self.impact_level,
            "risk_level": self.risk_level,
            "mitigations": self.mitigations,
            "warnings": self.warnings,
            "provenance": self.provenance,
            "configuration_version": self.configuration_version,
            "data_version": self.data_version,
            "legacy_validated": self.legacy_validated,
            "as_of": self.as_of,
        }


def build_assurance_record(
    assessment: EntityAssessment,
    provenance: Provenance,
    assurance_config: AssuranceConfig,
    course_of_action_assessments: Optional[list[EntityAssessment]] = None,
) -> AssuranceRecord:
    mitigations: list[dict[str, Any]] = []
    if assurance_config.mitigations_enabled and course_of_action_assessments is not None:
        mitigations = find_mitigations(assessment, course_of_action_assessments)

    raw_evidence = build_evidence(assessment) if assurance_config.evidence_enabled else []
    prov_dict = provenance.as_dict() if assurance_config.provenance_enabled else {}

    return AssuranceRecord(
        assessment_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{assessment.entity.stix_id}:{assessment.as_of}")),
        entity_id=assessment.entity.stix_id,
        entity_name=assessment.entity.name,
        entity_type=assessment.entity.entity_type,
        source_framework=SOURCE_FRAMEWORK,
        related_techniques=[t.technique_code for t in assessment.related_techniques if t.technique_code],
        raw_evidence=raw_evidence,
        severity=assessment.risk.severity_level,
        frequency=assessment.risk.frequency_level,
        likelihood=assessment.risk.likelihood_label,
        timeliness=assessment.risk.timeliness_level,
        combined_score=assessment.risk.impact_score,
        impact_level=assessment.risk.impact_label,
        risk_level=assessment.risk.risk_label,
        mitigations=mitigations,
        warnings=list(assessment.warnings) if assurance_config.warnings_enabled else [],
        provenance=prov_dict,
        configuration_version=provenance.scoring_config_sha256[:12],
        data_version=provenance.input_sha256[:12],
        legacy_validated=assessment.legacy_validated,
        as_of=assessment.as_of,
    )
