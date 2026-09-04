"""End-to-end pipeline orchestration (restructuring brief §6).

    STIX Loader -> STIX/Relationship Index -> Entity -> Related Techniques
    -> Severity/Frequency/Likelihood/Timeliness -> Aggregation -> Impact
    -> Risk Matrix -> Evidence + Provenance -> Assurance Record

This module wires together cti/, risk/, and assurance/ without adding any
new scoring logic of its own - see docs/METHODOLOGY.md for where every
number in an AssuranceRecord actually comes from.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from am_assurance.assurance.assurance_record import AssuranceRecord, build_assurance_record
from am_assurance.assurance.provenance import build_provenance
from am_assurance.core.config import AssuranceConfig, RiskMatrixConfig, ScoringConfig
from am_assurance.core.models import SUPPORTED_ENTITY_TYPES, EntityAssessment, ValidationIssue
from am_assurance.core.validation import validate_bundle
from am_assurance.cti.attack_index import AttackIndex
from am_assurance.cti.relationship_index import RelationshipIndex
from am_assurance.cti.stix_loader import load_bundle
from am_assurance.risk.assessor import assess_entity_type

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    records_by_type: dict[str, list[AssuranceRecord]] = field(default_factory=dict)
    validation_issues: list[ValidationIssue] = field(default_factory=list)
    run_metadata: dict = field(default_factory=dict)

    def all_records(self) -> list[AssuranceRecord]:
        return [r for records in self.records_by_type.values() for r in records]


def run_pipeline(
    input_path: Path,
    scoring_config_path: Path,
    risk_matrix_config_path: Path,
    assurance_config_path: Path,
    entity_types: Optional[list[str]] = None,
    as_of: Optional[datetime] = None,
    validate_only: bool = False,
) -> PipelineResult:
    entity_types = entity_types or sorted(SUPPORTED_ENTITY_TYPES)
    unknown = set(entity_types) - SUPPORTED_ENTITY_TYPES
    if unknown:
        raise ValueError(f"Unsupported entity type(s): {sorted(unknown)}. Supported: {sorted(SUPPORTED_ENTITY_TYPES)}")

    logger.info("Loading STIX bundle: %s", input_path)
    bundle = load_bundle(input_path)

    scoring_config = ScoringConfig.load(scoring_config_path)
    risk_matrix_config = RiskMatrixConfig.load(risk_matrix_config_path)
    assurance_config = AssuranceConfig.load(assurance_config_path)

    attack_index = AttackIndex.build(bundle)
    relationship_index = RelationshipIndex.build(bundle)

    logger.info("Validating bundle (%d objects)", len(bundle))
    validation_issues = validate_bundle(attack_index, relationship_index, scoring_config)
    error_count = sum(1 for i in validation_issues if i.severity == "ERROR")
    warning_count = sum(1 for i in validation_issues if i.severity == "WARNING")
    logger.info("Validation complete: %d ERROR, %d WARNING", error_count, warning_count)

    result = PipelineResult(validation_issues=validation_issues)

    if validate_only:
        return result

    provenance = build_provenance(bundle, scoring_config, risk_matrix_config, assurance_config)

    assessments_by_type: dict[str, list[EntityAssessment]] = {}
    for entity_type in entity_types:
        logger.info("Assessing entities of type: %s", entity_type)
        assessments_by_type[entity_type] = assess_entity_type(
            entity_type, attack_index, relationship_index, scoring_config, risk_matrix_config, as_of=as_of
        )

    coa_assessments = assessments_by_type.get("course-of-action", [])

    records_by_type: dict[str, list[AssuranceRecord]] = {}
    for entity_type, assessments in assessments_by_type.items():
        records_by_type[entity_type] = [
            build_assurance_record(a, provenance, assurance_config, course_of_action_assessments=coa_assessments)
            for a in assessments
        ]

    result.records_by_type = records_by_type
    result.run_metadata = _build_run_metadata(bundle, attack_index, records_by_type, validation_issues, provenance)
    return result


def _build_run_metadata(bundle, attack_index, records_by_type, validation_issues, provenance) -> dict:
    from collections import Counter

    type_counts = {t: len(objs) for t, objs in attack_index.objects_by_type.items()}
    entity_counts = {t: len(records) for t, records in records_by_type.items()}
    severity_counts = Counter(i.severity for i in validation_issues)

    return {
        "provenance": provenance.as_dict(),
        "stix_object_count": len(bundle),
        "stix_object_counts_by_type": type_counts,
        "assessed_entity_counts": entity_counts,
        "validation_status": {
            "ERROR": severity_counts.get("ERROR", 0),
            "WARNING": severity_counts.get("WARNING", 0),
            "INFO": severity_counts.get("INFO", 0),
        },
    }


def write_run_metadata(result: PipelineResult, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result.run_metadata, indent=2), encoding="utf-8")


def write_validation_report(result: PipelineResult, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [
        {
            "severity": i.severity,
            "record": i.record,
            "reason": i.reason,
            "original_value": i.original_value,
            "suggested_action": i.suggested_action,
        }
        for i in result.validation_issues
    ]
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
