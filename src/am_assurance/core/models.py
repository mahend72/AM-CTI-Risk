"""Core domain models shared across the pipeline.

These are plain dataclasses with no scoring logic in them - they exist to
give the values flowing through risk/, assurance/, and reporting/ a typed
shape instead of passing loose dicts around, as the legacy scripts did.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


#: Entity types the legacy scripts actually scored and validated against
#: legacy/original_results/*.json. See docs/METHODOLOGY.md "Entities covered".
LEGACY_VALIDATED_ENTITY_TYPES = frozenset({"malware", "intrusion-set", "course-of-action"})

#: All entity types the generic assessor is willing to run against. Same
#: relationship-traversal rule is applied to every one of them (see
#: docs/METHODOLOGY.md "Entity-technique relationship rule").
SUPPORTED_ENTITY_TYPES = frozenset(LEGACY_VALIDATED_ENTITY_TYPES | {"campaign"})


@dataclass(frozen=True)
class TechniqueEvidence:
    """One related attack-pattern technique and its scoring inputs.

    Mirrors a single `mit` record built inside the legacy
    Estimate_*.py.txt scripts' inner loop.
    """

    relation_id: str
    target_id: str
    technique_name: Optional[str]
    technique_code: Optional[str]
    base_score: Optional[float]
    severity_level: Optional[int]
    per_technique_frequency: Optional[int]
    rel_created: Optional[str] = None
    rel_modified: Optional[str] = None
    warning: Optional[str] = None
    """Set (e.g. "missing mitre-attack reference") when this evidence entry
    could not be fully scored - see docs/METHODOLOGY_DECISIONS.md D-5.
    Such entries are excluded from severity/frequency aggregation."""


@dataclass(frozen=True)
class RiskComponents:
    """The legacy-defined scoring factors for one entity.

    Note (see docs/METHODOLOGY.md "Final risk classification"): in the
    legacy Estimate_*.py.txt scripts, entity-level "severity" IS the
    impact level - `severity = impact_level(impact_score)` is the actual
    legacy variable name for what this module calls `impact_level`. There
    is no separate entity-level severity calculation distinct from impact
    in the original methodology (severity proper is only a per-technique
    factor - see TechniqueEvidence.severity_level). `severity_level` below
    is therefore always equal to `impact_level`; both are kept so the
    assurance record can expose a field literally named "severity" (as
    required) without inventing a new computation.
    """

    severity_level: int
    frequency_level: int
    timeliness_level: int
    likelihood_level: int
    likelihood_label: str
    impact_score: float
    impact_level: int
    impact_label: str
    risk_label: str


@dataclass(frozen=True)
class Entity:
    """A scored STIX entity (malware, intrusion-set, course-of-action, campaign)."""

    stix_id: str
    entity_type: str
    name: str
    created: str
    modified: str
    external_reference_count: int
    attacker_code: Optional[str] = None


@dataclass(frozen=True)
class EntityAssessment:
    """Full result of assessing one entity - the risk-engine output.

    This is the direct, behaviourally-equivalent successor to one element
    of the legacy Results/{COA,intrusion_set,malware}.json arrays.
    """

    entity: Entity
    related_techniques: list[TechniqueEvidence]
    risk: RiskComponents
    as_of: str
    """ISO-8601 timestamp used to compute timeliness for this assessment.
    See docs/REPRODUCIBILITY.md - the legacy code always used "now"."""
    legacy_validated: bool
    """True for malware/intrusion-set/course-of-action (regression-tested
    against legacy/original_results/*.json). False for campaign, which the
    legacy scripts never scored - see docs/METHODOLOGY.md."""
    warnings: list[str] = field(default_factory=list)


@dataclass
class ValidationIssue:
    """One finding from cti/... data validation. See core/validation.py."""

    severity: str  # "INFO" | "WARNING" | "ERROR"
    record: str
    reason: str
    original_value: Any = None
    suggested_action: Optional[str] = None
