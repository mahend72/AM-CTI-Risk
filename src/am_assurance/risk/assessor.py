"""Generic entity assessor.

Direct, behaviourally-equivalent successor to
Code/Estimate_malware.py.txt, Code/Estimate_intrusion_set.py.txt, and
Code/Estimate_courseOfaction.py.txt, which were ~90-line near-verbatim
copies of each other differing only in the `obj1['type']` filter and the
output field name (`mitigates` vs `uses`) - see
docs/CURRENT_IMPLEMENTATION_AUDIT.md §14. This module replaces all three
with one parameterised implementation. No scoring formula is changed; see
docs/METHODOLOGY.md for the full factor-by-factor specification and
docs/METHODOLOGY_DECISIONS.md for the two places (D-4, D-5) where a latent
defect was handled defensively rather than replicated verbatim, both
verified to have zero effect on the 93 pre-existing legacy results.
"""

from __future__ import annotations

from datetime import datetime, timezone

from am_assurance.core.config import AssuranceConfig, RiskMatrixConfig, ScoringConfig
from am_assurance.core.models import (
    LEGACY_VALIDATED_ENTITY_TYPES,
    Entity,
    EntityAssessment,
    RiskComponents,
    TechniqueEvidence,
)
from am_assurance.cti.attack_index import AttackIndex
from am_assurance.cti.relationship_index import RelationshipIndex
from am_assurance.cti.technique_mapping import related_attack_patterns
from am_assurance.risk import frequency as frequency_mod
from am_assurance.risk import impact as impact_mod
from am_assurance.risk import likelihood as likelihood_mod
from am_assurance.risk import risk_matrix as risk_matrix_mod
from am_assurance.risk import severity as severity_mod
from am_assurance.risk import timeliness as timeliness_mod
from am_assurance.risk.aggregation import average_nonzero


def assess_entity(
    entity_obj: dict,
    attack_index: AttackIndex,
    relationship_index: RelationshipIndex,
    scoring_config: ScoringConfig,
    risk_matrix_config: RiskMatrixConfig,
    as_of: datetime | None = None,
) -> EntityAssessment:
    """Assess one STIX entity object. `as_of` pins "now" for the
    time-dependent timeliness factor (see docs/REPRODUCIBILITY.md);
    defaults to the current UTC time, matching legacy `time.time()`."""

    if as_of is None:
        as_of = datetime.now(timezone.utc)

    entity_type = entity_obj.get("type")
    warnings: list[str] = []

    related = related_attack_patterns(entity_obj["id"], attack_index, relationship_index)
    evidence: list[TechniqueEvidence] = []

    for relobj, attack_pattern in related:
        technique_code = attack_index.mitre_attack_id(attack_pattern)

        if technique_code is None:
            # docs/METHODOLOGY_DECISIONS.md D-5: legacy would append an
            # incomplete `mit` dict here and later crash with KeyError.
            # Preserved intent: record as unscored evidence, warn, and
            # exclude from aggregation - never silently drop the relation.
            msg = (
                f"related attack-pattern {attack_pattern.get('id')} "
                "('{}') has no mitre-attack external reference; "
                "excluded from severity/frequency aggregation (see "
                "docs/METHODOLOGY_DECISIONS.md D-5)."
            ).format(attack_pattern.get("name"))
            warnings.append(msg)
            evidence.append(
                TechniqueEvidence(
                    relation_id=relobj.get("id"),
                    target_id=attack_pattern.get("id"),
                    technique_name=attack_pattern.get("name"),
                    technique_code=None,
                    base_score=None,
                    severity_level=None,
                    per_technique_frequency=None,
                    rel_created=attack_pattern.get("created"),
                    rel_modified=attack_pattern.get("modified"),
                    warning=msg,
                )
            )
            continue

        base_score, severity_level = severity_mod.severity(scoring_config, technique_code)
        per_technique_frequency = len(attack_pattern.get("external_references", []))

        evidence.append(
            TechniqueEvidence(
                relation_id=relobj.get("id"),
                target_id=attack_pattern.get("id"),
                technique_name=attack_pattern.get("name"),
                technique_code=technique_code,
                base_score=base_score,
                severity_level=severity_level,
                per_technique_frequency=per_technique_frequency,
                # Legacy quirk, preserved exactly (docs/CURRENT_IMPLEMENTATION_AUDIT.md
                # §2 step 3): the attack-pattern's own created/modified are stored
                # here, not the relationship's.
                rel_created=attack_pattern.get("created"),
                rel_modified=attack_pattern.get("modified"),
            )
        )

    scored = [e for e in evidence if e.base_score is not None]

    impact_score = average_nonzero(e.base_score for e in scored)
    entity_impact_level, entity_impact_label = impact_mod.impact_level(scoring_config, impact_score)

    # Legacy: plain mean (zeros included), computed inline in each
    # Estimate_*.py.txt script - deliberately NOT the same non-zero mean
    # `average()`/average_nonzero() uses for impact_score. See
    # docs/METHODOLOGY.md "Factor: Frequency".
    per_technique_frequencies = [e.per_technique_frequency for e in scored]
    mean_technique_frequency = (
        sum(per_technique_frequencies) / len(per_technique_frequencies) if per_technique_frequencies else 0.0
    )

    external_reference_count = len(entity_obj.get("external_references", []))
    frequency_value = external_reference_count * (mean_technique_frequency + scoring_config.frequency_offset)
    frequency_level = frequency_mod.frequency_level(scoring_config, frequency_value)

    modified_str = entity_obj["modified"]
    modified_dt = datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
    # Legacy applied int() truncation to the modified timestamp only (not
    # to time.time()) - preserved exactly; the effect is sub-second and
    # immaterial to any weeks-scale threshold, but this is what the
    # original code computed. See docs/CURRENT_IMPLEMENTATION_AUDIT.md §2.
    modified_epoch = int(modified_dt.timestamp())
    as_of_epoch = as_of.timestamp()

    like_weeks = timeliness_mod.like_weeks_since(modified_epoch, as_of_epoch)
    timeliness_level = timeliness_mod.timeliness_level(scoring_config, like_weeks)

    likelihood_level, likelihood_label = likelihood_mod.likelihood(scoring_config, timeliness_level, frequency_level)

    risk_label = risk_matrix_mod.risk_level(risk_matrix_config, entity_impact_level, likelihood_level)

    attacker_code = None
    for ref in entity_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            attacker_code = ref.get("external_id")
            break

    entity = Entity(
        stix_id=entity_obj["id"],
        entity_type=entity_type,
        name=entity_obj.get("name", ""),
        created=entity_obj.get("created", ""),
        modified=modified_str,
        external_reference_count=external_reference_count,
        attacker_code=attacker_code,
    )

    risk = RiskComponents(
        severity_level=entity_impact_level,  # legacy variable name collision - see note below
        frequency_level=frequency_level,
        timeliness_level=timeliness_level,
        likelihood_level=likelihood_level,
        likelihood_label=likelihood_label,
        impact_score=impact_score,
        impact_level=entity_impact_level,
        impact_label=entity_impact_label,
        risk_label=risk_label,
    )

    return EntityAssessment(
        entity=entity,
        related_techniques=evidence,
        risk=risk,
        as_of=as_of.isoformat(),
        legacy_validated=entity_type in LEGACY_VALIDATED_ENTITY_TYPES,
        warnings=warnings,
    )


def assess_entity_type(
    entity_type: str,
    attack_index: AttackIndex,
    relationship_index: RelationshipIndex,
    scoring_config: ScoringConfig,
    risk_matrix_config: RiskMatrixConfig,
    as_of: datetime | None = None,
) -> list[EntityAssessment]:
    """Legacy: the `for obj1 in data['objects']: if obj1['type'] ==
    <entity_type>` loop in each Estimate_*.py.txt script."""

    return [
        assess_entity(obj, attack_index, relationship_index, scoring_config, risk_matrix_config, as_of=as_of)
        for obj in attack_index.entities_of_type(entity_type)
    ]
