"""Interface stubs for future AI threat-intelligence ingestion.

INTENTIONALLY UNIMPLEMENTED. This module documents the shape a future
loader would have (mirroring src/am_assurance/cti/stix_loader.py's role
for MITRE ATT&CK for ICS) without ingesting, inventing, or scoring any AI
threat intelligence today. See docs/AI_ASSURANCE_EXTENSION.md.

Do not implement the bodies of these functions as part of a "restructuring
only" change - doing so would require a source of real AI threat
intelligence data (e.g. MITRE ATLAS) that is not present in this
repository, and would risk being read as this framework already
performing AI risk scoring, which docs/README.md explicitly states it
does not.
"""

from __future__ import annotations

from pathlib import Path

from am_assurance.ai_assurance.models import AIThreatEvidence


def load_ai_threat_evidence(source_path: Path) -> list[AIThreatEvidence]:
    """Future: load AI-security threat evidence from a source such as a
    MITRE ATLAS STIX export, an OWASP GenAI Security Project dataset, or a
    NIST AI RMF-aligned control catalogue.

    Not implemented. No such source is bundled with this repository.
    """

    raise NotImplementedError(
        "AI threat-intelligence ingestion is an architectural extension point only. "
        "See docs/AI_ASSURANCE_EXTENSION.md."
    )


def map_evidence_to_component(evidence: list[AIThreatEvidence], component_id: str) -> list[AIThreatEvidence]:
    """Future: filter/attach AIThreatEvidence to a given AIComponent.

    This is intentionally implemented (unlike load_ai_threat_evidence)
    because it performs no ingestion or scoring - it is pure filtering
    over already-constructed, caller-supplied AIThreatEvidence objects,
    useful for wiring up tests/future integrations without pretending a
    real data source exists yet.
    """

    return [e for e in evidence if e.target_component == component_id]
