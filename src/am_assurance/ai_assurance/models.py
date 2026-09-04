"""Data models for the future AI assurance layer.

These are schema-only dataclasses - no scoring method, no threshold, no
weight is defined anywhere in this module. See
docs/AI_ASSURANCE_EXTENSION.md for the architecture these support and
docs/METHODOLOGY.md for confirmation that none of this feeds the current
risk engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AutonomyLevel(str, Enum):
    """How independently the AI component can act without a human in the loop."""

    HUMAN_IN_THE_LOOP = "human_in_the_loop"
    HUMAN_ON_THE_LOOP = "human_on_the_loop"
    SUPERVISED_AUTONOMOUS = "supervised_autonomous"
    FULLY_AUTONOMOUS = "fully_autonomous"


class DecisionRole(str, Enum):
    """What kind of decision the AI component makes or influences."""

    ADVISORY = "advisory"
    RECOMMENDATION = "recommendation"
    DIRECT_CONTROL = "direct_control"
    QUALITY_GATE = "quality_gate"


@dataclass(frozen=True)
class AIComponent:
    """An AI-enabled component of an Additive Manufacturing system.

    Example component_type values (illustrative, not exhaustive):
    "visual_quality_inspection", "predictive_maintenance",
    "anomaly_detection", "generative_design", "process_optimisation",
    "llm_assistant", "autonomous_manufacturing_agent".
    """

    component_id: str
    name: str
    component_type: str
    purpose: str
    associated_am_asset: Optional[str] = None
    model_type: Optional[str] = None
    data_sources: list[str] = field(default_factory=list)
    decision_role: Optional[DecisionRole] = None
    autonomy_level: Optional[AutonomyLevel] = None
    safety_critical: bool = False
    human_override_available: bool = True


@dataclass(frozen=True)
class AIThreatEvidence:
    """A unit of AI-security threat evidence associated with an AIComponent.

    Not scored. Not aggregated into severity/frequency/likelihood/impact/
    risk_level. Exists so a future version can ingest sources such as
    MITRE ATLAS, the OWASP GenAI Security Project, or NIST AI RMF guidance
    (see docs/AI_ASSURANCE_EXTENSION.md) without inventing a numeric
    treatment ahead of that work.
    """

    threat_id: str
    source_framework: str
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    target_component: Optional[str] = None  # AIComponent.component_id
    attack_vector: Optional[str] = None
    evidence: Optional[str] = None
    source_reference: Optional[str] = None
