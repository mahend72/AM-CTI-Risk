"""Typed loaders for configs/scoring.yaml, configs/risk_matrix.yaml, and
configs/assurance.yaml.

Externalising these values (per the restructuring brief §12) must not
change any threshold, weight, or matrix value - see docs/METHODOLOGY.md and
configs/*.yaml for the values themselves. This module only loads and
validates their shape.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from am_assurance.core.exceptions import ConfigError


@dataclass(frozen=True)
class Threshold:
    """One row of a min-threshold table (severity/frequency/likelihood/impact)."""

    minimum: float
    level: int
    label: str | None = None


@dataclass(frozen=True)
class TimelinessRule:
    op: str
    value: float
    level: int
    gt: float | None = None


@dataclass(frozen=True)
class ScoringConfig:
    severity_buckets: dict[int, list[str]]
    severity_thresholds: list[Threshold]
    frequency_offset: float
    frequency_thresholds: list[Threshold]
    timeliness_rules: list[TimelinessRule]
    likelihood_thresholds: list[Threshold]
    impact_thresholds: list[Threshold]
    source_path: Path
    sha256: str

    @staticmethod
    def load(path: Path) -> "ScoringConfig":
        raw, digest = _load_yaml_with_hash(path)
        try:
            severity_thresholds = [_threshold(r) for r in raw["severity_thresholds"]]
            frequency_thresholds = [_threshold(r) for r in raw["frequency_thresholds"]]
            likelihood_thresholds = [_threshold(r) for r in raw["likelihood_thresholds"]]
            impact_thresholds = [_threshold(r) for r in raw["impact_thresholds"]]
            timeliness_rules = [
                TimelinessRule(op=r["op"], value=r["value"], level=r["level"], gt=r.get("gt"))
                for r in raw["timeliness_rules"]
            ]
            severity_buckets = {int(k): list(v) for k, v in raw["severity_buckets"].items()}
        except KeyError as exc:
            raise ConfigError(f"{path}: missing required key {exc}") from exc

        return ScoringConfig(
            severity_buckets=severity_buckets,
            severity_thresholds=severity_thresholds,
            frequency_offset=float(raw["frequency_offset"]),
            frequency_thresholds=frequency_thresholds,
            timeliness_rules=timeliness_rules,
            likelihood_thresholds=likelihood_thresholds,
            impact_thresholds=impact_thresholds,
            source_path=path,
            sha256=digest,
        )


@dataclass(frozen=True)
class RiskMatrixConfig:
    default_label: str
    matrix: dict[tuple[int, int], str]
    source_path: Path
    sha256: str

    @staticmethod
    def load(path: Path) -> "RiskMatrixConfig":
        raw, digest = _load_yaml_with_hash(path)
        try:
            matrix = {}
            for key, label in raw["matrix"].items():
                impact_s, likelihood_s = key.split(",")
                matrix[(int(impact_s), int(likelihood_s))] = label
            default_label = raw["default_label"]
        except (KeyError, ValueError) as exc:
            raise ConfigError(f"{path}: malformed matrix entry ({exc})") from exc

        return RiskMatrixConfig(default_label=default_label, matrix=matrix, source_path=path, sha256=digest)


@dataclass(frozen=True)
class AssuranceConfig:
    provenance_enabled: bool
    warnings_enabled: bool
    metadata_enabled: bool
    evidence_enabled: bool
    mitigations_enabled: bool
    flag_missing_technique_reference: bool
    flag_malformed_technique_ids: bool
    ai_assurance_enabled: bool
    ai_assurance_affects_risk_score: bool
    raw: dict[str, Any] = field(default_factory=dict)
    source_path: Path | None = None
    sha256: str | None = None

    @staticmethod
    def load(path: Path) -> "AssuranceConfig":
        raw, digest = _load_yaml_with_hash(path)
        provenance = raw.get("provenance", {})
        warnings_cfg = raw.get("warnings", {})
        metadata = raw.get("metadata", {})
        evidence = raw.get("evidence", {})
        mitigations = raw.get("mitigations", {})
        ai = raw.get("ai_assurance", {})

        ai_affects_score = bool(ai.get("affects_risk_score", False))
        if ai_affects_score:
            raise ConfigError(
                "configs/assurance.yaml: ai_assurance.affects_risk_score must be false. "
                "The AI assurance layer is an architectural extension point only - see "
                "docs/AI_ASSURANCE_EXTENSION.md. Refusing to load a configuration that "
                "would let AI signals influence the legacy cyber-risk score."
            )

        return AssuranceConfig(
            provenance_enabled=bool(provenance.get("enabled", True)),
            warnings_enabled=bool(warnings_cfg.get("enabled", True)),
            metadata_enabled=bool(metadata.get("enabled", True)),
            evidence_enabled=bool(evidence.get("enabled", True)),
            mitigations_enabled=bool(mitigations.get("enabled", True)),
            flag_missing_technique_reference=bool(warnings_cfg.get("flag_missing_technique_reference", True)),
            flag_malformed_technique_ids=bool(warnings_cfg.get("flag_malformed_technique_ids", True)),
            ai_assurance_enabled=bool(ai.get("enabled", False)),
            ai_assurance_affects_risk_score=ai_affects_score,
            raw=raw,
            source_path=path,
            sha256=digest,
        )


def _threshold(row: dict[str, Any]) -> Threshold:
    return Threshold(minimum=float(row["min"]), level=int(row["level"]), label=row.get("label"))


def _load_yaml_with_hash(path: Path) -> tuple[dict[str, Any], str]:
    if not path.exists():
        raise ConfigError(f"Configuration file not found: {path}")
    text = path.read_text(encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML ({exc})") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a top-level mapping")
    return data, digest
