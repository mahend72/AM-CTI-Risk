from __future__ import annotations

from pathlib import Path

import pytest

from am_assurance.core.config import AssuranceConfig, RiskMatrixConfig, ScoringConfig
from am_assurance.cti.attack_index import AttackIndex
from am_assurance.cti.relationship_index import RelationshipIndex
from am_assurance.cti.stix_loader import load_bundle

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def scoring_config() -> ScoringConfig:
    return ScoringConfig.load(REPO_ROOT / "configs/scoring.yaml")


@pytest.fixture(scope="session")
def risk_matrix_config() -> RiskMatrixConfig:
    return RiskMatrixConfig.load(REPO_ROOT / "configs/risk_matrix.yaml")


@pytest.fixture(scope="session")
def assurance_config() -> AssuranceConfig:
    return AssuranceConfig.load(REPO_ROOT / "configs/assurance.yaml")


@pytest.fixture(scope="session")
def bundle():
    return load_bundle(REPO_ROOT / "data/raw/ics-attack.json")


@pytest.fixture(scope="session")
def attack_index(bundle) -> AttackIndex:
    return AttackIndex.build(bundle)


@pytest.fixture(scope="session")
def relationship_index(bundle) -> RelationshipIndex:
    return RelationshipIndex.build(bundle)
