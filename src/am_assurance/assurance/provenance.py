"""Run/data provenance capture (restructuring brief §18).

Produces the facts needed to answer "can this conclusion be reproduced,
and against exactly what inputs was it computed" - never used to alter a
score.
"""

from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from am_assurance import __version__
from am_assurance.core.config import AssuranceConfig, RiskMatrixConfig, ScoringConfig
from am_assurance.cti.stix_loader import StixBundle


@dataclass(frozen=True)
class Provenance:
    generated_at: str
    project_version: str
    git_commit: Optional[str]
    python_version: str
    os: str
    input_path: str
    input_sha256: str
    scoring_config_sha256: str
    risk_matrix_config_sha256: str
    assurance_config_sha256: Optional[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "project_version": self.project_version,
            "git_commit": self.git_commit,
            "python_version": self.python_version,
            "os": self.os,
            "input_path": self.input_path,
            "input_sha256": self.input_sha256,
            "scoring_config_sha256": self.scoring_config_sha256,
            "risk_matrix_config_sha256": self.risk_matrix_config_sha256,
            "assurance_config_sha256": self.assurance_config_sha256,
        }


def build_provenance(
    bundle: StixBundle,
    scoring_config: ScoringConfig,
    risk_matrix_config: RiskMatrixConfig,
    assurance_config: AssuranceConfig,
) -> Provenance:
    return Provenance(
        generated_at=datetime.now(timezone.utc).isoformat(),
        project_version=__version__,
        git_commit=_git_commit(),
        python_version=platform.python_version(),
        os=f"{platform.system()} {platform.release()}",
        input_path=str(bundle.source_path),
        input_sha256=bundle.sha256,
        scoring_config_sha256=scoring_config.sha256,
        risk_matrix_config_sha256=risk_matrix_config.sha256,
        assurance_config_sha256=assurance_config.sha256,
    )


def _git_commit() -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parents[3],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None
