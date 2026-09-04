"""Load a STIX 2.0 bundle from disk exactly once per run.

Legacy behaviour (Estimate_*.py.txt): `json.load(open('ics-attack.json'))`,
re-scanned from scratch by nested loops for every single entity. This
module changes *how* the bundle is loaded and hashed (once, with a SHA-256
recorded for reproducibility - restructuring brief §18) but not what it
contains.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from am_assurance.core.exceptions import STIXLoadError


@dataclass(frozen=True)
class StixBundle:
    objects: list[dict[str, Any]]
    source_path: Path
    sha256: str

    def __len__(self) -> int:
        return len(self.objects)


def load_bundle(path: Path) -> StixBundle:
    if not path.exists():
        raise STIXLoadError(f"STIX bundle not found: {path}")

    raw_bytes = path.read_bytes()
    digest = hashlib.sha256(raw_bytes).hexdigest()

    try:
        data = json.loads(raw_bytes)
    except json.JSONDecodeError as exc:
        raise STIXLoadError(f"{path}: invalid JSON ({exc})") from exc

    if "objects" not in data or not isinstance(data["objects"], list):
        raise STIXLoadError(f"{path}: expected a STIX bundle with an 'objects' array")

    return StixBundle(objects=data["objects"], source_path=path, sha256=digest)
