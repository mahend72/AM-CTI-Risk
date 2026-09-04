"""Write AssuranceRecord lists to JSON (restructuring brief §8 example
shape)."""

from __future__ import annotations

import json
from pathlib import Path

from am_assurance.assurance.assurance_record import AssuranceRecord


def write_json_report(records: list[AssuranceRecord], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [r.as_dict() for r in records]
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
