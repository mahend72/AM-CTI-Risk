"""Flatten AssuranceRecords / legacy-comparison rows to CSV."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from am_assurance.assurance.assurance_record import AssuranceRecord

FIELDS = [
    "assessment_id",
    "entity_id",
    "entity_name",
    "entity_type",
    "severity",
    "frequency",
    "likelihood",
    "timeliness",
    "combined_score",
    "impact_level",
    "risk_level",
    "legacy_validated",
    "warning_count",
]


def write_csv_report(records: list[AssuranceRecord], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        for record in records:
            writer.writerow(_flatten(record))


def _flatten(record: AssuranceRecord) -> dict[str, Any]:
    return {
        "assessment_id": record.assessment_id,
        "entity_id": record.entity_id,
        "entity_name": record.entity_name,
        "entity_type": record.entity_type,
        "severity": record.severity,
        "frequency": record.frequency,
        "likelihood": record.likelihood,
        "timeliness": record.timeliness,
        "combined_score": record.combined_score,
        "impact_level": record.impact_level,
        "risk_level": record.risk_level,
        "legacy_validated": record.legacy_validated,
        "warning_count": len(record.warnings),
    }
