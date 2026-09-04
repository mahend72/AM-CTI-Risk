#!/usr/bin/env python3
"""CLI entry point for the CTI-driven AM risk/assurance pipeline.

Example (reproduces the current scientific pipeline by default):

    python scripts/run_assessment.py \\
        --input data/raw/ics-attack.json \\
        --config configs/scoring.yaml \\
        --risk-matrix configs/risk_matrix.yaml \\
        --output results/
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from am_assurance.core.models import SUPPORTED_ENTITY_TYPES  # noqa: E402
from am_assurance.pipeline import (  # noqa: E402
    run_pipeline,
    write_run_metadata,
    write_validation_report,
)
from am_assurance.reporting.csv_report import write_csv_report  # noqa: E402
from am_assurance.reporting.json_report import write_json_report  # noqa: E402
from am_assurance.reporting.summary import build_summary  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, default=REPO_ROOT / "data/raw/ics-attack.json")
    parser.add_argument("--config", type=Path, default=REPO_ROOT / "configs/scoring.yaml")
    parser.add_argument("--risk-matrix", type=Path, default=REPO_ROOT / "configs/risk_matrix.yaml")
    parser.add_argument("--assurance-config", type=Path, default=REPO_ROOT / "configs/assurance.yaml")
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "results")
    parser.add_argument(
        "--entity-type",
        action="append",
        choices=sorted(SUPPORTED_ENTITY_TYPES),
        help="Restrict to one entity type; repeat for multiple. Default: all supported types.",
    )
    parser.add_argument("--validate-only", action="store_true", help="Run validation and exit without scoring.")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument(
        "--legacy-comparison",
        action="store_true",
        help="Also compare results against legacy/original_results/*.json and write results/validation/legacy_comparison.csv.",
    )
    parser.add_argument(
        "--generate-provenance",
        action="store_true",
        help="Write results/provenance/<run>.json (provenance is always included in each assurance record regardless).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=args.log_level, format="%(levelname)s %(name)s: %(message)s")

    result = run_pipeline(
        input_path=args.input,
        scoring_config_path=args.config,
        risk_matrix_config_path=args.risk_matrix,
        assurance_config_path=args.assurance_config,
        entity_types=args.entity_type,
        validate_only=args.validate_only,
    )

    validation_path = args.output / "validation" / "data_validation_report.json"
    write_validation_report(result, validation_path)
    print(f"Validation report: {validation_path} ({len(result.validation_issues)} findings)")

    if args.validate_only:
        return 0

    for entity_type, records in result.records_by_type.items():
        out_path = args.output / "assessments" / f"{entity_type.replace('-', '_')}.json"
        write_json_report(records, out_path)
        print(f"{entity_type}: {len(records)} entities -> {out_path}")

    all_records = result.all_records()
    csv_path = args.output / "assessments" / "all_assessments.csv"
    write_csv_report(all_records, csv_path)

    metadata_path = args.output / "metadata" / "run_metadata.json"
    write_run_metadata(result, metadata_path)
    print(f"Run metadata: {metadata_path}")

    if args.generate_provenance:
        provenance_path = args.output / "provenance" / "run_provenance.json"
        provenance_path.parent.mkdir(parents=True, exist_ok=True)
        provenance_path.write_text(
            __import__("json").dumps(result.run_metadata.get("provenance", {}), indent=2), encoding="utf-8"
        )
        print(f"Provenance: {provenance_path}")

    if args.legacy_comparison:
        from tests.regression.legacy_comparison import write_legacy_comparison_csv

        comparison_path = args.output / "validation" / "legacy_comparison.csv"
        write_legacy_comparison_csv(result, comparison_path)
        print(f"Legacy comparison: {comparison_path}")

    summary = build_summary(all_records)
    print("Summary:", summary)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
