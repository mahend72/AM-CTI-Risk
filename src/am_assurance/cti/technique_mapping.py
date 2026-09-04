"""Entity -> related attack-pattern technique resolution, and optional
(informational-only) AM asset context.

`related_attack_patterns` reproduces the legacy relationship-traversal rule
exactly (docs/METHODOLOGY.md "Entity-technique relationship rule"): any
relationship, of any relationship_type, with source_ref == entity.id and a
target that resolves to an attack-pattern object.

`am_asset_context` is a SEPARATE, purely informational lookup. The
original repository never mapped techniques to specific Additive
Manufacturing assets in code - the "AM" framing exists only at the
narrative/paper level (see docs/CURRENT_IMPLEMENTATION_AUDIT.md §15 /
docs/METHODOLOGY.md). data/reference/am_asset_mapping.csv is currently an
empty template (see that file's header comment); this function returns
None for every technique until that mapping is curated. It is never
consulted by the risk engine - see docs/AI_ASSURANCE_EXTENSION.md and
docs/ARCHITECTURE.md for why this is kept as a clearly-separated,
non-scoring lookup rather than invented data.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Optional

from am_assurance.cti.attack_index import AttackIndex
from am_assurance.cti.relationship_index import RelationshipIndex


def related_attack_patterns(
    entity_id: str,
    attack_index: AttackIndex,
    relationship_index: RelationshipIndex,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Returns [(relationship_obj, attack_pattern_obj), ...] for every
    relationship sourced at entity_id whose target is an attack-pattern.
    """

    results = []
    for rel in relationship_index.outgoing(entity_id):
        target = attack_index.get(rel.get("target_ref", ""))
        if target is not None and target.get("type") == "attack-pattern":
            results.append((rel, target))
    return results


_AM_ASSET_MAPPING_CACHE: dict[Path, dict[str, str]] = {}


def am_asset_context(technique_id: str, csv_path: Path) -> Optional[str]:
    """Best-effort, non-scoring lookup of an AM-specific asset/process label
    for a technique, if data/reference/am_asset_mapping.csv has been
    curated with one. Returns None (never raises) if the file is absent,
    empty, or has no row for this technique - this must never block or
    alter risk scoring."""

    mapping = _AM_ASSET_MAPPING_CACHE.get(csv_path)
    if mapping is None:
        mapping = {}
        if csv_path.exists():
            with csv_path.open(newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    tid = row.get("technique_id")
                    asset = row.get("am_asset")
                    if tid and asset:
                        mapping[tid] = asset
        _AM_ASSET_MAPPING_CACHE[csv_path] = mapping

    return mapping.get(technique_id)
