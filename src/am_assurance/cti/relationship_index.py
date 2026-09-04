"""Index STIX relationship objects by source and target, once.

See cti/attack_index.py for the same rationale. Legacy selection rule
(preserved exactly - docs/METHODOLOGY.md "Entity-technique relationship
rule"): an entity is related to an attack-pattern if ANY relationship
(regardless of relationship_type) has source_ref == entity.id and
target_ref resolves to an object of type attack-pattern.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from am_assurance.cti.stix_loader import StixBundle


@dataclass
class RelationshipIndex:
    by_source: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))
    by_target: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))
    _all: list[dict[str, Any]] = field(default_factory=list)

    @staticmethod
    def build(bundle: StixBundle) -> "RelationshipIndex":
        index = RelationshipIndex()
        for obj in bundle.objects:
            if obj.get("type") != "relationship":
                continue
            index._all.append(obj)
            src = obj.get("source_ref")
            tgt = obj.get("target_ref")
            if src:
                index.by_source[src].append(obj)
            if tgt:
                index.by_target[tgt].append(obj)
        return index

    def outgoing(self, stix_id: str) -> list[dict[str, Any]]:
        return self.by_source.get(stix_id, [])

    def all_relationships(self) -> list[dict[str, Any]]:
        return self._all
