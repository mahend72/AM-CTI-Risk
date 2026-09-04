"""Index a STIX bundle by id and by type, once.

Legacy behaviour re-scanned `data['objects']` with a fresh `for obj2 in
data['objects']` loop for every single relationship of every single
entity - an unindexed O(entities x relationships x objects) scan
(restructuring brief §14). This module builds `objects_by_id` and
`objects_by_type` once; docs/CURRENT_IMPLEMENTATION_AUDIT.md §2 and the
regression tests in tests/integration/test_indexed_vs_legacy.py prove the
indexed lookups return the exact same objects the legacy nested scan would
have found - this is a performance change only, not a semantic one.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from am_assurance.cti.stix_loader import StixBundle


@dataclass
class AttackIndex:
    objects_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    objects_by_type: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))

    @staticmethod
    def build(bundle: StixBundle) -> "AttackIndex":
        index = AttackIndex()
        for obj in bundle.objects:
            obj_id = obj.get("id")
            if obj_id:
                index.objects_by_id[obj_id] = obj
            index.objects_by_type[obj.get("type", "")].append(obj)
        return index

    def get(self, stix_id: str) -> Optional[dict[str, Any]]:
        return self.objects_by_id.get(stix_id)

    def entities_of_type(self, entity_type: str) -> list[dict[str, Any]]:
        return self.objects_by_type.get(entity_type, [])

    def mitre_attack_id(self, attack_pattern: dict[str, Any]) -> Optional[str]:
        """The technique's external_id from its 'mitre-attack' reference, or
        None if the attack-pattern has no such reference (see
        docs/METHODOLOGY_DECISIONS.md D-5). Legacy: the first match, in
        external_references order, exactly as the legacy `break` did."""
        for ref in attack_pattern.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None

    def all_technique_ids(self) -> set[str]:
        ids = set()
        for ap in self.objects_by_type.get("attack-pattern", []):
            tid = self.mitre_attack_id(ap)
            if tid:
                ids.add(tid)
        return ids
