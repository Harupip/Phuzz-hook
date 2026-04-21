from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class EnergyResult:
    request_id: str = ""
    endpoint: str = ""
    score: int = 1
    coverage_delta: int = 0
    dominant_tier: str = "no_coverage"
    first_seen_count: int = 0
    rare_count: int = 0
    frequent_count: int = 0
    blindspot_hits: int = 0
    new_hooks_discovered: int = 0
    executed_callback_ids: list[str] = field(default_factory=list)
    new_callback_ids: list[str] = field(default_factory=list)
    rare_callback_ids: list[str] = field(default_factory=list)
    frequent_callback_ids: list[str] = field(default_factory=list)
    blindspot_callback_ids: list[str] = field(default_factory=list)
    new_hook_names: list[str] = field(default_factory=list)
    components: Dict[str, list] = field(default_factory=lambda: {
        "first_seen": [],
        "rare": [],
        "frequent": [],
    })

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "endpoint": self.endpoint,
            "score": self.score,
            "coverage_delta": self.coverage_delta,
            "dominant_tier": self.dominant_tier,
            "first_seen_count": self.first_seen_count,
            "rare_count": self.rare_count,
            "frequent_count": self.frequent_count,
            "blindspot_hits": self.blindspot_hits,
            "new_hooks_discovered": self.new_hooks_discovered,
            "executed_callback_ids": self.executed_callback_ids,
            "new_callback_ids": self.new_callback_ids,
            "rare_callback_ids": self.rare_callback_ids,
            "frequent_callback_ids": self.frequent_callback_ids,
            "blindspot_callback_ids": self.blindspot_callback_ids,
            "new_hook_names": self.new_hook_names,
            "summary": {
                "first_seen_items": len(self.components.get("first_seen", [])),
                "rare_items": len(self.components.get("rare", [])),
                "frequent_items": len(self.components.get("frequent", [])),
            },
        }
