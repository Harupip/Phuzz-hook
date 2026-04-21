from __future__ import annotations

from typing import Optional

from .config import EnergyConfig
from .models import EnergyResult
from .state import GlobalCoverageState


class EnergyCalculator:
    def __init__(self, config: Optional[EnergyConfig] = None):
        self.config = config or EnergyConfig.from_env()
        self.state = GlobalCoverageState()
        self._total_energy_computed = 0
        self._request_count = 0

    def _classify_tier(self, historical_count: int) -> str:
        if historical_count <= 0:
            return "first_seen"
        if historical_count <= self.config.rare_max_count:
            return "rare"
        return "frequent"

    def _tier_weight(self, tier: str) -> int:
        weights = {
            "first_seen": self.config.callback_first_seen,
            "rare": self.config.callback_rare,
            "frequent": self.config.callback_frequent,
        }
        return weights.get(tier, 1)

    def calculate(self, request_data: dict) -> EnergyResult:
        hook_cov = request_data.get("hook_coverage", {})
        executed = hook_cov.get("executed_callbacks", {})

        result = EnergyResult(
            request_id=str(request_data.get("request_id", "")),
            endpoint=str(request_data.get("endpoint", "")),
        )
        total_energy = 0
        seen_new_hooks: set[str] = set()
        result.executed_callback_ids = sorted(executed.keys())

        for cb_id, info in executed.items():
            hist_count = self.state.get_historical_count(cb_id)
            tier = self._classify_tier(hist_count)
            weight = self._tier_weight(tier)
            total_energy += weight

            if tier == "first_seen":
                result.first_seen_count += 1
                result.new_callback_ids.append(cb_id)
            elif tier == "rare":
                result.rare_count += 1
                result.rare_callback_ids.append(cb_id)
            else:
                result.frequent_count += 1
                result.frequent_callback_ids.append(cb_id)

            hook_name = info.get("hook_name", "unknown")
            callback_repr = info.get("callback_repr", "unknown_callback")
            result.components[tier].append({
                "callback_id": cb_id,
                "hook_name": hook_name,
                "callback_repr": callback_repr,
                "previous_executed_count": hist_count,
                "request_executed_count": int(info.get("executed_count", 1)),
                "energy": weight,
            })

            if self.state.is_blindspot(cb_id):
                total_energy += self.config.blindspot_bonus
                result.blindspot_hits += 1
                result.blindspot_callback_ids.append(cb_id)

            if hook_name and hook_name not in seen_new_hooks and self.state.is_new_hook(hook_name):
                total_energy += self.config.new_hook_bonus
                result.new_hooks_discovered += 1
                result.new_hook_names.append(hook_name)
                seen_new_hooks.add(hook_name)

        for tier_name in ("first_seen", "rare", "frequent"):
            if getattr(result, f"{tier_name}_count", 0) > 0:
                result.dominant_tier = tier_name
                break

        result.coverage_delta = len(result.new_callback_ids)
        result.score = max(1, min(total_energy, self.config.max_energy))
        return result

    def process_request(self, request_data: dict) -> EnergyResult:
        energy = self.calculate(request_data)
        self.state.update_from_request(request_data)
        self._request_count += 1
        self._total_energy_computed += energy.score
        return energy

    def get_stats(self) -> dict:
        return {
            "requests_processed": self._request_count,
            "total_energy_computed": self._total_energy_computed,
            "avg_energy_per_request": (
                round(self._total_energy_computed / self._request_count, 2)
                if self._request_count > 0 else 0
            ),
            "coverage": self.state.coverage_percent,
            "total_registered": len(self.state.registered_callbacks),
            "total_executed": len(self.state.executed_counts),
            "total_blindspots": len(self.state.blindspot_ids),
        }
