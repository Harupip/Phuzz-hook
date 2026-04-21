from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class EnergyConfig:
    callback_first_seen: int = 12
    callback_rare: int = 5
    callback_frequent: int = 1
    rare_max_count: int = 3
    blindspot_bonus: int = 8
    new_hook_bonus: int = 10
    coverage_delta_weight: float = 2.0
    max_energy: int = 200

    @classmethod
    def from_env(cls) -> "EnergyConfig":
        def _env_int(name: str, default: int) -> int:
            val = os.environ.get(name, "")
            return int(val) if val.isdigit() else default

        def _env_float(name: str, default: float) -> float:
            val = os.environ.get(name, "")
            try:
                return float(val) if val else default
            except ValueError:
                return default

        return cls(
            callback_first_seen=_env_int("FUZZER_ENERGY_CALLBACK_FIRST", 12),
            callback_rare=_env_int("FUZZER_ENERGY_CALLBACK_RARE", 5),
            callback_frequent=_env_int("FUZZER_ENERGY_CALLBACK_FREQUENT", 1),
            rare_max_count=_env_int("FUZZER_ENERGY_RARE_CALLBACK_MAX", 3),
            blindspot_bonus=_env_int("FUZZER_ENERGY_BLINDSPOT_BONUS", 8),
            new_hook_bonus=_env_int("FUZZER_ENERGY_NEW_HOOK_BONUS", 10),
            coverage_delta_weight=_env_float("FUZZER_ENERGY_COVERAGE_DELTA_WEIGHT", 2.0),  # trọng số của độ bao phủ mới
            max_energy=_env_int("FUZZER_ENERGY_MAX", 200),
        )
