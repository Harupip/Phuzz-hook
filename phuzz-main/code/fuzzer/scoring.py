class ScoringFormula():
    def calculate_score(self, candidate):
        pass
    def calculate_priority(self, candidate):
        pass
    def calculate_energy(self, candidate):
        pass


def _env_int(name, default):
    import os

    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        return int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw_value!r}") from exc


def _env_float(name, default):
    import os

    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        return float(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a float, got {raw_value!r}") from exc


def _env_str(name, default):
    import os

    raw_value = os.environ.get(name, "").strip()
    return raw_value or default


def _score_debug_enabled():
    import os

    return os.environ.get("PHUZZ_SCORE_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}


def calculate_hook_coverage_energy(request_data, state=None, config=None, update_state=False):
    """
    Bridge helper added on top of the original PHUZZ scoring module.

    This function is not part of the old path-based PHUZZ scoring flow.
    It exists so code outside `hook_energy/` can ask for a request-level
    hook energy score without knowing the collector/calculator internals.

    Parameters
    ----------
    request_data:
        One request artifact containing `hook_coverage`.
    state:
        Optional persistent hook-energy state shared across requests.
    config:
        Kept only for backward compatibility with older call sites.
        The current Fuzz_WP-style implementation does not use it.
    update_state:
        When True, finalize this request into the shared state.
        When False, compute energy in a read-only way.

    Why copy the state in read-only mode
    ------------------------------------
    `HookCollector.collect_request(...)` merges registered callbacks into
    the collector state as part of normalization. To preserve the old
    PHUZZ expectation that `update_state=False` must not mutate caller
    state, we calculate against a deep copy in that branch.
    """
    import copy

    del config
    from hook_energy import HookCollector, HookEnergyCalculator, HookEnergyDemoState

    if state is None:
        effective_state = HookEnergyDemoState()
    elif update_state:
        effective_state = state
    else:
        effective_state = copy.deepcopy(state)
    collector = HookCollector(state=effective_state)
    calculator = HookEnergyCalculator()
    observation = collector.collect_request(request_data)
    report = calculator.calculate_request_energy(observation, collector)

    if update_state:
        collector.finalize_request(report)
    return report


# Agent note:
# Read `SCORING_MODES_MINI.md` before changing this file again.
# This module now keeps both the original PHUZZ logic and the additive
# hook-energy layer side by side so future edits can be compared locally.
#
# Change only `ACTIVE_SCORING_MODE` when you want to switch runtime behavior:
#   1 = original PHUZZ scoring
#   2 = PHUZZ scoring plus hook-energy bonus
# Keep the commented old PHUZZ block below for direct line-by-line comparison.
# If you change the mode wiring or bonus rules, update the mini doc and tests
# in `tests/test_scoring_modes.py` in the same patch.
# Use explicit constants here so mode changes stay visible inside this file.
SCORING_MODE_PHUZZ = 1
SCORING_MODE_PHUZZ_HOOK = 2
ACTIVE_SCORING_MODE = _env_int("PHUZZ_SCORING_MODE", SCORING_MODE_PHUZZ_HOOK)

DEFAULT_HOOK_REQUESTS_DIR = _env_str("FUZZER_HOOK_REQUESTS_DIR", "/shared-tmpfs/hook-coverage/requests")
DEFAULT_HOOK_PRIORITY_WEIGHT = _env_float("FUZZER_HOOK_PRIORITY_WEIGHT", 1.0)
DEFAULT_HOOK_ENERGY_WEIGHT = _env_float("FUZZER_HOOK_ENERGY_WEIGHT", 1.0)


# Original PHUZZ scoring kept here for side-by-side comparison.
# class DefaultScoringFormula(ScoringFormula):
#     def calculate_score(self, candidate):
#         hit_counter=0
#         for path in candidate.new_paths:
#             filename, lines = path.split('::::')
#             hit_counter += lines.count("_")
#
#         return hit_counter + len(candidate.paths)
#
#     def calculate_priority(self, candidate):
#         return self.calculate_score(candidate)
#
#     def calculate_energy(self, candidate):
#         if candidate.parent is not None:
#             energy = max(1, candidate.parent.number_of_new_paths + abs(candidate.parent.score - candidate.score))
#         else:
#             energy = max(1, len(candidate.new_paths))
#         return energy


class PhuzzScoringFormula(ScoringFormula):
    def calculate_score(self, candidate):
        hit_counter=0
        debug_enabled = _score_debug_enabled()
        for path in candidate.new_paths:
            filename, lines = path.split('::::')  #phuzz-main/code/fuzzer/utils.py:50  -  stringify_hit_or_line
            underscore_count = lines.count("_")
            hit_counter += underscore_count
            if debug_enabled:
                line_segments = len(lines.split("_")) if lines else 0
                print(
                    f"[score-debug] new_path file={filename} raw={lines} "
                    f"segments={line_segments} underscores={underscore_count}"
                )

        score = hit_counter + len(candidate.paths)
        if debug_enabled:
            print(
                f"[score-debug] total hit_counter={hit_counter} total_paths={len(candidate.paths)} "
                f"score={score}"
            )
        candidate.base_score = score
        candidate.score = score
        return score

    def calculate_priority(self, candidate):
        priority = self.calculate_score(candidate)
        candidate.base_priority = priority
        candidate.priority = priority
        return priority

    def calculate_energy(self, candidate):
        current_score = getattr(candidate, "score", None)
        if current_score is None or (current_score == 0 and (candidate.paths or candidate.new_paths)):
            current_score = self.calculate_score(candidate)

        if candidate.parent is not None:
            energy = max(1, candidate.parent.number_of_new_paths + abs(candidate.parent.score - current_score))
        else:
            energy = max(1, len(candidate.new_paths))
        # Plain PHUZZ mode has no hook bonus, so base/final stay identical here.
        candidate.base_energy = int(energy)
        candidate.final_energy = int(energy)
        return energy 


class PhuzzHookScoringFormula(PhuzzScoringFormula):
    def __init__(self, requests_dir=None, priority_weight=None, energy_weight=None):
        from hook_energy.integration import HookEnergyTracker

        self.requests_dir = requests_dir or DEFAULT_HOOK_REQUESTS_DIR
        self.priority_weight = float(
            priority_weight if priority_weight is not None else DEFAULT_HOOK_PRIORITY_WEIGHT
        )
        self.energy_weight = float(
            energy_weight if energy_weight is not None else DEFAULT_HOOK_ENERGY_WEIGHT
        )
        self.tracker = HookEnergyTracker(self.requests_dir)

    def _apply_hook_report(self, candidate):
        report = self.tracker.consume_candidate(getattr(candidate, "coverage_id", ""))
        if report is None:
            candidate.hook_request_id = ""
            candidate.hook_energy = 0.0
            candidate.hook_energy_avg = 0.0
            return None

        candidate.hook_request_id = report.request_id
        # These two numbers come from the hook-energy request report:
        # - `hook_energy`: strongest rare-callback signal in this request
        # - `hook_energy_avg`: average rarity across all callbacks in this request
        candidate.hook_energy = float(report.hook_energy)
        candidate.hook_energy_avg = float(report.hook_energy_avg)
        return report

    def calculate_priority(self, candidate):
        from hook_energy.integration import apply_hook_priority_bonus

        base_priority = super().calculate_priority(candidate)
        self._apply_hook_report(candidate)
        final_priority = apply_hook_priority_bonus(
            base_priority,
            candidate.hook_energy,
            self.priority_weight,
        )
        candidate.base_priority = base_priority
        candidate.priority = final_priority
        return final_priority

    def calculate_energy(self, candidate):
        from hook_energy.integration import apply_hook_energy_bonus

        base_energy = super().calculate_energy(candidate)
        self._apply_hook_report(candidate)
        final_energy = apply_hook_energy_bonus(
            base_energy,
            candidate.hook_energy,
            self.energy_weight,
        )
        # Keep both numbers for debug output:
        # - `base_energy` shows original PHUZZ queue energy
        # - `final_energy` shows PHUZZ energy after hook bonus is rounded up and added
        candidate.base_energy = int(base_energy)
        candidate.final_energy = int(final_energy)
        return final_energy


class DefaultScoringFormula(ScoringFormula):
    def __init__(self, mode=None, requests_dir=None, priority_weight=None, energy_weight=None):
        # Keep selector logic narrow here so the old/new scoring split stays easy
        # to audit from this file alone.
        self.mode = ACTIVE_SCORING_MODE if mode is None else int(mode)
        if self.mode == SCORING_MODE_PHUZZ:
            self._formula = PhuzzScoringFormula()
        elif self.mode == SCORING_MODE_PHUZZ_HOOK:
            self._formula = PhuzzHookScoringFormula(
                requests_dir=requests_dir,
                priority_weight=priority_weight,
                energy_weight=energy_weight,
            )
        else:
            raise ValueError(
                f"Unknown scoring mode '{self.mode}'. Expected {SCORING_MODE_PHUZZ} (PHUZZ) "
                f"or {SCORING_MODE_PHUZZ_HOOK} (PHUZZ+hook)."
            )

    def calculate_score(self, candidate):
        return self._formula.calculate_score(candidate)

    def calculate_priority(self, candidate):
        return self._formula.calculate_priority(candidate)

    def calculate_energy(self, candidate):
        return self._formula.calculate_energy(candidate)
