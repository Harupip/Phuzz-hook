class ScoringFormula():
    def calculate_score(self, candidate):
        pass
    def calculate_priority(self, candidate):
        pass
    def calculate_energy(self, candidate):
        pass


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


class DefaultScoringFormula(ScoringFormula):
    def calculate_score(self, candidate):
        hit_counter=0
        for path in candidate.new_paths:
            filename, lines = path.split('::::')
            hit_counter += lines.count("_")

        return hit_counter + len(candidate.paths)

    def calculate_priority(self, candidate):
        return self.calculate_score(candidate)

    def calculate_energy(self, candidate):
        if candidate.parent is not None:
            energy = max(1, candidate.parent.number_of_new_paths + abs(candidate.parent.score - candidate.score))
        else:
            energy = max(1, len(candidate.new_paths))
        return energy 
