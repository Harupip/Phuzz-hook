from __future__ import annotations

from .collector import HookCollector
from .models import RequestCallbackExecution, RequestEnergyReport, RequestObservation


class HookEnergyCalculator:
    def score_callback(self, previous_execution_count: int) -> float:
        safe_count = max(0, int(previous_execution_count))
        return 1.0 / float(safe_count + 1)

    def calculate_request_energy(
        self,
        observation: RequestObservation,
        collector: HookCollector,
    ) -> RequestEnergyReport:
        scored_callbacks: list[RequestCallbackExecution] = []
        total_score = 0.0
        max_score = 0.0

        for item in observation.executed_callbacks:
            existing = collector.state.callbacks.get(item.callback_id)
            previous_execution_count = int(existing.total_execution_count) if existing is not None else 0
            score = self.score_callback(previous_execution_count)

            scored_callbacks.append(
                RequestCallbackExecution(
                    callback_id=item.callback_id,
                    hook_name=item.hook_name,
                    callback_identity=item.callback_identity,
                    priority=item.priority,
                    callback_type=item.callback_type,
                    request_execution_count=item.request_execution_count,
                    previous_execution_count=previous_execution_count,
                    score=score,
                )
            )
            total_score += score
            max_score = max(max_score, score)

        hook_energy_avg = total_score / len(scored_callbacks) if scored_callbacks else 0.0
        return RequestEnergyReport(
            request_id=observation.request_id,
            scenario_name=observation.scenario_name,
            endpoint=observation.endpoint,
            request_file=observation.request_file,
            executed_callbacks=scored_callbacks,
            hook_energy=max_score if scored_callbacks else 0.0,
            hook_energy_avg=hook_energy_avg,
        )


EnergyCalculator = HookEnergyCalculator
