from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class RunMetadata:
    label: str
    mode: str
    target_plugin: str = ""
    endpoint_family: str = ""
    timestamp: str = ""
    config_hints: dict = field(default_factory=dict)


@dataclass
class RunSummary:
    requests_total: int
    registered_callbacks_total: int
    executed_callbacks_total: int
    blindspots_total: int
    coverage_ratio: float
    exceptions_count: int
    vulnerability_counts: dict
    boosted_decisions_count: int
    avg_hook_energy: float
    max_hook_energy: float
    avg_priority_delta: float
    max_priority_delta: float
    avg_energy_delta: float
    max_energy_delta: float


@dataclass
class DecisionRecord:
    coverage_id: str
    hook_request_id: str
    mutated_param_name: str
    mutated_param_type: str
    base_score: float
    score: float
    base_priority: float
    priority: float
    base_energy: int
    final_energy: int
    hook_energy: float
    hook_energy_avg: float
    target: str = ""
    method: str = ""
    outcome_tags: list[str] = field(default_factory=list)


@dataclass
class CallbackRecord:
    callback_id: str
    hook_name: str
    callback_identity: str
    executed_count: int
    request_count: int
    rarity_score_current: float
    next_score_if_seen_again: float
    status: str


@dataclass
class RequestRecord:
    request_id: str
    endpoint: str
    request_method: str
    coverage_id: str = ""
    request_time_ms: float = 0.0
    executed_callbacks: list[dict] = field(default_factory=list)
    rarity_contribution_summary: list[str] = field(default_factory=list)


@dataclass
class ComparisonSummary:
    baseline_label: str
    hook_label: str
    metric_deltas: dict
    callbacks_only_in_hook: list[str]
    callbacks_only_in_baseline: list[str]
    outcome_deltas: dict
    interpretation_flags: list[str]


@dataclass
class HookVisualizationReport:
    metadata: RunMetadata
    summary: RunSummary
    decision_records: list[DecisionRecord]
    callback_records: list[CallbackRecord]
    request_records: list[RequestRecord]
    comparison: Optional[ComparisonSummary] = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
