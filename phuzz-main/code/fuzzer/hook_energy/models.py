from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class CallbackDescriptor:
    callback_id: str
    hook_name: str
    callback_identity: str
    priority: int
    callback_type: str
    is_active: bool = True
    status: str = "registered_only"
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    callback_runtime_id: Optional[str] = None
    stable_id: Optional[str] = None
    runtime_id: Optional[str] = None
    total_execution_count: int = 0
    total_request_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "callback_id": self.callback_id,
            "hook_name": self.hook_name,
            "callback_identity": self.callback_identity,
            "identity_label": f"{self.hook_name} :: {self.callback_identity} :: priority={self.priority}",
            "priority": self.priority,
            "callback_type": self.callback_type,
            "is_active": self.is_active,
            "status": self.status,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "callback_runtime_id": self.callback_runtime_id,
            "stable_id": self.stable_id,
            "runtime_id": self.runtime_id,
            "total_execution_count": self.total_execution_count,
            "total_request_count": self.total_request_count,
        }


@dataclass
class RequestCallbackExecution:
    callback_id: str
    hook_name: str
    callback_identity: str
    priority: int
    callback_type: str
    request_execution_count: int
    previous_execution_count: int = 0
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "callback_id": self.callback_id,
            "hook_name": self.hook_name,
            "callback_identity": self.callback_identity,
            "identity_label": f"{self.hook_name} :: {self.callback_identity} :: priority={self.priority}",
            "priority": self.priority,
            "callback_type": self.callback_type,
            "request_execution_count": self.request_execution_count,
            "previous_execution_count": self.previous_execution_count,
            "score": self.score,
        }


@dataclass
class RequestObservation:
    request_id: str
    scenario_name: str
    endpoint: str
    request_file: Optional[str] = None
    registered_callbacks: dict[str, CallbackDescriptor] = field(default_factory=dict)
    executed_callbacks: list[RequestCallbackExecution] = field(default_factory=list)


@dataclass
class RequestEnergyReport:
    request_id: str
    scenario_name: str
    endpoint: str
    request_file: Optional[str]
    executed_callbacks: list[RequestCallbackExecution] = field(default_factory=list)
    hook_energy: float = 0.0
    hook_energy_avg: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "scenario_name": self.scenario_name,
            "endpoint": self.endpoint,
            "request_file": self.request_file,
            "hook_energy": self.hook_energy,
            "hook_energy_avg": self.hook_energy_avg,
            "executed_callbacks": [item.to_dict() for item in self.executed_callbacks],
        }


EnergyResult = RequestEnergyReport
