"""Hook-aware coverage and scheduling guidance."""

from .coverage.collector import HookCollector
from .coverage.models import (
    CallbackDescriptor,
    EnergyResult,
    RequestCallbackExecution,
    RequestEnergyReport,
    RequestObservation,
)
from .coverage.reporter import HookEnergyReporter
from .coverage.state import GlobalCoverageState, HookEnergyDemoState
from .energy.calculator import EnergyCalculator, HookEnergyCalculator

__all__ = [
    "CallbackDescriptor",
    "EnergyCalculator",
    "EnergyResult",
    "GlobalCoverageState",
    "HookCollector",
    "HookEnergyCalculator",
    "HookEnergyDemoState",
    "HookEnergyReporter",
    "RequestCallbackExecution",
    "RequestEnergyReport",
    "RequestObservation",
]
