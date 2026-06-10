from __future__ import annotations

from typing import Any


def validate_static_report(static_report: dict[str, Any], hook_report: dict[str, Any]) -> dict[str, Any]:
    static_by_hook = {
        str(item.get("hook_name")): item
        for item in static_report.get("endpoints", [])
        if isinstance(item, dict) and item.get("hook_name")
    }
    dynamic_by_hook: dict[str, dict[str, Any]] = {}
    for item in hook_report.get("callbacks", []):
        if isinstance(item, dict) and item.get("hook_name"):
            dynamic_by_hook[str(item["hook_name"])] = item

    endpoints: list[dict[str, Any]] = []
    summary = {"registered_runtime": 0, "executed_runtime": 0, "static_only": 0, "dynamic_only": 0}
    executed_dynamic_hooks: set[str] = set()
    for hook_name, item in dynamic_by_hook.items():
        if _is_executed(item):
            executed_dynamic_hooks.add(hook_name)

    for hook_name, item in sorted(static_by_hook.items()):
        row = dict(item)
        dynamic = dynamic_by_hook.get(hook_name)
        if dynamic is None:
            status = "static_only"
        elif hook_name in executed_dynamic_hooks:
            status = "executed_runtime"
        else:
            status = "registered_runtime"
        row["validation_status"] = status
        endpoints.append(row)
        summary[status] += 1

    for hook_name, item in sorted(dynamic_by_hook.items()):
        if hook_name in static_by_hook:
            if hook_name in executed_dynamic_hooks:
                summary["executed_runtime"] += 1
            continue
        row = dict(item)
        row["validation_status"] = "dynamic_only"
        endpoints.append(row)
        summary["dynamic_only"] += 1
        if hook_name in executed_dynamic_hooks:
            summary["executed_runtime"] += 1

    return {"summary": summary, "endpoints": endpoints}


def _is_executed(item: dict[str, Any]) -> bool:
    return str(item.get("status", "")).lower() in {"covered", "executed", "executed_runtime"} or int(
        item.get("execute_count") or item.get("executed_count") or 0
    ) > 0
