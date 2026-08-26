from __future__ import annotations

import json
from pathlib import Path

from .models import RequestEnergyReport
from .state import HookEnergyDemoState


class HookEnergyReporter:
    def format_request_summary(self, report: RequestEnergyReport) -> str:
        lines = [
            f"Request: {report.scenario_name}",
            f"Request ID: {report.request_id}",
            f"Endpoint: {report.endpoint}",
        ]

        if not report.executed_callbacks:
            lines.append("Executed callbacks: none")
            lines.append("Final hook_energy = 0.000000")
            lines.append("Final hook_energy_avg = 0.000000")
            return "\n".join(lines)

        lines.append("Executed callbacks:")
        for item in report.executed_callbacks:
            lines.append(
                " - "
                f"{item.hook_name} :: {item.callback_identity} :: priority={item.priority} "
                f"=> N={item.previous_execution_count} "
                f"=> score={item.score:.6f} "
                f"=> request_hits={item.request_execution_count}"
            )

        lines.append(f"Final hook_energy = {report.hook_energy:.6f}")
        lines.append(f"Final hook_energy_avg = {report.hook_energy_avg:.6f}")
        return "\n".join(lines)

    def build_rankings(self, reports: list[RequestEnergyReport], state: HookEnergyDemoState) -> dict:
        top_requests = sorted(
            reports,
            key=lambda item: (-item.hook_energy, -item.hook_energy_avg, item.request_id),
        )[:10]

        callback_items = list(state.callbacks.values())
        rare_callbacks = sorted(
            [item for item in callback_items if item.total_execution_count > 0],
            key=lambda item: (item.total_execution_count, item.total_request_count, item.callback_id),
        )[:10]
        frequent_callbacks = sorted(
            callback_items,
            key=lambda item: (-item.total_execution_count, -item.total_request_count, item.callback_id),
        )[:10]
        never_executed_callbacks = sorted(
            [item for item in callback_items if item.total_execution_count == 0],
            key=lambda item: (item.hook_name, item.priority, item.callback_identity),
        )[:10]

        return {
            "top_requests_by_hook_energy": [
                {
                    "request_id": item.request_id,
                    "scenario_name": item.scenario_name,
                    "endpoint": item.endpoint,
                    "hook_energy": item.hook_energy,
                    "hook_energy_avg": item.hook_energy_avg,
                }
                for item in top_requests
            ],
            "top_rare_callbacks": [
                {
                    **item.to_dict(),
                    "current_score": 1.0 / float(item.total_execution_count),
                }
                for item in rare_callbacks
            ],
            "top_frequent_callbacks": [
                {
                    **item.to_dict(),
                    "next_score_if_seen_again": 1.0 / float(item.total_execution_count + 1),
                }
                for item in frequent_callbacks
            ],
            "callbacks_never_executed_yet": [item.to_dict() for item in never_executed_callbacks],
        }

    def format_rankings(self, rankings: dict) -> str:
        def _table_cell(value: object) -> str:
            return str(value).replace("\n", " ").strip()

        def _format_table(headers: list[str], rows: list[list[object]]) -> list[str]:
            normalized_rows = [[_table_cell(cell) for cell in row] for row in rows]
            widths = [len(header) for header in headers]

            for row in normalized_rows:
                for index, cell in enumerate(row):
                    widths[index] = max(widths[index], len(cell))

            def _border(char: str) -> str:
                return "+" + "+".join(char * (width + 2) for width in widths) + "+"

            def _render_row(cells: list[str]) -> str:
                padded_cells = [f" {cell.ljust(widths[index])} " for index, cell in enumerate(cells)]
                return "|" + "|".join(padded_cells) + "|"

            table_lines = [_border("-"), _render_row(headers), _border("=")]
            for row in normalized_rows:
                table_lines.append(_render_row(row))
                table_lines.append(_border("-"))
            return table_lines

        lines = ["== Hook Energy Rankings =="]

        lines.append("Top requests by hook_energy:")
        for item in rankings.get("top_requests_by_hook_energy", []):
            lines.append(
                " - "
                f"{item['scenario_name']} ({item['request_id']}) => hook_energy={item['hook_energy']:.6f} "
                f"| hook_energy_avg={item['hook_energy_avg']:.6f}"
            )

        lines.append("Top rare callbacks:")
        rare_rows = [
            [
                item["hook_name"],
                item["callback_identity"],
                item["priority"],
                item["total_execution_count"],
                f"{item['current_score']:.6f}",
            ]
            for item in rankings.get("top_rare_callbacks", [])
        ]
        lines.extend(
            _format_table(
                ["hook_name", "callback_identity", "priority", "total_execution_count", "current_score"],
                rare_rows,
            )
            if rare_rows
            else ["(none)"]
        )

        lines.append("Callbacks never executed yet:")
        never_rows = [
            [item["hook_name"], item["callback_identity"], item["priority"], item["status"]]
            for item in rankings.get("callbacks_never_executed_yet", [])
        ]
        lines.extend(
            _format_table(["hook_name", "callback_identity", "priority", "status"], never_rows)
            if never_rows
            else ["(none)"]
        )

        return "\n".join(lines)

    def write_summary(self, filepath: str, reports: list[RequestEnergyReport], state: HookEnergyDemoState) -> None:
        payload = {
            "schema_version": "hook-energy-demo-summary-v1",
            "requests_processed_in_run": [item.to_dict() for item in reports],
            "callback_registry": {callback_id: item.to_dict() for callback_id, item in sorted(state.callbacks.items())},
            "rankings": self.build_rankings(reports, state),
        }

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
