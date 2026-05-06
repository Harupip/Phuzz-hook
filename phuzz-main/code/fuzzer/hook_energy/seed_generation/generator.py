from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class LiveHookSeedGenerator:
    def build_reports(self, coverage_payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        callback_rows = self._build_callback_rows(coverage_payload)
        suggested_rows = [item for item in callback_rows if item["status"] == "uncovered" and item["is_active"]]

        gap_report = {
            "schema_version": "hook-gap-report-v1",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "coverage_metadata": coverage_payload.get("metadata", {}),
            "summary": {
                "registered_callbacks": len(callback_rows),
                "uncovered_callbacks": len([item for item in callback_rows if item["status"] == "uncovered"]),
                "active_uncovered_callbacks": len(suggested_rows),
                "direct_http_seed_candidates": len([item for item in suggested_rows if item["direct_http_supported"]]),
            },
            "callbacks": callback_rows,
        }

        compact_suggestions: list[dict[str, Any]] = []
        for item in suggested_rows:
            compact_item = {
                "hook_name": item["hook_name"],
                "callback_id": item["callback_id"],
                "callback_name": item["callback_name"],
                "seed_priority": item["seed_priority"],
                "generation_status": item["generation_status"],
            }
            if item["seed"] is not None:
                compact_item["seed"] = item["seed"]
            compact_suggestions.append(compact_item)

        seed_report = {
            "schema_version": "hook-seed-suggestions-v1",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "summary": {
                "suggested_entries": len(compact_suggestions),
                "direct_http_seed_candidates": len([item for item in suggested_rows if item["direct_http_supported"]]),
                "manual_only_entries": len([item for item in suggested_rows if not item["direct_http_supported"]]),
            },
            "suggested_seeds": compact_suggestions,
        }

        return gap_report, seed_report

    def write_artifacts(self, coverage_payload: dict[str, Any], output_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
        gap_report, seed_report = self.build_reports(coverage_payload)
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        (output_path / "hook_gap_report.json").write_text(
            json.dumps(gap_report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        (output_path / "suggested_seeds.json").write_text(
            json.dumps(seed_report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        (output_path / "suggested_seeds.md").write_text(
            self._build_seed_markdown(seed_report),
            encoding="utf-8",
        )
        return gap_report, seed_report

    def _build_callback_rows(self, coverage_payload: dict[str, Any]) -> list[dict[str, Any]]:
        coverage_data = coverage_payload.get("data", {})
        registered_callbacks = coverage_data.get("registered_callbacks", {})
        executed_callbacks = coverage_data.get("executed_callbacks", {})

        if not isinstance(registered_callbacks, dict):
            raise ValueError("total_coverage payload must contain a registered_callbacks mapping")
        if not isinstance(executed_callbacks, dict):
            executed_callbacks = {}

        rows: list[dict[str, Any]] = []
        for callback_id, registered_entry in sorted(registered_callbacks.items()):
            if not isinstance(registered_entry, dict):
                continue

            hook_name = str(registered_entry.get("hook_name", "")).strip()
            execute_count = self._safe_int(executed_callbacks.get(callback_id, {}).get("executed_count"), default=0)
            is_active = bool(registered_entry.get("is_active", True))
            status = "covered" if execute_count > 0 else "uncovered"
            seed_priority, priority_rank, target_family = self._classify_seed_priority(hook_name, is_active)
            seed, generation_status = self._generate_seed_template(hook_name, is_active, status)

            rows.append(
                {
                    "callback_id": str(callback_id),
                    "hook_name": hook_name,
                    "callback_name": self._resolve_callback_name(str(callback_id), registered_entry),
                    "callback_raw": str(registered_entry.get("callback_repr") or callback_id),
                    "callback_type": str(registered_entry.get("type", registered_entry.get("callback_type", "unknown"))),
                    "priority": self._safe_int(registered_entry.get("priority"), default=10),
                    "accepted_args": self._safe_int(registered_entry.get("accepted_args"), default=1),
                    "source_file": registered_entry.get("source_file"),
                    "source_line": self._safe_int(registered_entry.get("source_line")),
                    "is_active": is_active,
                    "registration_status": str(registered_entry.get("status", "registered_only")),
                    "register_count": 1,
                    "execute_count": execute_count,
                    "status": status,
                    "seed_priority": seed_priority,
                    "priority_rank": priority_rank,
                    "target_family": target_family,
                    "direct_http_supported": seed is not None,
                    "generation_status": generation_status,
                    "seed": seed,
                }
            )

        rows.sort(
            key=lambda item: (
                0 if item["status"] == "uncovered" else 1,
                0 if item["is_active"] else 1,
                -item["priority_rank"],
                item["hook_name"],
                item["callback_name"],
                item["callback_id"],
            )
        )
        return rows

    def _resolve_callback_name(self, callback_id: str, payload: dict[str, Any]) -> str:
        for key in ("callback_repr", "stable_id", "runtime_id"):
            value = str(payload.get(key, "")).strip()
            if value:
                return value
        return callback_id

    def _generate_seed_template(self, hook_name: str, is_active: bool, coverage_status: str) -> tuple[dict[str, Any] | None, str]:
        if not is_active:
            return None, "inactive_callback"
        if coverage_status != "uncovered":
            return None, "already_covered"
        if hook_name.startswith("wp_ajax_nopriv_"):
            return {
                "method": "POST",
                "path": "/wp-admin/admin-ajax.php",
                "content_type": "application/x-www-form-urlencoded",
                "body": {"action": hook_name.removeprefix("wp_ajax_nopriv_")},
                "auth_mode": "unauth-capable",
            }, "supported_http_seed"
        if hook_name.startswith("wp_ajax_"):
            return {
                "method": "POST",
                "path": "/wp-admin/admin-ajax.php",
                "content_type": "application/x-www-form-urlencoded",
                "body": {"action": hook_name.removeprefix("wp_ajax_")},
                "auth_mode": "authenticated",
            }, "supported_http_seed"
        if hook_name.startswith("admin_post_nopriv_"):
            return {
                "method": "POST",
                "path": "/wp-admin/admin-post.php",
                "content_type": "application/x-www-form-urlencoded",
                "body": {"action": hook_name.removeprefix("admin_post_nopriv_")},
                "auth_mode": "unauth-capable",
            }, "supported_http_seed"
        if hook_name.startswith("admin_post_"):
            return {
                "method": "POST",
                "path": "/wp-admin/admin-post.php",
                "content_type": "application/x-www-form-urlencoded",
                "body": {"action": hook_name.removeprefix("admin_post_")},
                "auth_mode": "authenticated",
            }, "supported_http_seed"
        return None, "manual_analysis_required"

    def _classify_seed_priority(self, hook_name: str, is_active: bool) -> tuple[str, int, str]:
        if not is_active:
            return "inactive", 0, "inactive"
        if hook_name.startswith("wp_ajax_nopriv_"):
            return "highest", 400, "wp_ajax_nopriv"
        if hook_name.startswith("wp_ajax_"):
            return "highest", 390, "wp_ajax"
        if hook_name.startswith("admin_post_nopriv_"):
            return "highest", 380, "admin_post_nopriv"
        if hook_name.startswith("admin_post_"):
            return "highest", 370, "admin_post"
        lowered = hook_name.lower()
        if lowered in {"init", "plugins_loaded", "wp_loaded"}:
            return "low", 100, "lifecycle"
        if any(token in lowered for token in ("ajax", "request", "submit", "endpoint", "api")):
            return "medium", 200, "request_oriented"
        return "low", 120, "internal_or_manual"

    def _build_seed_markdown(self, seed_report: dict[str, Any]) -> str:
        lines = [
            "# Suggested Seeds",
            "",
        ]
        suggestions = seed_report.get("suggested_seeds", [])
        if not suggestions:
            lines.append("No uncovered active callbacks were found.")
        else:
            for item in suggestions:
                lines.append(f"## {item['hook_name']}")
                lines.append(f"- Callback: `{item['callback_name']}`")
                lines.append(f"- Priority: `{item['seed_priority']}`")
                lines.append(f"- Generation: `{item['generation_status']}`")
                seed = item.get("seed")
                if isinstance(seed, dict):
                    lines.append(f"- Method: `{seed['method']}`")
                    lines.append(f"- Path: `{seed['path']}`")
                    lines.append(f"- Auth: `{seed['auth_mode']}`")
                    lines.append(f"- Body: `{json.dumps(seed['body'], ensure_ascii=False)}`")
                lines.append("")
        return "\n".join(lines).strip() + "\n"

    def _safe_int(self, value: Any, default: int | None = None) -> int | None:
        if value in (None, ""):
            return default
        return int(value)
