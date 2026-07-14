from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..entrypoints import direct_http_details, seed_template_for_callback
from .input_extractor import InputSignatureExtractor
from .source_resolver import SourcePathResolver


class LiveHookSeedGenerator:
    def __init__(
        self,
        input_extractor: InputSignatureExtractor | None = None,
        *,
        container_source_root: str | Path | None = None,
        host_source_root: str | Path | None = None,
        source_root: str | Path | None = None,
        unresolved_source_reason: str | None = None,
        include_observed_entrypoints: bool = False,
    ) -> None:
        resolver = SourcePathResolver(
            container_source_root=container_source_root,
            host_source_root=host_source_root,
            source_root=source_root,
            unresolved_reason=unresolved_source_reason,
        )
        self.input_extractor = input_extractor or InputSignatureExtractor(source_resolver=resolver)
        self.include_observed_entrypoints = include_observed_entrypoints

    def build_reports(self, coverage_payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        callback_rows = self._build_callback_rows(coverage_payload)
        suggested_rows = [
            item for item in callback_rows
            if item["is_active"] and (item["status"] == "uncovered" or item["validation_export"])
        ]

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
                "source_file": item["source_file"],
                "source_line": item["source_line"],
                "start_line": item["start_line"],
                "end_line": item["end_line"],
                "source_resolution": item["source_resolution"],
                "seed_priority": item["seed_priority"],
                "generation_status": item["generation_status"],
                "callback_repr": item["callback_raw"],
                "callback_source_file": item["source_file"],
                "callback_start_line": item["start_line"] or item["source_line"],
                "auth_mode": item.get("auth_mode"),
                "generated_reason": item["generation_status"],
                "fuzzing_ready": item["fuzzing_ready"],
                "setup_required": item["setup_required"],
                "manual_analysis": item["manual_analysis"],
                "missing_requirements": item["missing_requirements"],
            }
            if item.get('entrypoint_type'):
                compact_item['entrypoint_type'] = item['entrypoint_type']
            if item["seed"] is not None:
                compact_item["seed"] = item["seed"]
            for key in ("namespace", "route", "methods", "permission_callback"):
                if item.get(key) is not None:
                    compact_item[key] = item[key]
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
            extraction = self.input_extractor.extract(registered_entry)
            input_params = extraction.get("input_params", [])
            source_resolution = extraction.get(
                "source_resolution",
                {
                    "source_file": str(registered_entry.get("source_file") or ""),
                    "status": "unresolved",
                    "resolved_source_file": None,
                },
            )
            entrypoint_type = self._entrypoint_type_for_callback(hook_name, registered_entry)
            seed, generation_status = self._generate_seed_template(
                hook_name,
                is_active,
                status,
                input_params,
                registered_entry,
                self.include_observed_entrypoints,
            )
            if seed is not None:
                entrypoint_type = str(seed.get('entrypoint_type') or entrypoint_type)
            auth_mode = str(seed.get('auth_mode')) if isinstance(seed, dict) else None
            fuzzing_ready = bool(seed and seed.get('fuzzable_params'))
            missing_requirements = self._missing_requirements(entrypoint_type, seed, source_resolution)
            manual_analysis = generation_status == "manual_analysis_required"
            setup_required = self._setup_required(entrypoint_type, manual_analysis)

            row = {
                "callback_id": str(callback_id),
                "hook_name": hook_name,
                "callback_name": self._resolve_callback_name(str(callback_id), registered_entry),
                "callback_raw": str(registered_entry.get("callback_repr") or callback_id),
                "callback_type": str(registered_entry.get("type", registered_entry.get("callback_type", "unknown"))),
                "function_name": registered_entry.get("function_name"),
                "class_name": registered_entry.get("class_name"),
                "method_name": registered_entry.get("method_name"),
                "is_static": bool(registered_entry.get("is_static", False)),
                "is_closure": bool(registered_entry.get("is_closure", False)),
                "is_invokable": bool(registered_entry.get("is_invokable", False)),
                "formal_parameters": registered_entry.get("formal_parameters", []),
                "priority": self._safe_int(registered_entry.get("priority"), default=10),
                "accepted_args": self._safe_int(registered_entry.get("accepted_args"), default=1),
                "source_file": registered_entry.get("source_file"),
                "source_line": self._safe_int(registered_entry.get("source_line")),
                "start_line": self._safe_int(registered_entry.get("start_line")),
                "end_line": self._safe_int(registered_entry.get("end_line")),
                "source_resolution": source_resolution,
                "input_params": input_params,
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
                "entrypoint_type": entrypoint_type,
                "auth_mode": auth_mode,
                "generated_reason": generation_status,
                "fuzzing_ready": fuzzing_ready,
                "setup_required": setup_required,
                "manual_analysis": manual_analysis,
                "missing_requirements": missing_requirements,
                "seed": seed,
                "validation_export": self.include_observed_entrypoints and status == "covered" and seed is not None,
            }
            if entrypoint_type == "rest_route":
                row["entrypoint_type"] = "rest_route"
                row["namespace"] = registered_entry.get("namespace")
                row["route"] = registered_entry.get("route")
                row["methods"] = registered_entry.get("methods")
                row["permission_callback"] = registered_entry.get("permission_callback")
            rows.append(row)

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

    def _entrypoint_type_for_callback(self, hook_name: str, metadata: dict[str, Any]) -> str:
        direct = direct_http_details(hook_name, metadata)
        if direct is not None:
            return str(direct['entry_type'])
        raw_type = str(metadata.get('entrypoint_type') or '').strip()
        if raw_type:
            return raw_type
        if hook_name == 'xmlrpc_methods' and any(key in metadata for key in ('method_map', 'xmlrpc_method', 'methods')):
            return 'xmlrpc_method_map'
        if 'shortcode' in hook_name.lower() or any(key in metadata for key in ('shortcode', 'shortcode_tag')):
            return 'shortcode'
        return 'hook'

    def _missing_requirements(
        self,
        entrypoint_type: str,
        seed: dict[str, Any] | None,
        source_resolution: dict[str, Any],
    ) -> list[str]:
        if seed is not None:
            return [] if seed.get('fuzzable_params') else ['fuzzable_params']
        if entrypoint_type == 'xmlrpc_method_map':
            return ['xmlrpc_method_name', 'xmlrpc_body_template']
        if entrypoint_type == 'shortcode':
            return ['content_setup']
        if source_resolution.get('status') == 'unresolved':
            return ['callback_source_file']
        return ['direct_http_mapping']

    def _setup_required(self, entrypoint_type: str, manual_analysis: bool) -> bool:
        return manual_analysis and entrypoint_type in {"xmlrpc_method_map", "shortcode"}

    def _generate_seed_template(
        self,
        hook_name: str,
        is_active: bool,
        coverage_status: str,
        input_params: list[dict[str, Any]] | None = None,
        callback_metadata: dict[str, Any] | None = None,
        include_observed_entrypoints: bool = False,
    ) -> tuple[dict[str, Any] | None, str]:
        if not is_active:
            return None, "inactive_callback"
        if coverage_status != "uncovered" and not include_observed_entrypoints:
            return None, "already_covered"
        is_rest_route = str((callback_metadata or {}).get("entrypoint_type", "")) == "rest_route"
        is_seeded_hook = hook_name.startswith(
            ('wp_ajax_nopriv_', 'wp_ajax_', 'admin_post_nopriv_', 'admin_post_', 'login_form_')
        )
        is_seeded_hook = is_seeded_hook or hook_name in {'heartbeat_received', 'heartbeat_nopriv_received'}
        if not is_rest_route and not is_seeded_hook:
            return None, "manual_analysis_required"
        seed = seed_template_for_callback(hook_name, callback_metadata)
        if seed is None:
            return None, "manual_analysis_required"
        return self._attach_fuzzable_params(seed, input_params), "supported_http_seed"

    def _attach_fuzzable_params(
        self,
        seed: dict[str, Any],
        input_params: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        seed["fixed_params"] = list(seed.get("fixed_params", ["action"]))
        seed["fuzzable_params"] = []
        seed["input_params"] = input_params or []
        seed["discovered_file_params"] = []
        nested_parents = {
            str(item.get("name", "")).split("[", 1)[0]
            for item in input_params or []
            if "[" in str(item.get("name", ""))
        }

        if "query_params" not in seed:
            seed["query_params"] = {}
        if "cookies" not in seed:
            seed["cookies"] = {}

        for item in input_params or []:
            name = str(item.get("name", "")).strip()
            source = str(item.get("source", "REQUEST")).upper()
            if not name or name == "action":
                continue

            if source == "FILES":
                seed["discovered_file_params"].append(item)
                continue

            is_fixed_input = item.get("fuzzable") is False or str(item.get("role", "")) == "security_nonce"
            if name in nested_parents and not is_fixed_input:
                continue

            request_method = str(seed.get("method", "")).upper()
            if source == "GET" or (source == "REQUEST" and request_method == "GET"):
                target = seed["query_params"]
            elif source == "COOKIE":
                target = seed["cookies"]
            else:
                target = seed["body"]

            if name not in target:
                target[name] = "fuzz" if is_fixed_input else "FUZZ"
            if is_fixed_input:
                if name not in seed["fixed_params"]:
                    seed["fixed_params"].append(name)
                continue
            if name not in seed["fuzzable_params"]:
                seed["fuzzable_params"].append(name)

        return seed

    def _classify_seed_priority(self, hook_name: str, is_active: bool) -> tuple[str, int, str]:
        if not is_active:
            return "inactive", 0, "inactive"
        if hook_name.startswith("wp_ajax_nopriv_"):
            return "highest", 400, "wp_ajax_nopriv"
        if hook_name.startswith("wp_ajax_"):
            return "high", 300, "wp_ajax"
        if hook_name.startswith("admin_post_nopriv_"):
            return "highest", 400, "admin_post_nopriv"
        if hook_name.startswith("admin_post_"):
            return "high", 300, "admin_post"
        if hook_name.startswith("rest_route:"):
            return "high", 300, "rest_route"
        if hook_name.startswith('login_form_'):
            return "medium", 220, "login_form"
        if hook_name in {'heartbeat_received', 'heartbeat_nopriv_received'}:
            return "medium", 220, "heartbeat"
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

    def _normalize_methods(self, value: Any) -> list[str]:
        raw_items: list[Any]
        if isinstance(value, list):
            raw_items = value
        else:
            raw_items = [value]

        methods: list[str] = []
        for item in raw_items:
            for part in str(item or "").replace("|", ",").split(","):
                method = part.strip().upper()
                if method and method not in methods:
                    methods.append(method)
        return methods
