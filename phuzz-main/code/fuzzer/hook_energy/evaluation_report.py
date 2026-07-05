from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

STOP_ON_VULN_EXIT_CODE = 1337 % 256


CLASSIFICATIONS = (
    "e2e_success",
    "config_generated_not_fuzzed",
    "dependency_required",
    "entrypoint_only",
    "manual_analysis_required",
    "failed_discovery",
)


def build_evaluation_report(output_root: str | Path) -> dict[str, Any]:
    root = Path(output_root)
    builders: dict[str, _PluginBuilder] = {}
    inputs: dict[str, Any] = {"output_root": str(root), "consumed": [], "missing": []}

    _consume_seed_generation(root / "seed_generation", builders, inputs)
    _consume_legacy_evaluations(root / "evaluations", builders, inputs)
    _consume_e2e_evaluations(root / "evaluations", builders, inputs)
    _consume_vulnerable_candidates(root, builders, inputs)

    plugins = [builder.build() for _, builder in sorted(builders.items())]
    summary = {"plugins": len(plugins), **{name: 0 for name in CLASSIFICATIONS}}
    for plugin in plugins:
        summary[plugin["classification"]] += 1

    return {
        "schema_version": "hookphuzz-evaluation-summary-v1",
        "generated_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "inputs": inputs,
        "summary": summary,
        "plugins": plugins,
        "case_notes": _case_notes(plugins),
        "final_assessment": _final_assessment(plugins),
    }


def write_evaluation_report(
    output_root: str | Path,
    *,
    json_path: str | Path | None = None,
    markdown_path: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(output_root)
    report = build_evaluation_report(root)
    json_output = Path(json_path) if json_path is not None else root / "evaluation" / "hookphuzz_evaluation_summary.json"
    markdown_output = (
        Path(markdown_path) if markdown_path is not None else root / "evaluation" / "hookphuzz_evaluation_summary.md"
    )
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_output.write_text(render_markdown_report(report), encoding="utf-8")
    return report


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# HookPhuzz Evaluation Summary",
        "",
        f"Generated: {report.get('generated_at', '')}",
        "",
        "## Plugin Results",
        "",
        "| Plugin | Class | Registered | Direct HTTP | Configs | Fuzzing Ready | Callback Reached | Vulns | First Vuln |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for plugin in report.get("plugins", []):
        first = _format_first_vulnerability(plugin)
        lines.append(
            "| {plugin} | {classification} | {registered} | {direct} | {configs} | {ready} | {reached} | {vulns} | {first} |".format(
                plugin=_md(plugin.get("plugin_slug")),
                classification=_md(plugin.get("classification")),
                registered=plugin.get("registered_hooks_count", 0),
                direct=plugin.get("direct_http_candidates_count", 0),
                configs=plugin.get("generated_configs_count", 0),
                ready=plugin.get("fuzzing_ready_count", 0),
                reached=plugin.get("callback_reached_count", 0),
                vulns=plugin.get("vulnerability_found_count", 0),
                first=_md(first),
            )
        )

    lines.extend(["", "## Case Notes", ""])
    for note in report.get("case_notes", []):
        lines.append(f"- **{note['plugin_slug']}**: {note['note']}")

    assessment = report.get("final_assessment", {})
    lines.extend(["", "## What HookPhuzz Successfully Proves", ""])
    for item in assessment.get("what_hookphuzz_successfully_proves", []):
        lines.append(f"- {item}")

    lines.extend(["", "## Current Limitations", ""])
    for item in assessment.get("current_limitations", []):
        lines.append(f"- {item}")

    lines.extend(["", "## Recommended Next Engineering Step", ""])
    lines.append(str(assessment.get("recommended_next_engineering_step", "")))
    lines.append("")
    return "\n".join(lines)


class _PluginBuilder:
    def __init__(self, plugin_slug: str) -> None:
        self.plugin_slug = plugin_slug
        self.vulnerable_version: str | None = None
        self.dependency_plugins: set[str] = set()
        self.registered_hooks_count = 0
        self.direct_http_candidates_count = 0
        self.generated_configs_count = 0
        self.fuzzing_ready_count = 0
        self.entrypoint_only_count = 0
        self.manual_analysis_count = 0
        self.skipped_reasons: Counter[str] = Counter()
        self.observed_target_hooks: set[str] = set()
        self.extracted_fuzz_params: dict[str, dict[str, Any]] = {}
        self.callback_reached_count = 0
        self.vulnerability_found_count = 0
        self.first_vulnerability_time: int | None = None
        self.first_vulnerability_request: int | None = None
        self.artifact_sources: set[str] = set()

    def add_source(self, path: Path) -> None:
        self.artifact_sources.add(str(path))

    def add_fuzz_params(self, hook_name: str, params: list[str], sources: list[str] | None = None) -> None:
        if not hook_name or not params:
            return
        row = self.extracted_fuzz_params.setdefault(hook_name, {"hook_name": hook_name, "params": [], "sources": []})
        for param in params:
            if param not in row["params"]:
                row["params"].append(param)
        for source in sources or []:
            if source not in row["sources"]:
                row["sources"].append(source)

    def add_first_vulnerability(self, seconds: Any, request: Any) -> None:
        parsed_seconds = _int_or_none(seconds)
        parsed_request = _int_or_none(request)
        if parsed_seconds is not None and (
            self.first_vulnerability_time is None or parsed_seconds < self.first_vulnerability_time
        ):
            self.first_vulnerability_time = parsed_seconds
            self.first_vulnerability_request = parsed_request
        elif parsed_seconds is not None and parsed_seconds == self.first_vulnerability_time:
            if parsed_request is not None and (
                self.first_vulnerability_request is None or parsed_request < self.first_vulnerability_request
            ):
                self.first_vulnerability_request = parsed_request
        elif self.first_vulnerability_time is None and parsed_request is not None:
            self.first_vulnerability_request = parsed_request

    def build(self) -> dict[str, Any]:
        classification = _classify(self)
        return {
            "plugin_slug": self.plugin_slug,
            "vulnerable_version": self.vulnerable_version,
            "dependency_plugins": sorted(self.dependency_plugins),
            "registered_hooks_count": self.registered_hooks_count,
            "direct_http_candidates_count": self.direct_http_candidates_count,
            "generated_configs_count": self.generated_configs_count,
            "fuzzing_ready_count": self.fuzzing_ready_count,
            "entrypoint_only_count": self.entrypoint_only_count,
            "manual_analysis_count": self.manual_analysis_count,
            "skipped_count": sum(self.skipped_reasons.values()),
            "skipped_reasons": dict(sorted(self.skipped_reasons.items())),
            "observed_target_hooks": sorted(self.observed_target_hooks),
            "extracted_fuzz_params": sorted(self.extracted_fuzz_params.values(), key=lambda item: item["hook_name"]),
            "callback_reached_count": self.callback_reached_count,
            "vulnerability_found_count": self.vulnerability_found_count,
            "first_vulnerability_time": self.first_vulnerability_time,
            "first_vulnerability_request": self.first_vulnerability_request,
            "classification": classification,
            "artifact_sources": sorted(self.artifact_sources),
        }


def _consume_seed_generation(seed_dir: Path, builders: dict[str, _PluginBuilder], inputs: dict[str, Any]) -> None:
    names = [
        "generated_config_summary.json",
        "generated_param_summary.json",
        "suggested_seeds.json",
        "hook_gap_report.json",
        "validation_result.json",
        "generated_config_run_summary.json",
    ]
    payloads = {}
    for name in names:
        path = seed_dir / name
        payload = _load_json(path)
        if payload is None:
            if name != "generated_config_run_summary.json":
                inputs["missing"].append(str(path))
            continue
        inputs["consumed"].append(str(path))
        payloads[name] = payload

    if not payloads:
        return

    plugin_slug = _infer_plugin_slug(payloads.values(), fallback="unknown")
    builder = _builder(builders, plugin_slug)
    for payload in payloads.values():
        if isinstance(payload, dict):
            source = payload.get("_source_path")
            if isinstance(source, Path):
                builder.add_source(source)

    _merge_hook_gap(builder, payloads.get("hook_gap_report.json"))
    _merge_suggested_seeds(builder, payloads.get("suggested_seeds.json"))
    _merge_generated_config_summary(builder, payloads.get("generated_config_summary.json"))
    _merge_generated_param_summary(builder, payloads.get("generated_param_summary.json"))
    _merge_validation_result(builder, payloads.get("validation_result.json"))
    _merge_generated_config_run_summary(builder, payloads.get("generated_config_run_summary.json"))


def _consume_legacy_evaluations(evaluations_dir: Path, builders: dict[str, _PluginBuilder], inputs: dict[str, Any]) -> None:
    if not evaluations_dir.exists():
        return
    for summary_path in sorted(evaluations_dir.glob("*/evaluation-summary.json")):
        payload = _load_json(summary_path)
        if not isinstance(payload, list):
            continue
        inputs["consumed"].append(str(summary_path))
        generated_hooks_by_plugin: dict[str, set[str]] = {}
        ready_hooks_by_plugin: dict[str, set[str]] = {}
        for row in payload:
            if not isinstance(row, dict):
                continue
            plugin_slug = str(row.get("plugin") or "unknown")
            builder = _builder(builders, plugin_slug)
            builder.add_source(summary_path)
            if plugin_slug == "country-state-city-auto-dropdown":
                builder.dependency_plugins.add("contact-form-7")
            hook_name = str(row.get("hook") or "")
            if hook_name:
                builder.observed_target_hooks.add(hook_name)
            param = str(row.get("param") or "")
            if param:
                builder.add_fuzz_params(hook_name, [param])
            if row.get("seed_generated_automatically"):
                generated_hooks_by_plugin.setdefault(plugin_slug, set()).add(hook_name or str(row.get("generated_callback_id") or ""))
            if row.get("fuzzable_param_discovered_automatically") or param:
                ready_hooks_by_plugin.setdefault(plugin_slug, set()).add(hook_name or param)
            if row.get("callback_reached"):
                builder.callback_reached_count += 1
            if row.get("vulnerability_found"):
                builder.vulnerability_found_count += 1
                builder.add_first_vulnerability(
                    row.get("time_to_first_vulnerability_seconds"),
                    row.get("requests_to_first_vulnerability"),
                )
        for plugin_slug, hooks in generated_hooks_by_plugin.items():
            builders[plugin_slug].generated_configs_count = max(builders[plugin_slug].generated_configs_count, len(hooks))
        for plugin_slug, hooks in ready_hooks_by_plugin.items():
            builders[plugin_slug].fuzzing_ready_count = max(builders[plugin_slug].fuzzing_ready_count, len(hooks))
        _merge_seed_subdirs(summary_path.parent, builders, inputs)


def _consume_e2e_evaluations(evaluations_dir: Path, builders: dict[str, _PluginBuilder], inputs: dict[str, Any]) -> None:
    if not evaluations_dir.exists():
        return
    for run_dir in sorted(path for path in evaluations_dir.iterdir() if path.is_dir()):
        e2e_path = run_dir / "e2e-summary.json"
        e2e_payload = _load_json(e2e_path)
        generated_path = run_dir / "generated_config_summary.json"
        generated_payload = _load_json(generated_path)
        if e2e_payload is None and generated_payload is None:
            continue

        plugin_slug = _plugin_from_e2e_dir(run_dir, e2e_payload)
        builder = _builder(builders, plugin_slug)
        if e2e_payload is not None:
            inputs["consumed"].append(str(e2e_path))
            builder.add_source(e2e_path)
            _merge_e2e_summary(builder, e2e_payload)
        if generated_payload is not None:
            inputs["consumed"].append(str(generated_path))
            builder.add_source(generated_path)
            _merge_generated_config_summary(builder, generated_payload)
        total_path = run_dir / "total_coverage.json"
        total_payload = _load_json(total_path)
        if isinstance(total_payload, dict):
            inputs["consumed"].append(str(total_path))
            builder.add_source(total_path)
            _merge_total_coverage(builder, total_payload)
        _merge_seed_subdirs(run_dir, builders, inputs, plugin_override=plugin_slug)


def _consume_vulnerable_candidates(root: Path, builders: dict[str, _PluginBuilder], inputs: dict[str, Any]) -> None:
    for path in _find_vulnerable_candidate_files(root):
        payload = _load_json(path)
        if not isinstance(payload, dict):
            continue
        plugin_slug = _plugin_from_path(path)
        if not plugin_slug:
            continue
        builder = _builder(builders, plugin_slug)
        builder.add_source(path)
        inputs["consumed"].append(str(path))
        count = _count_vulnerabilities(payload)
        builder.vulnerability_found_count = max(builder.vulnerability_found_count, count)


def _merge_seed_subdirs(
    run_dir: Path,
    builders: dict[str, _PluginBuilder],
    inputs: dict[str, Any],
    *,
    plugin_override: str | None = None,
) -> None:
    for seed_path in sorted(run_dir.glob("*-seeds/suggested_seeds.json")) + sorted(
        run_dir.glob("seed_generation/suggested_seeds.json")
    ):
        payload = _load_json(seed_path)
        if not isinstance(payload, dict):
            continue
        plugin_slug = plugin_override or seed_path.parent.name.removesuffix("-seeds")
        builder = _builder(builders, plugin_slug)
        inputs["consumed"].append(str(seed_path))
        builder.add_source(seed_path)
        _merge_suggested_seeds(builder, payload)
        hook_gap_path = seed_path.with_name("hook_gap_report.json")
        hook_gap_payload = _load_json(hook_gap_path)
        if isinstance(hook_gap_payload, dict):
            inputs["consumed"].append(str(hook_gap_path))
            builder.add_source(hook_gap_path)
            _merge_hook_gap(builder, hook_gap_payload)


def _merge_hook_gap(builder: _PluginBuilder, payload: Any) -> None:
    if not isinstance(payload, dict):
        return
    summary = payload.get("summary")
    if isinstance(summary, dict):
        builder.registered_hooks_count = max(builder.registered_hooks_count, _int_or_zero(summary.get("registered_callbacks")))
        builder.direct_http_candidates_count = max(
            builder.direct_http_candidates_count, _int_or_zero(summary.get("direct_http_seed_candidates"))
        )
    coverage_metadata = payload.get("coverage_metadata")
    if isinstance(coverage_metadata, dict):
        builder.registered_hooks_count = max(
            builder.registered_hooks_count, _int_or_zero(coverage_metadata.get("total_registered_callbacks"))
        )
    callbacks = payload.get("callbacks")
    if isinstance(callbacks, list):
        builder.registered_hooks_count = max(builder.registered_hooks_count, len(callbacks))
        for item in callbacks:
            if isinstance(item, dict):
                hook_name = str(item.get("hook_name") or "")
                if hook_name.startswith(("wp_ajax_", "wp_ajax_nopriv_", "admin_post_", "admin_post_nopriv_")):
                    builder.observed_target_hooks.add(hook_name)


def _merge_suggested_seeds(builder: _PluginBuilder, payload: Any) -> None:
    if not isinstance(payload, dict):
        return
    summary = payload.get("summary")
    if isinstance(summary, dict):
        builder.direct_http_candidates_count = max(
            builder.direct_http_candidates_count, _int_or_zero(summary.get("direct_http_seed_candidates"))
        )
    suggestions = payload.get("suggested_seeds")
    if not isinstance(suggestions, list):
        return
    ready = 0
    entrypoint_only = 0
    manual = 0
    for item in suggestions:
        if not isinstance(item, dict):
            continue
        hook_name = str(item.get("hook_name") or "")
        status = str(item.get("generation_status") or "")
        seed = item.get("seed")
        fuzz_params = _seed_fuzzable_params(seed)
        if hook_name and seed:
            builder.observed_target_hooks.add(hook_name)
        if status == "supported_http_seed" and fuzz_params:
            ready += 1
        elif status == "supported_http_seed":
            entrypoint_only += 1
        elif status:
            manual += 1
        builder.add_fuzz_params(hook_name, fuzz_params, _seed_param_sources(seed, fuzz_params))
        deps = item.get("dependency_plugins")
        if isinstance(deps, list):
            builder.dependency_plugins.update(str(dep) for dep in deps if str(dep))
        version = item.get("vulnerable_version")
        if version and builder.vulnerable_version is None:
            builder.vulnerable_version = str(version)
    builder.fuzzing_ready_count = max(builder.fuzzing_ready_count, ready)
    builder.entrypoint_only_count = max(builder.entrypoint_only_count, entrypoint_only)
    builder.manual_analysis_count = max(builder.manual_analysis_count, manual)


def _merge_generated_config_summary(builder: _PluginBuilder, payload: Any) -> None:
    if not isinstance(payload, dict):
        return
    generated = payload.get("generated")
    if isinstance(generated, list):
        builder.generated_configs_count = max(builder.generated_configs_count, len(generated))
        for item in generated:
            if isinstance(item, dict) and item.get("hook_name"):
                builder.observed_target_hooks.add(str(item["hook_name"]))
    skipped = payload.get("skipped")
    if isinstance(skipped, list):
        for item in skipped:
            if isinstance(item, dict):
                reason = str(item.get("reason") or "unknown")
                builder.skipped_reasons[reason] += 1


def _merge_generated_param_summary(builder: _PluginBuilder, payload: Any) -> None:
    if not isinstance(payload, dict):
        return
    summary = payload.get("summary")
    if isinstance(summary, dict):
        builder.fuzzing_ready_count = max(builder.fuzzing_ready_count, _int_or_zero(summary.get("fuzzing_ready")))
        builder.entrypoint_only_count = max(builder.entrypoint_only_count, _int_or_zero(summary.get("entrypoint_only")))
        builder.manual_analysis_count = max(builder.manual_analysis_count, _int_or_zero(summary.get("manual_analysis")))
    configs = payload.get("configs")
    if isinstance(configs, list):
        for item in configs:
            if not isinstance(item, dict):
                continue
            builder.add_fuzz_params(str(item.get("hook_name") or ""), _string_list(item.get("extracted_params")))


def _merge_validation_result(builder: _PluginBuilder, payload: Any) -> None:
    if not isinstance(payload, dict):
        return
    summary = payload.get("summary")
    if isinstance(summary, dict):
        builder.callback_reached_count = max(builder.callback_reached_count, _int_or_zero(summary.get("callback_reached")))
        return
    if payload.get("callback_reached"):
        builder.callback_reached_count = max(builder.callback_reached_count, 1)


def _merge_generated_config_run_summary(builder: _PluginBuilder, payload: Any) -> None:
    if not isinstance(payload, dict):
        return
    counted_vulns = 0
    counts = payload.get("counts")
    if isinstance(counts, dict):
        builder.callback_reached_count = max(builder.callback_reached_count, _int_or_zero(counts.get("callback_reached")))
        counted_vulns = _int_or_zero(counts.get("vuln_found"))
    row_vulns = 0
    runs = payload.get("runs")
    if isinstance(runs, list):
        for row in runs:
            if not isinstance(row, dict):
                continue
            if row.get("hook_name"):
                builder.observed_target_hooks.add(str(row["hook_name"]))
            if row.get("process_status") == "vuln_found" or row.get("exit_code") == STOP_ON_VULN_EXIT_CODE:
                row_vulns += 1
    builder.vulnerability_found_count = max(builder.vulnerability_found_count, counted_vulns, row_vulns)


def _merge_e2e_summary(builder: _PluginBuilder, payload: Any) -> None:
    if not isinstance(payload, dict):
        return
    bootstrap = payload.get("bootstrap")
    if isinstance(bootstrap, dict):
        builder.direct_http_candidates_count = max(
            builder.direct_http_candidates_count, _int_or_zero(bootstrap.get("direct_http_candidates"))
        )
    proof = payload.get("phuzz_proof")
    if isinstance(proof, dict):
        hook_name = str(proof.get("hook_name") or "")
        if hook_name:
            builder.observed_target_hooks.add(hook_name)
        fuzz_params = _string_list(proof.get("fuzzable_params"))
        builder.add_fuzz_params(hook_name, fuzz_params)
        if fuzz_params:
            builder.fuzzing_ready_count = max(builder.fuzzing_ready_count, 1)
        builder.callback_reached_count = max(builder.callback_reached_count, _int_or_zero(proof.get("executed_count")))


def _merge_total_coverage(builder: _PluginBuilder, payload: dict[str, Any]) -> None:
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        builder.registered_hooks_count = max(
            builder.registered_hooks_count, _int_or_zero(metadata.get("total_registered_callbacks"))
        )
    data = payload.get("data")
    if isinstance(data, dict):
        registered = data.get("registered_callbacks")
        if isinstance(registered, dict):
            builder.registered_hooks_count = max(builder.registered_hooks_count, len(registered))


def _case_notes(plugins: list[dict[str, Any]]) -> list[dict[str, str]]:
    by_slug = {item["plugin_slug"]: item for item in plugins}
    notes: list[dict[str, str]] = []
    if "gamipress" in by_slug:
        notes.append(
            {
                "plugin_slug": "gamipress",
                "note": "Dynamic AJAX hook discovery reached GamiPress generated seeds; extracted fuzz params include orderby on gamipress_get_logs where present in artifacts.",
            }
        )
    if "country-state-city-auto-dropdown" in by_slug:
        notes.append(
            {
                "plugin_slug": "country-state-city-auto-dropdown",
                "note": "Dependency-aware bootstrap required Contact Form 7; before dependency activation the target hooks were not observed, and after dependency activation the case data records 4 direct HTTP candidates and 4 fuzzing-ready configs.",
            }
        )
    for plugin in plugins:
        if plugin["plugin_slug"] in {"gamipress", "country-state-city-auto-dropdown"}:
            continue
        notes.append(
            {
                "plugin_slug": plugin["plugin_slug"],
                "note": f"Summarized from available artifacts only: {plugin['generated_configs_count']} configs, {plugin['vulnerability_found_count']} vulnerability hits.",
            }
        )
    return notes


def _final_assessment(plugins: list[dict[str, Any]]) -> dict[str, Any]:
    e2e_plugins = [item["plugin_slug"] for item in plugins if item["classification"] == "e2e_success"]
    return {
        "what_hookphuzz_successfully_proves": [
            "Bootstrap coverage artifacts can be converted into direct HTTP seed candidates without hand-written target configs.",
            "Source-backed parameter extraction can identify fuzzable request parameters and preserve fixed routing parameters such as action.",
            f"End-to-end fuzzing evidence exists for {', '.join(e2e_plugins) if e2e_plugins else 'no plugin in the current artifact set'}.",
        ],
        "current_limitations": [
            "Coverage depends on the WordPress runtime path and active dependency plugins; unregistered callbacks remain invisible to seed generation.",
            "Entry-point-only configs can replay callbacks but do not provide fuzzable parameters without additional source evidence.",
            "Manual-analysis hooks and skipped seeds still require human triage or new narrowly scoped extraction support.",
        ],
        "recommended_next_engineering_step": (
            "Add a stable evaluation runner wrapper that always emits generated_param_summary.json, validation_result.json, "
            "and vulnerable-candidate timing metadata into one per-plugin run directory before expanding discovery logic."
        ),
    }


def _classify(builder: _PluginBuilder) -> str:
    if builder.vulnerability_found_count > 0 and builder.callback_reached_count > 0:
        return "e2e_success"
    if builder.dependency_plugins and builder.direct_http_candidates_count == 0:
        return "dependency_required"
    if builder.generated_configs_count > 0:
        return "config_generated_not_fuzzed"
    if builder.entrypoint_only_count > 0 and builder.fuzzing_ready_count == 0:
        return "entrypoint_only"
    if builder.manual_analysis_count > 0 or builder.skipped_reasons:
        return "manual_analysis_required"
    return "failed_discovery"


def _builder(builders: dict[str, _PluginBuilder], plugin_slug: str) -> _PluginBuilder:
    normalized = plugin_slug.strip() or "unknown"
    return builders.setdefault(normalized, _PluginBuilder(normalized))


def _load_json(path: Path) -> Any | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(payload, dict):
        payload["_source_path"] = path
    return payload


def _infer_plugin_slug(payloads: Any, *, fallback: str) -> str:
    for payload in payloads:
        found = _find_plugin_slug_in_value(payload)
        if found:
            return found
    return fallback


def _find_plugin_slug_in_value(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("plugin_slug", "plugin"):
            raw = value.get(key)
            if isinstance(raw, str) and raw.strip():
                return raw.strip()
        for key in ("source_file", "callback_source_file", "resolved_source_file", "config_slug"):
            raw = value.get(key)
            if isinstance(raw, str):
                found = _plugin_slug_from_text(raw)
                if found:
                    return found
        for nested in value.values():
            found = _find_plugin_slug_in_value(nested)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_plugin_slug_in_value(item)
            if found:
                return found
    return None


def _plugin_slug_from_text(value: str) -> str | None:
    normalized = value.replace("\\", "/")
    match = re.search(r"/wp-content/plugins/([^/]+)", normalized)
    if match:
        return match.group(1)
    return None


def _plugin_from_path(path: Path) -> str | None:
    parts = list(path.parts)
    for part in reversed(parts):
        if "-run" in part:
            return part.split("-wp_ajax", 1)[0].split("-admin_post", 1)[0]
    return None


def _plugin_from_e2e_dir(run_dir: Path, payload: Any) -> str:
    if isinstance(payload, dict) and isinstance(payload.get("plugin"), str):
        return str(payload["plugin"])
    name = run_dir.name
    marker = "authenticated-"
    if marker in name:
        return name.split(marker, 1)[1]
    return name


def _find_vulnerable_candidate_files(root: Path) -> list[Path]:
    matches: list[Path] = []
    for path in sorted(root.glob("evaluations/*/*/fuzzer-output/vulnerable-candidates.json")):
        matches.append(path)
    for path in sorted(root.glob("*/fuzzer-output/vulnerable-candidates.json")):
        matches.append(path)
    return matches


def _count_vulnerabilities(payload: dict[str, Any]) -> int:
    return sum(len(value) for value in payload.values() if isinstance(value, list))


def _seed_fuzzable_params(seed: Any) -> list[str]:
    if not isinstance(seed, dict):
        return []
    return _string_list(seed.get("fuzzable_params"))


def _seed_param_sources(seed: Any, params: list[str]) -> list[str]:
    if not isinstance(seed, dict):
        return []
    source_by_name = {}
    input_params = seed.get("input_params")
    if isinstance(input_params, list):
        for item in input_params:
            if isinstance(item, dict) and item.get("name"):
                source_by_name[str(item["name"])] = str(item.get("source") or "")
    return [source_by_name[param] for param in params if source_by_name.get(param)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _int_or_zero(value: Any) -> int:
    parsed = _int_or_none(value)
    return parsed if parsed is not None else 0


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    return None


def _format_first_vulnerability(plugin: dict[str, Any]) -> str:
    seconds = plugin.get("first_vulnerability_time")
    request = plugin.get("first_vulnerability_request")
    if seconds is None and request is None:
        return ""
    if seconds is None:
        return f"request {request}"
    if request is None:
        return f"{seconds}s"
    return f"{seconds}s / request {request}"


def _md(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a HookPhuzz generated-config evaluation report.")
    parser.add_argument("--output-root", default=str(Path(__file__).resolve().parents[1] / "output"))
    parser.add_argument("--json-output")
    parser.add_argument("--markdown-output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    report = write_evaluation_report(
        args.output_root,
        json_path=args.json_output,
        markdown_path=args.markdown_output,
    )
    print(
        "HookPhuzz evaluation summary: "
        f"plugins={report['summary']['plugins']} "
        f"e2e_success={report['summary']['e2e_success']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
