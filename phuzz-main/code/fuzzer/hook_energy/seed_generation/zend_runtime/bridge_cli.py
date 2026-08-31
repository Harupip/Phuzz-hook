from __future__ import annotations

import argparse
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from seed_generation.config.config_exporter import export_seed_configs
    from seed_generation.convergence.convergence import advance_convergence_state, canonical_runtime_parameter_identity, materialize_convergence_seeds, merge_enriched_seeds
    from zend_discovery.engine import candidate_from_seed_item, canonical_identity, canonical_identity_id, normalize_runtime_evidence, prepare_callback_registry, resolve_request_transport, rest_runtime_block_reason, run_enrichment
    from instrumentation.zend.rest.runtime import canonical_rest_parameter_name
else:
    from seed_generation.config.config_exporter import export_seed_configs
    from seed_generation.convergence.convergence import advance_convergence_state, canonical_runtime_parameter_identity, materialize_convergence_seeds, merge_enriched_seeds
    from zend_discovery.engine import candidate_from_seed_item, canonical_identity, canonical_identity_id, normalize_runtime_evidence, prepare_callback_registry, resolve_request_transport, rest_runtime_block_reason, run_enrichment
    from instrumentation.zend.rest.runtime import canonical_rest_parameter_name


def _read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def _write_json(path: Path, value: Any) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _seed_key(item: Mapping[str, Any]) -> tuple[str, str, str]:
    seed = item.get("seed") if isinstance(item.get("seed"), Mapping) else {}
    return (
        str(item.get("hook_name") or ""),
        str(item.get("callback_id") or ""),
        str(seed.get("seed_variant_id") or ""),
    )


def _run_key(row: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(row.get("hook_name") or ""),
        str(row.get("callback_id") or ""),
        str(row.get("seed_variant_id") or ""),
    )


def _artifact_name(row: Mapping[str, Any]) -> str:
    matched = str(row.get("matched_artifact") or "")
    if matched:
        return matched
    artifacts = row.get("request_artifacts")
    if isinstance(artifacts, list) and artifacts:
        return str(artifacts[0])
    return ""


def _variant_suffix(seed_item: Mapping[str, Any]) -> str:
    seed = seed_item.get("seed")
    if isinstance(seed, Mapping):
        variant = str(seed.get("seed_variant_id") or "")
        if variant:
            return f"::{variant}"
    return ""


def _candidate_iteration_key(
    seed_item: Mapping[str, Any],
    *,
    plugin_slug: str,
    legacy_run_id: str,
) -> str:
    candidate = candidate_from_seed_item(seed_item, plugin_slug=plugin_slug, legacy_run_id=legacy_run_id)
    return canonical_identity_id(candidate) + _variant_suffix(seed_item)


def _candidate_base_key(
    seed_item: Mapping[str, Any],
    *,
    plugin_slug: str,
    legacy_run_id: str,
) -> str:
    candidate = candidate_from_seed_item(seed_item, plugin_slug=plugin_slug, legacy_run_id=legacy_run_id)
    return canonical_identity_id(candidate)


def build_enrichment_inputs(
    raw_report: Mapping[str, Any],
    pass1_run_summary: Mapping[str, Any],
    pass1_artifacts_dir: Path,
    *,
    plugin_slug: str,
    legacy_run_id: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw_copy = deepcopy(dict(raw_report))
    raw_items = raw_copy.get("suggested_seeds", [])
    if not isinstance(raw_items, list):
        raise ValueError("suggested_seeds.json must contain a suggested_seeds array")
    by_key = {_seed_key(item): item for item in raw_items if isinstance(item, Mapping)}
    matched_items: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    for row in pass1_run_summary.get("runs", []):
        if not isinstance(row, Mapping) or row.get("callback_reached") is not True:
            continue
        raw_item = by_key.get(_run_key(row))
        artifact_name = _artifact_name(row)
        if raw_item is None or not artifact_name:
            continue
        artifact_path = pass1_artifacts_dir / artifact_name
        if not artifact_path.is_file():
            continue
        artifact = _read_json(artifact_path)
        if not isinstance(artifact, dict):
            continue
        request_id = str(artifact.get("request_id") or Path(artifact_name).stem)
        seed = raw_item.get("seed")
        if isinstance(seed, dict):
            seed["pass1_request_id"] = request_id
        raw_item["pass1_request_id"] = request_id
        candidate = candidate_from_seed_item(raw_item, plugin_slug=plugin_slug, legacy_run_id=legacy_run_id)
        matched_items.append(raw_item)
        artifacts.append(artifact)
    raw_copy["suggested_seeds"] = matched_items
    return raw_copy, artifacts


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run offline Zend enrichment for a generated Pass 1 run.")
    parser.add_argument("--operation", choices=("prepare-registry", "correlate-enrich", "converge-iteration", "verify-pass2", "combine-final", "list-targets"), default="correlate-enrich")
    parser.add_argument("--plugin-zip")
    parser.add_argument("--plugin-slug")
    parser.add_argument("--legacy-run-id")
    parser.add_argument("--registry")
    parser.add_argument("--callback-registry-output")
    parser.add_argument("--raw-suggested-seeds")
    parser.add_argument("--pass1-run-summary")
    parser.add_argument("--pass1-artifacts-dir")
    parser.add_argument("--zend-events-dir")
    parser.add_argument("--zend-output-root")
    parser.add_argument("--merged-suggested-seeds")
    parser.add_argument("--output-config-dir")
    parser.add_argument("--generated-config-summary")
    parser.add_argument("--pass2-run-summary")
    parser.add_argument("--pass2-artifacts-dir")
    parser.add_argument("--convergence-state")
    parser.add_argument("--convergence-state-output")
    parser.add_argument("--convergence-merged-seeds")
    parser.add_argument("--candidate-key")
    parser.add_argument("--targets-output")
    parser.add_argument("--final-seed-report", action="append", default=[])
    parser.add_argument("--expected-count", type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    try:
        if args.operation == "prepare-registry":
            _require(args, "registry", "plugin_slug", "callback_registry_output")
            registry = prepare_callback_registry(_read_json(Path(args.registry)), args.plugin_slug)
            _write_json(Path(args.callback_registry_output), registry)
            print(f"Zend callback registry prepared: registrations={len(registry['registrations'])} output={args.callback_registry_output}")
            return 0
        if args.operation == "verify-pass2":
            _require(args, "pass2_run_summary", "zend_events_dir", "merged_suggested_seeds")
            summary = verify_pass2_contract(
                _read_json(Path(args.pass2_run_summary)),
                _read_json(Path(args.merged_suggested_seeds)),
                Path(args.zend_events_dir),
                pass2_artifacts_dir=Path(args.pass2_artifacts_dir) if args.pass2_artifacts_dir else None,
            )
            print(
                "Zend Pass 2 verification: "
                f"accepted={summary['accepted']} total={summary['total']}"
            )
            return 0 if summary["accepted"] == summary["total"] and summary["total"] > 0 else 1
        if args.operation == "converge-iteration":
            _require(
                args, "plugin_slug", "legacy_run_id", "registry", "raw_suggested_seeds",
                "pass1_run_summary", "pass1_artifacts_dir", "zend_events_dir", "convergence_state",
                "convergence_state_output", "convergence_merged_seeds", "output_config_dir",
                "generated_config_summary",
            )
            result = converge_iteration(
                raw_report=_read_json(Path(args.raw_suggested_seeds)),
                pass_run_summary=_read_json(Path(args.pass1_run_summary)),
                pass_artifacts_dir=Path(args.pass1_artifacts_dir),
                zend_events_dir=Path(args.zend_events_dir),
                registry=_read_json(Path(args.registry)),
                plugin_slug=args.plugin_slug,
                legacy_run_id=args.legacy_run_id,
                known_state=_read_json(Path(args.convergence_state)),
                candidate_key=args.candidate_key,
            )
            _write_json(Path(args.convergence_state_output), result)
            _write_json(Path(args.convergence_merged_seeds), _redacted_probe_seed_report(result["merged_suggested_seeds"]))
            if result["status"] == "REPLAY_FAILED":
                print(f"Zend convergence iteration: status={result['status']} missing={len(result.get('missing_parameters', []))}")
                return 2
            export_seed_configs(
                result["merged_suggested_seeds"],
                output_config_dir=Path(args.output_config_dir),
                summary_path=Path(args.generated_config_summary),
                replay_only=True,
                rest_route_fallback=True,
            )
            print(f"Zend convergence iteration: status={result['status']} new={len(result['new_parameters'])}")
            return 0
        if args.operation == "combine-final":
            _require(args, "merged_suggested_seeds")
            combined = combine_final_seed_reports(
                [Path(item) for item in args.final_seed_report],
                expected_count=args.expected_count,
            )
            _write_json(Path(args.merged_suggested_seeds), _redacted_probe_seed_report(combined))
            print(f"Zend final seed reports combined: total={len(combined['suggested_seeds'])}")
            return 0
        if args.operation == "list-targets":
            _require(args, "raw_suggested_seeds", "plugin_slug", "legacy_run_id", "targets_output")
            targets = list_convergence_targets(
                _read_json(Path(args.raw_suggested_seeds)),
                plugin_slug=args.plugin_slug,
                legacy_run_id=args.legacy_run_id,
                generated_summary=_read_json(Path(args.generated_config_summary)) if args.generated_config_summary else None,
                pass1_run_summary=_read_json(Path(args.pass1_run_summary)) if args.pass1_run_summary else None,
            )
            _write_json(Path(args.targets_output), {"targets": targets})
            print(f"Zend convergence targets listed: total={len(targets)}")
            return 0

        _require(
            args,
            "plugin_zip",
            "plugin_slug",
            "legacy_run_id",
            "registry",
            "raw_suggested_seeds",
            "pass1_run_summary",
            "pass1_artifacts_dir",
            "zend_events_dir",
            "zend_output_root",
            "merged_suggested_seeds",
            "output_config_dir",
            "generated_config_summary",
        )
        raw_report = _read_json(Path(args.raw_suggested_seeds))
        registry = _read_json(Path(args.registry))
        pass1_run_summary = _read_json(Path(args.pass1_run_summary))
        raw_for_enrichment, pass1_artifacts = build_enrichment_inputs(
            raw_report,
            pass1_run_summary,
            Path(args.pass1_artifacts_dir),
            plugin_slug=args.plugin_slug,
            legacy_run_id=args.legacy_run_id,
        )
        zend_artifacts = [
            item for path in sorted(Path(args.zend_events_dir).glob("*.json"))
            if isinstance((item := _read_json(path)), dict)
        ]
        summary = run_enrichment(
            plugin_zip=Path(args.plugin_zip),
            plugin_slug=args.plugin_slug,
            legacy_run_id=args.legacy_run_id,
            registry=registry,
            raw_seed_report=raw_for_enrichment,
            pass1_artifacts=pass1_artifacts,
            output_root=Path(args.zend_output_root),
            zend_artifacts=zend_artifacts,
        )
        enriched_path = Path(args.zend_output_root) / args.legacy_run_id / "zend_enriched_seeds.json"
        merged = merge_enriched_seeds(raw_for_enrichment, _read_json(enriched_path))
        _write_json(Path(args.merged_suggested_seeds), _redacted_probe_seed_report(merged))
        config_summary = export_seed_configs(
            merged,
            output_config_dir=Path(args.output_config_dir),
            summary_path=Path(args.generated_config_summary),
            rest_route_fallback=True,
        )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(
        "Zend bridge summary: "
        f"accepted_pass1_proof={summary['accepted_pass1_proof']} "
        f"final_fuzz_export_allowed={summary['final_fuzz_export_allowed']} "
        f"generated={len(config_summary['generated'])}"
    )
    return 0


def _require(args: argparse.Namespace, *names: str) -> None:
    missing = [name.replace("_", "-") for name in names if not getattr(args, name, None)]
    if missing:
        raise ValueError("missing required arguments: " + ", ".join(f"--{name}" for name in missing))


def converge_iteration(
    *,
    raw_report: Mapping[str, Any],
    pass_run_summary: Mapping[str, Any],
    pass_artifacts_dir: Path,
    zend_events_dir: Path,
    registry: Mapping[str, Any],
    plugin_slug: str,
    legacy_run_id: str,
    known_state: Mapping[str, Any],
    candidate_key: str | None = None,
) -> dict[str, Any]:
    """Correlate one replay and materialize its direct runtime discoveries."""
    raw_report, pass_run_summary = _filter_iteration_inputs(
        raw_report,
        pass_run_summary,
        plugin_slug=plugin_slug,
        legacy_run_id=legacy_run_id,
        candidate_key=str(candidate_key or ""),
    )
    raw_for_iteration, uopz_artifacts = build_enrichment_inputs(
        raw_report, pass_run_summary, pass_artifacts_dir,
        plugin_slug=plugin_slug, legacy_run_id=legacy_run_id,
    )
    raw_items = raw_for_iteration.get("suggested_seeds", [])
    rows = pass_run_summary.get("runs", [])
    if not isinstance(raw_items, list) or len(raw_items) != 1 or not isinstance(rows, list) or len(rows) != 1:
        raise RuntimeError("REPLAY_FAILED: Phase 2 requires exactly one generated candidate and one replay row")
    row = rows[0]
    if not isinstance(row, Mapping) or row.get("callback_reached") is not True:
        raise RuntimeError("REPLAY_FAILED: callback was not reached")
    artifact_name = str(row.get("matched_artifact") or "")
    if not artifact_name or Path(artifact_name).name != artifact_name:
        raise RuntimeError("REPLAY_FAILED: matched request artifact is missing")
    request_id = Path(artifact_name).stem
    if not request_id or len(uopz_artifacts) != 1:
        raise RuntimeError("REPLAY_FAILED: matched request artifact correlation failed")
    uopz = uopz_artifacts[0]
    if str(uopz.get("request_id") or "") != request_id or uopz.get("compat_request_id_matches") is False:
        raise RuntimeError("REPLAY_FAILED: request-ID headers are incompatible")
    zend_path = zend_events_dir / artifact_name
    if not zend_path.is_file():
        raise RuntimeError("REPLAY_FAILED: matched Zend artifact is missing")
    zend = _read_json(zend_path)
    if not isinstance(zend, Mapping) or str(zend.get("request_id") or "") != request_id:
        raise RuntimeError("REPLAY_FAILED: Zend request correlation failed")
    raw_item = raw_items[0]
    if not isinstance(raw_item, Mapping):
        raise RuntimeError("REPLAY_FAILED: generated candidate is invalid")
    candidate = candidate_from_seed_item(
        _normalization_seed_item(raw_item),
        plugin_slug=plugin_slug,
        legacy_run_id=legacy_run_id,
    )
    candidate_key = _candidate_iteration_key(raw_item, plugin_slug=plugin_slug, legacy_run_id=legacy_run_id)
    base_candidate_key = _candidate_base_key(raw_item, plugin_slug=plugin_slug, legacy_run_id=legacy_run_id)
    callback_map = registry.get("callback_map") if isinstance(registry.get("callback_map"), Mapping) else {}
    canonical_callback = str(callback_map.get(candidate.get("callback_id")) or "")
    runtime_block_reason = (
        rest_runtime_block_reason(zend, canonical_callback)
        if candidate.get("entrypoint_type") == "rest"
        else ""
    )
    observed = normalize_runtime_evidence(candidate, uopz, zend, registry)
    prior = known_state.get("known_parameters", [])
    if not isinstance(prior, list):
        raise ValueError("convergence state known_parameters must be a list")
    advanced = advance_convergence_state(prior, observed)
    missing = _missing_known_parameters(prior, observed)
    probe_parameter_names = (
        _rest_get_param_probe_names(candidate, uopz)
        if not prior and not observed and not runtime_block_reason
        else []
    )
    status = (
        "REPLAY_FAILED" if missing
        else "CONTINUE" if probe_parameter_names
        else "CONVERGED" if not advanced["new_parameters"]
        else "CONTINUE"
    )
    seed = raw_item.get("seed")
    is_probe_variant = isinstance(seed, Mapping) and seed.get("probe_variant") is True
    merged = materialize_convergence_seeds(
        raw_for_iteration,
        plugin_slug=plugin_slug,
        candidate_key=base_candidate_key,
        known_parameters=advanced["known_parameters"],
        for_replay=status == "CONTINUE" and not is_probe_variant,
    )
    if probe_parameter_names:
        merged = _materialize_rest_get_param_probe(merged, probe_parameter_names)
    return {
        "status": status,
        "legacy_run_id": legacy_run_id,
        "candidate_key": candidate_key,
        "request_id": request_id,
        "known_before": prior,
        "observed_parameters": observed,
        "runtime_block_reason": runtime_block_reason or None,
        "probe_parameter_names": probe_parameter_names,
        "new_parameters": advanced["new_parameters"],
        "missing_parameters": missing,
        "known_parameters": advanced["known_parameters"],
        "merged_suggested_seeds": merged,
    }


def _normalization_seed_item(seed_item: Mapping[str, Any]) -> Mapping[str, Any]:
    seed = seed_item.get("seed")
    probe = seed_item.get("probe_request")
    if not isinstance(seed, Mapping) or not seed.get("probe_variant") or not isinstance(probe, Mapping):
        return seed_item
    parameters = probe.get("parameters")
    parameter_names = (
        [str(value) for value in parameters if str(value)]
        if isinstance(parameters, list)
        else [str(probe.get("parameter") or "")]
    )
    fixed = seed.get("fixed_params")
    if not parameter_names or not isinstance(fixed, list):
        return seed_item
    normalized = deepcopy(dict(seed_item))
    normalized_seed = normalized.get("seed")
    if not isinstance(normalized_seed, dict):
        return seed_item
    normalized_seed["fixed_params"] = [name for name in fixed if str(name) not in parameter_names]
    return normalized


def _rest_get_param_probe_names(candidate: Mapping[str, Any], uopz: Mapping[str, Any]) -> list[str]:
    if candidate.get("entrypoint_type") != "rest":
        return []
    method = str(candidate.get("resolved_method") or candidate.get("method") or "").upper()
    if method not in {"GET", "HEAD", "POST"}:
        return []
    request_params = uopz.get("request_params")
    if method in {"GET", "HEAD"}:
        existing = request_params.get("query_params") if isinstance(request_params, Mapping) else {}
    else:
        existing = request_params.get("body_params") if isinstance(request_params, Mapping) else {}
    existing = existing if isinstance(existing, Mapping) else {}
    events = uopz.get("rest_parameter_events")
    if not isinstance(events, list):
        return []
    names: list[str] = []
    for event in events:
        if not isinstance(event, Mapping) or event.get("accessor") != "WP_REST_Request::get_param":
            continue
        name = str(event.get("name") or "")
        if not name or "[" in name or "]" in name or _security_name(name) or name in existing or name in names:
            continue
        names.append(name)
    return names


def _materialize_rest_get_param_probe(report: Mapping[str, Any], names: list[str]) -> dict[str, Any]:
    merged = deepcopy(dict(report))
    items = merged.get("suggested_seeds")
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise ValueError("REST get_param probe requires exactly one candidate")
    item = items[0]
    seed = item.get("seed")
    if not isinstance(seed, dict):
        raise ValueError("REST get_param probe candidate is invalid")
    method = str(seed.get("resolved_method") or seed.get("method") or "").upper()
    if method in {"GET", "HEAD"}:
        target = seed.setdefault("query_params", {})
        location = "query"
        content_type = ""
        missing_requirement = "correlated_runtime_query_observation"
    elif method == "POST":
        target = seed.setdefault("body", {})
        location = "form"
        content_type = "application/x-www-form-urlencoded"
        missing_requirement = "correlated_runtime_form_observation"
        headers = seed.setdefault("headers", {})
        if not isinstance(headers, dict):
            raise ValueError("REST post probe headers must be an object")
        headers["Content-Type"] = content_type
        seed["content_type"] = content_type
    else:
        raise ValueError("REST get_param probe requires GET, HEAD, or POST")
    if not isinstance(target, dict):
        raise ValueError(f"REST {location} probe target must be an object")
    for name in names:
        target[name] = "probe"
    fixed = seed.get("fixed_params") if isinstance(seed.get("fixed_params"), list) else []
    seed["fixed_params"] = list(dict.fromkeys([str(value) for value in fixed if str(value)] + names))
    seed["fuzzable_params"] = []
    seed["input_params"] = []
    seed["export_allowed"] = True
    seed["replay_allowed"] = True
    seed["probe_variant"] = True
    item["fuzzing_ready"] = False
    probe_status = "rest_post_param_runtime_probe" if method == "POST" else "rest_get_param_runtime_probe"
    item["generation_status"] = probe_status
    item["generated_reason"] = probe_status
    item["missing_requirements"] = [missing_requirement]
    item["probe_request"] = {
        "parameters": names,
        "location": location,
        "content_type": content_type,
        "candidate_value_redacted": True,
    }
    return merged


def _filter_iteration_inputs(
    raw_report: Mapping[str, Any],
    pass_run_summary: Mapping[str, Any],
    *,
    plugin_slug: str,
    legacy_run_id: str,
    candidate_key: str,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    if not candidate_key:
        return raw_report, pass_run_summary
    raw_items = raw_report.get("suggested_seeds", [])
    rows = pass_run_summary.get("runs", [])
    if not isinstance(raw_items, list) or not isinstance(rows, list):
        return raw_report, pass_run_summary
    selected = [
        item for item in raw_items
        if isinstance(item, Mapping)
        and _candidate_iteration_key(item, plugin_slug=plugin_slug, legacy_run_id=legacy_run_id) == candidate_key
    ]
    selected_keys = {_seed_key(item) for item in selected}
    filtered_rows = [row for row in rows if isinstance(row, Mapping) and _run_key(row) in selected_keys]
    raw_copy = deepcopy(dict(raw_report))
    summary_copy = deepcopy(dict(pass_run_summary))
    raw_copy["suggested_seeds"] = selected
    summary_copy["runs"] = filtered_rows
    return raw_copy, summary_copy


def _missing_known_parameters(
    known_parameters: list[Mapping[str, Any]],
    observed_parameters: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    observed = {
        identity for parameter in observed_parameters
        if (identity := canonical_runtime_parameter_identity(parameter)) is not None
    }
    missing: list[dict[str, Any]] = []
    for parameter in known_parameters:
        identity = canonical_runtime_parameter_identity(parameter)
        if identity is not None and identity not in observed:
            missing.append(dict(parameter))
    return missing


def verify_pass2_contract(
    pass2_run_summary: Mapping[str, Any],
    merged_seed_report: Mapping[str, Any],
    zend_events_dir: Path,
    *,
    pass2_artifacts_dir: Path | None = None,
) -> dict[str, int]:
    expected = _expected_pass2_params(merged_seed_report)
    legacy_run_id = str(pass2_run_summary.get("legacy_run_id") or "")
    total = 0
    accepted = 0
    for row in pass2_run_summary.get("runs", []):
        if not isinstance(row, Mapping) or row.get("callback_reached") is not True:
            continue
        want = expected.get((str(row.get("hook_name") or ""), str(row.get("callback_id") or "")), {})
        want_params = want.get("params") if isinstance(want, Mapping) else set()
        canonical_callback = str(want.get("callback") or "") if isinstance(want, Mapping) else ""
        if not want_params or not canonical_callback:
            continue
        total += 1
        artifact_name = str(row.get("matched_artifact") or "")
        if not artifact_name or Path(artifact_name).name != artifact_name:
            continue
        zend_path = zend_events_dir / artifact_name
        uopz_path = pass2_artifacts_dir / artifact_name if pass2_artifacts_dir is not None else None
        if not zend_path.is_file():
            continue
        try:
            zend = _read_json(zend_path)
            uopz = _read_json(uopz_path) if uopz_path is not None and uopz_path.is_file() else {}
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(zend, Mapping):
            continue
        if not isinstance(uopz, Mapping):
            uopz = {}
        zend_run_id = str(zend.get("run_id") or "")
        if legacy_run_id and zend_run_id and zend_run_id != legacy_run_id:
            continue
        if str(zend.get("request_id") or "") != Path(artifact_name).stem:
            continue
        if uopz and str(uopz.get("request_id") or "") != Path(artifact_name).stem:
            continue
        zend_method = str(zend.get("request_method") or zend.get("method") or "").upper()
        row_method = str(row.get("resolved_method") or "").upper()
        if zend_method and row_method and zend_method != row_method:
            continue
        observed = _zend_observed_params(zend, uopz, canonical_callback) | _zend_observed_rest_params(
            zend,
            uopz,
            canonical_callback,
            rest_identity=want.get("rest_identity") if isinstance(want, Mapping) else None,
        )
        if _expected_params_observed(want_params, observed):
            accepted += 1
    return {"accepted": accepted, "total": total}


def _expected_params_observed(
    want_params: set[tuple[str, str, str]],
    observed: set[tuple[str, str, str]],
) -> bool:
    return all(_expected_param_observed(param, observed) for param in want_params)


def _expected_param_observed(
    param: tuple[str, str, str],
    observed: set[tuple[str, str, str]],
) -> bool:
    if param in observed:
        return True
    name, source, location = param
    if source == "POST" and location == "form":
        parent = _bracket_parent_name(name)
        if parent and (parent, source, location) in observed:
            return True
    return False


def _bracket_parent_name(name: str) -> str:
    bracket = name.find("[")
    if bracket <= 0 or not name.endswith("]"):
        return ""
    return name[:bracket]


def _expected_pass2_params(merged_seed_report: Mapping[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    expected: dict[tuple[str, str], dict[str, Any]] = {}
    for item in merged_seed_report.get("suggested_seeds", []):
        if not isinstance(item, Mapping):
            continue
        seed = item.get("seed") if isinstance(item.get("seed"), Mapping) else {}
        params = {
            (str(param.get("name")), source, _param_location(param, source))
            for param in (seed.get("input_params") or [])
            if isinstance(param, Mapping)
            and (source := _param_source(param)) in {"GET", "POST", "JSON", "URL"}
            and str(param.get("name"))
        }
        value = {
            "callback": str(seed.get("zend_canonical_callback") or ""),
            "params": params,
            "rest_identity": _expected_rest_identity(item, seed),
        }
        callback_id = str(item.get("callback_id") or "")
        expected[(str(item.get("hook_name") or ""), callback_id)] = value
        expected.setdefault((callback_id, callback_id), value)
    return expected


def _expected_rest_identity(item: Mapping[str, Any], seed: Mapping[str, Any]) -> dict[str, Any]:
    entrypoint_type = str(item.get("entrypoint_type") or seed.get("entrypoint_type") or "").lower()
    if entrypoint_type not in {"rest", "rest_route", "rest_api", "wp_rest", "wp_rest_route"}:
        return {}
    return {
        "namespace": str(item.get("namespace") or ""),
        "route_pattern": str(item.get("route_pattern") or item.get("route") or ""),
        "endpoint_definition_index": item.get("endpoint_definition_index"),
        "materialized_route": str(item.get("materialized_route") or seed.get("path") or item.get("route") or ""),
        "method": str(seed.get("resolved_method") or seed.get("method") or "").upper(),
    }


def _zend_observed_params(
    zend: Mapping[str, Any],
    uopz: Mapping[str, Any],
    canonical_callback: str,
) -> set[tuple[str, str, str]]:
    summaries = zend.get("callback_summaries")
    if not isinstance(summaries, list):
        return set()
    matched = [
        summary for summary in summaries
        if isinstance(summary, Mapping) and str(summary.get("callback") or "") == canonical_callback
    ]
    if len(matched) != 1:
        return set()
    params = matched[0].get("unique_parameters")
    if not isinstance(params, list):
        return set()
    observed: set[tuple[str, str, str]] = set()
    for param in params:
        if not isinstance(param, Mapping):
            continue
        source = str(param.get("source") or "").upper()
        path = param.get("path")
        try:
            helper_depth = int(param.get("helper_depth"))
            observed_count = int(param.get("observed_count"))
        except (TypeError, ValueError):
            continue
        if (
            not isinstance(path, list)
            or len(path) != 1
            or not isinstance(path[0], str)
            or helper_depth != 0
            or observed_count < 1
        ):
            continue
        location = {"GET": "query", "POST": "form"}.get(source)
        if source == "REQUEST":
            request_params = uopz.get("request_params") if isinstance(uopz.get("request_params"), Mapping) else {}
            request_headers = uopz.get("headers")
            if not isinstance(request_headers, Mapping):
                request_headers = request_params.get("headers")
            request_headers = dict(request_headers) if isinstance(request_headers, Mapping) else {}
            content_type = uopz.get("content_type") or uopz.get("request_content_type")
            if not content_type:
                content_type = request_params.get("content_type")
            if content_type and not any(str(key).lower() == "content-type" for key in request_headers):
                request_headers["Content-Type"] = content_type
            resolved = resolve_request_transport(
                path[0],
                request_method=str(zend.get("request_method") or zend.get("method") or ""),
                request_params=request_params,
                headers=request_headers,
            )
            if resolved is None:
                continue
            source, location = resolved
        elif source not in {"GET", "POST"}:
            continue
        observed.add((path[0], source, location))
    return observed


def _zend_observed_rest_params(
    zend: Mapping[str, Any],
    uopz: Mapping[str, Any],
    canonical_callback: str,
    *,
    rest_identity: Any = None,
) -> set[tuple[str, str, str]]:
    events = zend.get("rest_parameter_events")
    if not isinstance(events, list):
        return set()
    request_params = uopz.get("request_params") if isinstance(uopz.get("request_params"), Mapping) else {}
    json_params = request_params.get("json_params") if isinstance(request_params, Mapping) else None
    body_params = request_params.get("body_params") if isinstance(request_params, Mapping) else None
    observed: set[tuple[str, str, str]] = set()
    seen_locations: dict[str, set[str]] = {}
    bucket_locations = {"GET": "query", "POST": "form", "JSON": "json", "URL": "path"}
    for event in events:
        if not isinstance(event, Mapping) or str(event.get("callback") or "") != canonical_callback:
            continue
        if not _rest_runtime_identity_matches(event, uopz, rest_identity):
            continue
        if event.get("source") == "REST":
            bucket = str(event.get("bucket") or "").upper()
            name = canonical_rest_parameter_name(bucket, event.get("path"), event.get("parameter"))
            location = bucket_locations.get(bucket, "")
        else:
            name = event.get("name")
            location = str(event.get("location") or "")
        try:
            observed_count = int(event.get("observed_count") or 0)
        except (TypeError, ValueError):
            continue
        if (
            not isinstance(name, str)
            or not name
            or location not in {"query", "form", "json", "path"}
            or observed_count < 1
            or _security_name(name)
        ):
            continue
        if location == "json" and isinstance(json_params, Mapping) and name not in json_params:
            continue
        if location == "form" and isinstance(body_params, Mapping) and name not in body_params:
            continue
        seen_locations.setdefault(name, set()).add(location)
        source = {"query": "GET", "form": "POST", "json": "JSON", "path": "URL"}[location]
        observed.add((name, source, location))
    if any(len(locations) != 1 for locations in seen_locations.values()):
        return set()
    return observed


def _rest_runtime_identity_matches(event: Mapping[str, Any], uopz: Mapping[str, Any], rest_identity: Any) -> bool:
    if not isinstance(rest_identity, Mapping) or not rest_identity:
        return True
    comparable = {
        key: value
        for key, value in rest_identity.items()
        if event.get(key) not in (None, "")
    }
    if comparable:
        return all(event.get(key) == value for key, value in comparable.items())
    route = str(rest_identity.get("materialized_route") or "")
    if route.startswith("/wp-json/"):
        route = route[len("/wp-json") :]
    endpoint = str(uopz.get("endpoint") or "")
    if route and endpoint and endpoint != "REST:" + route:
        return False
    method = str(rest_identity.get("method") or "").upper()
    uopz_method = str(uopz.get("http_method") or uopz.get("method") or uopz.get("request_method") or "").upper()
    return not (method and uopz_method and method != uopz_method)


def _param_source(param: Mapping[str, Any]) -> str:
    source = str(param.get("source") or "").upper()
    if source:
        return source
    location = str(param.get("location") or "")
    return {"query": "GET", "form": "POST", "body": "POST", "json": "JSON", "path": "URL"}.get(location, "")


def _param_location(param: Mapping[str, Any], source: str) -> str:
    location = str(param.get("location") or "")
    if location in {"query", "form", "json", "path"}:
        return location
    return {"GET": "query", "POST": "form", "JSON": "json", "URL": "path"}.get(source, "")


def _security_name(name: str) -> bool:
    lowered = name.lower()
    return any(part in lowered for part in ("nonce", "cookie", "secret", "password", "token", "authorization"))


def combine_final_seed_reports(paths: Sequence[Path], *, expected_count: int | None = None) -> dict[str, Any]:
    if expected_count is not None and len(paths) != expected_count:
        raise ValueError(f"expected {expected_count} final seed reports, got {len(paths)}")
    combined: dict[str, Any] = {"suggested_seeds": []}
    for path in paths:
        payload = _read_json(Path(path))
        items = payload.get("suggested_seeds") if isinstance(payload, Mapping) else None
        if not isinstance(items, list):
            raise ValueError(f"{path} must contain a suggested_seeds array")
        combined["suggested_seeds"].extend(item for item in items if isinstance(item, Mapping))
    return _block_ambiguous_probe_locations(combined)


def _redacted_probe_seed_report(seed_report: Mapping[str, Any]) -> dict[str, Any]:
    report = deepcopy(dict(seed_report))
    items = report.get("suggested_seeds")
    if not isinstance(items, list):
        return report
    redacted: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        row = deepcopy(dict(item))
        seed = row.get("seed")
        if isinstance(seed, dict) and seed.get("probe_variant"):
            seed["body"] = _redact_probe_mapping(seed.get("body"))
            seed["query_params"] = _redact_probe_mapping(seed.get("query_params"))
        redacted.append(row)
    report["suggested_seeds"] = redacted
    return report


def _redact_probe_mapping(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): "redacted" for key in value.keys()}
    return value


def _block_ambiguous_probe_locations(seed_report: Mapping[str, Any]) -> dict[str, Any]:
    report = deepcopy(dict(seed_report))
    items = report.get("suggested_seeds")
    if not isinstance(items, list):
        return report
    grouped: dict[tuple[str, str], set[str]] = {}
    for item in items:
        if not isinstance(item, Mapping):
            continue
        seed = item.get("seed")
        if not isinstance(seed, Mapping) or not seed.get("probe_variant"):
            continue
        identity = _candidate_base_key(
            item,
            plugin_slug=str(item.get("plugin_slug") or ""),
            legacy_run_id="",
        )
        for param in seed.get("input_params", []):
            if not isinstance(param, Mapping) or param.get("fuzzable") is False:
                continue
            name = str(param.get("name") or "")
            location = str(param.get("location") or "")
            if not name or location not in {"form", "json"}:
                continue
            grouped.setdefault((identity, name), set()).add(location)
    ambiguous = {key for key, locations in grouped.items() if locations == {"form", "json"}}
    if not ambiguous:
        return report
    for item in items:
        if not isinstance(item, Mapping):
            continue
        seed = item.get("seed")
        if not isinstance(seed, dict):
            continue
        identity = _candidate_base_key(
            item,
            plugin_slug=str(item.get("plugin_slug") or ""),
            legacy_run_id="",
        )
        parameter_keys = {
            (identity, str(param.get("name") or ""))
            for param in seed.get("input_params", [])
            if isinstance(param, Mapping)
            and param.get("fuzzable") is not False
            and str(param.get("name") or "")
        }
        blocked_names = {
            name for item_identity, name in parameter_keys.intersection(ambiguous)
            if item_identity == identity
        }
        if not blocked_names:
            continue
        input_params = seed.get("input_params")
        if isinstance(input_params, list):
            updated_input_params: list[Any] = []
            for param in input_params:
                if not isinstance(param, Mapping):
                    updated_input_params.append(param)
                    continue
                name = str(param.get("name") or "")
                if name not in blocked_names:
                    updated_input_params.append(param)
                    continue
                blocked_param = dict(param)
                blocked_param["fuzzable"] = False
                blocked_param["block_reason"] = "ambiguous_runtime_probe_location"
                updated_input_params.append(blocked_param)
            seed["input_params"] = updated_input_params
        fuzzable_params = seed.get("fuzzable_params")
        remaining_fuzzable = [
            str(name) for name in fuzzable_params
            if str(name) and str(name) not in blocked_names
        ] if isinstance(fuzzable_params, list) else []
        seed["fuzzable_params"] = list(dict.fromkeys(remaining_fuzzable))
        fixed_params = seed.get("fixed_params") if isinstance(seed.get("fixed_params"), list) else []
        seed["fixed_params"] = list(dict.fromkeys(
            [str(name) for name in fixed_params if str(name)] + sorted(blocked_names)
        ))
        existing_blocked = seed.get("blocked_parameters") if isinstance(seed.get("blocked_parameters"), list) else []
        seed["blocked_parameters"] = list(dict.fromkeys(
            [str(name) for name in existing_blocked if str(name)] + sorted(blocked_names)
        ))
        if seed["fuzzable_params"]:
            continue
        seed["export_allowed"] = False
        seed["replay_allowed"] = True
        seed["block_reason"] = "ambiguous_runtime_probe_location"
        item["generation_status"] = "ambiguous_runtime_probe_location"
        item["generated_reason"] = "ambiguous_runtime_probe_location"
        item["fuzzing_ready"] = False
        item["missing_requirements"] = ["unique_runtime_bucket_location"]
    return report


def list_convergence_targets(
    raw_report: Mapping[str, Any],
    *,
    plugin_slug: str,
    legacy_run_id: str,
    generated_summary: Mapping[str, Any] | None = None,
    pass1_run_summary: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    items = raw_report.get("suggested_seeds", [])
    if not isinstance(items, list):
        raise ValueError("suggested_seeds.json must contain a suggested_seeds array")
    targets: list[dict[str, Any]] = []
    seen: set[str] = set()
    generated_keys: set[tuple[str, str, str]] | None = None
    pass1_callback_keys: set[tuple[str, str, str]] | None = None
    expected_auth_skip_keys: set[tuple[str, str, str]] = set()
    if generated_summary is not None:
        rows = generated_summary.get("generated")
        if not isinstance(rows, list):
            raise ValueError("generated_config_summary.json must contain a generated array")
        generated_keys = {_run_key(row) for row in rows if isinstance(row, Mapping)}
    if pass1_run_summary is not None:
        rows = pass1_run_summary.get("runs")
        if not isinstance(rows, list):
            raise ValueError("pass1-generated_config_run_summary.json must contain a runs array")
        pass1_callback_keys = {
            _run_key(row)
            for row in rows
            if isinstance(row, Mapping) and row.get("callback_reached") is True
        }
        expected_auth_skip_keys = {
            _run_key(row)
            for row in rows
            if isinstance(row, Mapping) and row.get("expected_auth_skip") is True
        }
    for item in items:
        if not isinstance(item, Mapping):
            continue
        if generated_keys is not None and _seed_key(item) not in generated_keys:
            continue
        if pass1_callback_keys is not None and _seed_key(item) not in pass1_callback_keys:
            continue
        if _seed_key(item) in expected_auth_skip_keys:
            continue
        candidate = candidate_from_seed_item(item, plugin_slug=plugin_slug, legacy_run_id=legacy_run_id)
        key = _candidate_iteration_key(item, plugin_slug=plugin_slug, legacy_run_id=legacy_run_id)
        if key in seen:
            continue
        seen.add(key)
        targets.append({
            "candidate_key": key,
            "hook_name": str(item.get("hook_name") or ""),
            "callback_id": str(item.get("callback_id") or ""),
            "entrypoint_type": str(candidate.get("entrypoint_type") or ""),
            "method": str(candidate.get("method") or ""),
            "route": str(candidate.get("materialized_route") or candidate.get("route") or candidate.get("path") or ""),
        })
    return targets


if __name__ == "__main__":
    raise SystemExit(main())
