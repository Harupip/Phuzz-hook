from __future__ import annotations

import argparse
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from hook_energy.seed_generation.config_exporter import export_seed_configs
    from zend_discovery.convergence import advance_convergence_state, materialize_convergence_seeds, merge_enriched_seeds
    from zend_discovery.engine import candidate_from_seed_item, canonical_identity, canonical_identity_id, normalize_runtime_evidence, prepare_callback_registry, run_enrichment
else:
    from .config_exporter import export_seed_configs
    from zend_discovery.convergence import advance_convergence_state, materialize_convergence_seeds, merge_enriched_seeds
    from zend_discovery.engine import candidate_from_seed_item, canonical_identity, canonical_identity_id, normalize_runtime_evidence, prepare_callback_registry, run_enrichment


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
        artifacts.append(artifact)
    return raw_copy, artifacts


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run offline Zend enrichment for a legacy generated Pass 1 run.")
    parser.add_argument("--operation", choices=("prepare-registry", "correlate-enrich", "converge-iteration", "verify-pass2"), default="correlate-enrich")
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
    parser.add_argument("--convergence-state")
    parser.add_argument("--convergence-state-output")
    parser.add_argument("--convergence-merged-seeds")
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
            )
            _write_json(Path(args.convergence_state_output), result)
            _write_json(Path(args.convergence_merged_seeds), result["merged_suggested_seeds"])
            export_seed_configs(
                result["merged_suggested_seeds"],
                output_config_dir=Path(args.output_config_dir),
                summary_path=Path(args.generated_config_summary),
                replay_only=True,
            )
            print(f"Zend convergence iteration: status={result['status']} new={len(result['new_parameters'])}")
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
        _write_json(Path(args.merged_suggested_seeds), merged)
        config_summary = export_seed_configs(
            merged,
            output_config_dir=Path(args.output_config_dir),
            summary_path=Path(args.generated_config_summary),
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
) -> dict[str, Any]:
    """Correlate one replay and materialize its direct runtime discoveries."""
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
    candidate = candidate_from_seed_item(raw_item, plugin_slug=plugin_slug, legacy_run_id=legacy_run_id)
    candidate_key = canonical_identity_id(candidate)
    observed = normalize_runtime_evidence(candidate, uopz, zend, registry)
    prior = known_state.get("known_parameters", [])
    if not isinstance(prior, list):
        raise ValueError("convergence state known_parameters must be a list")
    advanced = advance_convergence_state(prior, observed)
    merged = materialize_convergence_seeds(
        raw_for_iteration,
        plugin_slug=plugin_slug,
        candidate_key=candidate_key,
        known_parameters=advanced["known_parameters"],
    )
    return {
        "status": "CONVERGED" if not advanced["new_parameters"] else "CONTINUE",
        "legacy_run_id": legacy_run_id,
        "candidate_key": candidate_key,
        "request_id": request_id,
        "known_before": prior,
        "observed_parameters": observed,
        "new_parameters": advanced["new_parameters"],
        "known_parameters": advanced["known_parameters"],
        "merged_suggested_seeds": merged,
    }


def verify_pass2_contract(
    pass2_run_summary: Mapping[str, Any],
    merged_seed_report: Mapping[str, Any],
    zend_events_dir: Path,
) -> dict[str, int]:
    expected = {
        (
            str(item.get("hook_name") or ""),
            str(item.get("callback_id") or ""),
        ): {
            "callback": str(((item.get("seed") or {}).get("zend_canonical_callback") or "") if isinstance(item.get("seed"), Mapping) else ""),
            "params": {
                (str(param.get("name")), _param_source(param), "query" if _param_source(param) == "GET" else "form")
                for param in (((item.get("seed") or {}).get("input_params") or []) if isinstance(item.get("seed"), Mapping) else [])
                if isinstance(param, Mapping) and _param_source(param) in {"GET", "POST"} and str(param.get("name"))
            },
        }
        for item in merged_seed_report.get("suggested_seeds", [])
        if isinstance(item, Mapping)
    }
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
        if not zend_path.is_file():
            continue
        try:
            zend = _read_json(zend_path)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(zend, Mapping):
            continue
        zend_run_id = str(zend.get("run_id") or "")
        if legacy_run_id and zend_run_id and zend_run_id != legacy_run_id:
            continue
        if str(zend.get("request_id") or "") != Path(artifact_name).stem:
            continue
        zend_method = str(zend.get("request_method") or zend.get("method") or "").upper()
        row_method = str(row.get("resolved_method") or "").upper()
        if zend_method and row_method and zend_method != row_method:
            continue
        observed = _zend_observed_params(zend, canonical_callback)
        if want_params <= observed:
            accepted += 1
    return {"accepted": accepted, "total": total}


def _zend_observed_params(zend: Mapping[str, Any], canonical_callback: str) -> set[tuple[str, str, str]]:
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
            source not in {"GET", "POST"}
            or not isinstance(path, list)
            or len(path) != 1
            or not isinstance(path[0], str)
            or helper_depth != 0
            or observed_count < 1
        ):
            continue
        observed.add((path[0], source, "query" if source == "GET" else "form"))
    return observed


def _param_source(param: Mapping[str, Any]) -> str:
    source = str(param.get("source") or "").upper()
    if source:
        return source
    location = str(param.get("location") or "")
    return {"query": "GET", "form": "POST", "body": "POST"}.get(location, "")


if __name__ == "__main__":
    raise SystemExit(main())
