from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from discovery.entrypoints.classifier import _classify_callback, _normalize_callback
    from discovery.entrypoints.entrypoints import rest_seed_template, seed_template_for_callback
    from discovery.entrypoints.method_resolution import resolve_http_methods
    from seed_generation.config.config_exporter import export_seed_configs
    from seed_generation.source_assisted.input_extractor import InputSignatureExtractor
    from seed_generation.verification.seed_validator import validate_candidate
else:
    from discovery.entrypoints.classifier import _classify_callback, _normalize_callback
    from discovery.entrypoints.entrypoints import rest_seed_template, seed_template_for_callback
    from discovery.entrypoints.method_resolution import resolve_http_methods
    from seed_generation.config.config_exporter import export_seed_configs
    from seed_generation.source_assisted.input_extractor import InputSignatureExtractor
    from seed_generation.verification.seed_validator import validate_candidate


def build_recursive_seed_report(
    payloads: Sequence[Mapping[str, Any]],
    *,
    max_hook_depth: int = 3,
    input_extractor: InputSignatureExtractor | None = None,
) -> dict[str, Any]:
    if max_hook_depth < 1:
        raise ValueError("max_hook_depth must be at least 1")

    extractor = input_extractor or InputSignatureExtractor()
    generated: list[dict[str, Any]] = []
    manual: list[dict[str, Any]] = []
    seen: set[str] = set()
    duplicates_skipped = 0
    depth_skipped = 0

    for payload in payloads:
        for fallback_id, row in _registered_callbacks(payload).items():
            callback = dict(row)
            callback.setdefault("callback_id", fallback_id)
            level = _integer(callback.get("hook_level"))
            if level is None or level < 1 or not callback.get("registered_inside_callback"):
                continue
            if level > max_hook_depth:
                depth_skipped += 1
                continue
            if not isinstance(callback.get("parent_callback"), Mapping) or not callback["parent_callback"]:
                continue

            identity = _identity(callback)
            if identity in seen:
                duplicates_skipped += 1
                continue
            seen.add(identity)

            provenance = _provenance(callback, level)
            seed, reason = _seed_for_callback(callback, extractor)
            if seed is None:
                manual.append({**provenance, "generation_status": "manual_analysis_required", "reason": reason})
            else:
                generated.append({**provenance, "generation_status": "supported_http_seed", "seed": seed})

    generated.sort(key=lambda item: (item["hook_level"], item["child_hook_name"], item["callback_id"]))
    manual.sort(key=lambda item: (item["hook_level"], item["child_hook_name"], item["callback_id"]))
    return {
        "schema_version": 1,
        "generated_from": "child_hook",
        "max_hook_depth": max_hook_depth,
        "summary": {
            "generated": len(generated),
            "manual_analysis": len(manual),
            "duplicates_skipped": duplicates_skipped,
            "depth_skipped": depth_skipped,
        },
        "suggested_seeds": generated,
        "manual_analysis_queue": manual,
    }


def validate_recursive_seeds(
    seed_report: Mapping[str, Any],
    *,
    base_url: str,
    hook_coverage_dir: str | Path,
    timeout: float,
    validator: Callable[..., dict[str, Any]] = validate_candidate,
) -> dict[str, Any]:
    validations = []
    for item in seed_report.get("suggested_seeds", []):
        _, row = _validate_item(
            item,
            base_url=base_url,
            hook_coverage_dir=hook_coverage_dir,
            timeout=timeout,
            validator=validator,
        )
        validations.append(row)

    return {
        "schema_version": 1,
        "summary": {
            "total": len(validations),
            "callback_reached": sum(item["callback_reached"] for item in validations),
        },
        "validations": validations,
    }


def run_recursive_child_hook_seeds(
    payloads: Sequence[Mapping[str, Any]],
    *,
    base_url: str,
    hook_coverage_dir: str | Path,
    timeout: float,
    max_hook_depth: int = 3,
    validator: Callable[..., dict[str, Any]] = validate_candidate,
) -> tuple[dict[str, Any], dict[str, Any]]:
    report = build_recursive_seed_report(payloads, max_hook_depth=max_hook_depth)
    generated = report["suggested_seeds"]
    manual = report["manual_analysis_queue"]
    queue = list(generated)
    seen = {_item_identity(item) for item in generated + manual}
    validations: list[dict[str, Any]] = []

    while queue:
        item = queue.pop(0)
        result, row = _validate_item(
            item,
            base_url=base_url,
            hook_coverage_dir=hook_coverage_dir,
            timeout=timeout,
            validator=validator,
        )
        validations.append(row)
        for relative_path in result.get("artifacts", {}).get("new_request_artifacts", []):
            artifact_path = Path(hook_coverage_dir) / str(relative_path)
            if not artifact_path.is_file():
                continue
            payload = json.loads(artifact_path.read_text(encoding="utf-8-sig"))
            if not isinstance(payload, Mapping):
                continue
            discovered = build_recursive_seed_report([payload], max_hook_depth=max_hook_depth)
            for collection, target in (
                (discovered["suggested_seeds"], generated),
                (discovered["manual_analysis_queue"], manual),
            ):
                for child in collection:
                    identity = _item_identity(child)
                    if identity in seen:
                        report["summary"]["duplicates_skipped"] += 1
                        continue
                    seen.add(identity)
                    child["recursive_depth"] = item["recursive_depth"] + 1
                    if child["recursive_depth"] > max_hook_depth:
                        report["summary"]["depth_skipped"] += 1
                        continue
                    target.append(child)
                    if target is generated:
                        queue.append(child)

    generated.sort(key=lambda child: (child["recursive_depth"], child["child_hook_name"], child["callback_id"]))
    manual.sort(key=lambda child: (child["recursive_depth"], child["child_hook_name"], child["callback_id"]))
    report["summary"]["generated"] = len(generated)
    report["summary"]["manual_analysis"] = len(manual)

    return report, {
        "schema_version": 1,
        "summary": {
            "total": len(validations),
            "callback_reached": sum(item["callback_reached"] for item in validations),
        },
        "validations": validations,
    }


def write_recursive_artifacts(
    seed_report: Mapping[str, Any],
    validation_report: Mapping[str, Any],
    output_dir: Path,
    *,
    config_target_base: str = "http://web",
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    seeds_path = output_dir / "recursive_child_hook_seeds.json"
    validation_path = output_dir / "validation_result.json"
    config_dir = output_dir / "configs"
    config_summary_path = output_dir / "generated_config_summary.json"

    seeds_path.write_text(json.dumps(seed_report, indent=2), encoding="utf-8")
    validation_path.write_text(json.dumps(validation_report, indent=2), encoding="utf-8")
    export_seed_configs(
        seed_report,
        output_config_dir=config_dir,
        summary_path=config_summary_path,
        target_base=config_target_base,
    )
    summary = json.loads(config_summary_path.read_text(encoding="utf-8"))
    for item in summary.get("generated", []):
        config_slug = str(item.get("config_slug") or "")
        file_slug = Path(config_slug.replace("\\", "/")).name
        if file_slug:
            item["config_path"] = str(config_dir / f"{file_slug}.json")
    config_summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return {
        "seeds": seeds_path,
        "validation": validation_path,
        "config_summary": config_summary_path,
        "configs": sorted(config_dir.glob("*.json")),
    }


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate and validate replayable seeds for recursive child hooks.")
    parser.add_argument("--input-file", action="append", required=True, help="Hook registry or request artifact JSON.")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--max-hook-depth", type=int, default=3)
    parser.add_argument("--base-url")
    parser.add_argument("--hook-coverage-dir")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--config-target-base", default="http://web")
    parser.add_argument("--skip-validation", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    if not args.skip_validation and (not args.base_url or not args.hook_coverage_dir):
        raise SystemExit("--base-url and --hook-coverage-dir are required unless --skip-validation is used")

    payloads = [json.loads(Path(path).read_text(encoding="utf-8-sig")) for path in args.input_file]
    if args.skip_validation:
        report = build_recursive_seed_report(payloads, max_hook_depth=args.max_hook_depth)
        validation = {"schema_version": 1, "summary": {"total": 0, "callback_reached": 0}, "validations": []}
    else:
        report, validation = run_recursive_child_hook_seeds(
            payloads,
            base_url=args.base_url,
            hook_coverage_dir=args.hook_coverage_dir,
            timeout=args.timeout,
            max_hook_depth=args.max_hook_depth,
        )
    write_recursive_artifacts(
        report,
        validation,
        Path(args.output_dir),
        config_target_base=args.config_target_base,
    )
    return 0 if args.skip_validation or validation["summary"]["callback_reached"] == validation["summary"]["total"] else 1


def _registered_callbacks(payload: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    containers = (payload.get("data"), payload.get("hook_coverage"), payload)
    for container in containers:
        if isinstance(container, Mapping) and isinstance(container.get("registered_callbacks"), Mapping):
            return {
                str(callback_id): row
                for callback_id, row in container["registered_callbacks"].items()
                if isinstance(row, Mapping)
            }
    return {}


def _identity(callback: Mapping[str, Any]) -> str:
    stable_id = str(callback.get("stable_id") or "").strip()
    if stable_id:
        return f"stable:{stable_id}"
    return f"callback:{callback.get('hook_name', '')}:{callback.get('callback_id', '')}"


def _item_identity(item: Mapping[str, Any]) -> str:
    stable_id = str(item.get("stable_id") or "").strip()
    if stable_id:
        return f"stable:{stable_id}"
    return f"callback:{item.get('child_hook_name', '')}:{item.get('callback_id', '')}"


def _provenance(callback: Mapping[str, Any], hook_level: int) -> dict[str, Any]:
    callback_id = str(callback.get("callback_id") or callback.get("callback_repr") or "")
    hook_name = str(callback.get("hook_name") or "")
    return {
        "generated_from": "child_hook",
        "hook_level": hook_level,
        "recursive_depth": hook_level,
        "parent_callback": dict(callback["parent_callback"]),
        "child_hook_name": hook_name,
        "child_callback": callback_id,
        "hook_name": hook_name,
        "callback_id": callback_id,
        "callback_name": str(callback.get("callback_repr") or callback_id),
        "stable_id": callback.get("stable_id"),
        "source_file": callback.get("source_file"),
        "source_line": _integer(callback.get("source_line")),
    }


def _seed_for_callback(
    callback: Mapping[str, Any],
    extractor: InputSignatureExtractor,
) -> tuple[dict[str, Any] | None, str]:
    classified = _classify_callback(_normalize_callback(dict(callback)), 1)
    seed = seed_template_for_callback(str(callback.get("hook_name") or ""), callback)
    if seed is None and str(callback.get("hook_name") or "") == "rest_api_init":
        seed = rest_seed_template(callback)
    if seed is None:
        return None, str(classified.get("reason") or "Unsupported child hook")

    input_params = extractor.extract(dict(callback)).get("input_params", [])
    decisions = resolve_http_methods(
        input_params=input_params,
        route_declared_methods=(
            callback.get("methods", callback.get("method"))
            if str(seed.get("entrypoint_type")) == "rest_route"
            else None
        ),
        runtime_observation=(
            callback.get("_executed_callback")
            if isinstance(callback.get("_executed_callback"), Mapping)
            else None
        ),
        expected_callback=callback,
    )
    decision = decisions[0]
    if decision["method_status"] != "resolved":
        return None, "HTTP method is ambiguous without source, route, or correlated runtime evidence"
    seed.update(decision)
    if len(decisions) > 1:
        seed["methods"] = decision["candidate_methods"]
    method = str(decision["resolved_method"])
    seed.setdefault("headers", {})
    seed.setdefault("query_params", {})
    seed.setdefault("cookies", {})
    seed.setdefault("fuzzable_params", [])
    seed.setdefault("discovered_file_params", [])
    action = seed["body"].pop("action", seed["query_params"].pop("action", None))
    if action is not None:
        target = seed["query_params"] if method in {"GET", "DELETE", "OPTIONS", "HEAD"} else seed["body"]
        target["action"] = action
    seed["input_params"] = input_params
    for item in input_params:
        name = str(item.get("name") or "").strip()
        source = str(item.get("source") or "REQUEST").upper()
        if not name or name in seed["fixed_params"]:
            continue
        if source == "FILES":
            seed["discovered_file_params"].append(item)
            continue
        target = (
            seed["query_params"]
            if source == "GET" or (source == "REQUEST" and method == "GET")
            else seed["cookies"]
            if source == "COOKIE"
            else seed["body"]
        )
        target.setdefault(name, "FUZZ")
        seed["fuzzable_params"].append(name)
    return seed, "supported_http_seed"


def _candidate_from_seed(item: Mapping[str, Any]) -> dict[str, Any]:
    seed = item["seed"]
    return {
        "candidate_id": item["callback_id"],
        "hook_name": item["child_hook_name"],
        "callback_id": item["callback_id"],
        "callback_repr": item["callback_name"],
        "http_template": {
            "method": seed["method"],
            "path": seed["path"],
            "query_params": seed.get("query_params", {}),
            "body_params": seed.get("body", {}),
            "headers": seed.get("headers", {}),
        },
    }


def _validate_item(
    item: Mapping[str, Any],
    *,
    base_url: str,
    hook_coverage_dir: str | Path,
    timeout: float,
    validator: Callable[..., dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    result = validator(
        candidate=_candidate_from_seed(item),
        base_url=base_url,
        hook_coverage_dir=hook_coverage_dir,
        timeout=timeout,
    )
    outcome = result.get("result", {})
    return result, {
        "expected_hook": item["child_hook_name"],
        "expected_callback": item["callback_id"],
        "callback_reached": bool(outcome.get("expected_callback_reached")),
        "parent_callback": item["parent_callback"],
        "hook_level": item["hook_level"],
        "recursive_depth": item["recursive_depth"],
        "request": result.get("request"),
        "status": outcome.get("status"),
        "reason": outcome.get("reason"),
    }


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


if __name__ == "__main__":
    raise SystemExit(main())
