"""Score existing online-linked runs against experiment reference configs.

Offline only: reads ``output/online-linked/*`` and the experiment reference
directories, reuses ``compare_configs`` for MATCH status, and adds
name-level recall/precision and fixed/fuzz agreement so changes can be
compared against a saved baseline report.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

from .cli import _load_json
from .comparator import compare_configs
from .identity import request_identity
from .models import NormalizedConfig, Status
from .normalizer import normalize_config
from .online_linked import COMPARISON_POLICY, _VALID_CAMPAIGN_STATUSES, _output_conflicts, _write_json_atomic


SECTIONS = ("query_params", "body_params", "headers", "cookies")
METRICS = (
    "hook_recall", "param_recall", "param_precision", "classification_agreement", "match_count",
    "request_param_recall", "request_param_precision",
)
_REFERENCE_DIR = re.compile(r"^\d+-(?P<slug>.+?)(?:\.\d[\w.]*)?\.zip$")


def reference_slug(dirname: str) -> str | None:
    match = _REFERENCE_DIR.match(dirname)
    return match.group("slug") if match else None


def _is_ignored(source: str, name: str) -> bool:
    # Generated configs always declare Content-Type; references never do. Not a discovery signal.
    return source == "headers" and name.lower() == "content-type"


def _literal_name(pattern: str) -> str | None:
    """Selector that names exactly one parameter (e.g. ``option_id``, ``Content\\-Type``)."""
    if not pattern or set(re.sub(r"\\.", "", pattern)) & set(".^$*+?{}[]|()\\"):
        return None
    return re.sub(r"\\(.)", r"\1", pattern)


def _declared_params(config: NormalizedConfig) -> set[tuple[str, str]]:
    names = set()
    for source in SECTIONS:
        names.update((source, name) for name in config.parameters.get(source, {}))
        selectors = config.selectors.get(source, {})
        for pattern in selectors.get("fixed", frozenset()) | selectors.get("fuzz", frozenset()):
            literal = _literal_name(pattern)
            if literal:
                names.add((source, literal))
    return names


def _classify(config: NormalizedConfig, source: str, name: str) -> str:
    selectors = config.selectors.get(source, {})
    for kind in ("fixed", "fuzz"):
        if any(re.fullmatch(pattern, name) for pattern in selectors.get(kind, frozenset())):
            return kind
    return "unclassified"


def _hook_key(config: NormalizedConfig) -> str:
    path = urlsplit(config.target).path
    family = "ajax" if path.endswith("/wp-admin/admin-ajax.php") else "admin_post" if path.endswith("/wp-admin/admin-post.php") else None
    if family is None:
        identity = request_identity(config)
        return f"{identity.family}:{identity.endpoint}"
    # Query action first: when POST `action` is fuzzed it appears in both sections, and the query value names the hook.
    for source in ("query_params", "body_params"):
        value = config.parameters.get(source, {}).get("action", {}).get("value")
        if isinstance(value, str) and value:
            return f"{family}:{value}"
    raise ValueError("missing_action")


def _reference_auth(path: Path) -> str:
    # Experiment configs mark the unauthenticated variant only by filename: fuzzer-config.nopriv_<action>.json
    return "nopriv" if path.name.startswith("fuzzer-config.nopriv_") else "priv"


def _export_auth(hook: str) -> str:
    return "nopriv" if hook.startswith(("wp_ajax_nopriv_", "admin_post_nopriv_")) else "priv"


def _hook_label(key: tuple[str, str]) -> str:
    return key[0] if key[1] == "priv" else f"{key[0]} (nopriv)"


def _request_view(params: set[tuple[str, str]]) -> set[tuple[str, str]]:
    # $_REQUEST merges GET and POST (cookies excluded by PHP's default request_order "GP").
    return {("request" if source in ("query_params", "body_params") else source, name) for source, name in params}


def _label(param: tuple[str, str]) -> str:
    return f"{param[0]}:{param[1]}"


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _metrics(counts: Counter) -> dict[str, Any]:
    return {
        "hook_recall": _ratio(counts["paired_reference_hooks"], counts["reference_hooks"]),
        "param_recall": _ratio(counts["hit_params"], counts["reference_params"]),
        "param_precision": _ratio(counts["hit_params"], counts["actual_params"]),
        "classification_agreement": _ratio(counts["agreed_params"], counts["shared_params"]),
        "match_count": counts["match_count"],
        "request_param_recall": _ratio(counts["request_hit_params"], counts["request_reference_params"]),
        "request_param_precision": _ratio(counts["request_hit_params"], counts["request_actual_params"]),
    }


def _load_config(path: Path) -> tuple[dict | None, NormalizedConfig | None, str | None]:
    raw, error = _load_json(path)
    if error is not None:
        return None, None, error["message"]
    result = normalize_config(raw, COMPARISON_POLICY)
    if result.errors:
        return None, None, "; ".join(f"{e.path} {e.message}" for e in result.errors)
    return raw, result.config, None


def _load_references(directory: Path, errors: list[str]) -> dict[tuple[str, str], tuple[Path, dict, NormalizedConfig]]:
    references: dict[tuple[str, str], tuple[Path, dict, NormalizedConfig]] = {}
    duplicates: set[tuple[str, str]] = set()
    for path in sorted(directory.rglob("fuzzer-config*.json")):
        raw, config, error = _load_config(path)
        if error is None:
            try:
                key = (_hook_key(config), _reference_auth(path))
            except ValueError as exc:
                error = str(exc)
        if error is not None:
            errors.append(f"reference {path}: {error}")
            continue
        if key in references:
            duplicates.add(key)
        references[key] = (path, raw, config)
    for key in sorted(duplicates):
        errors.append(f"reference hook {_hook_label(key)} is declared by more than one config; excluded")
        references.pop(key)
    return references


def _load_exports(run_dir: Path, errors: list[str], counts: Counter) -> list[tuple[str, Path, dict, NormalizedConfig]] | None:
    """Return None when the summary cannot be read: then nothing was scored."""
    summary, error = _load_json(run_dir / "final-config-summary.json")
    if error is not None:
        errors.append(f"final-config-summary: {error['message']}")
        return None
    if not isinstance(summary, dict) or not isinstance(summary.get("candidates"), list):
        errors.append("final-config-summary: expected an object with a candidates list")
        return None
    if not all(isinstance(candidate, dict) for candidate in summary["candidates"]):
        errors.append("final-config-summary: every candidate must be an object")
        return None
    exports = []
    for candidate in summary["candidates"]:
        hook = candidate.get("hook_name")
        selected = candidate.get("selected_version")
        if selected is None:
            counts["unexported_candidates"] += 1
            continue
        exported = candidate.get("exported_configs", [])
        if not isinstance(exported, list) or not all(isinstance(e, dict) for e in exported):
            errors.append(f"{hook}: exported_configs must be a list of objects")
            continue
        if not isinstance(hook, str) or not hook:
            errors.append(f"candidate with selected_version {selected!r}: hook_name must be a non-empty string")
            continue
        entry = next((e for e in exported if e.get("version") == selected), None)
        # Older summaries (before exported_configs) carry the selected path on the candidate itself.
        config_path = (entry or candidate).get("config_path")
        if not isinstance(config_path, str) or not config_path:
            errors.append(f"{hook}: selected_version {selected!r} has no exported config path")
            continue
        path = run_dir / "final-configs" / PureWindowsPath(config_path).name
        raw, config, error = _load_config(path)
        if error is not None:
            errors.append(f"{hook}: {path}: {error}")
            continue
        exports.append((hook, path, raw, config))
    return exports


def _score_pair(reference: tuple[Path, dict, NormalizedConfig], export: tuple[str, Path, dict, NormalizedConfig], counts: Counter) -> dict:
    ref_path, ref_raw, ref_config = reference
    hook, path, raw, config = export
    ref_params = {p for p in _declared_params(ref_config) if not _is_ignored(*p)}
    all_actual = _declared_params(config)
    actual_params = {p for p in all_actual if not _is_ignored(*p)}
    shared = ref_params & actual_params
    mismatched = sorted(p for p in shared if _classify(ref_config, *p) != _classify(config, *p))
    status = compare_configs(ref_raw, raw, COMPARISON_POLICY).status
    ref_request, actual_request = _request_view(ref_params), _request_view(actual_params)

    counts.update({
        "request_reference_params": len(ref_request),
        "request_actual_params": len(actual_request),
        "request_hit_params": len(ref_request & actual_request),
        "reference_params": len(ref_params),
        "actual_params": len(actual_params),
        "hit_params": len(shared),
        "shared_params": len(shared),
        "agreed_params": len(shared) - len(mismatched),
        "match_count": int(status == Status.MATCH),
    })
    return {
        "hook": hook,
        "config": str(path),
        "reference": str(ref_path),
        "comparison_status": status.value,
        "missing_params": sorted(map(_label, ref_params - actual_params)),
        "extra_params": sorted(map(_label, actual_params - ref_params)),
        "ignored_params": sorted(map(_label, all_actual - actual_params)),
        "classification_mismatches": [_label(p) for p in mismatched],
    }


def _score_plugin(run_dir: Path, batch: dict, reference_dir: Path) -> dict:
    errors: list[str] = []
    references = _load_references(reference_dir, errors)
    counts: Counter = Counter({"reference_hooks": len(references), "unexported_candidates": 0})
    errors_before_exports = len(errors)
    exports = _load_exports(run_dir, errors, counts)
    if exports is None:
        return {"status": "INVALID_EXPORT_SUMMARY", "run": run_dir.name, "reference_dir": str(reference_dir),
                "errors": errors}
    pairs, unreferenced, paired_keys = [], [], set()
    for export in exports:
        try:
            action_key = _hook_key(export[3])
        except ValueError as exc:
            errors.append(f"{export[0]}: {export[1]}: {exc}")
            continue
        key = (action_key, _export_auth(export[0]))
        if key not in references:
            # Reference declares one variant only: it covers every export of that action.
            variants = [k for k in references if k[0] == action_key]
            key = variants[0] if len(variants) == 1 else None
        if key is None:
            unreferenced.append(export[0])
            continue
        paired_keys.add(key)
        pairs.append(_score_pair(references[key], export, counts))
    if not pairs and not unreferenced and len(errors) > errors_before_exports:
        # Every selected export failed to load: nothing was scored, so 0 coverage would be a lie.
        return {"status": "INVALID_EXPORTS", "run": run_dir.name, "reference_dir": str(reference_dir),
                "errors": errors}
    counts["paired_reference_hooks"] = len(paired_keys)
    reasons = Counter(c.get("terminal_reason") for c in batch.get("candidates", []) if c.get("terminal_reason"))
    return {
        "status": "SCORED",
        "run": run_dir.name,
        "campaign_status": batch.get("campaign_status"),
        "reference_dir": str(reference_dir),
        "counts": dict(counts),
        "metrics": _metrics(counts),
        "terminal_reasons": dict(sorted(reasons.items())),
        "pairs": sorted(pairs, key=lambda p: p["hook"]),
        "missing_hooks": sorted(map(_hook_label, set(references) - paired_keys)),
        "unreferenced_exports": sorted(unreferenced),
        "errors": errors,
    }


def _select_runs(runs_dir: Path, skipped: list[dict]) -> dict[str, tuple[Path, dict] | None]:
    by_slug: dict[str, list[tuple[Path, dict]]] = {}
    for run_dir in sorted(p for p in runs_dir.iterdir() if p.is_dir()):
        batch, error = _load_json(run_dir / "batch-state.json")
        if error is not None or not isinstance(batch, dict) or not batch.get("plugin_slug"):
            skipped.append({"run": run_dir.name, "reason": "unreadable batch-state.json"})
            continue
        by_slug.setdefault(batch["plugin_slug"], []).append((run_dir, batch))
    selected: dict[str, tuple[Path, dict] | None] = {}
    for slug, runs in by_slug.items():
        selected[slug] = None
        for run_dir, batch in sorted(runs, key=lambda r: r[0].name, reverse=True):
            if batch.get("campaign_status") in _VALID_CAMPAIGN_STATUSES:
                selected[slug] = (run_dir, batch)
                break
            skipped.append({"run": run_dir.name, "reason": f"campaign_status={batch.get('campaign_status')}"})
    return selected


def build_report(runs_dir: Path, references_dir: Path) -> dict:
    runs_dir, references_dir = Path(runs_dir), Path(references_dir)
    for directory in (runs_dir, references_dir):
        if not directory.is_dir():
            raise ValueError(f"not a directory: {directory}")
    skipped: list[dict] = []
    selected = _select_runs(runs_dir, skipped)
    reference_dirs: dict[str, list[Path]] = {}
    for path in sorted(p for p in references_dir.iterdir() if p.is_dir()):
        slug = reference_slug(path.name)
        if slug:
            reference_dirs.setdefault(slug, []).append(path)

    plugins: dict[str, dict] = {}
    for slug in sorted(set(selected) | set(reference_dirs)):
        refs = reference_dirs.get(slug, [])
        run = selected.get(slug)
        if len(refs) > 1:
            plugins[slug] = {"status": "AMBIGUOUS_REFERENCE", "reference_dirs": [str(p) for p in refs]}
        elif not refs:
            plugins[slug] = {"status": "NO_REFERENCE"}
        elif slug not in selected:
            plugins[slug] = {"status": "NO_RUN"}
        elif run is None:
            plugins[slug] = {"status": "NO_COMPLETED_RUN"}
        else:
            plugins[slug] = _score_plugin(run[0], run[1], refs[0])

    scored = [p for p in plugins.values() if p["status"] == "SCORED"]
    totals: Counter = Counter()
    reasons: Counter = Counter()
    for plugin in scored:
        totals.update(plugin["counts"])
        reasons.update(plugin["terminal_reasons"])
    return {
        "runs_dir": str(runs_dir),
        "references_dir": str(references_dir),
        "policy": "semantic; params by (section, name), request_* merge query+body; headers:Content-Type ignored",
        "aggregate": {
            "status_counts": dict(sorted(Counter(p["status"] for p in plugins.values()).items())),
            "counts": dict(totals),
            "metrics": _metrics(totals),
            "terminal_reasons": dict(sorted(reasons.items())),
        },
        "plugins": plugins,
        "skipped_runs": skipped,
    }


def diff_baseline(baseline: dict, current: dict) -> dict:
    regressions, improvements = [], []
    for slug, before in sorted(baseline.get("plugins", {}).items()):
        if before.get("status") != "SCORED":
            continue
        after = current.get("plugins", {}).get(slug)
        if after is None or after.get("status") != "SCORED":
            regressions.append({"plugin": slug, "metric": "status", "baseline": "SCORED",
                                "current": after.get("status") if after else "MISSING"})
            continue
        for metric in METRICS:
            old, new = before["metrics"].get(metric), after["metrics"].get(metric)
            if old is None:
                continue
            entry = {"plugin": slug, "metric": metric, "baseline": old, "current": new}
            if new is None or new < old - 1e-9:
                regressions.append(entry)
            elif new > old + 1e-9:
                improvements.append(entry)
    return {"regressions": regressions, "improvements": improvements}


def _fmt(value: Any) -> str:
    return "-" if value is None else (f"{value:.2f}" if isinstance(value, float) else str(value))


def _print_summary(report: dict, output: Path) -> None:
    for slug, plugin in report["plugins"].items():
        if plugin["status"] == "SCORED":
            m = plugin["metrics"]
            print(f"{slug}: hooks={_fmt(m['hook_recall'])} recall={_fmt(m['param_recall'])} "
                  f"precision={_fmt(m['param_precision'])} class={_fmt(m['classification_agreement'])} "
                  f"match={m['match_count']} req_recall={_fmt(m['request_param_recall'])} "
                  f"req_precision={_fmt(m['request_param_precision'])} errors={len(plugin['errors'])} run={plugin['run']}")
    agg = report["aggregate"]
    print(f"Status: {agg['status_counts']}")
    print("Aggregate: " + " ".join(f"{k}={_fmt(v)}" for k, v in agg["metrics"].items()))
    print(f"Terminal reasons: {agg['terminal_reasons']}")
    print(f"Skipped runs: {len(report['skipped_runs'])}")
    diff = report.get("baseline_diff")
    if diff is not None:
        print(f"Baseline: {len(diff['regressions'])} regressions, {len(diff['improvements'])} improvements")
        for entry in diff["regressions"]:
            print(f"  REGRESSION {entry['plugin']} {entry['metric']}: {_fmt(entry['baseline'])} -> {_fmt(entry['current'])}")
    print(f"Report: {output}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score online-linked runs against experiment reference configs")
    parser.add_argument("--runs", required=True, type=Path)
    parser.add_argument("--references", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args(argv)

    baseline = None
    # The report must never replace a run, a reference config or the baseline it compares against.
    if _output_conflicts(args.output, [args.runs, args.references]):
        print("Benchmark error: --output must be outside --runs and --references", file=sys.stderr)
        return 2
    if args.baseline is not None:
        if _output_conflicts(args.output, [args.baseline]):
            print("Benchmark error: --output would overwrite --baseline", file=sys.stderr)
            return 2
        baseline, error = _load_json(args.baseline)
        if error is not None or not isinstance(baseline, dict):
            print(f"Benchmark error: baseline {args.baseline}: {error['message'] if error else 'not an object'}", file=sys.stderr)
            return 2
    try:
        report = build_report(args.runs, args.references)
    except (OSError, ValueError) as exc:
        print(f"Benchmark error: {exc}", file=sys.stderr)
        return 2
    if baseline is not None:
        report["baseline_diff"] = diff_baseline(baseline, report)
    try:
        _write_json_atomic(args.output, report)
    except (OSError, TypeError, ValueError) as exc:
        print(f"Benchmark error: cannot write {args.output}: {exc}", file=sys.stderr)
        return 2
    _print_summary(report, args.output)
    statuses = report["aggregate"]["status_counts"]
    if not statuses.get("SCORED") and (statuses.get("INVALID_EXPORT_SUMMARY") or statuses.get("INVALID_EXPORTS")):
        # Bad input left nothing scored: the report is written, but the run is not a success.
        print("Benchmark error: no run could be scored; see INVALID_EXPORT_SUMMARY/INVALID_EXPORTS errors",
              file=sys.stderr)
        return 2
    return 1 if baseline is not None and report["baseline_diff"]["regressions"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
