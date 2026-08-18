from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


SUCCESS_STATUSES = frozenset({
    "PASS",
    "SUCCESS",
    "CONVERGED",
    "PASS_PARTIAL_AUTH_EXPECTED",
})

PRUNABLE_RUN_ARTIFACTS = (
    "hookphuzz-callback-registry.json",
    "pass1-configs",
    "pass1-generated_config_summary.json",
    "pass1-generated_config_run_summary.json",
    "targets",
    "current",
    "logs",
    "zend_convergence_targets.json",
    "final-generated_config_summary.json",
    "generated_param_summary.json",
    "validation_result.json",
)

PRUNABLE_SEED_ARTIFACTS = (
    "suggested_seeds.json",
    "runtime_coverage_snapshot.json",
)


class RetentionError(RuntimeError):
    pass


@dataclass(frozen=True)
class RetentionResult:
    terminal_status: str
    decision: str
    kept: int
    pruned: int
    debug_artifacts: bool


def is_success_status(status: str) -> bool:
    return str(status or "").strip().upper() in SUCCESS_STATUSES


def retain_artifacts(
    run_dir: str | Path,
    *,
    terminal_status: str,
    seed_output_dir: str | Path | None = None,
    merged_suggested_seeds: str | Path | None = None,
    final_config_summary: str | Path | None = None,
    final_run_summary: str | Path | None = None,
    zend_discovery_run_dir: str | Path | None = None,
    keep_debug_artifacts: bool = False,
) -> RetentionResult:
    run_path = _validate_run_dir(run_dir)
    seed_path = _validate_seed_dir(seed_output_dir) if seed_output_dir is not None else None
    zend_discovery_path = (
        _validate_zend_discovery_dir(zend_discovery_run_dir, run_path.name)
        if zend_discovery_run_dir is not None
        else None
    )
    merged_path = Path(merged_suggested_seeds).resolve() if merged_suggested_seeds is not None else None
    normalized_status = str(terminal_status or "").strip().upper()

    if not is_success_status(normalized_status) or keep_debug_artifacts:
        return RetentionResult(
            terminal_status=normalized_status,
            decision="PRESERVED",
            kept=_count_entries(run_path),
            pruned=0,
            debug_artifacts=bool(keep_debug_artifacts),
        )

    _validate_retained_artifacts(
        run_path,
        seed_path,
        final_config_summary=final_config_summary,
        final_run_summary=final_run_summary,
    )

    pruned = 0
    for relative_path in PRUNABLE_RUN_ARTIFACTS:
        pruned += _remove_artifact(run_path / relative_path)
    if seed_path is not None:
        seed_artifacts = PRUNABLE_SEED_ARTIFACTS
        if not _can_prune_suggested_seeds(seed_path, merged_path):
            seed_artifacts = tuple(name for name in seed_artifacts if name != "suggested_seeds.json")
        for name in seed_artifacts:
            pruned += _remove_artifact(seed_path / name)
    if zend_discovery_path is not None:
        pruned += _remove_artifact(zend_discovery_path)

    return RetentionResult(
        terminal_status=normalized_status,
        decision="SUCCESS",
        kept=_count_entries(run_path),
        pruned=pruned,
        debug_artifacts=False,
    )


def _validate_run_dir(value: str | Path) -> Path:
    path = Path(value).resolve()
    if path.name in {"", ".", ".."} or path.parent.name != "zend-bridge":
        raise RetentionError(f"Refusing retention outside zend-bridge/<run_id>: {path}")
    if not path.is_dir():
        raise RetentionError(f"Zend run directory does not exist: {path}")
    return path


def _validate_seed_dir(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    path = Path(value).resolve()
    if path.name != "seed_generation":
        raise RetentionError(f"Refusing retention outside seed_generation: {path}")
    if not path.is_dir():
        raise RetentionError(f"Seed output directory does not exist: {path}")
    return path


def _validate_zend_discovery_dir(value: str | Path, run_name: str) -> Path:
    path = Path(value).resolve()
    if path.name != run_name or path.parent.name != "zend-discovery":
        raise RetentionError(f"Refusing retention outside zend-discovery/<run_id>: {path}")
    return path


def _validate_retained_artifacts(
    run_path: Path,
    seed_path: Path | None,
    *,
    final_config_summary: str | Path | None,
    final_run_summary: str | Path | None,
) -> None:
    required = [run_path / "zend_convergence_summary.json", run_path / "final"]
    resolved_final_run = Path(final_run_summary).resolve() if final_run_summary is not None else None
    if resolved_final_run is None:
        for candidate in (
            run_path / "final-generated_config_run_summary.json",
            run_path / "final" / "generated_config_run_summary.json",
        ):
            if candidate.is_file():
                resolved_final_run = candidate
                break
    if resolved_final_run is not None:
        if not _is_within(resolved_final_run, run_path):
            raise RetentionError(f"Final replay summary is outside current run: {resolved_final_run}")
        required.append(resolved_final_run)
    else:
        required.append(run_path / "final-generated_config_run_summary.json")

    if final_config_summary is not None:
        config_summary_path = Path(final_config_summary).resolve()
        if seed_path is not None and not _is_within(config_summary_path, seed_path):
            raise RetentionError(f"Final config summary is outside seed_generation: {config_summary_path}")
        required.append(config_summary_path)

    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise RetentionError("Retained final artifacts are incomplete: " + ", ".join(missing))


def _can_prune_suggested_seeds(seed_path: Path, merged_path: Path | None) -> bool:
    if merged_path is None or not merged_path.is_file():
        return False
    raw_path = seed_path / "suggested_seeds.json"
    if not raw_path.is_file():
        return False
    try:
        raw_items = json.loads(raw_path.read_text(encoding="utf-8-sig")).get("suggested_seeds")
        merged_items = json.loads(merged_path.read_text(encoding="utf-8-sig")).get("suggested_seeds")
    except (OSError, AttributeError, TypeError, json.JSONDecodeError):
        return False
    if not isinstance(raw_items, list) or not isinstance(merged_items, list):
        return False
    if len(raw_items) != len(merged_items):
        return False
    return {_seed_identity(item) for item in raw_items} == {_seed_identity(item) for item in merged_items}


def _seed_identity(item: object) -> str:
    if not isinstance(item, dict):
        return json.dumps(item, sort_keys=True, separators=(",", ":"))
    seed = item.get("seed")
    identity = {
        field: item.get(field)
        for field in ("plugin_slug", "hook_name", "callback_id", "seed_variant_id", "entrypoint_type", "route")
    }
    if isinstance(seed, dict):
        identity["seed"] = {
            field: seed.get(field) for field in ("path", "method", "auth_mode", "seed_variant_id")
        }
    return json.dumps(identity, sort_keys=True, separators=(",", ":"))


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _remove_artifact(path: Path) -> int:
    if not path.exists() and not path.is_symlink():
        return 0
    count = _count_entries(path)
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()
    return count


def _count_entries(path: Path) -> int:
    if not path.exists() and not path.is_symlink():
        return 0
    if path.is_file() or path.is_symlink():
        return 1
    return 1 + sum(1 for _ in path.rglob("*"))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Apply success-only Zend artifact retention.")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--terminal-status", required=True)
    parser.add_argument("--seed-output-dir")
    parser.add_argument("--merged-suggested-seeds")
    parser.add_argument("--final-config-summary")
    parser.add_argument("--final-run-summary")
    parser.add_argument("--zend-discovery-run-dir")
    parser.add_argument("--keep-debug-artifacts", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        result = retain_artifacts(
            args.run_dir,
            terminal_status=args.terminal_status,
            seed_output_dir=args.seed_output_dir,
            merged_suggested_seeds=args.merged_suggested_seeds,
            final_config_summary=args.final_config_summary,
            final_run_summary=args.final_run_summary,
            zend_discovery_run_dir=args.zend_discovery_run_dir,
            keep_debug_artifacts=args.keep_debug_artifacts,
        )
    except (OSError, RetentionError, ValueError) as exc:
        print(f"Artifact retention failed: {exc}", file=sys.stderr)
        return 2

    if result.decision == "SUCCESS":
        print(
            "Artifact retention: SUCCESS "
            f"kept={result.kept} pruned={result.pruned} "
            f"debug_artifacts={str(result.debug_artifacts).lower()}"
        )
    else:
        print(
            "Artifact retention: PRESERVED "
            f"status={result.terminal_status or 'UNKNOWN'} kept={result.kept} "
            f"pruned={result.pruned} debug_artifacts={str(result.debug_artifacts).lower()}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
