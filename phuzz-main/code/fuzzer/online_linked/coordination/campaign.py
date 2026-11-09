"""Run the online-linked candidate campaign and export its results."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from core.online_handoff import DEFAULT_PRIORITY_ENERGY_MODE, priority_energy_mode as _priority_energy_mode
from filesystem_paths import check_directory_io, filesystem_path
from hook_energy.seed_generation.generated_config_runner import load_finding_artifact
from hook_energy.seed_generation.online_common import _write_json
from online_linked.coordinator import OnlineLinkedCoordinator, _budget_pair
from online_linked.coordination.candidate_identity import (
    _CANDIDATE_CONTEXT_KEY_VERSION,
    _batch_candidate_identity,
    _candidate_context_key,
    _candidate_slug,
)
from online_linked.export import export_online_linked_batch


def _sync_callback_registry_to_web(registry_path: Path) -> None:
    """Reload callback targets in the running web container before child replay."""
    result = subprocess.run(
        ["docker", "compose", "ps", "-q", "web"],
        timeout=30,
        check=False,
        capture_output=True,
        text=True,
    )
    container_id = str(result.stdout or "").strip()
    if result.returncode != 0 or not container_id:
        raise RuntimeError("CALLBACK_REGISTRY_REFRESH_FAILED: web container is unavailable")
    result = subprocess.run(
        ["docker", "cp", str(registry_path), f"{container_id}:/shared/hookphuzz-callback-registry.json"],
        timeout=30,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = str(result.stderr or "").strip()
        raise RuntimeError(f"CALLBACK_REGISTRY_REFRESH_FAILED: {detail or 'docker cp failed'}")


def run_online_linked(args: argparse.Namespace) -> int:
    for name in ("max_seconds", "max_versions", "max_candidates", "campaign_seconds"):
        value = getattr(args, name, 1)
        if type(value) is not int or value < 1:
            raise ValueError(f"{name} must be a positive integer")
    max_seconds, hard_seconds = args.max_seconds, getattr(args, "hard_candidate_seconds", None)
    if hard_seconds is not None:
        max_seconds, hard_seconds = _budget_pair("candidate seconds", max_seconds,
            hard_seconds, max_seconds, max_seconds)
    max_versions, hard_versions = _budget_pair("versions", args.max_versions,
        getattr(args, "hard_max_versions", None), max(20, args.max_versions * 4), 20)
    initial_candidates = getattr(args, "max_candidates", 32)
    initial_campaign_seconds = getattr(args, "campaign_seconds", 3600)
    max_candidates, hard_max_candidates = _budget_pair("candidates", initial_candidates,
        getattr(args, "hard_max_candidates", None), max(128, initial_candidates), 128)
    campaign_seconds, hard_campaign_seconds = _budget_pair("campaign seconds", initial_campaign_seconds,
        getattr(args, "hard_campaign_seconds", None), max(86400, initial_campaign_seconds), 86400)
    suggested_path = Path(args.suggested_seeds)
    payload = json.loads(filesystem_path(suggested_path).read_text(encoding="utf-8-sig"))
    items = payload.get("suggested_seeds") if isinstance(payload, Mapping) else None
    if not isinstance(items, list):
        raise ValueError("suggested_seeds.json must contain a suggested_seeds array")

    batch_dir = Path(args.output_root) / "online-linked" / args.legacy_run_id
    check_directory_io(batch_dir)
    check_directory_io(Path(args.config_root) / "online-linked")
    candidate_input_dir = batch_dir / "candidates"
    filesystem_path(candidate_input_dir).mkdir(parents=True, exist_ok=True)
    registry_source = Path(args.callback_registry)
    batch_registry = batch_dir / "callback-registry.json"
    context = {
        "budget_policy": "progress_idle_v1",
        "plugin_slug": args.plugin_slug, "legacy_run_id": args.legacy_run_id, "service": args.service,
        "input_hash": hashlib.sha256(filesystem_path(suggested_path).read_bytes()).hexdigest(),
        "registry_hash": hashlib.sha256(filesystem_path(registry_source).read_bytes()).hexdigest(),
        "bootstrap_hash": hashlib.sha256(filesystem_path(Path(args.bootstrap_config)).read_bytes()).hexdigest()
                          if args.bootstrap_config else None,
        "config_root": str(Path(args.config_root).resolve()),
        "runtime_cookie_probes": bool(getattr(args, "runtime_cookie_probes", False)),
        "budgets": [max_seconds, hard_seconds, max_versions, hard_versions,
                    max_candidates, hard_max_candidates, campaign_seconds, hard_campaign_seconds],
    }
    resume = bool(getattr(args, "resume", False))
    if not resume:
        filesystem_path(batch_registry).write_text(filesystem_path(registry_source).read_text(encoding="utf-8-sig"), encoding="utf-8")
    batch_state: dict[str, Any] = {
        "schema_version": 1,
        "context_key_version": _CANDIDATE_CONTEXT_KEY_VERSION,
        "mode": "online-linked-batch",
        "plugin_slug": args.plugin_slug,
        "legacy_run_id": args.legacy_run_id,
        "max_seconds_per_candidate": args.max_seconds,
        "max_versions_per_candidate": args.max_versions,
        "max_candidates": max_candidates,
        "campaign_seconds": campaign_seconds,
        "hard_max_candidates": hard_max_candidates,
        "hard_campaign_seconds": hard_campaign_seconds,
        "campaign_status": "running",
        "candidates": [],
        "non_http_skipped": [],
        "expansion_events": [],
        "resume_context": context,
        "priority_energy_mode": DEFAULT_PRIORITY_ENERGY_MODE if resume else _priority_energy_mode(
            os.environ.get("HOOKPHUZZ_PRIORITY_ENERGY_MODE")),
    }
    skipped = False
    queue: list[tuple[int, Mapping[str, Any], str]] = []
    queued_ids: set[str] = set()
    queued_context_keys: set[str] = set()
    for index, raw_item in enumerate(items, start=1):
        if not isinstance(raw_item, Mapping):
            continue
        if not isinstance(raw_item.get("seed"), Mapping):
            # No HTTP seed: build_config_for_seed_item raises missing_seed and
            # bootstrap matching needs a seed, so v0 can never start.
            batch_state["non_http_skipped"].append({
                "index": index, "hook_name": str(raw_item.get("hook_name") or ""),
                "callback_id": str(raw_item.get("callback_id") or ""), "reason": "missing_seed",
            })
            continue
        identity = _batch_candidate_identity(raw_item, args.plugin_slug)
        context_key = _candidate_context_key(raw_item, args.plugin_slug)
        if context_key in queued_context_keys:
            continue
        queued_ids.add(identity)
        queued_context_keys.add(context_key)
        queue.append((index, dict(raw_item), "initial"))
    # Known input needs slots, not progress credit or extra campaign time.
    max_candidates = min(hard_max_candidates, max(initial_candidates, len(queue)))
    started_at = time.monotonic()
    campaign_deadline = started_at + campaign_seconds
    hard_campaign_deadline = campaign_deadline + hard_campaign_seconds - campaign_seconds
    progress_keys: set[tuple[str, str]] = set()
    blocked_pending: list[tuple[int, Mapping[str, Any], str]] = []
    active_entry: tuple[int, Mapping[str, Any], str] | None = None
    batch_state_path = batch_dir / "batch-state.json"
    if resume:
        saved = json.loads(batch_state_path.read_text(encoding="utf-8-sig"))
        if (saved.get("resume_context") or {}).get("budget_policy") != "progress_idle_v1":
            raise ValueError("resume budget policy incompatible; create a new run")
        if saved.get("context_key_version") != _CANDIDATE_CONTEXT_KEY_VERSION:
            raise ValueError("resume batch context-key version missing or unsupported")
        if not isinstance(saved.get("queued_context_keys"), list):
            raise ValueError("resume batch context-key queue is missing")
        if saved.get("resume_context") != context:
            raise ValueError("resume campaign context or budgets changed")
        budget = saved["budget"]
        offline_seconds = max(0.0, time.time() - budget["saved_at"])
        campaign_deadline = started_at + max(0.0, budget["remaining_seconds"] - offline_seconds)
        hard_campaign_deadline = started_at + max(0.0, budget["hard_remaining_seconds"] - offline_seconds)
        max_candidates = saved["effective_max_candidates"]
        progress_keys = {tuple(key) for key in budget["progress_keys"]}
        batch_state = saved
        queue = [(row["index"], row["item"], row["source"]) for row in saved["pending_candidates"]]
        queued_ids = set(saved["queued_ids"])
        queued_context_keys = set(saved["queued_context_keys"])
        batch_state.update(campaign_status="running", terminal_reason=None)
        # The saved mode wins; a checkpoint from before the option uses the default.
        batch_state["priority_energy_mode"] = _priority_energy_mode(saved.get("priority_energy_mode"))
        skipped = any(row.get("terminal_status") == "NOT_VERIFIED" for row in saved["candidates"])

    def checkpoint(registry: Mapping[str, Any] | None = None) -> None:
        now = time.monotonic()
        records = {row["index"]: row for row in batch_state["candidates"]}
        batch_state["pending_candidates"] = [
            {"index": index, "item": dict(item), "source": source,
             "state_path": records.get(index, {}).get("state_path"),
             "terminal_reason": records.get(index, {}).get("terminal_reason")}
            for index, item, source in queue + ([active_entry] if active_entry else []) + blocked_pending
        ]
        registry_bytes = batch_registry.read_bytes()
        if registry is not None:
            batch_state["registry_previous_hash"] = hashlib.sha256(registry_bytes).hexdigest()
            # Match the existing atomic JSON writer, including Windows newlines.
            registry_text = json.dumps(registry, indent=2, ensure_ascii=False) + "\n"
            registry_bytes = registry_text.replace("\n", os.linesep).encode("utf-8")
            batch_state["registry_snapshot"] = registry_bytes.decode("utf-8")
        else:
            batch_state.pop("registry_previous_hash", None)
            batch_state.pop("registry_snapshot", None)
        batch_state.update(effective_max_candidates=max_candidates, queued_ids=sorted(queued_ids),
                           queued_context_keys=sorted(queued_context_keys),
                           campaign_deadline=campaign_deadline, hard_campaign_deadline=hard_campaign_deadline,
                           registry_snapshot_hash=hashlib.sha256(registry_bytes).hexdigest())
        batch_state["budget"] = {
            "remaining_seconds": max(0.0, campaign_deadline - now),
            "hard_remaining_seconds": max(0.0, hard_campaign_deadline - now),
            "progress_keys": sorted(progress_keys), "saved_at": time.time(),
        }
        _write_json(batch_state_path, batch_state)
        if registry is not None:
            # Commit the recoverable snapshot before publishing the mutable file.
            _write_json(batch_registry, registry)

    if resume and hashlib.sha256(batch_registry.read_bytes()).hexdigest() != batch_state["registry_snapshot_hash"]:
        snapshot = batch_state.get("registry_snapshot", "").encode("utf-8")
        if (hashlib.sha256(batch_registry.read_bytes()).hexdigest() != batch_state.get("registry_previous_hash")
                or hashlib.sha256(snapshot).hexdigest() != batch_state["registry_snapshot_hash"]):
            raise ValueError("resume campaign registry snapshot changed")
        _write_json(batch_registry, json.loads(snapshot))
    if resume and bool(getattr(args, "sync_registry", False)) and queue:
        _sync_callback_registry_to_web(batch_registry)

    initial_context_keys = {_candidate_context_key(item, args.plugin_slug)
                            for item in items if isinstance(item, Mapping)}

    def credit_progress(kind: str, key: str) -> float | None:
        nonlocal campaign_deadline, max_candidates
        identity = (kind, key)
        if identity in progress_keys:
            return None
        if time.monotonic() < campaign_deadline:
            if kind == "runtime_callback" and key in initial_context_keys:
                return None
            progress_keys.add(identity)
            campaign_deadline = min(hard_campaign_deadline,
                                    campaign_deadline + args.max_seconds)
            if kind == "runtime_callback":
                max_candidates = min(hard_max_candidates, max_candidates + 1)
            checkpoint()
        return campaign_deadline

    next_index = max([entry[0] for entry in queue] + [row["index"] for row in batch_state["candidates"]] + [0]) + 1
    while queue:
        queue.sort(key=lambda entry: not str(entry[1].get("hook_name") or "").startswith("wp_ajax_"))
        previous = next((row for row in batch_state["candidates"] if row["index"] == queue[0][0]), None)
        if previous is None and len(batch_state["candidates"]) >= max_candidates:
            reason = "HARD_CANDIDATE_COUNT_CAP" if max_candidates >= hard_max_candidates else "CANDIDATE_BUDGET_EXPIRED"
            batch_state["campaign_status"] = reason
            batch_state["expansion_events"].append({"reason": reason})
            break
        if time.monotonic() >= campaign_deadline:
            reason = "HARD_CAMPAIGN_TIME_CAP" if campaign_deadline >= hard_campaign_deadline else "CAMPAIGN_BUDGET_EXPIRED"
            batch_state["campaign_status"] = reason
            batch_state["expansion_events"].append({"reason": reason})
            break
        index, raw_item, source = queue.pop(0)
        previous = next((row for row in batch_state["candidates"] if row["index"] == index), None)
        if previous and previous.get("terminal_status") != "PARTIAL":
            continue
        slug = _candidate_slug(raw_item, index)
        candidate_run_id = f"{args.legacy_run_id}-candidate-{slug}"
        candidate_input = candidate_input_dir / f"{slug}.json"
        candidate_record = {
            "index": index,
            "hook_name": str(raw_item.get("hook_name") or ""),
            "callback_id": str(raw_item.get("callback_id") or ""),
            "run_id": candidate_run_id,
            "identity": _batch_candidate_identity(raw_item, args.plugin_slug),
            "context_key": _candidate_context_key(raw_item, args.plugin_slug),
            "source": source,
            "item": dict(raw_item),
            "input_path": str(candidate_input),
        }
        if isinstance(raw_item.get("lineage"), Mapping):
            candidate_record["lineage"] = dict(raw_item["lineage"])
        try:
            filesystem_path(candidate_input).write_text(
                json.dumps({**payload, "suggested_seeds": [dict(raw_item)]}, indent=2) + "\n",
                encoding="utf-8",
            )
            if previous is None:
                batch_state["candidates"].append(candidate_record)
            else:
                batch_state["candidates"][batch_state["candidates"].index(previous)] = candidate_record
            candidate_record.update(terminal_status="PARTIAL", terminal_reason="CANDIDATE_INTERRUPTED",
                                    state_path=(previous or {}).get("state_path"))
            active_entry = (index, raw_item, source)
            checkpoint()
            coordinator = OnlineLinkedCoordinator(
                suggested_seeds=candidate_input,
                bootstrap_config=Path(args.bootstrap_config) if args.bootstrap_config else None,
                config_root=Path(args.config_root),
                output_root=Path(args.output_root),
                plugin_slug=args.plugin_slug,
                legacy_run_id=candidate_run_id,
                max_seconds=args.max_seconds,
                max_versions=args.max_versions,
                runtime_cookie_probes=bool(getattr(args, "runtime_cookie_probes", False)),
                registry_path=batch_registry,
                service=args.service,
                load_finding_artifact=load_finding_artifact,
                campaign_deadline=campaign_deadline,
                campaign_dir=batch_dir,
                hard_seconds=hard_seconds,
                hard_versions=hard_versions,
                resume=bool(previous and previous.get("state_path") and Path(previous["state_path"]).is_file()),
                progress_callback=lambda kind, key, identity=candidate_record["identity"]:
                    credit_progress(kind, key if kind == "runtime_callback" else identity + ":" + key),
                registry_checkpoint_callback=checkpoint,
                priority_energy_mode=batch_state["priority_energy_mode"],
            )
            candidate_record["state_path"] = str(coordinator.state_path)
            checkpoint()
            result = coordinator.run()
            skipped = skipped or result != 0 or coordinator.state.get("terminal_status") in {"NOT_VERIFIED", "PARTIAL"}
            candidate_record.update({
                "exit_code": result,
                "state_path": str(coordinator.state_path),
                "terminal_status": coordinator.state.get("terminal_status"),
                "terminal_reason": coordinator.state.get("terminal_reason"),
                "versions": len(coordinator.state.get("versions", [])),
            })
            if coordinator.state.get("terminal_status") == "PARTIAL":
                blocked_pending.append((index, dict(raw_item), source))
            for child in coordinator.state.get("candidate_queue", []):
                if not isinstance(child, Mapping):
                    continue
                child_identity = _batch_candidate_identity(child, args.plugin_slug)
                child_context_key = _candidate_context_key(child, args.plugin_slug)
                if child_context_key in queued_context_keys:
                    continue
                queued_ids.add(child_identity)
                queued_context_keys.add(child_context_key)
                child_item = {**dict(child), "context_key": child_context_key}
                child_entry = (next_index, child_item, "runtime_registration")
                next_index += 1
                if time.monotonic() >= campaign_deadline:
                    batch_state["campaign_status"] = "CAMPAIGN_BUDGET_EXPIRED"
                    batch_state["expansion_events"].append({
                        "reason": "CAMPAIGN_BUDGET_EXPIRED",
                        "identity": child_identity,
                        "context_key": child_context_key,
                        "lineage": dict(child.get("lineage") or {}),
                    })
                    queue.append(child_entry)
                    continue
                # The coordinator already credited real discoveries. This also
                # supports stored/fake queues without granting duplicate credit.
                credit_progress("runtime_callback", child_context_key)
                if bool(getattr(args, "sync_registry", False)):
                    try:
                        _sync_callback_registry_to_web(batch_registry)
                    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
                        batch_state["expansion_events"].append({
                            "reason": "CALLBACK_REGISTRY_REFRESH_FAILED",
                            "identity": child_identity,
                            "context_key": child_context_key,
                            "detail": str(exc),
                            "lineage": dict(child.get("lineage") or {}),
                        })
                        skipped = True
                        blocked_pending.append(child_entry)
                        continue
                    if time.monotonic() >= campaign_deadline:
                        batch_state["campaign_status"] = "CAMPAIGN_BUDGET_EXPIRED"
                        batch_state["expansion_events"].append({
                            "reason": "CAMPAIGN_BUDGET_EXPIRED",
                            "identity": child_identity,
                            "context_key": child_context_key,
                            "lineage": dict(child.get("lineage") or {}),
                        })
                        queue.append(child_entry)
                        continue
                queue.append(child_entry)
        except Exception as exc:
            # Candidate-local failures must not discard the remaining batch.
            skipped = True
            candidate_record.update({
                "exit_code": 2,
                "state_path": candidate_record.get("state_path", ""),
                "terminal_status": "PARTIAL" if previous else "NOT_VERIFIED",
                "terminal_reason": f"CANDIDATE_FAILED: {type(exc).__name__}: {exc}",
                "versions": candidate_record.get("versions", 0),
            })
            if previous:
                blocked_pending.append((index, dict(raw_item), source))
        active_entry = None
        if candidate_record not in batch_state["candidates"]:
            batch_state["candidates"].append(candidate_record)
        checkpoint()

    if batch_state["campaign_status"] == "running" and time.monotonic() >= campaign_deadline:
        batch_state["campaign_status"] = "CAMPAIGN_BUDGET_EXPIRED"
        batch_state["expansion_events"].append({"reason": "CAMPAIGN_BUDGET_EXPIRED"})
    if batch_state["campaign_status"] == "running":
        batch_state["campaign_status"] = "complete_with_skips" if skipped else "complete"
    if queue or blocked_pending or any(row.get("terminal_status") == "PARTIAL" for row in batch_state["candidates"]):
        batch_state["terminal_reason"] = (batch_state["campaign_status"] if batch_state["campaign_status"]
            not in {"complete", "complete_with_skips"} else next(
                (row.get("terminal_reason") for row in batch_state["candidates"] if row.get("terminal_status") == "PARTIAL"),
                "CALLBACK_REGISTRY_REFRESH_FAILED"))
        batch_state["campaign_status"] = "PARTIAL"
        batch_state["stop_reasons"] = list(dict.fromkeys([
            batch_state["terminal_reason"],
            *(row.get("terminal_reason") for row in batch_state["candidates"] if row.get("terminal_status") == "PARTIAL"),
        ]))

    checkpoint()
    try:
        export_online_linked_batch(batch_state_path)
    except Exception as exc:
        print(f"EXPORT_FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f"Online-linked batch state: {batch_state_path}")
    print(f"Online-linked campaign status: {batch_state['campaign_status']}")
    print(f"Online-linked candidates: {len(batch_state['candidates'])}")
    print(
        "Online-linked terminal statuses: "
        + json.dumps(
            {
                status: sum(row.get("terminal_status") == status for row in batch_state["candidates"])
                for status in sorted({str(row.get("terminal_status") or "") for row in batch_state["candidates"]})
            },
            sort_keys=True,
        )
    )
    return 0


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run online-linked Zend expansion with immutable workers.")
    parser.add_argument("--suggested-seeds", required=True)
    parser.add_argument("--bootstrap-config", default="")
    parser.add_argument("--config-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--plugin-slug", required=True)
    parser.add_argument("--legacy-run-id", required=True)
    parser.add_argument("--callback-registry", required=True)
    parser.add_argument("--max-seconds", type=int, choices=range(1, 121), default=120, help="Initial candidate seconds (default 120)")
    parser.add_argument("--max-versions", type=int, choices=range(1, 21), default=2, help="Initial versions including v0 (default 2)")
    parser.add_argument("--max-candidates", type=int, choices=range(1, 129), default=32, help="Initial candidate slots (default 32)")
    parser.add_argument("--campaign-seconds", type=int, choices=range(1, 86401), default=3600, help="Initial campaign seconds (default 3600)")
    parser.add_argument("--hard-max-candidates", type=int, help="Absolute candidate cap (default max(128, initial))")
    parser.add_argument("--hard-campaign-seconds", type=int, help="Absolute campaign seconds (default max(86400, initial))")
    parser.add_argument("--hard-candidate-seconds", type=int, help="Absolute candidate seconds (default: no candidate hard cap)")
    parser.add_argument("--hard-max-versions", type=int, help="Absolute versions including v0 (default max(20, 4 * initial))")
    parser.add_argument("--resume", action="store_true", help="Reload this run's checkpoint; retain caps and credits, recheck gates")
    parser.add_argument("--sync-registry", action="store_true")
    parser.add_argument("--runtime-cookie-probes", action="store_true")
    parser.add_argument("--service", default="fuzzer-wordpress-plugin")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    try:
        return run_online_linked(args)
    except (OSError, ValueError) as exc:
        print(f"Online-linked failed: {exc}", file=sys.stderr)
        return 2
