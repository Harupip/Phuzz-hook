"""Copy each candidate's latest verified config into one folder."""

import hashlib
import json
import re
import sys
from pathlib import Path

from hook_energy.seed_generation.online_common import config_hash


def export_online_linked_batch(batch_state_path: Path, destination: Path | None = None) -> int:
    batch = json.loads(batch_state_path.read_text(encoding="utf-8-sig"))
    destination = destination or batch_state_path.parent / "final-configs"
    destination.mkdir(parents=True, exist_ok=False)
    count = 0
    seen = set()
    summaries = []
    for candidate in batch["candidates"]:
        identity = candidate["identity"]
        if identity in seen:
            continue
        seen.add(identity)
        summary = {"identity": identity, "hook_name": candidate.get("hook_name"),
                   "selected_version": None, "skipped_versions": [], "discovery_status": "NOT_ASSESSED"}
        summaries.append(summary)
        try:
            state_path = Path(candidate["state_path"])
            if not state_path.is_absolute():
                state_path = batch_state_path.parent / state_path
            state = json.loads(state_path.read_text(encoding="utf-8-sig"))
            if (not candidate.get("run_id") or state["legacy_run_id"] != candidate["run_id"]
                    or state["plugin_slug"] != batch["plugin_slug"]):
                raise ValueError("RUN_MISMATCH")
            versions = sorted(
                (v for v in state["versions"] if re.fullmatch(r"v[0-9]+", v.get("version", ""))),
                key=lambda v: int(v["version"][1:]), reverse=True,
            )
            summary.update(
                latest_version=versions[0]["version"] if versions else None,
                terminal_status=state.get("terminal_status"), terminal_reason=state.get("terminal_reason"),
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            summary.update(discovery_status="PARTIAL", reason=str(exc))
            print(f"Config skipped {identity}: {exc}", file=sys.stderr)
            continue
        for version in versions:
            try:
                content = _verified_config(version)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                summary["skipped_versions"].append({
                    "version": version["version"], "reason": str(exc),
                    "terminal_reason": version.get("terminal_reason"),
                })
                print(f"Config skipped {identity}/{version['version']}: {exc}", file=sys.stderr)
                continue
            hook = re.sub(r"[^A-Za-z0-9_-]+", "-", candidate.get("hook_name", "hook"))[:40]
            suffix = hashlib.sha256(identity.encode()).hexdigest()[:16]
            # Exclusive creation preserves existing output; bytes retain all metadata/auth.
            with (destination / f"fuzzer-config.{hook}.{suffix}.json").open("xb") as output:
                output.write(content)
            count += 1
            summary.update(selected_version=version["version"],
                           config_path=str(destination / f"fuzzer-config.{hook}.{suffix}.json"))
            break
        summary.update(_discovery_summary(state, summary["selected_version"]))
    summary_name = "final-config-summary.json" if destination.name == "final-configs" else f"{destination.name}-summary.json"
    summary_path = destination.parent / summary_name
    summary_path.write_text(json.dumps({"schema_version": 1, "candidates": summaries}, indent=2) + "\n", encoding="utf-8")
    print(f"Final configs: {destination} ({count} files, {len(seen) - count} skipped)")
    return count


def _discovery_summary(state: dict, selected_version: str | None) -> dict:
    """Describe observed work, without claiming all possible inputs were found."""
    observed = {}
    verified = {}

    def add(rows, target):
        for row in rows or []:
            if isinstance(row, dict) and row.get("name"):
                identity = {"name": row["name"], "source": str(row.get("source") or "").upper(),
                            "location": str(row.get("location") or "").lower()}
                target[tuple(identity.values())] = identity

    for version in state.get("versions", []):
        add(version.get("known_parameters"), observed)
        if version.get("version") == selected_version:
            add(version.get("known_parameters"), verified)
        convergence = (version.get("readiness") or {}).get("convergence") or {}
        add(convergence.get("observed_parameters"), observed)
    for probe in state.get("probe_attempts", []):
        add([probe.get("candidate")], observed)
    add(state.get("pending_runtime_candidates"), observed)
    for attempt in state.get("replay_input_trials", []):
        add(attempt.get("expected_parameters"), observed)
    for event in state.get("events", []):
        if event.get("kind") == "PARAMETER_PROBE":
            add([event.get("candidate")], observed)
        elif event.get("kind") == "PARAMETER_DISCOVERY":
            add(event.get("parameters"), observed)
    pending = [observed[key] for key in sorted(observed) if key not in verified]
    reason = str(state.get("terminal_reason") or "")
    partial = bool(pending or selected_version is None or state.get("terminal_status") == "NOT_VERIFIED"
                   or "BUDGET" in reason or "LIMIT" in reason)
    return {"discovery_status": "PARTIAL" if partial else "NOT_ASSESSED",
            "verified_parameters": [verified[key] for key in sorted(verified)],
            "pending_parameters": pending}


def _verified_config(version: dict) -> bytes:
    content, config = _verified_base(version)
    if (version.get("config_type") != "fuzzing_ready" or config.get("config_type") != "fuzzing_ready"
            or version.get("probe_variant") is True
            or (config.get("metadata") or {}).get("probe_variant") is True):
        raise ValueError("NOT_FUZZING_READY")
    return content


def _verified_base(version: dict) -> tuple[bytes, dict]:
    gate = version.get("readiness" if version["version"] == "v0" else "replay_result") or {}
    pass2 = gate.get("pass2_verification") or {}
    accepted, total = pass2.get("accepted"), pass2.get("total")
    if (gate.get("passed") is not True or type(total) is not int or total <= 0
            or type(accepted) is not int or accepted != total):
        raise ValueError("GATE_NOT_VERIFIED")
    path = Path(version["config_path"])
    # Only inspect the path inside this version, not ancestor workspace names.
    parts = path.parts
    roots = [i for i, part in enumerate(parts[:-1])
             if part == "versions" and parts[i + 1] == version["version"]]
    relative_parts = parts[roots[-1] + 2:] if roots else parts[-2:]
    if any(part.lower() in {"probe", "replay"} for part in relative_parts):
        raise ValueError("PROBE_OR_REPLAY")
    content = path.read_bytes()
    config = json.loads(content.decode("utf-8-sig"))
    if config_hash(config) != version.get("config_hash"):
        raise ValueError("CONFIG_HASH_MISMATCH")
    return content, config
