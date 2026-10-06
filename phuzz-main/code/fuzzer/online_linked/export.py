"""Copy each candidate's distinct verified configs into one folder."""

import hashlib
import json
import re
import sys
from pathlib import Path

from filesystem_paths import filesystem_path

from hook_energy.seed_generation.online_common import config_hash


def export_online_linked_batch(batch_state_path: Path, destination: Path | None = None) -> int:
    batch = json.loads(filesystem_path(batch_state_path).read_text(encoding="utf-8-sig"))
    destination = destination or batch_state_path.parent / "final-configs"
    summary_name = "final-config-summary.json" if destination.name == "final-configs" else f"{destination.name}-summary.json"
    summary_path = destination.parent / summary_name
    previous = json.loads(filesystem_path(summary_path).read_text(encoding="utf-8-sig")) if filesystem_path(summary_path).exists() else {}
    filesystem_path(destination).mkdir(parents=True, exist_ok=True)
    count = 0
    seen = set()
    summaries = []
    for candidate in batch["candidates"]:
        identity = candidate["identity"]
        if identity in seen:
            continue
        seen.add(identity)
        summary = {"identity": identity, "hook_name": candidate.get("hook_name"),
                   "selected_version": None, "exported_configs": [], "skipped_versions": [],
                   "discovery_status": "NOT_ASSESSED"}
        summaries.append(summary)
        try:
            state_path = Path(candidate["state_path"])
            if not state_path.is_absolute():
                state_path = batch_state_path.parent / state_path
            state = json.loads(filesystem_path(state_path).read_text(encoding="utf-8-sig"))
            if (not candidate.get("run_id") or state["legacy_run_id"] != candidate["run_id"]
                    or state["plugin_slug"] != batch["plugin_slug"]):
                raise ValueError("RUN_MISMATCH")
            versions = sorted(
                (v for v in state["versions"] if re.fullmatch(r"v[0-9]+", v.get("version", ""))),
                key=lambda v: int(v["version"][1:]), reverse=True,
            )
            summary.update(
                state_path=str(state_path),
                latest_version=versions[0]["version"] if versions else None,
                terminal_status=state.get("terminal_status"), terminal_reason=state.get("terminal_reason"),
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            summary.update(discovery_status="PARTIAL", reason=str(exc))
            print(f"Config skipped {identity}: {exc}", file=sys.stderr)
            continue
        exported = {}
        representatives = []
        verified_versions = []
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
            # Per-request evidence changes across equivalent replays; retain it
            # in the copied bytes, but do not create another identical request.
            semantic = json.loads(content.decode("utf-8-sig"))
            if isinstance(semantic.get("metadata"), dict):
                semantic["metadata"].pop("online_request_seed", None)
                method_evidence = semantic["metadata"].get("method_evidence")
                if isinstance(method_evidence, dict):
                    for key in ("request_id", "run_id"):
                        method_evidence.pop(key, None)
            request_key = config_hash(semantic)
            verified_versions.append(version["version"])
            if request_key in exported:
                exported[request_key]["equivalent_versions"].append(version["version"])
                continue
            replacement = next((row for config, newer, row in representatives
                                if _covers_version(config, newer, semantic, version)), None)
            if replacement is not None:
                replacement["superseded_versions"].append(version["version"])
                continue
            hook = re.sub(r"[^A-Za-z0-9_-]+", "-", candidate.get("hook_name", "hook"))[:40]
            suffix = hashlib.sha256(identity.encode()).hexdigest()[:16]
            version_suffix = f".{version['version']}" if exported else ""
            config_path = destination / f"fuzzer-config.{hook}.{suffix}{version_suffix}.json"
            config_path = next((path for path in filesystem_path(destination).glob(f"fuzzer-config.{hook}.{suffix}*.json")
                                if path.read_bytes() == content), config_path)
            if filesystem_path(config_path).exists() and filesystem_path(config_path).read_bytes() != content:
                config_path = config_path.with_name(f"{config_path.stem}.{hashlib.sha256(content).hexdigest()}.json")
            # Reuse exact bytes on resume; never overwrite a prior export.
            if not filesystem_path(config_path).exists():
                with filesystem_path(config_path).open("xb") as output:
                    output.write(content)
            elif filesystem_path(config_path).read_bytes() != content:
                raise ValueError(f"EXPORTED_CONFIG_CHANGED: {config_path}")
            count += 1
            row = {"version": version["version"], "config_path": str(config_path),
                   "source_config_path": version["config_path"], "config_hash": version["config_hash"],
                   "equivalent_versions": [], "superseded_versions": []}
            exported[request_key] = row
            representatives.append((semantic, version, row))
            summary["exported_configs"].append(row)
            if summary["selected_version"] is None:
                summary.update(selected_version=version["version"], config_path=str(config_path))
        summary.update(_discovery_summary(state, verified_versions))
    _archive_superseded_exports(previous, summaries, destination)
    summary_path.write_text(json.dumps({"schema_version": 1, "candidates": summaries}, indent=2) + "\n", encoding="utf-8")
    skipped = sum(row["selected_version"] is None for row in summaries)
    print(f"Final configs: {destination} ({count} files, {skipped} skipped)")
    return count


def _covers_version(new_config: dict, newer: dict, old_config: dict, older: dict) -> bool:
    """Only collapse verified input growth with unchanged existing request fields."""
    def parameters(version):
        return {(row["name"], str(row.get("source") or "").upper(), str(row.get("location") or "").lower())
                for row in version.get("known_parameters", []) if isinstance(row, dict) and row.get("name")}

    old_parameters = parameters(older)
    if not old_parameters or not old_parameters <= parameters(newer):
        return False
    buckets = {"query_params", "body_params", "json_params"}
    if config_hash({k: v for k, v in old_config.items() if k not in buckets}) != config_hash({
        k: v for k, v in new_config.items() if k not in buckets
    }):
        return False
    for bucket in buckets:
        old, new = old_config.get(bucket), new_config.get(bucket)
        if config_hash(old) == config_hash(new):
            continue
        if not isinstance(old, dict) or not isinstance(new, dict):
            return False
        if config_hash({k: v for k, v in old.items() if k not in {"data", "fuzz", "fixed"}}) != config_hash({
            k: v for k, v in new.items() if k not in {"data", "fuzz", "fixed"}
        }):
            return False
        # Generated form/query configs use named rows; other shapes stay separate.
        old_rows, new_rows = old.get("data"), new.get("data")
        if not isinstance(old_rows, list) or not isinstance(new_rows, list):
            return False
        for row in old_rows:
            if (not isinstance(row, dict) or not isinstance(row.get("name"), str)
                    or not any(config_hash(row) == config_hash(item) for item in new_rows)):
                return False
            for policy in ("fixed", "fuzz"):
                if [pattern for pattern in old.get(policy, []) if re.match(pattern, row["name"])] != [
                    pattern for pattern in new.get(policy, []) if re.match(pattern, row["name"])
                ]:
                    return False
    return True


def _archive_superseded_exports(previous: dict, summaries: list[dict], destination: Path) -> None:
    """Keep prior bytes, but remove replaced exports from the active flat folder."""
    active = {filesystem_path(row["config_path"]).resolve()
              for summary in summaries for row in summary["exported_configs"]}
    replaced = {(summary["identity"], version) for summary in summaries
                for row in summary["exported_configs"]
                for version in row["superseded_versions"] + row["equivalent_versions"]}
    for summary in previous.get("candidates", []):
        for row in summary.get("exported_configs", []):
            if (summary["identity"], row["version"]) not in replaced:
                continue
            path = filesystem_path(row["config_path"])
            if path.resolve() in active or path.resolve().parent != filesystem_path(destination).resolve() or not path.is_file():
                continue
            content = path.read_bytes()
            if config_hash(json.loads(content.decode("utf-8-sig"))) != row.get("config_hash"):
                raise ValueError(f"EXPORTED_CONFIG_CHANGED: {path}")
            archive = filesystem_path(destination) / "superseded"
            archive.mkdir(exist_ok=True)
            target = archive / path.name
            if target.exists():
                if target.read_bytes() != content:
                    raise ValueError(f"EXPORTED_CONFIG_CHANGED: {target}")
                path.unlink()
            else:
                path.rename(target)


def _discovery_summary(state: dict, selected_versions: list[str]) -> dict:
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
        if version.get("version") in selected_versions:
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
    partial = bool(pending or not selected_versions or state.get("terminal_status") == "NOT_VERIFIED"
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
    content = filesystem_path(path).read_bytes()
    config = json.loads(content.decode("utf-8-sig"))
    if config_hash(config) != version.get("config_hash"):
        raise ValueError("CONFIG_HASH_MISMATCH")
    return content, config
