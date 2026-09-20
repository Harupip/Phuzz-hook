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
    for candidate in batch["candidates"]:
        identity = candidate["identity"]
        if identity in seen:
            continue
        seen.add(identity)
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
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"Config skipped {identity}: {exc}", file=sys.stderr)
            continue
        for version in versions:
            try:
                content = _verified_config(version)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                print(f"Config skipped {identity}/{version['version']}: {exc}", file=sys.stderr)
                continue
            hook = re.sub(r"[^A-Za-z0-9_-]+", "-", candidate.get("hook_name", "hook"))[:40]
            suffix = hashlib.sha256(identity.encode()).hexdigest()[:16]
            # Exclusive creation preserves existing output; bytes retain all metadata/auth.
            with (destination / f"fuzzer-config.{hook}.{suffix}.json").open("xb") as output:
                output.write(content)
            count += 1
            break
    print(f"Final configs: {destination} ({count} files, {len(seen) - count} skipped)")
    return count


def _verified_config(version: dict) -> bytes:
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
    if (version.get("config_type") != "fuzzing_ready" or config.get("config_type") != "fuzzing_ready"
            or version.get("probe_variant") is True
            or (config.get("metadata") or {}).get("probe_variant") is True):
        raise ValueError("NOT_FUZZING_READY")
    if config_hash(config) != version.get("config_hash"):
        raise ValueError("CONFIG_HASH_MISMATCH")
    return content
