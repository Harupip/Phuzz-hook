"""Export verified configs and separate incomplete discovery drafts."""

import hashlib
import json
import re
import sys
from pathlib import Path

from filesystem_paths import filesystem_path

from hook_energy.seed_generation.online_common import config_hash
from zend_discovery.engine import resolve_request_transport, runtime_parameter_is_accepted

PARAMETER_REPLAY_POLICY = "parameter_replay_v1"
_BUCKET_TRANSPORT = {"query_params": "GET", "body_params": "POST", "cookies": "COOKIE"}
_TRANSPORT_BUCKET = {source: bucket for bucket, source in _BUCKET_TRANSPORT.items()}


def config_name_is_fuzzable(section: dict, name: str) -> bool:
    if not name:
        return False
    fixed = section.get("fixed", [])
    fuzz = section.get("fuzz", [])
    if not isinstance(fixed, list) or not isinstance(fuzz, list):
        return False
    is_fixed = any(re.match(str(selector), name) for selector in fixed)
    is_fuzzable = any(re.match(str(selector), name) for selector in fuzz)
    return is_fuzzable and not is_fixed


def config_fields(path: Path, *, fuzzable_only: bool = True) -> set:
    """(bucket, name) of a config's data rows; by default only the fuzzable ones."""
    config = json.loads(filesystem_path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(config, dict):
        raise ValueError("Expected a config object")
    fields = set()
    for bucket in ("query_params", "body_params", "headers", "cookies"):
        section = config.get(bucket, {})
        for row in section.get("data", []):
            name = str(row.get("name") or "")
            if bucket == "headers" and name.lower() in {"host", "cookie"}:
                continue
            if name and (not fuzzable_only or config_name_is_fuzzable(section, name)):
                fields.add((bucket, name))
    return fields


def config_fuzzable_fields(path: Path) -> set:
    return config_fields(path)


def callback_name(value) -> str:
    return re.sub(r"\s*(?:->|::)\s*", "::", str(value or "").strip())


def handoff_new_fields(child_known: list, parent_known: list, parent_fields: set, request: dict) -> list:
    """Fields a handoff adds over the running parent: identity plus config bucket.

    Shared by the coordinator (to build ``verified_parameters``) and the exporter
    (to require the whole batch), so both use one definition of "new".
    """
    def key(parameter):
        return (str(parameter.get("name") or ""), str(parameter.get("source") or "").upper(),
                str(parameter.get("location") or ""))

    request = request if isinstance(request, dict) else {}
    params = request.get("request_params") if isinstance(request.get("request_params"), dict) else {}
    headers = params.get("headers") if isinstance(params.get("headers"), dict) else {}
    method = str(request.get("http_method") or request.get("method") or "").upper()
    known = {key(p) for p in parent_known or [] if isinstance(p, dict)}
    fields = {}
    for parameter in child_known or []:
        if not isinstance(parameter, dict) or key(parameter) in known:
            continue
        name, source, location = key(parameter)
        transport = source
        if source == "REQUEST":
            resolved = resolve_request_transport(name, request_method=method, request_params=params, headers=headers)
            transport = resolved[0] if resolved else ""
        bucket = _TRANSPORT_BUCKET.get(transport, "")
        if (bucket, name) in parent_fields:
            continue
        fields.setdefault((bucket, name), {"bucket": bucket, "name": name, "source": source, "location": location})
    return list(fields.values())


def parameter_replay_failures(fields: list, request: dict, zend: dict) -> list:
    """Return the ``verified_parameters`` rows that one replay does not prove.

    Each field needs an attributed Zend read/guard of exactly its transport (or a
    $_REQUEST read resolving to it) under its root callback, and its key in that
    request bucket. No events never counts as proof.
    """
    events = zend.get("events") if isinstance(zend, dict) else None
    request = request if isinstance(request, dict) else {}
    params = request.get("request_params") if isinstance(request.get("request_params"), dict) else {}
    headers = params.get("headers") if isinstance(params.get("headers"), dict) else {}
    method = str(request.get("http_method") or request.get("method") or "").upper()
    failures = []
    for field in fields:
        name = str(field.get("name") or "") if isinstance(field, dict) else ""
        transport = _BUCKET_TRANSPORT.get(str(field.get("bucket") or "")) if name else None
        callback = str(field.get("canonical_callback") or "") if name else ""
        proven = False
        for source in (transport, "REQUEST") if isinstance(events, list) and events and transport and callback else ():
            if source == "REQUEST" and (resolve_request_transport(
                    name, request_method=method, request_params=params, headers=headers) or ("",))[0] != transport:
                continue
            operations = {
                str(event.get("operation") or "").strip().lower() for event in events
                if isinstance(event, dict) and str(event.get("source") or "").upper() == source
                and event.get("path") == [name]
                and isinstance(event.get("callback_context"), dict)
                and event["callback_context"].get("attributed") is True
                and str(event["callback_context"].get("root_callback") or "") == callback
            }
            parameter = {"name": name, "source": source, "path": [name], "helper_depth": 0, "observed_count": 1}
            if runtime_parameter_is_accepted(parameter, request, zend, canonical_callback=callback,
                                             request_method=method, operations=operations,
                                             runtime_cookie_probes=True):
                proven = True
                break
        if not proven:
            failures.append(field)
    return failures


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
        context_key = candidate.get("context_key")
        export_key = str(context_key) if context_key else identity
        if export_key in seen:
            continue
        seen.add(export_key)
        summary = {"identity": identity, "hook_name": candidate.get("hook_name"),
                   "selected_version": None, "exported_configs": [], "partial_configs": [], "skipped_versions": [],
                   "discovery_status": "NOT_ASSESSED"}
        if context_key:
            summary["context_key"] = str(context_key)
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
                content = _verified_config(version, {v["version"]: v for v in versions})
            except (OSError, ValueError, KeyError, TypeError) as exc:
                skipped = {
                    "version": version["version"], "reason": str(exc),
                    "terminal_reason": version.get("terminal_reason"),
                }
                gate = version.get("readiness" if version["version"] == "v0" else "replay_result") or {}
                runner = gate.get("runner") if isinstance(gate, dict) else None
                runs = runner.get("runs") if isinstance(runner, dict) else None
                if isinstance(runs, list) and len(runs) == 1 and isinstance(runs[0], dict) and runs[0].get("diagnostics"):
                    skipped["diagnostics"] = runs[0]["diagnostics"]
                    skipped["readiness_evidence"] = {
                        "config_type": version.get("config_type"), "gate_passed": gate.get("passed"),
                        "verification_policy": gate.get("verification_policy"),
                        "baseline_evidence": gate.get("baseline_evidence"),
                        "pass2_verification": gate.get("pass2_verification"),
                    }
                summary["skipped_versions"].append(skipped)
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
            suffix = hashlib.sha256(export_key.encode()).hexdigest()[:16]
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
            gate = version.get("readiness" if version["version"] == "v0" else "replay_result") or {}
            if gate.get("verification_policy") in {"callback_baseline_v1", PARAMETER_REPLAY_POLICY}:
                row.update(verification_policy=gate["verification_policy"], baseline_evidence=gate["baseline_evidence"])
            exported[request_key] = row
            representatives.append((semantic, version, row))
            summary["exported_configs"].append(row)
            if summary["selected_version"] is None:
                summary.update(selected_version=version["version"], config_path=str(config_path))
        summary.update(_discovery_summary(state, verified_versions))
        summary["partial_configs"] = _export_partial_config(state, versions, summary, destination)
    _archive_superseded_exports(previous, summaries, destination)
    filesystem_path(summary_path).write_text(json.dumps({"schema_version": 1, "candidates": summaries}, indent=2) + "\n", encoding="utf-8")
    skipped = sum(row["selected_version"] is None for row in summaries)
    print(f"Final configs: {destination} ({count} files, {skipped} skipped)")
    partial_count = sum(len(row.get("partial_configs", [])) for row in summaries)
    if partial_count:
        print(f"Partial configs (unverified): {destination.parent / 'partial-configs'} ({partial_count} files)")
    return count


def _export_partial_config(state: dict, versions: list[dict], summary: dict, destination: Path) -> list[dict]:
    """Preserve observations at budget expiry without promoting them to verified inputs."""
    reason = str(state.get("terminal_reason") or "")
    parameters = summary["verified_parameters"] + summary["pending_parameters"]
    if not versions or not parameters or not any(word in reason for word in ("BUDGET", "TIME_CAP", "LIMIT", "NO_NEW_PROGRESS")):
        return []
    version = versions[0]
    config = json.loads(filesystem_path(version["config_path"]).read_text(encoding="utf-8-sig"))
    if config_hash(config) != version.get("config_hash"):
        raise ValueError(f"CONFIG_HASH_MISMATCH: {version['config_path']}")
    placements = {("GET", "query"): "query_params", ("POST", "form"): "body_params",
                  ("COOKIE", "cookie"): "cookies"}
    unplaced = []
    for parameter in parameters:
        bucket = placements.get((parameter["source"], parameter["location"]))
        if bucket is None:
            unplaced.append(parameter)
            continue
        section = config.setdefault(bucket, {"data": [], "fixed": [], "fuzz": [], "weight": 1})
        name = parameter["name"]
        if not any(row.get("name") == name for row in section["data"]):
            section["data"].append({"name": name, "value": "fuzz"})
            section["fuzz"].append(re.escape(name))
    metadata = config.setdefault("metadata", {})
    if any(p["source"] == "POST" and p["location"] == "form" for p in parameters):
        if config.get("methods") != ["POST"]:
            config["methods"] = ["POST"]
            metadata.update(resolved_method="POST", method_source="partial_export_inferred",
                            method_confidence="unverified")
    metadata.pop("online_request_seed", None)
    metadata.pop("method_evidence", None)
    config["config_type"] = "partial"
    metadata["fuzzing_ready"] = False
    metadata["partial_export"] = {
        "status": "PARTIAL", "reason": reason,
        "warning": "Discovery stopped before completion. Inputs may be missing or belong to incompatible branches. "
                   "This combined config has not passed a callback baseline; it is not ready for fuzzing.",
        "combined_request_verified": False,
        "verified_parameters": summary["verified_parameters"],
        "pending_parameters": summary["pending_parameters"],
        "unplaced_parameters": unplaced,
        "state_path": summary["state_path"],
        "source_config_path": version["config_path"],
    }
    digest = config_hash(config)
    hook = re.sub(r"[^A-Za-z0-9_-]+", "-", summary.get("hook_name") or "hook")[:40]
    identity = hashlib.sha256(summary["identity"].encode()).hexdigest()[:16]
    folder = destination.parent / "partial-configs"
    filesystem_path(folder).mkdir(parents=True, exist_ok=True)
    path = folder / f"fuzzer-config.{hook}.{identity}.{digest[:16]}.partial.json"
    content = (json.dumps(config, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if filesystem_path(path).exists():
        if filesystem_path(path).read_bytes() != content:
            raise ValueError(f"EXPORTED_CONFIG_CHANGED: {path}")
    else:
        with filesystem_path(path).open("xb") as output:
            output.write(content)
    return [{"config_path": str(path), "config_hash": digest, "status": "PARTIAL", "reason": reason}]


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
    replaced = {(summary.get("context_key") or summary["identity"], version) for summary in summaries
                for row in summary["exported_configs"]
                for version in row["superseded_versions"] + row["equivalent_versions"]}
    for summary in previous.get("candidates", []):
        export_key = summary.get("context_key") or summary["identity"]
        for row in summary.get("exported_configs", []):
            if (export_key, row["version"]) not in replaced:
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
    for pending_probe in state.get("pending_probe_queue", []):
        add([pending_probe.get("candidate")], observed)
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


def _verified_config(version: dict, versions: dict | None = None) -> bytes:
    content, config = _verified_base(version, versions or {})
    if (version.get("config_type") != "fuzzing_ready" or config.get("config_type") != "fuzzing_ready"
            or version.get("probe_variant") is True
            or (config.get("metadata") or {}).get("probe_variant") is True):
        raise ValueError("NOT_FUZZING_READY")
    return content


def _verified_base(version: dict, versions: dict | None = None) -> tuple[bytes, dict]:
    gate = version.get("readiness" if version["version"] == "v0" else "replay_result") or {}
    if gate.get("passed") is not True:
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
    policy = gate.get("verification_policy")
    if policy == "callback_baseline_v1":
        _verify_baseline_gate(version, gate, config)
    elif policy == PARAMETER_REPLAY_POLICY:
        # HTTP status is diagnostic here; the field proof replaces the 2xx rule.
        _verify_baseline_gate(version, gate, config, require_2xx=False)
        fields = gate.get("verified_parameters")
        row = gate["runner"]["runs"][0]
        if not isinstance(fields, list) or not fields or parameter_replay_failures(
                fields, row.get("request_payload") or {}, row.get("zend_payload") or {}):
            raise ValueError("PARAMETER_REPLAY_NOT_VERIFIED")
        # The proof must name this version's callback, not just agree with its own trace.
        expected = callback_name(version.get("canonical_callback"))
        if not expected or any(callback_name(f.get("canonical_callback")) != expected for f in fields):
            raise ValueError("PARAMETER_REPLAY_CALLBACK_MISMATCH")
        # ... and cover every field this version adds over its parent.
        parent = (versions or {}).get(version.get("parent_version")) or {}
        parent_fields = config_fuzzable_fields(Path(version["parent_config"])) if version.get("parent_config") else set()
        required = handoff_new_fields(version.get("known_parameters") or [], parent.get("known_parameters") or [],
                                      parent_fields, row.get("request_payload") or {})
        if not {(f["bucket"], f["name"]) for f in required} <= {(f.get("bucket"), f.get("name")) for f in fields}:
            raise ValueError("PARAMETER_REPLAY_BATCH_INCOMPLETE")
    elif policy is None:
        # Historical records retain their original eligibility contract.
        pass2 = gate.get("pass2_verification") or {}
        accepted, total = pass2.get("accepted"), pass2.get("total")
        if type(total) is not int or total <= 0 or type(accepted) is not int or accepted != total:
            raise ValueError("GATE_NOT_VERIFIED")
    else:
        raise ValueError("UNKNOWN_VERIFICATION_POLICY")
    return content, config


def _verify_baseline_gate(version: dict, gate: dict, config: dict, *, require_2xx: bool = True) -> None:
    proof = gate.get("baseline_evidence")
    fields = {"request_id", "run_id", "plugin_slug", "callback_id", "http_method", "auth_context", "seed_variant_id"}
    if (not isinstance(proof, dict) or not fields <= proof.keys()
            or any(not isinstance(proof[key], str) or not proof[key] for key in fields - {"seed_variant_id"})
            or not isinstance(proof["seed_variant_id"], str)):
        raise ValueError("BASELINE_EVIDENCE_INCOMPLETE")
    metadata = config.get("metadata") or {}
    expected = {
        "plugin_slug": version.get("plugin_slug"), "callback_id": version.get("callback_id"),
        "http_method": version.get("resolved_method") or metadata.get("resolved_method"),
        "auth_context": version.get("auth_context") or metadata.get("auth_context"),
        "seed_variant_id": version.get("seed_variant_id", metadata.get("seed_variant_id", "")),
    }
    if any(proof[key] != value for key, value in expected.items()) or proof["http_method"] not in config.get("methods", []):
        raise ValueError("BASELINE_IDENTITY_MISMATCH")
    runner = gate.get("runner") or {}
    if not isinstance(runner, dict) or gate.get("budget_expired") is True:
        raise ValueError("BASELINE_RUN_MISMATCH")
    rows = runner.get("runs") or []
    if not isinstance(rows, list) or runner.get("legacy_run_id") != proof["run_id"] or len(rows) != 1 or not isinstance(rows[0], dict):
        raise ValueError("BASELINE_RUN_MISMATCH")
    row = rows[0]
    request, zend = row.get("request_payload") or {}, row.get("zend_payload") or {}
    if (row.get("callback_reached") is not True or row.get("validation_status") != "callback_reached"
            or row.get("process_status") in {"failed", "runner_error", "window_elapsed"}
            or row.get("callback_id") != proof["callback_id"] or row.get("hook_name") != version.get("hook_name")
            or row.get("resolved_method") != proof["http_method"]
            or str(row.get("seed_variant_id") or "") != proof["seed_variant_id"]
            or row.get("matched_artifact") != proof["request_id"] + ".json"):
        raise ValueError("BASELINE_CALLBACK_NOT_VERIFIED")
    for payload in (request, zend):
        if not isinstance(payload, dict):
            raise ValueError("BASELINE_ARTIFACT_MISMATCH")
        runs = [payload[key] for key in ("run_id", "legacy_run_id") if payload.get(key)]
        if payload.get("request_id") != proof["request_id"] or not runs or any(run != proof["run_id"] for run in runs):
            raise ValueError("BASELINE_ARTIFACT_MISMATCH")
        if payload.get("seed_variant_id") is not None and str(payload["seed_variant_id"]) != proof["seed_variant_id"]:
            raise ValueError("BASELINE_ARTIFACT_MISMATCH")
        if payload.get("callback_id") is not None and payload["callback_id"] != proof["callback_id"]:
            raise ValueError("BASELINE_ARTIFACT_MISMATCH")
    auth = request.get("auth_context")
    if auth is None and isinstance(request.get("metadata"), dict):
        auth = request["metadata"].get("auth_context")
    if auth is None:
        params = request.get("request_params") or {}
        headers = params.get("headers") if isinstance(params, dict) else {}
        if not isinstance(headers, dict):
            raise ValueError("BASELINE_REQUEST_MISMATCH")
        auth = next((value for key, value in headers.items() if key.lower() == "x-hookphuzz-auth-context"), None)
    if (auth != proof["auth_context"]
            or (zend.get("request_method") or zend.get("method") or proof["http_method"]).upper() != proof["http_method"]):
        raise ValueError("BASELINE_REQUEST_MISMATCH")
    if request.get("target_plugin") != proof["plugin_slug"] or str(request.get("http_method") or request.get("method") or "").upper() != proof["http_method"]:
        raise ValueError("BASELINE_REQUEST_MISMATCH")
    response = request.get("response")
    if require_2xx and (not isinstance(response, dict) or not 200 <= int(response.get("status_code", 0)) < 300):
        raise ValueError("BASELINE_HTTP_NOT_VERIFIED")
    replay_path = Path(version["replay_config_path"])
    if (gate.get("config_path") != str(replay_path) or gate.get("config_hash") != version.get("replay_config_hash")
            or config_hash(json.loads(filesystem_path(replay_path).read_text(encoding="utf-8-sig"))) != gate["config_hash"]):
        raise ValueError("BASELINE_CONFIG_HASH_MISMATCH")
