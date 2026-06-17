from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    import requests
except ImportError:
    requests = None


def load_candidate(candidate_file: Path, candidate_id: str | None) -> dict[str, Any]:
    payload = json.loads(Path(candidate_file).read_text(encoding="utf-8-sig"))

    if isinstance(payload, Mapping) and isinstance(payload.get("candidates"), list):
        candidates = [item for item in payload["candidates"] if isinstance(item, Mapping)]
        if candidate_id:
            for item in candidates:
                if candidate_id in {
                    _optional_string(item.get("candidate_id")),
                    _optional_string(item.get("callback_id")),
                }:
                    return _normalize_candidate(item)
            raise ValueError(f"Candidate id not found: {candidate_id}")

        if len(candidates) != 1:
            raise ValueError("--candidate-id is required when candidate file contains multiple candidates")
        return _normalize_candidate(candidates[0])

    if not isinstance(payload, Mapping):
        raise ValueError("candidate-file must contain a JSON object")
    return _normalize_candidate(payload)


def build_validation_request(candidate: dict[str, Any], *, base_url: str, validation_id: str) -> dict[str, Any]:
    http_template = candidate.get("http_template")
    if not isinstance(http_template, Mapping):
        raise ValueError("candidate must contain an http_template")

    method = str(http_template.get("method", "")).strip().upper()
    if method not in {"GET", "POST"}:
        raise ValueError(f"Unsupported validation request method: {method or '<missing>'}")

    path = str(http_template.get("path", "")).strip()
    if not path:
        raise ValueError("candidate http_template.path is required")

    query_params = _mapping_to_strings(http_template.get("query_params", {}))
    body_params = _mapping_to_strings(http_template.get("body_params", {}))
    headers = _mapping_to_strings(http_template.get("headers", {}))
    headers.update(
        {
            "X-HookPhuzz-Validation-ID": validation_id,
            "X-HookPhuzz-Candidate-ID": str(candidate.get("candidate_id") or ""),
            "X-Fuzzer-Covid": validation_id,
        }
    )

    return {
        "method": method,
        "url": _build_url(base_url, path, query_params),
        "params": {},
        "data": body_params if method == "POST" else {},
        "headers": headers,
        "timeout": None,
        "query_params": query_params,
        "body_params": body_params,
    }


def validate_candidate(
    *,
    candidate: dict[str, Any],
    base_url: str,
    hook_coverage_dir: str | Path,
    timeout: float,
    validation_id: str | None = None,
    http_client: Any = None,
) -> dict[str, Any]:
    resolved_validation_id = validation_id or f"hookphuzz-validation-{uuid.uuid4().hex}"
    request = build_validation_request(candidate, base_url=base_url, validation_id=resolved_validation_id)
    request["timeout"] = timeout

    before_artifacts = set(list_request_artifacts(hook_coverage_dir))
    started = time.perf_counter()
    status_code = None
    response_size = 0
    error = None

    try:
        response = _send_request(
            http_client,
            method=request["method"],
            url=request["url"],
            headers=request["headers"],
            timeout=timeout,
            data=request["data"],
        )
        status_code = getattr(response, "status_code", None)
        response_size = _response_size(response)
    except Exception as exc:
        error = str(exc)

    duration_ms = int(round((time.perf_counter() - started) * 1000))
    after_artifacts = set(list_request_artifacts(hook_coverage_dir))
    new_artifacts = sorted(after_artifacts - before_artifacts)
    observed = _collect_observed(hook_coverage_dir, new_artifacts)
    result = _build_result(candidate, observed, artifact_count=len(new_artifacts))

    return {
        "schema_version": 1,
        "validation_id": resolved_validation_id,
        "validated_at": _utc_now(),
        "candidate_id": candidate.get("candidate_id"),
        "hook_name": candidate.get("hook_name"),
        "callback_id": candidate.get("callback_id"),
        "request": {
            "method": request["method"],
            "url": request["url"],
            "query_params": request["query_params"],
            "body_params": request["body_params"],
        },
        "response": {
            "status_code": status_code,
            "duration_ms": duration_ms,
            "response_size": response_size,
            "error": error,
        },
        "artifacts": {
            "new_request_artifacts": new_artifacts,
            "artifact_count": len(new_artifacts),
        },
        "result": result,
        "observed": {
            "executed_callback_ids": sorted(observed["executed_callback_ids"]),
            "executed_hook_names": sorted(observed["executed_hook_names"]),
            "registered_callback_ids": sorted(observed["registered_callback_ids"]),
            "blindspot_callback_ids": sorted(observed["blindspot_callback_ids"]),
            "newly_registered_child_hooks": sorted(
                observed["newly_registered_child_hooks"].values(),
                key=lambda item: (item["hook_name"] or "", item["callback_id"]),
            ),
            "endpoints": sorted(observed["endpoints"]),
            "http_methods": sorted(observed["http_methods"]),
            "http_targets": sorted(observed["http_targets"]),
        },
    }


def write_validation_result(result: dict[str, Any], output_file: Path, pretty: bool = False) -> Path:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, indent=2 if pretty else None, ensure_ascii=False),
        encoding="utf-8",
    )
    return output_path


def list_request_artifacts(hook_coverage_dir: str | Path) -> list[str]:
    requests_dir = Path(hook_coverage_dir) / "requests"
    if not requests_dir.exists():
        return []
    return [f"requests/{path.name}" for path in sorted(requests_dir.glob("*.json")) if path.is_file()]


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Replay one HookPhuzz seed candidate and validate hook coverage.")
    parser.add_argument("--base-url", required=True, help="Base WordPress URL, for example http://localhost:8080.")
    parser.add_argument("--candidate-file", required=True, help="Path to entrypoint_candidates.json or one seed JSON.")
    parser.add_argument("--candidate-id", help="Candidate id to validate when candidate-file contains multiple candidates.")
    parser.add_argument(
        "--hook-coverage-dir",
        required=True,
        help="Hook coverage directory containing a requests/ subdirectory.",
    )
    parser.add_argument("--output-file", required=True, help="Path to write validation_result.json.")
    parser.add_argument("--timeout", type=float, required=True, help="HTTP replay timeout in seconds.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print validation_result.json.")
    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        candidate = load_candidate(Path(args.candidate_file), args.candidate_id)
        result = validate_candidate(
            candidate=candidate,
            base_url=args.base_url,
            hook_coverage_dir=Path(args.hook_coverage_dir),
            timeout=args.timeout,
        )
        output_path = write_validation_result(result, Path(args.output_file), pretty=args.pretty)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(
        "Seed validation summary: "
        f"candidate_id={result['candidate_id']} "
        f"hook_fired={result['result']['expected_hook_fired']} "
        f"callback_reached={result['result']['expected_callback_reached']} "
        f"artifacts={result['artifacts']['artifact_count']} "
        f"output={output_path}"
    )
    return 0


def _normalize_candidate(candidate: Mapping[str, Any]) -> dict[str, Any]:
    hook_name = _optional_string(candidate.get("hook_name"))
    callback_id = _optional_string(candidate.get("callback_id"))
    callback_repr = _optional_string(
        candidate.get("callback_repr", candidate.get("callback_name", candidate.get("callback_raw")))
    )
    candidate_id = _optional_string(candidate.get("candidate_id")) or callback_id or callback_repr or "candidate"
    http_template = _normalize_http_template(candidate)

    return {
        "candidate_id": candidate_id,
        "hook_name": hook_name,
        "callback_id": callback_id,
        "callback_repr": callback_repr,
        "http_template": http_template,
    }


def _normalize_http_template(candidate: Mapping[str, Any]) -> dict[str, Any]:
    http_template = candidate.get("http_template")
    if isinstance(http_template, Mapping):
        return {
            "method": str(http_template.get("method", "")).upper(),
            "path": str(http_template.get("path", "")),
            "query_params": _mapping_to_strings(http_template.get("query_params", {})),
            "body_params": _mapping_to_strings(http_template.get("body_params", http_template.get("body", {}))),
            "headers": _mapping_to_strings(http_template.get("headers", {})),
        }

    seed = candidate.get("seed")
    if isinstance(seed, Mapping):
        return {
            "method": str(seed.get("method", "")).upper(),
            "path": str(seed.get("path", "")),
            "query_params": _mapping_to_strings(seed.get("query_params", {})),
            "body_params": _mapping_to_strings(seed.get("body_params", seed.get("body", {}))),
            "headers": _mapping_to_strings(seed.get("headers", {})),
        }

    return {
        "method": str(candidate.get("method", "")).upper(),
        "path": str(candidate.get("path", "")),
        "query_params": _mapping_to_strings(candidate.get("query_params", {})),
        "body_params": _mapping_to_strings(candidate.get("body_params", candidate.get("body", {}))),
        "headers": _mapping_to_strings(candidate.get("headers", {})),
    }


def _collect_observed(hook_coverage_dir: str | Path, artifact_paths: list[str]) -> dict[str, set[str]]:
    observed = {
        "executed_callback_ids": set(),
        "executed_callback_reprs": set(),
        "executed_hook_names": set(),
        "endpoints": set(),
        "http_methods": set(),
        "http_targets": set(),
        "registered_callback_ids": set(),
        "blindspot_callback_ids": set(),
        "newly_registered_child_hooks": {},
    }

    for relative_path in artifact_paths:
        payload = _load_json(Path(hook_coverage_dir) / relative_path)
        if not isinstance(payload, Mapping):
            continue

        for key in ("hook_name", "fired_hook", "endpoint"):
            value = _optional_string(payload.get(key))
            if value:
                observed["executed_hook_names"].add(value)
        for payload_key, observed_key in (
            ("endpoint", "endpoints"),
            ("http_method", "http_methods"),
            ("http_target", "http_targets"),
        ):
            value = _optional_string(payload.get(payload_key))
            if value:
                observed[observed_key].add(value)

        hook_coverage = payload.get("hook_coverage", {})
        if not isinstance(hook_coverage, Mapping):
            hook_coverage = {}

        executed = _normalize_callback_mapping(hook_coverage.get("executed_callbacks", {}))
        registered = _normalize_callback_mapping(hook_coverage.get("registered_callbacks", {}))
        blindspots = _normalize_callback_mapping(hook_coverage.get("blindspot_callbacks", {}))

        for callback_id, entry in executed.items():
            observed["executed_callback_ids"].add(callback_id)
            explicit_id = _optional_string(entry.get("callback_id"))
            if explicit_id:
                observed["executed_callback_ids"].add(explicit_id)

            for key in ("hook_name", "fired_hook"):
                value = _optional_string(entry.get(key))
                if value:
                    observed["executed_hook_names"].add(value)
            for key in ("callback_repr", "callback_name", "stable_id", "runtime_id"):
                value = _optional_string(entry.get(key))
                if value:
                    observed["executed_callback_reprs"].add(value)

        observed["registered_callback_ids"].update(registered.keys())
        for callback_id, entry in registered.items():
            explicit_id = _optional_string(entry.get("callback_id"))
            if explicit_id:
                observed["registered_callback_ids"].add(explicit_id)
            child_hook = _child_hook_summary(callback_id, entry)
            if child_hook is not None:
                observed["newly_registered_child_hooks"][child_hook["callback_id"]] = child_hook

        observed["blindspot_callback_ids"].update(blindspots.keys())
        for entry in blindspots.values():
            explicit_id = _optional_string(entry.get("callback_id"))
            if explicit_id:
                observed["blindspot_callback_ids"].add(explicit_id)

    return observed


def _build_result(candidate: dict[str, Any], observed: dict[str, set[str]], *, artifact_count: int) -> dict[str, Any]:
    hook_name = _optional_string(candidate.get("hook_name"))
    callback_id = _optional_string(candidate.get("callback_id"))
    callback_repr = _optional_string(candidate.get("callback_repr"))

    expected_hook_fired = bool(hook_name and _hook_name_observed(hook_name, observed))
    if callback_id:
        expected_callback_reached = callback_id in observed["executed_callback_ids"]
    elif callback_repr:
        expected_callback_reached = callback_repr in observed["executed_callback_reprs"]
    else:
        expected_callback_reached = False

    if expected_callback_reached:
        confidence = "high"
        if callback_id:
            reason = "Expected callback id was found in executed_callbacks"
        else:
            reason = "Expected callback repr was found in executed_callbacks"
    elif expected_hook_fired:
        confidence = "medium"
        reason = "Expected hook was observed, but expected callback was not found in executed_callbacks"
    else:
        confidence = "low"
        reason = _failure_reason(
            artifact_count=artifact_count,
            callback_id=callback_id,
            callback_repr=callback_repr,
            observed=observed,
        )

    return {
        "expected_hook_fired": expected_hook_fired,
        "expected_callback_reached": expected_callback_reached,
        "confidence": confidence,
        "reason": reason,
    }


def _hook_name_observed(hook_name: str, observed: dict[str, set[str]]) -> bool:
    for key in ("executed_hook_names", "endpoints", "http_targets"):
        for value in observed[key]:
            if value == hook_name or hook_name in value:
                return True
    return False


def _failure_reason(
    *,
    artifact_count: int,
    callback_id: str | None,
    callback_repr: str | None,
    observed: dict[str, set[str]],
) -> str:
    if artifact_count == 0:
        return "No new hook coverage request artifacts were created"
    if callback_id and callback_id in observed["registered_callback_ids"]:
        return "Expected callback was registered but was not executed"
    if callback_id and callback_id in observed["blindspot_callback_ids"]:
        return "Expected callback was reported as a blindspot and was not executed"
    if not callback_id and not callback_repr:
        return "Candidate has no callback_id or callback_repr to match against executed_callbacks"
    return "Expected hook and callback were not observed in new hook coverage request artifacts"


def _normalize_callback_mapping(payload: Any) -> dict[str, dict[str, Any]]:
    if isinstance(payload, Mapping):
        normalized = {}
        for callback_id, item in payload.items():
            if isinstance(item, Mapping):
                normalized[str(callback_id)] = dict(item)
        return normalized

    if isinstance(payload, list):
        normalized = {}
        for index, item in enumerate(payload, start=1):
            if not isinstance(item, Mapping):
                continue
            callback_id = _optional_string(item.get("callback_id")) or f"callback-{index}"
            normalized[callback_id] = dict(item)
        return normalized

    return {}


def _child_hook_summary(callback_id: str, entry: Mapping[str, Any]) -> dict[str, Any] | None:
    hook_level = _optional_int(entry.get("hook_level"))
    if not bool(entry.get("registered_inside_callback")) and (hook_level is None or hook_level <= 0):
        return None

    resolved_callback_id = _optional_string(entry.get("callback_id")) or callback_id
    return {
        "hook_name": _optional_string(entry.get("hook_name")),
        "callback_id": resolved_callback_id,
        "hook_level": hook_level,
        "parent_callback_id": _optional_string(entry.get("parent_callback_id")),
    }


def _send_request(http_client: Any, **kwargs):
    if http_client is None:
        if requests is None:
            raise RuntimeError("The requests package is required when no HTTP client is injected.")
        http_client = requests
    request_func = getattr(http_client, "request", http_client)
    return request_func(**kwargs)


def _response_size(response: Any) -> int:
    content = getattr(response, "content", None)
    if isinstance(content, bytes):
        return len(content)
    if isinstance(content, str):
        return len(content.encode("utf-8"))
    text = getattr(response, "text", None)
    if isinstance(text, str):
        return len(text.encode("utf-8"))
    return 0


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _build_url(base_url: str, path: str, query_params: dict[str, str]) -> str:
    if path.startswith(("http://", "https://")):
        raw_url = path
    else:
        raw_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

    parsed = urlsplit(raw_url)
    combined_query: list[tuple[str, Any]] = parse_qsl(parsed.query, keep_blank_values=True)
    combined_query.extend(query_params.items())
    query = urlencode(combined_query, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def _mapping_to_strings(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _optional_string(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return int(value)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
