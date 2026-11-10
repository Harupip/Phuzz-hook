"""Request, parameter and callback matching for online-linked evidence.

Pure functions: callers pass the coordinator's plugin slug, registry and versions explicitly.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import urllib.parse
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from filesystem_paths import filesystem_path
from hook_energy.seed_generation.online_common import config_hash
from online_linked.coordination.candidate_identity import _canonical_callback_name
from online_linked.export import (
    config_fuzzable_fields as _config_fuzzable_fields,
    config_name_is_fuzzable as _config_name_is_fuzzable,
    handoff_new_fields,
)
from zend_discovery.engine import prepare_callback_registry, runtime_parameter_is_accepted


def _parameter_key(parameter: Any) -> tuple[str, str, str]:
    if not isinstance(parameter, Mapping):
        return "", "", ""
    return (
        str(parameter.get("name") or ""),
        str(parameter.get("source") or "").upper(),
        str(parameter.get("location") or ""),
    )


def _replace_fuzzable_values_with_placeholder(config: dict[str, Any]) -> None:
    """Use PHUZZ's fuzz sentinel in the published fuzzing config only."""
    for section_name in ("query_params", "body_params", "headers", "cookies"):
        section = config.get(section_name)
        if not isinstance(section, Mapping):
            continue
        data = section.get("data")
        fixed = section.get("fixed", [])
        fuzz = section.get("fuzz", [])
        if not isinstance(data, list) or not isinstance(fixed, list) or not isinstance(fuzz, list):
            continue
        for row in data:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "")
            if not name:
                continue
            if _config_name_is_fuzzable(section, name):
                row["value"] = "fuzz"


def _request_id(run_id: str) -> str:
    return "r-" + hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:24]


def _method_parameter_key(parameter: Mapping[str, Any], method: str = "") -> tuple[str, tuple[str, str, str]]:
    return (str(method or parameter.get("request_method") or "").upper(), _parameter_key(parameter))


def _is_ajax(parent: Mapping[str, Any]) -> bool:
    return (
        str(parent.get("entrypoint_type") or "").startswith("ajax")
        or str(parent.get("hook_name") or "").startswith("wp_ajax_")
    )


# Only the fuzzer's own per-request tracking headers are ignored; application headers such as
# User-Agent or Accept can select a WordPress branch (wp_is_mobile()), so they are compared.
_UNCOMPARED_HEADER_PREFIXES = ("x-fuzzer-", "x-hookphuzz-")


def _request_payload_hash(request: Any) -> str:
    """Hash of everything a request sent that can select a branch; "" when that is not known.

    Method, route, query, form/JSON body, cookies and every header except the fuzzer's tracking ones.
    "" never matches, so an incomplete artifact makes the worker re-score the seed.
    """
    if not isinstance(request, Mapping) or not isinstance(request.get("request_params"), Mapping):
        return ""
    params = request["request_params"]
    method = str(request.get("http_method") or request.get("method") or "").upper()
    target = str(request.get("http_target") or "")
    if not method or not target:
        return ""
    headers = params.get("headers") if isinstance(params.get("headers"), Mapping) else {}
    cookies = params.get("cookies")
    return config_hash({
        "method": method,
        "route": urllib.parse.urlsplit(target).path,
        "endpoint": request.get("endpoint"),
        **{name: params.get(name) or {} for name in ("query_params", "body_params", "json_params")},
        "cookies": cookies if isinstance(cookies, (Mapping, list)) else {},
        "headers": {
            str(key).lower(): value for key, value in headers.items()
            if not str(key).lower().startswith(_UNCOMPARED_HEADER_PREFIXES)
        },
    })


def _safe_parameter_identity(parameter: Mapping[str, Any]) -> dict[str, str]:
    return {
        "name": str(parameter.get("name") or ""),
        "source": str(parameter.get("source") or "").upper(),
        "location": str(parameter.get("location") or "").lower(),
    }


def _runtime_candidate_key(candidate: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(candidate.get("name") or ""),
        str(candidate.get("source") or "").upper(),
        str(candidate.get("location") or "").lower(),
    )


def _request_context_key(request_params: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        request_params, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, default=str,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _coherent_evidence_key(evidence: Mapping[str, Any]) -> tuple[str, str, str]:
    request = evidence.get("request")
    request_params = request.get("request_params") if isinstance(request, Mapping) else {}
    return (
        str(evidence.get("request_id") or ""),
        str(evidence.get("worker_run_id") or evidence.get("run_id") or ""),
        _request_context_key(request_params) if isinstance(request_params, Mapping) else "",
    )


def _request_auth_context(request: Mapping[str, Any]) -> str:
    value = request.get("auth_context")
    if value is None and isinstance(request.get("metadata"), Mapping):
        value = request["metadata"].get("auth_context")
    params = request.get("request_params")
    headers = params.get("headers") if isinstance(params, Mapping) else None
    if value is None and isinstance(headers, Mapping):
        value = next(
            (item for key, item in headers.items()
             if str(key).lower() == "x-hookphuzz-auth-context"),
            None,
        )
    return str(value or "").strip()


def _request_callback_matches(request: Mapping[str, Any], parent: Mapping[str, Any]) -> bool:
    expected_hook = str(parent.get("hook_name") or "")
    expected_callback = str(parent.get("callback_id") or "")
    explicit_hook = str(request.get("hook_name") or "").strip()
    explicit_callback = str(request.get("callback_id") or "").strip()
    if explicit_hook and explicit_hook != expected_hook:
        return False
    if explicit_callback and explicit_callback != expected_callback:
        return False
    if explicit_hook and explicit_callback:
        return True
    coverage = request.get("hook_coverage")
    if not isinstance(coverage, Mapping):
        return False
    for bucket in ("executed_callbacks",):
        entries = coverage.get(bucket)
        if not isinstance(entries, Mapping):
            continue
        for key, raw in entries.items():
            if not isinstance(raw, Mapping):
                continue
            callback_ids = {str(key)}
            if raw.get("callback_id"):
                callback_ids.add(str(raw["callback_id"]))
            hooks = {
                str(raw.get(field) or "")
                for field in ("hook_name", "fired_hook")
                if raw.get(field)
            }
            if expected_callback in callback_ids and expected_hook in hooks:
                return True
    return False


def config_request_key(config: Mapping[str, Any]) -> str:
    semantic: dict[str, Any] = {
        key: copy.deepcopy(config.get(key))
        for key in ("target", "methods", "entrypoint_type")
    }
    for section_name in ("query_params", "body_params", "json_params", "headers", "cookies"):
        section = config.get(section_name)
        if not isinstance(section, Mapping):
            continue
        data = copy.deepcopy(section.get("data"))
        if isinstance(data, list):
            for row in data:
                if (
                    section_name != "json_params"
                    and isinstance(row, Mapping)
                    and _config_name_is_fuzzable(section, str(row.get("name") or ""))
                ):
                    row["value"] = "<fuzzable>"
        elif isinstance(data, Mapping):
            for name in data:
                if section_name != "json_params" and _config_name_is_fuzzable(section, str(name)):
                    data[name] = "<fuzzable>"
        semantic[section_name] = {"data": data}
    return json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def published_config_with_same_request(
    config: Mapping[str, Any],
    proposed_parameters: Sequence[Mapping[str, Any]] | None,
    *,
    versions: Sequence[Any],
) -> dict[str, Any] | None:
    candidate_key = config_request_key(config)
    candidate_parameters = None
    if proposed_parameters is not None:
        candidate_parameters = {
            tuple(_safe_parameter_identity(parameter).values())
            for parameter in proposed_parameters
            if isinstance(parameter, Mapping)
        }
    for version in versions:
        if not isinstance(version, Mapping):
            continue
        if candidate_parameters is not None:
            published_parameters = {
                tuple(_safe_parameter_identity(parameter).values())
                for parameter in version.get("known_parameters", [])
                if isinstance(parameter, Mapping)
            }
            if published_parameters != candidate_parameters:
                continue
        try:
            # The published config is the normalized proposal. Replay
            # payloads contain per-request fuzz mutations and are not
            # semantic progress by themselves.
            published_path = version["config_path"]
            published = json.loads(filesystem_path(Path(str(published_path))).read_text(encoding="utf-8-sig"))
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            continue
        if config_request_key(published) == candidate_key:
            return dict(version)
    return None


def _expected_callback(parent: Mapping[str, Any], *, plugin_slug: str, registry: Mapping[str, Any]) -> str:
    callback_map = registry.get("callback_map")
    if not isinstance(callback_map, Mapping):
        callback_map = prepare_callback_registry(registry, plugin_slug).get("callback_map", {})
    expected = callback_map.get(str(parent.get("callback_id") or ""))
    return str(expected or parent.get("canonical_callback") or "")


def inherit_callback_identity(
    parameter: Mapping[str, Any], parent: Mapping[str, Any], *, plugin_slug: str, registry: Mapping[str, Any],
) -> dict[str, Any]:
    """Fill legacy parameter rows with the already-verified parent identity."""
    normalized = dict(parameter)
    parent_callback_id = str(parent.get("callback_id") or "")
    if parent_callback_id and not str(normalized.get("callback_id") or ""):
        expected = _canonical_callback_name(_expected_callback(parent, plugin_slug=plugin_slug, registry=registry))
        actual = _canonical_callback_name(normalized.get("canonical_callback"))
        if expected and actual == expected:
            normalized["callback_id"] = parent_callback_id
    return normalized


def admission_complete(
    parameter: Any, evidence: Mapping[str, Any], parent: Mapping[str, Any],
    *, plugin_slug: str, registry: Mapping[str, Any],
) -> bool:
    if not isinstance(parameter, Mapping):
        return False
    required = (
        parameter.get("name"),
        parameter.get("source"),
        parameter.get("location"),
        parameter.get("evidence_kind"),
        parameter.get("request_id"),
        parameter.get("run_id"),
        parameter.get("plugin_slug"),
        parameter.get("canonical_callback"),
        parameter.get("request_method"),
    )
    evidence_run_id = str(
        evidence.get("worker_run_id")
        or evidence.get("run_id")
        or parent.get("worker_run_id")
        or ""
    )
    expected_callback = _expected_callback(parent, plugin_slug=plugin_slug, registry=registry)
    parent_callback_id = str(parent.get("callback_id") or "")
    parameter_callback_id = str(parameter.get("callback_id") or "")
    request = evidence.get("request")
    if isinstance(request, Mapping):
        request_callback_id = str(request.get("callback_id") or "")
        request_hook_name = str(request.get("hook_name") or "")
        request_auth_context = str(request.get("auth_context") or "")
        request_metadata = request.get("metadata")
        if isinstance(request_metadata, Mapping):
            request_auth_context = request_auth_context or str(request_metadata.get("auth_context") or "")
        if (
            (request_callback_id and request_callback_id != parent_callback_id)
            or (request_hook_name and request_hook_name != str(parent.get("hook_name") or ""))
            or (request_auth_context and request_auth_context != str(parent.get("auth_context") or ""))
        ):
            return False
    return (
        all(str(value or "").strip() for value in required)
        and str(parameter.get("request_id")) == str(evidence.get("request_id"))
        and str(parameter.get("run_id")) == evidence_run_id
        and str(parameter.get("plugin_slug")) == plugin_slug
        and str(parameter.get("request_method")).upper() == str(parent.get("resolved_method") or "").upper()
        and (not parent_callback_id or parameter_callback_id == parent_callback_id)
        and _canonical_callback_name(parameter.get("canonical_callback"))
        == _canonical_callback_name(expected_callback)
    )


def probe_admission_complete(
    parameter: Mapping[str, Any], evidence: Mapping[str, Any], parent: Mapping[str, Any],
    *, plugin_slug: str, registry: Mapping[str, Any], runtime_cookie_probes: bool, ajax: bool,
) -> bool:
    if not admission_complete(parameter, evidence, parent, plugin_slug=plugin_slug, registry=registry):
        return False
    request = evidence.get("request")
    zend = evidence.get("zend")
    source = str(parameter.get("source") or "").upper()
    location = str(parameter.get("location") or "").lower()
    request_method = str(parent.get("resolved_method") or "").upper()
    access_forms = parameter.get("access_forms")
    operations = {
        str(value).strip().lower()
        for value in access_forms
        if str(value).strip()
    } if isinstance(access_forms, list) else None
    artifact_method = str(
        (request.get("http_method") if isinstance(request, Mapping) else "")
        or (request.get("method") if isinstance(request, Mapping) else "")
        or (zend.get("request_method") if isinstance(zend, Mapping) else "")
        or (zend.get("method") if isinstance(zend, Mapping) else "")
        or request_method
    ).upper()
    return (
        isinstance(request, Mapping)
        and isinstance(zend, Mapping)
        and request.get("target_plugin") == plugin_slug
        and (source, location) in ({("GET", "query"), ("POST", "form")} | (
            {("COOKIE", "cookie")} if runtime_cookie_probes else set()
        ))
        and artifact_method == request_method
        and runtime_parameter_is_accepted(
            parameter,
            request,
            zend,
            canonical_callback=_canonical_callback_name(_expected_callback(parent, plugin_slug=plugin_slug, registry=registry)),
            request_method=str(parent.get("resolved_method") or ""),
            operations=operations,
            runtime_cookie_probes=runtime_cookie_probes,
            accept_absent_key=ajax,
        )
    )


def baseline_identity_complete(
    request: Mapping[str, Any],
    zend: Mapping[str, Any],
    parent: Mapping[str, Any],
    *,
    plugin_slug: str,
) -> bool:
    request_id = str(request.get("request_id") or "").strip()
    if not request_id or zend.get("request_id") != request_id:
        return False
    expected_run = str(parent.get("worker_run_id") or "")
    if not expected_run:
        return False
    for payload in (request, zend):
        run_ids = [str(payload[key]) for key in ("run_id", "legacy_run_id") if payload.get(key)]
        if not run_ids or any(value != expected_run for value in run_ids):
            return False
        if payload.get("seed_variant_id") is not None and str(payload["seed_variant_id"]) != str(parent.get("seed_variant_id") or ""):
            return False
    if str(request.get("target_plugin") or "").strip() != plugin_slug:
        return False
    if not _request_callback_matches(request, parent):
        return False
    expected_auth = str(parent.get("auth_context") or "").strip()
    if expected_auth and _request_auth_context(request) != expected_auth:
        return False
    expected_method = str(parent.get("resolved_method") or "").upper()
    request_method = str(request.get("http_method") or request.get("method") or "").upper()
    zend_method = str(zend.get("request_method") or zend.get("method") or "").upper()
    if request_method != expected_method or (zend_method and zend_method != expected_method):
        return False
    return True


def baseline_evidence(
    evidence: Mapping[str, Any], version: Mapping[str, Any], *, plugin_slug: str,
) -> dict[str, str]:
    request = evidence["request"]
    return {
        "request_id": str(evidence["request_id"]),
        "run_id": str(evidence["worker_run_id"]),
        "plugin_slug": plugin_slug,
        "callback_id": str(version["callback_id"]),
        "http_method": str(request.get("http_method") or request.get("method") or "").upper(),
        "auth_context": _request_auth_context(request),
        "seed_variant_id": str(version.get("seed_variant_id") or ""),
    }


def parameter_replay_fields(
    parent: Mapping[str, Any], child: Mapping[str, Any], baseline: Mapping[str, Any] | None,
    *, plugin_slug: str, registry: Mapping[str, Any],
) -> list[dict[str, str]]:
    """Fields ``child`` adds over the running ``parent``: config bucket, name and Zend identity."""
    request = baseline.get("request") if isinstance(baseline, Mapping) else None
    request = dict(request) if isinstance(request, Mapping) else {}
    request.setdefault("http_method", str(child.get("resolved_method") or ""))
    try:
        parent_fields = _config_fuzzable_fields(Path(str(parent["config_path"])))
    except (KeyError, OSError, ValueError, re.error):
        parent_fields = set()
    callback = _expected_callback(child, plugin_slug=plugin_slug, registry=registry)
    return [
        {**row, "canonical_callback": callback}
        for row in handoff_new_fields(
            [dict(p) for p in child.get("known_parameters") or [] if isinstance(p, Mapping)],
            [dict(p) for p in parent.get("known_parameters") or [] if isinstance(p, Mapping)],
            parent_fields, request,
        )
    ]


def probe_context_key(
    parent: Mapping[str, Any], probe: Mapping[str, Any], evidence: Mapping[str, Any], *, plugin_slug: str,
) -> str:
    request = evidence.get("request")
    params = request.get("request_params") if isinstance(request, Mapping) else None
    params = params if isinstance(params, Mapping) else {}
    # Ignore request IDs and metadata; preserve input types and array order.
    inputs = {
        bucket: params.get(bucket, {})
        for bucket in ("query_params", "body_params", "json_params", "cookies")
    }
    input_hash = hashlib.sha256(
        json.dumps(inputs, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return json.dumps([
        str(parent.get("version") or ""),
        str(parent.get("worker_run_id") or ""),
        str(parent.get("callback_id") or ""),
        str(parent.get("hook_name") or ""),
        str(parent.get("entrypoint_type") or ""),
        str(probe.get("name") or ""),
        str(probe.get("source") or "").upper(),
        str(probe.get("location") or ""),
        str(probe.get("callback_id") or parent.get("callback_id") or ""),
        str(probe.get("plugin_slug") or plugin_slug),
        str(probe.get("canonical_callback") or parent.get("canonical_callback") or ""),
        str(probe.get("request_method") or parent.get("resolved_method") or "").upper(),
        input_hash,
    ], separators=(",", ":"))
