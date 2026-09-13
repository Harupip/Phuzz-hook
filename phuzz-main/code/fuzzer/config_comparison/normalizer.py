from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from urllib.parse import parse_qsl, urlsplit, urlunsplit
from typing import Any

from .models import ConfigError, DifferenceKind, NormalizedConfig, NormalizationResult
from .policy import ComparisonPolicy


SOURCES = ("headers", "cookies", "query_params", "body_params")
SECTION_KEYS = frozenset({"data", "fixed", "fuzz"})
TOP_LEVEL_KEYS = frozenset({"target", "methods", *SOURCES})
MISSING = object()


def pointer_escape(value: str) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def _freeze_typed(value: Any) -> tuple[Any, ...]:
    if value is None:
        return ("null",)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        return ("float", value)
    if isinstance(value, str):
        return ("string", value)
    if isinstance(value, list):
        return ("list", tuple(_freeze_typed(item) for item in value))
    if isinstance(value, dict):
        items = tuple(
            sorted(
                ((str(key), _freeze_typed(item)) for key, item in value.items()),
                key=lambda item: item[0],
            )
        )
        return ("dict", items)
    return (type(value).__name__, repr(value))


def _error(kind: DifferenceKind, path: str, message: str) -> ConfigError:
    return ConfigError(kind=kind, path=path, message=message)


def _normalize_target(value: Any, errors: list[ConfigError]) -> tuple[str, list[tuple[str, str]]]:
    if not isinstance(value, str) or not value.strip():
        errors.append(_error(DifferenceKind.INVALID_CONFIG, "/target", "target must be a non-empty absolute HTTP(S) URL"))
        return "", []

    raw = value.strip()
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or parsed.hostname is None:
            raise ValueError("target must be a non-empty absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            errors.append(_error(DifferenceKind.INVALID_CONFIG, "/target", "userinfo_not_allowed"))
            return "", []
        if parsed.fragment or "#" in raw:
            errors.append(_error(DifferenceKind.INVALID_CONFIG, "/target", "fragment_not_allowed"))
            return "", []
        port = parsed.port
    except ValueError as exc:
        message = "invalid_port" if "port" in str(exc).lower() else str(exc)
        errors.append(_error(DifferenceKind.INVALID_CONFIG, "/target", message))
        return "", []

    hostname = parsed.hostname.lower()
    if ":" in hostname and not hostname.startswith("["):
        netloc = f"[{hostname}]"
    else:
        netloc = hostname
    default_port = (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    )
    if port is not None and not default_port:
        netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    return urlunsplit((parsed.scheme.lower(), netloc, path, "", "")), query_pairs


def _normalize_methods(value: Any, errors: list[ConfigError]) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        errors.append(_error(DifferenceKind.INVALID_CONFIG, "/methods", "methods must be a non-empty list"))
        return ()
    methods: set[str] = set()
    for index, method in enumerate(value):
        if not isinstance(method, str) or not method.strip():
            errors.append(_error(DifferenceKind.INVALID_CONFIG, f"/methods/{index}", "method must be a non-empty string"))
            continue
        methods.add(method.strip().upper())
    if not methods:
        errors.append(_error(DifferenceKind.INVALID_CONFIG, "/methods", "methods must contain a non-empty string"))
    return tuple(sorted(methods))


def _normalize_selectors(
    source: str,
    section: Mapping[str, Any],
    errors: list[ConfigError],
) -> dict[str, frozenset[str]]:
    selectors: dict[str, frozenset[str]] = {}
    for selector_kind in ("fixed", "fuzz"):
        value = section.get(selector_kind, []) if selector_kind in section else []
        if not isinstance(value, list):
            errors.append(_error(DifferenceKind.INVALID_CONFIG, f"/{source}/{selector_kind}", "selector must be a list"))
            selectors[selector_kind] = frozenset()
            continue
        patterns: set[str] = set()
        for index, pattern in enumerate(value):
            if not isinstance(pattern, str):
                errors.append(_error(DifferenceKind.INVALID_CONFIG, f"/{source}/{selector_kind}/{index}", "selector must be a string"))
                continue
            try:
                re.compile(pattern)
            except re.error:
                errors.append(_error(DifferenceKind.INVALID_CONFIG, f"/{source}/{selector_kind}", "invalid_regex"))
                continue
            patterns.add(pattern)
        selectors[selector_kind] = frozenset(patterns)
    return selectors


def _normalize_section(
    source: str,
    raw_section: Any,
    errors: list[ConfigError],
) -> tuple[dict[str, dict[str, Any]], dict[str, frozenset[str]], dict[str, Any]]:
    if not isinstance(raw_section, Mapping):
        errors.append(_error(DifferenceKind.INVALID_CONFIG, f"/{source}", "section must be an object"))
        return {}, {"fixed": frozenset(), "fuzz": frozenset()}, {}
    if "data" not in raw_section:
        errors.append(_error(DifferenceKind.INVALID_CONFIG, f"/{source}/data", "data is required when section is present"))
        data: list[Any] = []
    else:
        data = raw_section.get("data")
        if not isinstance(data, list):
            errors.append(_error(DifferenceKind.INVALID_CONFIG, f"/{source}/data", "data must be a list"))
            data = []

    parameters: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(data):
        item_path = f"/{source}/data/{index}"
        if not isinstance(item, Mapping):
            errors.append(_error(DifferenceKind.INVALID_CONFIG, item_path, "data entry must be an object"))
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name:
            errors.append(_error(DifferenceKind.INVALID_CONFIG, f"{item_path}/name", "parameter name must be a non-empty string"))
            continue
        if name in parameters:
            errors.append(_error(DifferenceKind.DUPLICATE_PARAMETER, f"/{source}/{pointer_escape(name)}", "duplicate_parameter"))
            continue
        has_value = "value" in item
        has_seeds = "seeds" in item
        if not has_value and not has_seeds:
            errors.append(_error(DifferenceKind.INVALID_CONFIG, f"/{source}/{pointer_escape(name)}", "missing_value_and_seeds"))
            continue
        if has_seeds and (not isinstance(item.get("seeds"), list) or not item.get("seeds")):
            errors.append(_error(DifferenceKind.INVALID_CONFIG, f"{item_path}/seeds", "seeds must be a non-empty list"))
            continue
        parameters[name] = copy.deepcopy(dict(item))

    selectors = _normalize_selectors(source, raw_section, errors)
    extras = copy.deepcopy({key: value for key, value in raw_section.items() if key not in SECTION_KEYS})
    return parameters, selectors, extras


def normalize_config(config: dict, policy: ComparisonPolicy) -> NormalizationResult:
    errors: list[ConfigError] = []
    if not isinstance(config, dict):
        return NormalizationResult(None, [_error(DifferenceKind.INVALID_CONFIG, "", "config must be an object")])

    target, query_pairs = _normalize_target(config.get("target", MISSING), errors)
    methods = _normalize_methods(config.get("methods", MISSING), errors)
    parameters: dict[str, dict[str, dict[str, Any]]] = {}
    selectors: dict[str, dict[str, frozenset[str]]] = {}
    section_extras: dict[str, dict[str, Any]] = {}

    for source in ("headers", "cookies", "query_params", "body_params"):
        raw_section = config.get(source, MISSING)
        if raw_section is MISSING:
            parameters[source] = {}
            selectors[source] = {"fixed": frozenset(), "fuzz": frozenset()}
            section_extras[source] = {}
            continue
        section_parameters, section_selectors, extras = _normalize_section(source, raw_section, errors)
        parameters[source] = section_parameters
        selectors[source] = section_selectors
        section_extras[source] = extras

    query_names = set()
    for name, value in query_pairs:
        if not name:
            errors.append(_error(DifferenceKind.INVALID_CONFIG, "/target", "query parameter name must be non-empty"))
            continue
        if name in query_names:
            errors.append(_error(DifferenceKind.DUPLICATE_PARAMETER, f"/query_params/{pointer_escape(name)}", "duplicate_parameter"))
            continue
        query_names.add(name)
        if name in parameters["query_params"]:
            errors.append(_error(DifferenceKind.INVALID_CONFIG, f"/query_params/{pointer_escape(name)}", "conflicting_query_definition"))
            continue
        parameters["query_params"][name] = {"name": name, "value": value, "origin": "target_query"}
        selectors["query_params"]["fixed"] = frozenset(set(selectors["query_params"]["fixed"]) | {name})

    extras = copy.deepcopy({key: value for key, value in config.items() if key not in TOP_LEVEL_KEYS})
    if errors:
        return NormalizationResult(None, errors)
    return NormalizationResult(
        NormalizedConfig(
            target=target,
            methods=methods,
            parameters=parameters,
            selectors=selectors,
            section_extras=section_extras,
            extras=extras,
        ),
        [],
    )
