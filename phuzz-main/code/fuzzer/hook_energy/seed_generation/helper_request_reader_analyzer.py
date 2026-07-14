from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


class HelperRequestReaderAnalyzer:
    """Find helpers that directly return a formal-key HTTP read.

    Exact supported source patterns only. This is not arbitrary dataflow.
    Unsupported transformations reject by default.
    """

    _CLASS = re.compile(r"\bclass\s+(?P<name>[A-Za-z_]\w*)[^\{]*\{")
    _FUNCTION = re.compile(r"\b(?P<static>static\s+)?function\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*\{")
    _PARAM = re.compile(r"\$(?P<name>[A-Za-z_]\w*)")
    _HTTP_READ = re.compile(r"\$_(?P<source>GET|POST|REQUEST|COOKIE)\s*\[\s*\$(?P<key>[A-Za-z_]\w*)\s*\]")
    _BULK_READ = re.compile(r"\$_(?P<source>GET|POST|REQUEST|COOKIE)\b(?!\s*\[)")
    _COMPUTED_READ = re.compile(r"\$_(?P<source>GET|POST|REQUEST|COOKIE)\s*\[\s*(?!\$[A-Za-z_]\w*\s*\])")
    _FILTER_READ = re.compile(r"filter_input\s*\(\s*INPUT_(?P<source>GET|POST)\s*,\s*\$(?P<key>[A-Za-z_]\w*)\s*\)")
    _REST_READ = re.compile(r"\$(?P<request>[A-Za-z_]\w*)\s*->\s*get_param\s*\(\s*\$(?P<key>[A-Za-z_]\w*)\s*\)")
    _SUPPORTED = ["GET", "POST", "REQUEST", "COOKIE", "FILTER_INPUT_GET", "FILTER_INPUT_POST", "REST_GET_PARAM"]

    def analyze(self, source_root: str | Path, *, display_root: str | Path | None = None) -> dict[str, Any]:
        root = Path(source_root)
        readers: list[dict[str, Any]] = []
        rejections: list[dict[str, Any]] = []
        symbols: dict[str, list[dict[str, Any]]] = {}
        for source_file in sorted(root.rglob("*.php")):
            result = self._analyze_file(source_file, root, display_root)
            for reader in result["readers"]:
                symbols.setdefault(reader["symbol"], []).append(reader)
            rejections.extend(result["rejections"])

        for symbol, rows in sorted(symbols.items()):
            signatures = {(row["http_source"], row["formal_key_argument_index"], row.get("definition_file")) for row in rows}
            if len(signatures) == 1:
                readers.append(rows[0])
            else:
                for row in rows:
                    rejections.append(_reject_from(row, "ambiguous_symbol_multiple_incompatible_definitions"))

        return {
            "schema_version": "hookphuzz-helper-reader-registry-v2",
            "analysis_mode": "source-assisted",
            "accepted_confidence_threshold": "high",
            "supported_sources": self._SUPPORTED,
            "readers": readers,
            "rejections": rejections,
        }

    def _analyze_file(self, source_file: Path, source_root: Path, display_root: str | Path | None) -> dict[str, list[dict[str, Any]]]:
        source = source_file.read_text(encoding="utf-8", errors="replace")
        readers: list[dict[str, Any]] = []
        rejections: list[dict[str, Any]] = []
        class_spans: list[tuple[int, int, str]] = []
        for class_match in self._CLASS.finditer(source):
            class_body_end = _closing_brace(source, class_match.end() - 1)
            if class_body_end is None:
                continue
            class_spans.append((class_match.end(), class_body_end, class_match["name"]))
            class_body = source[class_match.end() : class_body_end]
            for method_match in self._FUNCTION.finditer(class_body):
                method_open = class_match.end() + method_match.end() - 1
                method_end = _closing_brace(source, method_open)
                if method_end is None or method_end > class_body_end:
                    continue
                symbol_type = "static_method" if method_match["static"] else "instance_method"
                result = self._reader_for_symbol(
                    source_file, source_root, display_root, source,
                    f"{class_match['name']}::{method_match['name']}", symbol_type,
                    method_match, method_open, method_end,
                    declaring_class=class_match["name"], method_name=method_match["name"],
                )
                (readers if result["accepted"] else rejections).append(result["row"])

        for function_match in self._FUNCTION.finditer(source):
            if any(start <= function_match.start() <= end for start, end, _ in class_spans):
                continue
            function_open = function_match.end() - 1
            function_end = _closing_brace(source, function_open)
            if function_end is None:
                continue
            result = self._reader_for_symbol(source_file, source_root, display_root, source, function_match["name"], "function", function_match, function_open, function_end)
            (readers if result["accepted"] else rejections).append(result["row"])
        return {"readers": readers, "rejections": rejections}

    def _reader_for_symbol(
        self,
        source_file: Path,
        source_root: Path,
        display_root: str | Path | None,
        source: str,
        symbol: str,
        symbol_type: str,
        symbol_match: re.Match[str],
        body_open: int,
        body_end: int,
        *,
        declaring_class: str | None = None,
        method_name: str | None = None,
    ) -> dict[str, Any]:
        params = [match["name"] for match in self._PARAM.finditer(symbol_match["params"])]
        body = source[body_open + 1 : body_end]
        symbol_start = body_open - (symbol_match.end() - symbol_match.start()) + 1
        start_line = source.count("\n", 0, symbol_start) + 1
        end_line = source.count("\n", 0, body_end) + 1
        definition_file = source_file.resolve()
        if display_root is not None:
            definition_file = Path(display_root) / source_file.relative_to(source_root)
        base: dict[str, Any] = {
            "symbol": symbol,
            "symbol_type": symbol_type,
            "definition_file": str(definition_file).replace("\\", "/"),
            "definition_start_line": start_line,
            "definition_end_line": end_line,
        }
        if declaring_class:
            base["declaring_class"] = declaring_class
        if method_name:
            base["method_name"] = method_name

        matches = self._accepted_reads(body, params)
        if len(matches) != 1:
            return {"accepted": False, "row": {**base, "reason": _rejection_reason(body, params, len(matches))}}

        match = matches[0]
        evidence_line = source.count("\n", 0, body_open + 1 + match["start"]) + 1
        if evidence_line < start_line or evidence_line > end_line:
            return {"accepted": False, "row": {**base, "reason": "evidence_line_outside_function_body", "evidence_line": evidence_line}}
        if match["key"] not in params:
            return {"accepted": False, "row": {**base, "reason": "key_argument_cannot_be_mapped"}}

        row: dict[str, Any] = {
            "schema_version": "hookphuzz-helper-reader-v2",
            **base,
            "formal_key_argument_index": params.index(match["key"]),
            "formal_key_argument_name": match["key"],
            "http_source": match["source"],
            "source_expression": match["expression"],
            "reader_kind": "custom_helper",
            "evidence": {
                "source_expression": match["expression"],
                "source_line": evidence_line,
                "return_relation": "returns_value_read_from_http_source",
            },
            "confidence": "high",
            "analysis_mode": "source-assisted",
        }
        if match.get("request"):
            row["formal_request_argument_index"] = params.index(match["request"])
            row["formal_request_argument_name"] = match["request"]
        return {"accepted": True, "row": row}

    def _accepted_reads(self, body: str, params: list[str]) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for match in self._HTTP_READ.finditer(body):
            if match["key"] in params and _is_returned_read(body, match.start()):
                matches.append({"source": match["source"], "key": match["key"], "expression": match.group(0), "start": match.start()})
        for match in self._FILTER_READ.finditer(body):
            if match["key"] in params and _is_returned_read(body, match.start()):
                matches.append({"source": f"FILTER_INPUT_{match['source']}", "key": match["key"], "expression": match.group(0), "start": match.start()})
        for match in self._REST_READ.finditer(body):
            if match["request"] in params and match["key"] in params and _is_returned_read(body, match.start()):
                matches.append({"source": "REST_GET_PARAM", "key": match["key"], "request": match["request"], "expression": match.group(0), "start": match.start()})
        unique: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str | None]] = set()
        for item in matches:
            key = (item["source"], item["key"], item.get("request"))
            if key not in seen:
                unique.append(item)
                seen.add(key)
        return unique


def _reject_from(row: dict[str, Any], reason: str) -> dict[str, Any]:
    return {key: row[key] for key in ("symbol", "symbol_type", "definition_file", "definition_start_line", "definition_end_line") if key in row} | {"reason": reason}


def _rejection_reason(body: str, params: list[str], accepted_count: int) -> str:
    if accepted_count > 1:
        return "ambiguous_symbol_multiple_http_sources"
    if HelperRequestReaderAnalyzer._COMPUTED_READ.search(body):
        return "unsupported_computed_superglobal_key"
    if HelperRequestReaderAnalyzer._BULK_READ.search(body):
        return "unsupported_bulk_superglobal_read"
    if "filter_input" in body or "get_param" in body:
        return "key_argument_cannot_be_mapped"
    if any(token in body for token in ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE")):
        return "missing_source_evidence"
    if "sanitize_text_field" in body:
        return "sanitizes_argument_without_http_read"
    if re.search(r"\breturn\s+(['\"]|\d|true\b|false\b|null\b)", body, re.IGNORECASE):
        return "returns_constant_without_http_read"
    if params:
        return "no_direct_http_read_from_formal_key"
    return "source_body_unavailable_or_no_formals"


def _closing_brace(source: str, opening_index: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(opening_index, len(source)):
        char = source[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _is_returned_read(body: str, index: int) -> bool:
    statement_start = max(body.rfind(";", 0, index), body.rfind("{", 0, index), body.rfind("}", 0, index)) + 1
    return re.match(r"\s*return\b", body[statement_start:index]) is not None


def write_registry(source_root: str | Path, output: str | Path, *, display_root: str | Path | None = None) -> dict[str, Any]:
    registry = HelperRequestReaderAnalyzer().analyze(source_root, display_root=display_root)
    Path(output).write_text(json.dumps(registry, indent=2), encoding="utf-8")
    return registry


def write_analysis_outputs(
    source_root: str | Path,
    output: str | Path,
    *,
    display_root: str | Path | None = None,
    summary_output: str | Path | None = None,
    rejections_output: str | Path | None = None,
) -> dict[str, Any]:
    registry = write_registry(source_root, output, display_root=display_root)
    if summary_output is not None:
        summary = {
            "schema_version": registry["schema_version"],
            "accepted_registry_entries": len(registry["readers"]),
            "rejected_registry_entries": len(registry["rejections"]),
            "supported_sources": registry["supported_sources"],
            "analysis_mode": registry["analysis_mode"],
        }
        Path(summary_output).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if rejections_output is not None:
        Path(rejections_output).write_text(json.dumps(registry["rejections"], indent=2), encoding="utf-8")
    return registry

