from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


class HelperRequestReaderAnalyzer:
    """Find helpers that directly read a formal key from a supported HTTP superglobal."""

    _CLASS = re.compile(r"\bclass\s+(?P<name>[A-Za-z_]\w*)[^\{]*\{")
    _METHOD = re.compile(
        r"\b(?P<static>static\s+)?function\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*\{"
    )
    _PARAM = re.compile(r"\$(?P<name>[A-Za-z_]\w*)")
    _HTTP_READ = re.compile(r"\$_(?P<source>GET|POST|REQUEST|COOKIE)\s*\[\s*\$(?P<key>[A-Za-z_]\w*)\s*\]")

    def analyze(self, source_root: str | Path, *, display_root: str | Path | None = None) -> dict[str, Any]:
        root = Path(source_root)
        readers: list[dict[str, Any]] = []
        for source_file in sorted(root.rglob("*.php")):
            readers.extend(self._analyze_file(source_file, root, display_root))
        return {"schema_version": "hookphuzz-helper-reader-registry-v1", "readers": readers}

    def _analyze_file(self, source_file: Path, source_root: Path, display_root: str | Path | None) -> list[dict[str, Any]]:
        source = source_file.read_text(encoding="utf-8", errors="replace")
        readers: list[dict[str, Any]] = []
        for class_match in self._CLASS.finditer(source):
            class_body_end = _closing_brace(source, class_match.end() - 1)
            if class_body_end is None:
                continue
            class_name = class_match["name"]
            class_body = source[class_match.end() : class_body_end]
            for method_match in self._METHOD.finditer(class_body):
                if not method_match["static"]:
                    continue
                method_open = class_match.end() + method_match.end() - 1
                method_end = _closing_brace(source, method_open)
                if method_end is None or method_end > class_body_end:
                    continue
                reader = self._reader_for_method(
                    source_file, source_root, display_root, source, class_name, method_match, method_open, method_end
                )
                if reader:
                    readers.append(reader)
        return readers

    def _reader_for_method(
        self,
        source_file: Path,
        source_root: Path,
        display_root: str | Path | None,
        source: str,
        class_name: str,
        method_match: re.Match[str],
        method_open: int,
        method_end: int,
    ) -> dict[str, Any] | None:
        params = [match["name"] for match in self._PARAM.finditer(method_match["params"])]
        body = source[method_open + 1 : method_end]
        reads = [
            match
            for match in self._HTTP_READ.finditer(body)
            if match["key"] in params and _is_returned_read(body, match.start())
        ]
        distinct_reads = {(match["source"], match["key"]) for match in reads}
        if len(distinct_reads) != 1:
            return None
        read = reads[0]
        key_index = params.index(read["key"])
        method_start = method_open - (method_match.end() - method_match.start()) + 1
        start_line = source.count("\n", 0, method_start) + 1
        end_line = source.count("\n", 0, method_end) + 1
        source_line = source.count("\n", 0, method_open + 1 + read.start()) + 1
        expression = read.group(0)
        definition_file = source_file.resolve()
        if display_root is not None:
            definition_file = Path(display_root) / source_file.relative_to(source_root)
        return {
            "schema_version": "hookphuzz-helper-reader-v1",
            "symbol": f"{class_name}::{method_match['name']}",
            "symbol_type": "static_method",
            "declaring_class": class_name,
            "method_name": method_match["name"],
            "formal_key_argument_index": key_index,
            "formal_key_argument_name": read["key"],
            "http_source": read["source"],
            "reader_kind": "custom_helper",
            "definition_file": str(definition_file).replace("\\", "/"),
            "definition_start_line": start_line,
            "definition_end_line": end_line,
            "evidence": {
                "source_expression": expression,
                "source_line": source_line,
                "return_relation": "returns_value_read_from_http_source",
            },
            "confidence": "high",
            "analysis_mode": "source-assisted",
        }


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
