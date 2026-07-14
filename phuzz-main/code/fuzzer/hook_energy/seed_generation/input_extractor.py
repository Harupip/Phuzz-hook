from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .source_resolver import SourcePathResolver


class InputSignatureExtractor:
    DEFAULT_WINDOW_LINES = 200

    SUPERGLOBAL_PATTERN = re.compile(
        r"\$_(?P<source>GET|POST|REQUEST|COOKIE|FILES)\s*(?P<chain>(?:\[\s*['\"][A-Za-z0-9_\-]+['\"]\s*\])+)"
    )
    ARRAY_OFFSET_PATTERN = re.compile(
        r"\[\s*(?P<quote>['\"])(?P<name>[A-Za-z0-9_\-]+)(?P=quote)\s*\]"
    )
    FILTER_INPUT_PATTERN = re.compile(
        r"filter_input\s*\(\s*INPUT_(?P<source>GET|POST|COOKIE)\s*,\s*(?P<quote>['\"])(?P<name>[A-Za-z0-9_\-]+)(?P=quote)",
        re.IGNORECASE,
    )
    REST_GET_PARAM_PATTERN = re.compile(r"\$(?P<receiver>[A-Za-z_]\w*)\s*->\s*get_param\s*\(\s*(?P<quote>['\"])(?P<name>[A-Za-z0-9_-]+)(?P=quote)\s*\)")
    REFERER_HELPER_PATTERN = re.compile(
        r"\b(?:check_ajax_referer|check_admin_referer)\s*\(\s*(['\"])[^'\"]+\1\s*,\s*(?P<quote>['\"])(?P<name>[A-Za-z0-9_\-]+)(?P=quote)",
        re.IGNORECASE,
    )
    JSON_BODY_ASSIGNMENT_PATTERN = re.compile(
        r"\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*json_decode\s*\(\s*file_get_contents\s*\(\s*['\"]php://input['\"]\s*\)",
        re.IGNORECASE,
    )
    ARRAY_KEY_PATTERN_TEMPLATE = r"\${var}\s*\[\s*(?P<quote>['\"])(?P<name>[A-Za-z0-9_\-]+)(?P=quote)\s*\]"
    SHORTCODE_DEFAULTS_PATTERN = re.compile(
        r"shortcode_atts\s*\(\s*(?P<helper>[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*,",
        re.IGNORECASE,
    )
    FUNCTION_PATTERN_TEMPLATE = r"function\s+{name}\s*\("
    ARRAY_KEY_LITERAL_PATTERN = re.compile(r"(?P<quote>['\"])(?P<name>[A-Za-z0-9_\-]+)(?P=quote)\s*=>")

    LOCATION_BY_SOURCE = {
        "GET": "query",
        "POST": "body",
        "REQUEST": "body_or_query",
        "COOKIE": "cookie",
        "FILES": "body",
        "BODY_JSON": "body",
        "REST_GET_PARAM": "query",
    }

    def __init__(
        self,
        source_resolver: SourcePathResolver | None = None,
        *,
        container_source_root: str | Path | None = None,
        host_source_root: str | Path | None = None,
        source_root: str | Path | None = None,
        unresolved_source_reason: str | None = None,
    ) -> None:
        self.source_resolver = source_resolver or SourcePathResolver(
            container_source_root=container_source_root,
            host_source_root=host_source_root,
            source_root=source_root,
            unresolved_reason=unresolved_source_reason,
        )

    def extract(self, callback_metadata: dict[str, Any]) -> dict[str, Any]:
        callback_name = self._callback_name(callback_metadata)
        source_file = callback_metadata.get("source_file")
        source_resolution = self.source_resolver.resolve(source_file)
        if not source_file:
            return {"callback": callback_name, "input_params": [], "source_resolution": source_resolution.to_dict()}

        path = Path(str(source_resolution.resolved_source_file or ""))
        if not path.exists() or not path.is_file():
            return {"callback": callback_name, "input_params": [], "source_resolution": source_resolution.to_dict()}

        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return {"callback": callback_name, "input_params": [], "source_resolution": source_resolution.to_dict()}

        start_line = self._safe_int(callback_metadata.get("start_line"), callback_metadata.get("source_line")) or 1
        end_line = self._safe_int(callback_metadata.get("end_line"))
        if end_line is None:
            end_line = self._infer_function_end_line(lines, start_line) or start_line + self.DEFAULT_WINDOW_LINES - 1

        start_index = max(start_line - 1, 0)
        end_index = min(max(end_line, start_line), len(lines))
        callback_lines = lines[start_index:end_index]
        input_params = self._extract_from_lines(callback_lines, start_index + 1)
        if callback_metadata.get("entrypoint_type") == "rest_route":
            self._extend_rest_literals(input_params, callback_lines, start_index + 1, callback_metadata)
        self._extend_from_shallow_helpers(input_params, lines[start_index:end_index], path, start_index + 1)
        return {
            "callback": callback_name,
            "input_params": input_params,
            "source_resolution": source_resolution.to_dict(),
        }

    def _extract_from_lines(self, lines: list[str], first_line_number: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        json_body_vars: set[str] = set()

        for offset, line in enumerate(lines):
            line_number = first_line_number + offset
            for match in self.JSON_BODY_ASSIGNMENT_PATTERN.finditer(line):
                json_body_vars.add(match.group("var"))
            for match in self.SUPERGLOBAL_PATTERN.finditer(line):
                name = self._name_from_chain(match.group("chain"))
                if name:
                    self._append_match(results, seen, match.group("source"), name, match.group(0), line_number)
            for match in self.FILTER_INPUT_PATTERN.finditer(line):
                self._append_match(results, seen, match.group("source").upper(), match.group("name"), match.group(0), line_number)
            for match in self.REFERER_HELPER_PATTERN.finditer(line):
                self._append_match(
                    results,
                    seen,
                    "REQUEST",
                    match.group("name"),
                    match.group(0),
                    line_number,
                    confidence="wordpress_nonce_helper",
                    role="security_nonce",
                    fuzzable=False,
                )
            for var_name in json_body_vars:
                key_pattern = re.compile(self.ARRAY_KEY_PATTERN_TEMPLATE.format(var=re.escape(var_name)))
                for match in key_pattern.finditer(line):
                    self._append_match(results, seen, "BODY_JSON", match.group("name"), match.group(0), line_number)

        return results

    def _extend_from_shallow_helpers(
        self,
        results: list[dict[str, Any]],
        lines: list[str],
        source_path: Path,
        first_line_number: int,
    ) -> None:
        helper_names = []
        for line in lines:
            for match in self.SHORTCODE_DEFAULTS_PATTERN.finditer(line):
                helper_names.append(match.group("helper"))

        if not helper_names:
            return

        seen = {(str(item.get("source", "")), str(item.get("name", ""))) for item in results}
        plugin_root = self._plugin_root_for(source_path)
        for helper_name in helper_names:
            helper_body = self._find_function_body(plugin_root, helper_name)
            if helper_body is None:
                continue
            helper_lines, helper_first_line = helper_body
            for offset, helper_line in enumerate(helper_lines):
                line_number = helper_first_line + offset
                for match in self.ARRAY_KEY_LITERAL_PATTERN.finditer(helper_line):
                    self._append_match(
                        results,
                        seen,
                        "REQUEST",
                        match.group("name"),
                        match.group(0),
                        line_number,
                        confidence="shallow_helper_shortcode_defaults",
                    )

    def _plugin_root_for(self, source_path: Path) -> Path:
        parts = source_path.parts
        if "includes" in parts:
            include_index = parts.index("includes")
            if include_index > 0:
                return Path(*parts[:include_index])
        return source_path.parent

    def _find_function_body(self, plugin_root: Path, function_name: str) -> tuple[list[str], int] | None:
        pattern = re.compile(self.FUNCTION_PATTERN_TEMPLATE.format(name=re.escape(function_name)))
        try:
            paths = sorted(plugin_root.rglob("*.php"))
        except OSError:
            return None

        for path in paths:
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for index, line in enumerate(lines):
                if not pattern.search(line):
                    continue
                start_line = index + 1
                end_line = self._infer_function_end_line(lines, start_line) or min(
                    len(lines), start_line + self.DEFAULT_WINDOW_LINES - 1
                )
                return lines[index:end_line], start_line
        return None

    def _infer_function_end_line(self, lines: list[str], start_line: int) -> int | None:
        start_index = max(start_line - 1, 0)
        depth = 0
        saw_open = False
        for index in range(start_index, len(lines)):
            line = lines[index]
            depth += line.count("{")
            if "{" in line:
                saw_open = True
            depth -= line.count("}")
            if saw_open and depth <= 0:
                return index + 1
        return None

    def _name_from_chain(self, chain: str) -> str:
        keys = [match.group("name") for match in self.ARRAY_OFFSET_PATTERN.finditer(chain)]
        if not keys:
            return ""
        return keys[0] + "".join(f"[{key}]" for key in keys[1:])

    def _append_match(
        self,
        results: list[dict[str, Any]],
        seen: set[tuple[str, str]],
        source: str,
        name: str,
        evidence: str,
        line_number: int,
        confidence: str = "static_regex",
        role: str | None = None,
        fuzzable: bool | None = None,
    ) -> None:
        if name == "action":
            return
        key = (source, name)
        if key in seen:
            for item in results:
                if item.get("source") == source and item.get("name") == name:
                    if role is not None:
                        item["role"] = role
                    if fuzzable is not None:
                        item["fuzzable"] = fuzzable
            return
        seen.add(key)
        row = {
            "name": name,
            "source": source,
            "location": self.LOCATION_BY_SOURCE.get(source, "body_or_query"),
            "confidence": confidence,
            "evidence": evidence,
            "line": line_number,
        }
        if role is not None:
            row["role"] = role
        if fuzzable is not None:
            row["fuzzable"] = fuzzable
        results.append(row)

    def _extend_rest_literals(self, results, lines, first_line_number, metadata) -> None:
        formal = {str(item.get("name")) for item in metadata.get("formal_parameters", []) if isinstance(item, dict)}
        seen = {(str(item.get("source", "")), str(item.get("name", ""))) for item in results}
        for offset, line in enumerate(lines):
            for match in self.REST_GET_PARAM_PATTERN.finditer(line):
                if match.group("receiver") in formal:
                    self._append_match(results, seen, "REST_GET_PARAM", match.group("name"), match.group(0), first_line_number + offset, confidence="rest_literal")

    def _callback_name(self, callback_metadata: dict[str, Any]) -> str:
        for key in ("callback_repr", "callback_name", "stable_id", "runtime_id"):
            value = str(callback_metadata.get(key, "")).strip()
            if value:
                return value
        class_name = str(callback_metadata.get("class_name", "")).strip()
        method_name = str(callback_metadata.get("method_name", "")).strip()
        if class_name and method_name:
            return f"{class_name}::{method_name}"
        function_name = str(callback_metadata.get("function_name", "")).strip()
        if function_name:
            return function_name
        return ""

    def _safe_int(self, value: Any, fallback: Any = None) -> int | None:
        candidate = value if value not in (None, "") else fallback
        if candidate in (None, ""):
            return None
        try:
            return int(candidate)
        except (TypeError, ValueError):
            return None
