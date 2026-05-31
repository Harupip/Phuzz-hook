from __future__ import annotations

import re
from pathlib import Path
from typing import Any


class InputSignatureExtractor:
    DEFAULT_WINDOW_LINES = 200

    SUPERGLOBAL_PATTERN = re.compile(
        r"\$_(?P<source>GET|POST|REQUEST|COOKIE|FILES)\s*\[\s*(?P<quote>['\"])(?P<name>[A-Za-z0-9_\-]+)(?P=quote)\s*\]"
    )
    FILTER_INPUT_PATTERN = re.compile(
        r"filter_input\s*\(\s*INPUT_(?P<source>GET|POST|COOKIE)\s*,\s*(?P<quote>['\"])(?P<name>[A-Za-z0-9_\-]+)(?P=quote)",
        re.IGNORECASE,
    )

    LOCATION_BY_SOURCE = {
        "GET": "query",
        "POST": "body",
        "REQUEST": "body_or_query",
        "COOKIE": "cookie",
        "FILES": "body",
    }

    def extract(self, callback_metadata: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        source_file = callback_metadata.get("source_file")
        if not source_file:
            return {"input_params": []}

        path = Path(str(source_file))
        if not path.exists() or not path.is_file():
            return {"input_params": []}

        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return {"input_params": []}

        start_line = self._safe_int(callback_metadata.get("start_line"), callback_metadata.get("source_line")) or 1
        end_line = self._safe_int(callback_metadata.get("end_line"))
        if end_line is None:
            end_line = start_line + self.DEFAULT_WINDOW_LINES - 1

        start_index = max(start_line - 1, 0)
        end_index = min(max(end_line, start_line), len(lines))
        return {"input_params": self._extract_from_lines(lines[start_index:end_index], start_index + 1)}

    def _extract_from_lines(self, lines: list[str], first_line_number: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        for offset, line in enumerate(lines):
            line_number = first_line_number + offset
            for match in self.SUPERGLOBAL_PATTERN.finditer(line):
                self._append_match(results, seen, match.group("source"), match.group("name"), match.group(0), line_number)
            for match in self.FILTER_INPUT_PATTERN.finditer(line):
                self._append_match(results, seen, match.group("source").upper(), match.group("name"), match.group(0), line_number)

        return results

    def _append_match(
        self,
        results: list[dict[str, Any]],
        seen: set[tuple[str, str]],
        source: str,
        name: str,
        evidence: str,
        line_number: int,
    ) -> None:
        key = (source, name)
        if key in seen:
            return
        seen.add(key)
        results.append(
            {
                "name": name,
                "source": source,
                "location": self.LOCATION_BY_SOURCE.get(source, "body_or_query"),
                "confidence": "static_regex",
                "evidence": evidence,
                "line": line_number,
            }
        )

    def _safe_int(self, value: Any, fallback: Any = None) -> int | None:
        candidate = value if value not in (None, "") else fallback
        if candidate in (None, ""):
            return None
        try:
            return int(candidate)
        except (TypeError, ValueError):
            return None
