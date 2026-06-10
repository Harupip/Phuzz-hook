from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from .config_writer import StaticSeedConfigWriter
from .models import StaticEndpoint, StaticParam


class StaticSeedScanner:
    SKIP_DIRS = {"vendor", "node_modules", "tests", ".git", "build", "dist"}
    PREFIXES = {
        "wp_ajax_nopriv_": ("wp_ajax", "/wp-admin/admin-ajax.php", "unauthenticated"),
        "wp_ajax_": ("wp_ajax", "/wp-admin/admin-ajax.php", "authenticated"),
        "admin_post_nopriv_": ("admin_post", "/wp-admin/admin-post.php", "unauthenticated"),
        "admin_post_": ("admin_post", "/wp-admin/admin-post.php", "authenticated"),
    }
    SINKS = {
        r"\$wpdb->query\s*\(": "SQLi:$wpdb->query",
        r"\$wpdb->get_results\s*\(": "SQLi:$wpdb->get_results",
        r"\$wpdb->get_row\s*\(": "SQLi:$wpdb->get_row",
        r"\bmysqli_query\s*\(": "SQLi:mysqli_query",
        r"\b(PDO::query|->query)\s*\(": "SQLi:PDO::query",
        r"\b(PDO::exec|->exec)\s*\(": "SQLi:PDO::exec",
        r"\b(system|exec|shell_exec|passthru)\s*\(": "RCE:{name}",
        r"\b(file_get_contents|fopen|file|include|require|readfile)\s*\(": "Path Traversal/LFI:{name}",
        r"\b(unserialize|maybe_unserialize)\s*\(": "Insecure deserialization:{name}",
        r"\bwp_redirect\s*\(": "Open Redirect:wp_redirect",
        r"\bheader\s*\(\s*['\"]Location:": "Open Redirect:header(Location)",
    }

    def __init__(self, base_url: str = "http://web") -> None:
        self.base_url = base_url.rstrip("/")

    def scan(
        self,
        plugin_path: Path | str,
        plugin_slug: str,
        output_dir: Path | str,
        *,
        write_configs: bool = False,
        include_rest: bool = False,
        include_unresolved: bool = False,
        min_confidence: str = "low",
    ) -> dict[str, Any]:
        plugin = Path(plugin_path)
        output = Path(output_dir)
        endpoints: list[StaticEndpoint] = []
        files = list(self._php_files(plugin))
        for file in files:
            text = file.read_text(encoding="utf-8", errors="replace")
            symbols = self._symbols(text)
            bodies = self._callable_bodies(text)
            for call, args, line in self._calls(text, {"add_action", "add_filter"}):
                endpoint = self._hook_endpoint(call, args, file, line, symbols, bodies)
                if endpoint and (include_unresolved or not endpoint.unresolved):
                    endpoints.append(endpoint)
            if include_rest:
                for _, args, line in self._calls(text, {"register_rest_route"}):
                    endpoints.extend(self._rest_endpoints(args, file, line, bodies))

        endpoint_dicts = [item.to_dict() for item in endpoints if self._meets_confidence(item.confidence, min_confidence)]
        output.mkdir(parents=True, exist_ok=True)
        configs_written = 0
        if write_configs:
            configs_written = len(StaticSeedConfigWriter(output).write_configs(plugin_slug, endpoint_dicts))
        report = {
            "plugin_slug": plugin_slug,
            "plugin_path": str(plugin),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "summary": {
                "php_files_scanned": len(files),
                "hooks_found": len([item for item in endpoint_dicts if item["kind"] != "rest"]),
                "resolved_http_endpoints": len([item for item in endpoint_dicts if item["kind"] != "rest" and not item.get("unresolved")]),
                "rest_routes_found": len([item for item in endpoint_dicts if item["kind"] == "rest"]),
                "configs_written": configs_written,
            },
            "endpoints": endpoint_dicts,
        }
        (output / "static_seed_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        return report

    def _php_files(self, plugin: Path) -> list[Path]:
        return sorted(
            path
            for path in plugin.rglob("*.php")
            if not any(part in self.SKIP_DIRS for part in path.relative_to(plugin).parts[:-1])
        )

    def _hook_endpoint(
        self,
        call: str,
        args: str,
        file: Path,
        line: int,
        symbols: dict[str, str],
        bodies: dict[str, str],
    ) -> StaticEndpoint | None:
        parts = self._split_args(args)
        if not parts:
            return None
        hook_name, confidence = self._resolve_string(parts[0], symbols)
        expression = parts[0].strip()
        if hook_name and not any(hook_name.startswith(prefix) for prefix in self.PREFIXES):
            return None
        if hook_name is None:
            if not self._looks_direct_expression(expression):
                return None
            callback = self._callback(parts[1] if len(parts) > 1 else "")
            return StaticEndpoint(
                kind="wp_ajax",
                hook_name=None,
                target="",
                method="POST",
                auth_mode="unknown",
                callback=callback,
                source_file=str(file),
                source_line=line,
                confidence="low",
                unresolved=True,
                expression_text=expression,
            )
        if call == "add_filter" and not any(hook_name.startswith(prefix) for prefix in self.PREFIXES):
            return None
        prefix = next(prefix for prefix in self.PREFIXES if hook_name.startswith(prefix))
        kind, path, auth = self.PREFIXES[prefix]
        action = hook_name.removeprefix(prefix)
        callback = self._callback(parts[1] if len(parts) > 1 else "")
        body = bodies.get(callback or "", "")
        params = self._params(body, str(file), rest=False)
        if not params:
            params = [StaticParam("fuzz", "REQUEST", str(file), line, "low")]
        sinks = self._sinks(body)
        return StaticEndpoint(
            kind=kind,
            hook_name=hook_name,
            action=action,
            target=self.base_url + path,
            method="POST",
            auth_mode=auth,
            callback=callback,
            params=params,
            fixed_params={"action": action},
            fuzz_params=self._param_names(params),
            sink_hints=sinks,
            source_file=str(file),
            source_line=line,
            confidence=confidence,
        )

    def _rest_endpoints(self, args: str, file: Path, line: int, bodies: dict[str, str]) -> list[StaticEndpoint]:
        parts = self._split_args(args)
        if len(parts) < 3:
            return []
        namespace = self._literal(parts[0])
        route = self._literal(parts[1])
        if not namespace or not route:
            return []
        callback = self._array_value(parts[2], "callback") or self._callback(parts[2])
        permission = self._array_value(parts[2], "permission_callback")
        methods = self._methods(parts[2])
        auth = "unauthenticated" if permission == "__return_true" else "unknown"
        body = bodies.get(callback or "", "")
        params = self._params(body, str(file), rest=True) or [StaticParam("fuzz", "REST", str(file), line, "low")]
        sinks = self._sinks(body)
        clean_route = "/" + "/".join([namespace.strip("/"), route.strip("/")])
        return [
            StaticEndpoint(
                kind="rest",
                route=clean_route,
                namespace=namespace,
                target=self.base_url + "/wp-json" + clean_route,
                method=method,
                auth_mode=auth,
                callback=callback,
                params=params,
                fuzz_params=self._param_names(params),
                sink_hints=sinks,
                source_file=str(file),
                source_line=line,
                confidence="high",
                permission_callback=permission,
            )
            for method in methods
        ]

    def _symbols(self, text: str) -> dict[str, str]:
        symbols = {m.group(1): m.group(2) for m in re.finditer(r"\$([A-Za-z_]\w*)\s*=\s*['\"]([^'\"]+)['\"]\s*;", text)}
        symbols.update({m.group(1): m.group(2) for m in re.finditer(r"define\s*\(\s*['\"]([A-Za-z_]\w*)['\"]\s*,\s*['\"]([^'\"]+)['\"]", text)})
        symbols.update({m.group(1): m.group(2) for m in re.finditer(r"\bconst\s+([A-Za-z_]\w*)\s*=\s*['\"]([^'\"]+)['\"]", text)})
        return symbols

    def _callable_bodies(self, text: str) -> dict[str, str]:
        bodies: dict[str, str] = {}
        for match in re.finditer(r"\bfunction\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*\{", text):
            bodies[match.group(1)] = self._brace_body(text, match.end() - 1)
        return bodies

    def _calls(self, text: str, names: set[str]) -> list[tuple[str, str, int]]:
        calls: list[tuple[str, str, int]] = []
        for match in re.finditer(r"\b(" + "|".join(re.escape(name) for name in names) + r")\s*\(", text):
            end = self._matching_paren(text, match.end() - 1)
            if end != -1:
                calls.append((match.group(1), text[match.end() : end], text.count("\n", 0, match.start()) + 1))
        return calls

    def _matching_paren(self, text: str, start: int) -> int:
        depth = 0
        quote = ""
        escape = False
        for index in range(start, len(text)):
            ch = text[index]
            if quote:
                escape = (not escape and ch == "\\")
                if ch == quote and not escape:
                    quote = ""
                elif ch != "\\":
                    escape = False
                continue
            if ch in {"'", '"'}:
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return index
        return -1

    def _brace_body(self, text: str, start: int) -> str:
        depth = 0
        for index in range(start, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    return text[start + 1 : index]
        return ""

    def _split_args(self, args: str) -> list[str]:
        parts: list[str] = []
        start = 0
        depth = 0
        quote = ""
        for index, ch in enumerate(args):
            if quote:
                if ch == quote and args[index - 1] != "\\":
                    quote = ""
                continue
            if ch in {"'", '"'}:
                quote = ch
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append(args[start:index].strip())
                start = index + 1
        tail = args[start:].strip()
        if tail:
            parts.append(tail)
        return parts

    def _resolve_string(self, expr: str, symbols: dict[str, str]) -> tuple[str | None, str]:
        literal = self._literal(expr)
        if literal is not None:
            return literal, "high"
        pieces = [part.strip() for part in expr.split(".")]
        if len(pieces) > 1:
            resolved = ""
            for piece in pieces:
                value = self._literal(piece)
                if value is None and piece.startswith("$"):
                    value = symbols.get(piece[1:])
                if value is None:
                    return None, "low"
                resolved += value
            return resolved, "medium"
        return None, "low"

    def _literal(self, expr: str) -> str | None:
        match = re.fullmatch(r"\s*['\"]([^'\"]*)['\"]\s*", expr, re.S)
        return match.group(1) if match else None

    def _callback(self, expr: str) -> str | None:
        literal = self._literal(expr)
        if literal:
            return literal
        strings = re.findall(r"['\"]([^'\"]+)['\"]", expr)
        return strings[-1] if strings else expr.strip() or None

    def _array_value(self, expr: str, key: str) -> str | None:
        match = re.search(r"['\"]" + re.escape(key) + r"['\"]\s*=>\s*([^,\]\n]+)", expr)
        if not match:
            return None
        return self._callback(match.group(1).strip())

    def _methods(self, expr: str) -> list[str]:
        value = self._array_value(expr, "methods")
        if not value:
            return ["GET", "POST"]
        upper = value.upper()
        aliases = {"CREATABLE": "POST", "READABLE": "GET", "EDITABLE": "POST", "DELETABLE": "DELETE"}
        return [aliases.get(upper.split("::")[-1], upper)]

    def _params(self, body: str, file: str, *, rest: bool) -> list[StaticParam]:
        params: dict[str, StaticParam] = {}
        for source, name in re.findall(r"\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]", body):
            params.setdefault(name, StaticParam(name, source, file, self._line(body, name), "high"))
        for source, name in re.findall(r"filter_input\s*\(\s*INPUT_(GET|POST|COOKIE)\s*,\s*['\"]([^'\"]+)['\"]", body):
            params.setdefault(name, StaticParam(name, source, file, self._line(body, name), "high"))
        if rest:
            for name in re.findall(r"->get_param\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", body):
                params.setdefault(name, StaticParam(name, "REST", file, self._line(body, name), "high"))
            for name in re.findall(r"\$[A-Za-z_]\w*\s*\[\s*['\"]([^'\"]+)['\"]\s*\]", body):
                params.setdefault(name, StaticParam(name, "REST", file, self._line(body, name), "medium"))
        return list(params.values())

    def _sinks(self, body: str) -> list[str]:
        hints: list[str] = []
        for pattern, label in self.SINKS.items():
            for match in re.finditer(pattern, body):
                name = match.group(1) if "{name}" in label and match.groups() else ""
                hint = label.replace("{name}", name)
                if hint not in hints:
                    hints.append(hint)
        return hints

    def _line(self, text: str, needle: str) -> int:
        index = text.find(needle)
        return text.count("\n", 0, max(index, 0)) + 1

    def _param_names(self, params: list[StaticParam]) -> list[str]:
        names: list[str] = []
        for item in params:
            if item.name not in names and item.name != "action":
                names.append(item.name)
        return names or ["fuzz"]

    def _looks_direct_expression(self, expr: str) -> bool:
        return any(prefix in expr for prefix in self.PREFIXES)

    def _meets_confidence(self, confidence: str, minimum: str) -> bool:
        rank = {"low": 0, "medium": 1, "high": 2}
        return rank.get(confidence, 0) >= rank.get(minimum, 0)
