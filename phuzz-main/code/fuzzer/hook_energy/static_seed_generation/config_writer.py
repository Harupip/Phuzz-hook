from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


class StaticSeedConfigWriter:
    def __init__(self, output_dir: Path | str) -> None:
        self.output_dir = Path(output_dir)

    def write_configs(self, plugin_slug: str, endpoints: list[dict[str, Any]]) -> list[Path]:
        config_dir = self.output_dir / "configs"
        config_dir.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        for endpoint in endpoints:
            if endpoint.get("unresolved") or endpoint.get("confidence") == "low":
                continue
            action = endpoint.get("action")
            if endpoint.get("kind") != "rest" and not action:
                continue
            config = self._build_config(endpoint)
            suffix = str(action or endpoint.get("route", "rest")).strip("/").replace("/", "_")
            filename = f"{plugin_slug}_{endpoint.get('kind')}_{self._safe_name(suffix)}.json"
            path = config_dir / filename
            path.write_text(json.dumps(config, indent=4, ensure_ascii=False), encoding="utf-8")
            written.append(path)
        return written

    def _build_config(self, endpoint: dict[str, Any]) -> dict[str, Any]:
        method = str(endpoint.get("method") or "GET").upper()
        fixed = dict(endpoint.get("fixed_params") or {})
        fuzz_names = list(endpoint.get("fuzz_params") or ["fuzz"])
        fixed_names = list(fixed.keys())
        data = [{"name": name, "value": value} for name, value in fixed.items()]
        data.extend({"name": name, "value": "fuzz"} for name in fuzz_names if name not in fixed)
        param_key = "query_params" if method == "GET" else "body_params"
        return {
            "target": endpoint["target"],
            "methods": [method],
            param_key: {
                "data": data,
                "fixed": fixed_names,
                "fuzz": [name for name in fuzz_names if name not in fixed],
                "weight": 1,
            },
        }

    def _safe_name(self, value: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "endpoint"
