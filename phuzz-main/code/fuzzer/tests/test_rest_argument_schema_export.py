from __future__ import annotations

import sys
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from seed_generation.config.config_exporter import build_config_for_seed_item


class RestArgumentSchemaExportTests(unittest.TestCase):
    def test_json_primitive_values_remain_native(self) -> None:
        _, config = build_config_for_seed_item({"hook_name": "rest_route:demo/v1/items", "callback_id": "cb", "seed": {
            "auth_mode": "unauth-capable", "method": "POST", "path": "/wp-json/demo/v1/items", "body": {"enabled": True, "count": 1, "ratio": 1.0},
            "query_params": {}, "headers": {"Content-Type": "application/json"}, "fixed_params": ["enabled", "count", "ratio"], "fuzzable_params": [],
        }})
        values = {item["name"]: item["value"] for item in config["body_params"]["data"]}
        self.assertEqual(values, {"enabled": True, "count": 1, "ratio": 1.0})


if __name__ == "__main__":
    unittest.main()
