import unittest
from pathlib import Path

from hook_energy.seed_generation.online_common import config_hash
from online_linked.coordination.version_record import new_version_record

RECORD_KEYS = [
    "version", "parent_version", "parent_config", "config_path", "config_type", "config_hash",
    "discovery_event", "replay_result", "replay_config_path", "worker_status", "status",
    "terminal_reason", "hook_name", "callback_id", "canonical_callback", "plugin_slug",
    "entrypoint_type", "resolved_method", "auth_context", "seed_variant_id", "seed_item",
]


class NewVersionRecordTests(unittest.TestCase):
    def test_new_version_record_key_order_and_fallbacks(self):
        """The record is written to the state JSON, so key order is part of the artifact format;
        metadata fallbacks decide which hook/callback identity later evidence is matched against."""
        config = {
            "config_type": " Hook ", "entrypoint_type": "ajax",
            "metadata": {"hook_name": "h", "callback_id": "c", "callback_repr": "cb",
                         "resolved_method": "POST", "seed_variant_id": "meta-seed"},
        }
        seed_item = {"hook_name": "x", "callback_id": "y", "seed": {"seed_variant_id": "s"}}
        parent = {"version": "v0", "config_path": "p/v0.json"}
        record = new_version_record(
            "v1", config, Path("p/v1.json"), parent, "evt", seed_item, plugin_slug="plug",
        )
        self.assertEqual(list(record), RECORD_KEYS)
        self.assertEqual(record["parent_version"], "v0")
        self.assertEqual(record["parent_config"], "p/v0.json")
        self.assertEqual(record["config_type"], "hook")
        self.assertEqual(record["config_hash"], config_hash(config))
        self.assertEqual(record["hook_name"], "h")
        self.assertEqual(record["seed_variant_id"], "meta-seed")
        self.assertEqual(record["auth_context"], "authenticated")
        self.assertEqual(record["plugin_slug"], "plug")
        self.assertEqual((record["worker_status"], record["status"]), ("pending", "pending"))

        timed = new_version_record(
            "v1", config, Path("p/v1.json"), parent, "evt", seed_item,
            plugin_slug="plug", config_generation_seconds=-1.5,
        )
        self.assertEqual(list(timed), RECORD_KEYS + ["config_generation_seconds"])
        self.assertEqual(timed["config_generation_seconds"], 0.0)
        with self.assertRaises(ValueError):
            new_version_record(
                "v1", config, Path("p/v1.json"), parent, "evt", seed_item,
                plugin_slug="plug", config_generation_seconds="bad",
            )

        bare = new_version_record(
            "v0", {"metadata": "not-a-mapping"}, Path("p/v0.json"), None, None, seed_item,
            plugin_slug="plug",
        )
        self.assertEqual(bare["hook_name"], "x")
        self.assertEqual(bare["callback_id"], "y")
        self.assertEqual(bare["seed_variant_id"], "s")
        self.assertIsNone(bare["parent_version"])
        self.assertIsNone(bare["parent_config"])

        seed_item["hook_name"] = "mutated"
        seed_item["seed"]["seed_variant_id"] = "mutated"
        self.assertEqual(bare["seed_item"]["hook_name"], "x")
        self.assertEqual(bare["seed_item"]["seed"]["seed_variant_id"], "s")


if __name__ == "__main__":
    unittest.main()
