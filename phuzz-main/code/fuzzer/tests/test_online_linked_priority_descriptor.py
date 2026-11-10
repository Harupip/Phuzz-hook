import unittest

from online_linked.coordination.priority_descriptor import (
    field_covers,
    missing_verified_fields,
    priority_descriptor,
    priority_targets,
    verified_fields,
)
from online_linked.coordination.request_matching import _request_payload_hash


class PriorityDescriptorTests(unittest.TestCase):
    def test_verified_fields_skips_non_mappings_and_stringifies(self):
        """Only structured replay proof contributes field identities."""
        self.assertEqual(verified_fields({"verified_parameters": None}), set())
        self.assertEqual(verified_fields({"verified_parameters": [
            False, "ignored", {"bucket": "body_params", "name": 17}, {"name": "missing_bucket"}, {},
        ]}), {("body_params", "17"), ("", "missing_bucket"), ("", "")})

    def test_field_covers_top_level_and_nested_selector(self):
        """Top-level proof admits nested selectors only in the same input bucket."""
        proven = ("body_params", "a")
        self.assertTrue(field_covers(("body_params", "a[b]"), proven))
        self.assertFalse(field_covers(("query_params", "a[b]"), proven))
        self.assertFalse(field_covers(("body_params", "ab"), proven))

    def test_missing_and_targets_are_sorted(self):
        """Missing proof blocks handoff, while targets retain only fuzzable proven selectors."""
        verified = {("body_params", name) for name in ("z_missing", "a_missing", "cfx_settings")}
        fuzzable = {("body_params", name) for name in ("cfx_settings[alert_emails]", "cfx_settings[account]", "other")}
        self.assertEqual(missing_verified_fields(verified, fuzzable), [
            ("body_params", "a_missing"), ("body_params", "z_missing"),
        ])
        self.assertEqual(priority_targets(verified, fuzzable), [
            ("body_params", "cfx_settings[account]"), ("body_params", "cfx_settings[alert_emails]"),
        ])

    def test_priority_descriptor_key_order_and_seed_energy_guard(self):
        """Energy carries over only when the replay uses the scored request and payload."""
        payload = {
            "http_method": "POST", "http_target": "http://web/wp-admin/admin-ajax.php",
            "request_params": {"body_params": {"new_param": "seed"}},
        }
        payload_hash = _request_payload_hash(payload)
        self.assertTrue(payload_hash)
        ack = {"allocated_energy": True, "attempts_used": "3", "seed_phuzz_energy": 31, "request_id": "r"}
        child = {"replay_config_hash": "hash", "discovery_payload_hash": payload_hash}
        attempt = {"request_id": "r"}
        replay = {"runner": {"runs": [{"request_payload": payload}]}}

        def descriptor(**overrides):
            return priority_descriptor(**{
                "replay_slug": "replay", "child": child, "targets": [("body_params", "new_param")],
                "mode": "seed_plus_bonus", "ack": ack, "attempt": attempt, "replay_result": replay, **overrides,
            })

        default = descriptor(ack={**ack, "seed_phuzz_energy": None})
        keys = ["replay_slug", "replay_hash", "targets", "mode", "allocated_energy", "attempts_used"]
        self.assertEqual(list(default), keys)
        self.assertEqual(default["targets"], [["body_params", "new_param"]])
        self.assertEqual((default["allocated_energy"], default["attempts_used"]), (0, 0))
        carry = descriptor()
        self.assertEqual(list(carry), [*keys, "seed_phuzz_energy"])
        self.assertEqual(carry["seed_phuzz_energy"], 31)
        for overrides in (
            {"attempt": {"request_id": "other"}},
            {"child": {**child, "discovery_payload_hash": "other"}},
            {"ack": {**ack, "seed_phuzz_energy": True}},
            {"replay_result": {}},
        ):
            with self.subTest(overrides=overrides):
                self.assertNotIn("seed_phuzz_energy", descriptor(**overrides))
