from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from phase10 import logical_key, merge_evidence, path_parts, path_name, placement_for_source, phuzz_config


def row(kind="opcode_runtime", placement="body", path=None):
    return {"plugin": "plugin-a", "entrypoint": "wp_ajax_a", "root_callback": "A::go", "source": "POST",
            "parameter_path": path or ["cfx_settings", "alert_emails"], "placement": placement,
            "provenance": {"kind": kind}}


class Phase10MergeTests(unittest.TestCase):
    def test_nested_path_round_trip(self):
        self.assertEqual(path_parts("cfx_settings[alert_emails]"), ("cfx_settings", "alert_emails"))
        self.assertEqual(path_name(("cfx_settings", "alert_emails")), "cfx_settings[alert_emails]")

    def test_duplicate_preserves_both_provenance(self):
        merged = merge_evidence([row(), row("uopz_helper")])
        self.assertEqual(len(merged), 1)
        self.assertEqual({item["kind"] for item in merged[0]["provenance"]}, {"opcode_runtime", "uopz_helper"})

    def test_same_name_different_callback_is_not_deduplicated(self):
        other = row(); other["root_callback"] = "B::go"
        self.assertEqual(len(merge_evidence([row(), other])), 2)

    def test_request_placement_has_distinct_keys(self):
        query = row(placement="query"); query["source"] = "REQUEST"
        body = row(placement="body"); body["source"] = "REQUEST"
        self.assertNotEqual(logical_key(query), logical_key(body))

    def test_fixed_action_and_cookie_schema(self):
        cookie = row(placement="cookie", path=["token"]); cookie["source"] = "COOKIE"
        config = phuzz_config(cookie, target="http://web/a", method="POST", fixed={"action": "a"})
        self.assertEqual(config["body_params"]["fixed"], ["action"])
        self.assertEqual(config["cookie_params"]["data"][0]["name"], "token")

    def test_placements(self):
        self.assertEqual(placement_for_source("REQUEST", request_placement="query"), "query")
        self.assertEqual(placement_for_source("COOKIE"), "cookie")

    def test_noise_plugin_never_shares_a_logical_key(self):
        noise = row(); noise["plugin"] = "hookphuzz-phase10-noise"
        self.assertNotEqual(logical_key(row()), logical_key(noise))


if __name__ == "__main__":
    unittest.main()
