import copy
import json
import tempfile
import unittest
from pathlib import Path

from hook_energy.seed_generation.zend_runtime.bridge_cli import verify_pass2_contract


class ZendPass2IdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.zend_dir = Path(self.tmp.name) / "zend"
        self.request_dir = Path(self.tmp.name) / "request"
        self.zend_dir.mkdir()
        self.request_dir.mkdir()

    def fixture(self, method, variant, name, request_id):
        seed = {
            "hook_name": "wp_ajax_save", "callback_id": "cb-1",
            "seed": {
                "method": method, "resolved_method": method, "seed_variant_id": variant,
                "zend_canonical_callback": "Demo::save",
                "input_params": [{
                    "name": name, "source": method,
                    "location": "query" if method == "GET" else "form",
                }],
            },
        }
        row = {
            "hook_name": "wp_ajax_save", "callback_id": "cb-1",
            "resolved_method": method, "seed_variant_id": variant,
            "callback_reached": True, "matched_artifact": request_id + ".json",
        }
        zend = {
            "schema_version": 4, "run_id": "run-1", "request_id": request_id,
            "request_method": method,
            "callback_summaries": [{
                "callback": "Demo::save",
                "unique_parameters": [{
                    "source": method, "path": [name], "helper_depth": 0,
                    "observed_count": 1,
                }],
            }],
        }
        request = {
            "request_id": request_id, "http_method": method,
            "request_params": {
                "query_params" if method == "GET" else "body_params": {name: "probe"},
            },
        }
        self.write_artifact(self.zend_dir, row, zend)
        self.write_artifact(self.request_dir, row, request)
        return seed, row

    def write_artifact(self, directory, row, artifact):
        (directory / row["matched_artifact"]).write_text(json.dumps(artifact), encoding="utf-8")

    def verify(self, seeds, rows):
        return verify_pass2_contract(
            {"legacy_run_id": "run-1", "runs": rows},
            {"suggested_seeds": seeds}, self.zend_dir,
            pass2_artifacts_dir=self.request_dir,
        )

    def test_get_and_post_same_callback_accept_together(self):
        get, get_row = self.fixture("GET", "", "post_id", "get")
        post, post_row = self.fixture("POST", "", "term", "post")
        for seed, row in ((get, get_row), (post, post_row)):
            self.assertEqual(self.verify([seed], [row]), {"accepted": 1, "total": 1})
        for seeds in ([get, post], [post, get]):
            self.assertEqual(self.verify(seeds, [get_row, post_row]), {"accepted": 2, "total": 2})

    def test_variants_do_not_overwrite_or_borrow_expected(self):
        first, first_row = self.fixture("POST", "first", "first_key", "first")
        second, second_row = self.fixture("POST", "second", "second_key", "second")
        for seeds in ([first, second], [second, first]):
            self.assertEqual(self.verify(seeds, [first_row, second_row]), {"accepted": 2, "total": 2})
            wrong = dict(second_row, seed_variant_id="first")
            self.assertEqual(self.verify(seeds, [wrong]), {"accepted": 0, "total": 1})
            unknown = dict(second_row, seed_variant_id="unknown")
            self.assertEqual(self.verify(seeds, [unknown]), {"accepted": 0, "total": 1})

    def test_legacy_missing_variant_requires_unique_expected(self):
        first, first_row = self.fixture("POST", "first", "first_key", "first")
        second, second_row = self.fixture("POST", "second", "second_key", "second")
        legacy = copy.deepcopy(second_row)
        legacy.pop("seed_variant_id")
        self.assertEqual(self.verify([second], [legacy]), {"accepted": 1, "total": 1})
        self.assertEqual(self.verify([first, second], [legacy]), {"accepted": 0, "total": 1})
        explicit_default = dict(legacy, seed_variant_id="")
        self.assertEqual(self.verify([second], [explicit_default]), {"accepted": 0, "total": 1})

    def test_legacy_missing_row_method_uses_correlated_artifact_method(self):
        get, get_row = self.fixture("GET", "", "post_id", "get")
        post, post_row = self.fixture("POST", "", "term", "post")
        get_row.pop("resolved_method")
        post_row.pop("resolved_method")
        self.assertEqual(self.verify([get, post], [get_row, post_row]), {"accepted": 2, "total": 2})

    def test_legacy_missing_all_methods_requires_unique_expected(self):
        get, get_row = self.fixture("GET", "", "post_id", "get")
        post, _ = self.fixture("POST", "", "term", "post")
        post["seed"]["input_params"] = copy.deepcopy(get["seed"]["input_params"])
        get_row.pop("resolved_method")
        for directory, field in ((self.zend_dir, "request_method"), (self.request_dir, "http_method")):
            artifact = json.loads((directory / get_row["matched_artifact"]).read_text(encoding="utf-8"))
            artifact.pop(field)
            self.write_artifact(directory, get_row, artifact)
        self.assertEqual(self.verify([get], [get_row]), {"accepted": 1, "total": 1})
        self.assertEqual(self.verify([get, post], [get_row]), {"accepted": 0, "total": 1})

    def test_artifact_with_other_method_is_rejected(self):
        get, get_row = self.fixture("GET", "", "post_id", "get")
        post, _ = self.fixture("POST", "", "term", "post")
        for directory, field in ((self.zend_dir, "request_method"), (self.request_dir, "http_method")):
            artifact = json.loads((directory / get_row["matched_artifact"]).read_text(encoding="utf-8"))
            wrong = dict(artifact, **{field: "POST"})
            self.write_artifact(directory, get_row, wrong)
            self.assertEqual(self.verify([get, post], [get_row]), {"accepted": 0, "total": 1})
            self.write_artifact(directory, get_row, artifact)
        self.assertEqual(self.verify([post], [get_row]), {"accepted": 0, "total": 1})

    def test_artifact_with_other_variant_is_rejected(self):
        first, first_row = self.fixture("POST", "first", "first_key", "first")
        second, _ = self.fixture("POST", "second", "second_key", "second")
        for directory in (self.zend_dir, self.request_dir):
            artifact = json.loads((directory / first_row["matched_artifact"]).read_text(encoding="utf-8"))
            self.write_artifact(directory, first_row, dict(artifact, seed_variant_id="second"))
            self.assertEqual(self.verify([first, second], [first_row]), {"accepted": 0, "total": 1})
            self.write_artifact(directory, first_row, artifact)

    def test_legacy_callback_alias_requires_unique_compatible_expected(self):
        first, first_row = self.fixture("POST", "first", "first_key", "first")
        alias = dict(first_row, hook_name="cb-1")
        self.assertEqual(self.verify([first], [alias]), {"accepted": 1, "total": 1})
        other_hook = copy.deepcopy(first)
        other_hook["hook_name"] = "wp_ajax_other"
        self.assertEqual(self.verify([first, other_hook], [alias]), {"accepted": 0, "total": 1})


if __name__ == "__main__":
    unittest.main()
