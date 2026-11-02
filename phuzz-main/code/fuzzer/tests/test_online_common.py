import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.online_common import _write_json, select_v0, validate_v0_config


def online_config() -> dict:
    return {
        "target": "http://web/wp-admin/admin-ajax.php",
        "methods": ["POST"],
        "config_type": "fuzzing_ready",
        "body_params": {
            "data": [{"name": "action", "value": "hookphuzz_stage1_direct"}, {"name": "name", "value": "Alice"}],
            "fixed": ["action"],
            "fuzz": ["name"],
        },
        "metadata": {
            "hook_name": "wp_ajax_nopriv_hookphuzz_stage1_direct",
            "callback_id": "fixture-callback",
            "callback_repr": "HookPhuzzFixture::stage1",
            "resolved_method": "POST",
            "entrypoint_type": "ajax_unauthenticated",
        },
    }



class OnlineCommonTests(unittest.TestCase):
    def test_checkpoint_retries_transient_windows_replace_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "state.json"
            path.write_text('{"old": true}', encoding="utf-8")
            original_replace = Path.replace
            calls = []

            def replace(source, target):
                calls.append(source)
                if len(calls) < 3:
                    error = PermissionError("temporarily locked")
                    error.winerror = 5
                    raise error
                return original_replace(source, target)

            with patch.object(Path, "replace", replace), patch("hook_energy.seed_generation.online_common.time.sleep"):
                _write_json(path, {"new": True})
            self.assertEqual(len(calls), 3)
            self.assertEqual(json.loads(path.read_text()), {"new": True})
            self.assertFalse(path.with_name("state.json.tmp").exists())

    def test_checkpoint_replace_failure_is_bounded_and_preserves_old_state(self) -> None:
        for winerror, expected_calls in ((5, 5), (32, 5), (33, 5), (None, 1)):
            with self.subTest(winerror=winerror), tempfile.TemporaryDirectory() as tmp_dir:
                path = Path(tmp_dir) / "state.json"
                path.write_text('{"old": true}', encoding="utf-8")
                error = PermissionError("cannot replace")
                error.winerror = winerror
                with patch.object(Path, "replace", side_effect=error) as replace, patch("hook_energy.seed_generation.online_common.time.sleep"):
                    with self.assertRaises(PermissionError):
                        _write_json(path, {"new": True})
                self.assertEqual(replace.call_count, expected_calls)
                self.assertEqual(json.loads(path.read_text()), {"old": True})

    def test_v0_requires_target_method_callback_and_fuzzable_config(self) -> None:
        config = online_config()
        self.assertEqual(validate_v0_config(config), (True, ""))

        for field in ("target", "methods"):
            candidate = copy.deepcopy(config)
            candidate.pop(field)
            self.assertFalse(validate_v0_config(candidate)[0], field)

        candidate = copy.deepcopy(config)
        candidate["metadata"].pop("callback_repr")
        candidate["metadata"].pop("callback_id")
        self.assertEqual(validate_v0_config(candidate), (False, "MISSING_CALLBACK"))

        candidate = copy.deepcopy(config)
        candidate["config_type"] = "replay_only"
        candidate["body_params"]["fuzz"] = []
        self.assertEqual(validate_v0_config(candidate), (False, "NOT_FUZZING_READY"))
        self.assertEqual(validate_v0_config(candidate, require_fuzzing_ready=False), (True, ""))


    def test_bootstrap_config_fallback_keeps_callback_evidence_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            suggested = root / "suggested_seeds.json"
            suggested.write_text(json.dumps({"suggested_seeds": [{
                "hook_name": "wp_ajax_nopriv_hookphuzz_stage1_direct",
                "callback_id": "fixture-callback",
                "callback_repr": "HookPhuzzFixture::stage1",
                "seed": {
                    "method": "POST",
                    "resolved_method": "POST",
                    "path": "/wp-admin/admin-ajax.php",
                    "fuzzable_params": [],
                },
            }]}), encoding="utf-8")
            bootstrap = root / "bootstrap.json"
            bootstrap.write_text(json.dumps(online_config()), encoding="utf-8")
            selected = select_v0(suggested, bootstrap)

            self.assertIsNotNone(selected)
            _, config = selected
            self.assertEqual(config["metadata"]["callback_id"], "fixture-callback")
            self.assertIn("name", config["body_params"]["fuzz"])
