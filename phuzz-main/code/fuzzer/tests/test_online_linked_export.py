from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.online_common import config_hash
from online_linked.export import (
    export_online_linked_batch,
)


class OnlineLinkedExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.states = self.root / "states"
        self.states.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def config(self, *, auth_context: str = "guest", variant: str = "post") -> dict:
        return {
            "target": "http://web/wp-admin/admin-ajax.php",
            "methods": ["POST"],
            "body_params": {
                "data": [
                    {"name": "action", "value": "fixture"},
                    {"name": "settings[nested]", "value": {"enabled": False, "count": 0}},
                ],
                "fixed": ["action"],
                "fuzz": ["settings\\[nested\\]"],
                "weight": 3,
            },
            "query_params": {
                "data": [{"name": "page", "value": 0}],
                "fixed": [],
                "fuzz": ["page"],
                "weight": 1,
            },
            "headers": {
                "data": [{"name": "X-Trace", "value": "fixed"}],
                "fixed": ["X\\-Trace"],
                "fuzz": [],
                "weight": 0,
            },
            "cookies": {
                "data": [{"name": "wordpress_test_cookie", "value": "WP Cookie"}],
                "fixed": ["wordpress_test_cookie"],
                "fuzz": [],
                "weight": 0,
            },
            "metadata": {
                "hook_name": "wp_ajax_nopriv_fixture",
                "callback_id": "cb-fixture",
                "callback_repr": "Fixture::handle",
                "resolved_method": "POST",
                "auth_context": auth_context,
                "seed_variant_id": variant,
                "online_request_seed": {
                    "request_id": "req-1",
                    "run_id": "candidate-1-v1",
                    "values": [{"name": "settings[nested]", "value_origin": "observed"}],
                },
                "runtime_option": {"keep": True},
            },
            "entrypoint_type": "ajax_unauthenticated",
            "config_type": "fuzzing_ready",
            "runtime_option": {"keep": ["exactly", 0, False, None]},
        }

    def write_state(
        self,
        *,
        identity: str = "plugin|cb-fixture|ajax_unauthenticated|wp_ajax_nopriv_fixture|/wp-admin/admin-ajax.php|POST|post",
        run_id: str = "campaign-candidate-1",
        plugin: str = "fixture",
        versions: list[dict] | None = None,
        hook_name: str = "wp_ajax_nopriv_fixture",
        callback_id: str = "cb-fixture",
        terminal_status: str = "BOUNDED_ONLINE_COMPLETE",
        terminal_reason: str = "BUDGET_EXPIRED",
        filename: str = "candidate-1-state.json",
    ) -> tuple[dict, Path]:
        state_path = self.states / filename
        state = {
            "schema_version": 1,
            "mode": "online-linked",
            "plugin_slug": plugin,
            "legacy_run_id": run_id,
            "versions": versions or [],
            "workers": [],
            "terminal_status": terminal_status,
            "terminal_reason": terminal_reason,
        }
        state_path.write_text(json.dumps(state), encoding="utf-8")
        return {
            "index": 1,
            "hook_name": hook_name,
            "callback_id": callback_id,
            "run_id": run_id,
            "identity": identity,
            "state_path": str(state_path),
        }, state_path

    def version(
        self,
        name: str,
        *,
        config: dict | None = None,
        gate: bool = True,
        pass2: tuple[int, int] = (1, 1),
        worker_status: str = "not_started_budget_expired",
        config_type: str = "fuzzing_ready",
        probe: bool = False,
        config_path: Path | None = None,
    ) -> dict:
        payload = copy.deepcopy(config or self.config())
        payload["config_type"] = config_type
        if probe:
            payload.setdefault("metadata", {})["probe_variant"] = True
        if config_path is None:
            metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
            auth = str(metadata.get("auth_context") or "auth")
            variant = str(metadata.get("seed_variant_id") or "default")
            config_path = self.root / "configs" / f"{name}-{auth}-{variant}.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        accepted, total = pass2
        record = {
            "version": name,
            "config_path": str(config_path),
            "config_type": config_type,
            "config_hash": config_hash(payload),
            "hook_name": "wp_ajax_nopriv_fixture",
            "callback_id": "cb-fixture",
            "worker_status": worker_status,
            "status": "fuzzing",
            "terminal_reason": "",
        }
        gate_record = {
            "passed": gate,
            "pass2_verification": {"accepted": accepted, "total": total},
        }
        if name == "v0":
            record["readiness"] = gate_record
        else:
            record["replay_result"] = {
                **gate_record,
                "config_path": str(config_path),
                "config_hash": config_hash(payload),
            }
        return record

    def batch(self, candidates: list[dict], *, plugin: str = "fixture", run_id: str = "campaign") -> Path:
        batch_path = self.root / "batch-state.json"
        batch_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "mode": "online-linked-batch",
                    "plugin_slug": plugin,
                    "legacy_run_id": run_id,
                    "campaign_status": "complete_with_skips",
                    "candidates": candidates,
                }
            ),
            encoding="utf-8",
        )
        return batch_path

    def test_flat_folder_preserves_exact_config_bytes(self):
        version = self.version("v0")
        candidate, _ = self.write_state(versions=[version])
        self.assertEqual(export_online_linked_batch(self.batch([candidate])), 1)
        files = list((self.root / "final-configs").iterdir())
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].name.startswith("fuzzer-config."))
        self.assertEqual(files[0].read_bytes(), Path(version["config_path"]).read_bytes())

    def test_latest_numeric_verified_version_and_fallback(self):
        for rejected in (False, True):
            with self.subTest(rejected=rejected):
                new_config = self.config()
                new_config["metadata"]["new_parameter"] = "v10-only"
                versions = [self.version("v2"), self.version("v10", config=new_config, gate=not rejected)]
                candidate, _ = self.write_state(versions=versions)
                destination = self.root / str(rejected)
                self.assertEqual(export_online_linked_batch(self.batch([candidate]), destination), 1)
                selected = versions[0 if rejected else 1]
                self.assertEqual(next(destination.iterdir()).read_bytes(), Path(selected["config_path"]).read_bytes())

    def test_rejected_versions_leave_empty_folder(self):
        versions = [self.version("v0", pass2=(0, 0)), self.version("v1", pass2=(1, 2)),
                    self.version("v2", probe=True), self.version("v3", config_type="replay_only")]
        candidate, _ = self.write_state(versions=versions)
        self.assertEqual(export_online_linked_batch(self.batch([candidate])), 0)
        self.assertEqual(list((self.root / "final-configs").iterdir()), [])

    def test_unrelated_probe_parent_does_not_reject_real_version(self):
        version = self.version("v1", config_path=self.root / "probe" / "project" / "versions" / "v1" / "v1-config.json")
        candidate, _ = self.write_state(versions=[version])
        self.assertEqual(export_online_linked_batch(self.batch([candidate])), 1)

    def test_mismatched_run_and_changed_config_are_skipped(self):
        version = self.version("v0")
        first, _ = self.write_state(versions=[version])
        first["run_id"] = "another-run"
        second, _ = self.write_state(identity="second", filename="second.json", versions=[version])
        Path(version["config_path"]).write_text("{}")
        with redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(export_online_linked_batch(self.batch([first, second])), 0)
        self.assertIn("RUN_MISMATCH", errors.getvalue())

    def test_same_hook_distinct_identities_and_existing_output(self):
        version = self.version("v0")
        first, _ = self.write_state(identity="guest", versions=[version])
        second, _ = self.write_state(identity="auth", filename="second.json", versions=[version])
        batch = self.batch([first, second])
        self.assertEqual(export_online_linked_batch(batch), 2)
        before = {p.name: p.read_bytes() for p in (self.root / "final-configs").iterdir()}
        with self.assertRaises(FileExistsError):
            export_online_linked_batch(batch)
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.root / "final-configs").iterdir()})
