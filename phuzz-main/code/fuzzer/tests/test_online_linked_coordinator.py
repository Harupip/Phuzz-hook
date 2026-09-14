import copy
import io
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stderr
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
from typing import Any


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.online_linked_coordinator import (
    OnlineLinkedCoordinator,
    _batch_candidate_identity,
    run_online_linked,
)
from hook_energy.seed_generation.generated_config_runner import STOP_ON_VULN_EXIT_CODE
from hook_energy.seed_generation.probe_sender import ParentInspectionTimeout
from seed_generation.config.config_exporter import SeedConfigSkip, export_seed_configs
from seed_generation.convergence.convergence import materialize_convergence_seeds
from zend_discovery.engine import candidate_from_seed_item, canonical_identity_id


def seed_item() -> dict:
    return {
        "hook_name": "wp_ajax_nopriv_fixture",
        "callback_id": "cb-fixture",
        "callback_repr": "fixture_callback",
        "seed": {
            "auth_mode": "unauth-capable",
            "method": "POST",
            "resolved_method": "POST",
            "method_status": "resolved",
            "path": "/wp-admin/admin-ajax.php",
            "body": {"action": "fixture", "seed": "base"},
            "query_params": {},
            "headers": {},
            "fixed_params": ["action"],
            "fuzzable_params": ["seed"],
        },
    }


def config_for(item: dict, *, include_new: bool = False) -> dict:
    names = ["action", "seed"] + (["new_param"] if include_new else [])
    return {
        "target": "http://web/wp-admin/admin-ajax.php",
        "methods": ["POST"],
        "body_params": {
            "data": [{"name": name, "value": "base" if name == "seed" else "fixture"} for name in names],
            "fixed": ["action"],
            "fuzz": ["seed"] + (["new_param"] if include_new else []),
            "weight": 1,
        },
        "metadata": {
            "callback_id": item["callback_id"],
            "callback_repr": item["callback_repr"],
            "hook_name": item["hook_name"],
            "resolved_method": "POST",
        },
        "config_type": "fuzzing_ready",
    }


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class OnlineLinkedCoordinatorTests(unittest.TestCase):
    def test_worker_exit_inspect_timeout_is_bounded_and_distinct(self):
        coordinator = object.__new__(OnlineLinkedCoordinator)
        coordinator._active_container = "parent-container"
        calls = []

        def inspect(command, **kwargs):
            calls.append(kwargs)
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        coordinator.run_command = inspect
        with self.assertRaises(ParentInspectionTimeout):
            coordinator._worker_exit_code(0.05)
        self.assertLessEqual(calls[0]["timeout"], 0.05)

    def test_worker_exit_inspect_keeps_legacy_noarg_behavior(self):
        coordinator = object.__new__(OnlineLinkedCoordinator)
        coordinator._active_container = "parent-container"
        calls = []

        def inspect(command, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(returncode=0, stdout="running")

        coordinator.run_command = inspect
        self.assertIsNone(coordinator._worker_exit_code())
        self.assertEqual(calls[0]["timeout"], 30)

    def run_php_json_producer(self, raw_body: str) -> dict:
        php = Path(shutil.which("php") or r"C:\xampp\php\php.exe")
        self.assertTrue(php.is_file(), f"PHP CLI required; resolved {php}")
        hook_path = Path(__file__).resolve().parents[2] / "web" / "instrumentation" / "hook_coverage" / "uopz_hook_wp.php"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            harness = root / "harness.php"
            harness.write_text(
                "<?php\n"
                "$hook = getenv('HOOKPHUZZ_HOOK_FILE');\n"
                "require $hook;\n"
                "echo json_encode($GLOBALS['__uopz_request']['request_params'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env.update({
                "HOOKPHUZZ_HOOK_FILE": str(hook_path),
                "FUZZER_HOOK_OUTPUT_DIR": str(root / "coverage"),
                "FUZZER_ENABLE_REQUEST_LOG": "0",
            })
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            process = subprocess.Popen(
                [str(php), "-S", f"127.0.0.1:{port}", str(harness)],
                cwd=root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/harness.php",
                    data=raw_body.encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                expires = time.monotonic() + 5
                while True:
                    try:
                        with urllib.request.urlopen(request, timeout=0.5) as response:
                            return json.loads(response.read().decode("utf-8"))
                    except urllib.error.URLError:
                        if process.poll() is not None or time.monotonic() >= expires:
                            stdout, stderr = process.communicate(timeout=5)
                            raise AssertionError(f"PHP producer did not serve request: {stdout}\n{stderr}")
                        time.sleep(0.02)
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)

    def test_php_producer_preserves_json_object_array_and_status(self):
        cases = (
            ("{}", "empty", {}, "object"),
            ('{"payload":{}}', "decoded", {"payload": {}}, "object"),
            ('{"payload":[]}', "decoded", {"payload": []}, "object"),
            ('{"payload":{"flag":false,"zero":0,"nil":null,"nested":[{}, {"x":0}]}}', "decoded", {
                "payload": {"flag": False, "zero": 0, "nil": None, "nested": [{}, {"x": 0}]},
            }, "object"),
            ("[]", "decoded", [], "array"),
            ("false", "decoded", False, "boolean"),
            ("0", "decoded", 0, "number"),
            ("null", "decoded", None, "null"),
        )
        for raw, status, expected_value, expected_type in cases:
            with self.subTest(raw=raw):
                params = self.run_php_json_producer(raw)
                self.assertEqual(params["json_params_status"], status)
                self.assertEqual(params["json_params_type"], expected_type)
                self.assertEqual(params["json_params"], expected_value)

        missing = self.run_php_json_producer("")
        self.assertEqual(missing["json_params_status"], "missing")
        self.assertEqual(missing["json_params_error"], "JSON_BODY_MISSING")
        invalid = self.run_php_json_producer("{bad")
        self.assertEqual(invalid["json_params_status"], "invalid")
        self.assertTrue(invalid["json_params_error"])

    def test_php_json_values_reach_child_and_replay_with_original_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            coordinator = self.make_coordinator(root, [])
            params = self.run_php_json_producer(
                '{"payload":{"object":{},"array":[],"flag":false,"zero":0,"nil":null}}'
            )
            config = config_for(seed_item())
            config["headers"] = {"data": [{"name": "Content-Type", "value": "application/json"}]}
            config["body_params"] = {
                "data": [
                    {"name": "payload[object]", "value": "probe"},
                    {"name": "payload[array]", "value": "probe"},
                    {"name": "payload[flag]", "value": "probe"},
                    {"name": "payload[zero]", "value": "probe"},
                    {"name": "payload[nil]", "value": "probe"},
                ],
                "fixed": [],
                "fuzz": ["payload[object]", "payload[array]", "payload[flag]", "payload[zero]", "payload[nil]"],
            }
            parent_path = root / "parent.json"
            parent_path.write_text(json.dumps(config), encoding="utf-8")
            coordinator._restore_request_values(
                config,
                {"request_id": "php", "request": {"request_params": params}},
                {"config_path": str(parent_path), "worker_run_id": "run-v0"},
            )
            values = {row["name"]: row["value"] for row in config["body_params"]["data"]}
            self.assertEqual(values["payload[object]"], {})
            self.assertEqual(values["payload[array]"], [])
            self.assertIs(values["payload[flag]"], False)
            self.assertEqual(values["payload[zero]"], 0)
            self.assertIsNone(values["payload[nil]"])
            replay = copy.deepcopy(config)
            coordinator.force_replay_only_fn(replay)
            replay_values = {row["name"]: row["value"] for row in replay["body_params"]["data"]}
            self.assertEqual(replay_values, values)

    def test_same_hook_different_runtime_callback_is_queued_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            item, config, target_key = coordinator._select_v0()
            config_path = coordinator._write_config("v0", config)
            version = coordinator._new_version("v0", config, config_path, None, None, item)
            version["worker_run_id"] = "run-v0"
            coordinator._active_version = "v0"
            coordinator._target_key = target_key
            coordinator.state["queued_candidate_ids"].append(_batch_candidate_identity(item, "fixture"))
            request = coordinator.load_artifact("req-v0.json")
            request["hook_coverage"] = {"registered_callbacks": {
                "cb-child": {
                    "callback_id": "cb-child",
                    "callback_repr": "child_callback",
                    "hook_name": "wp_ajax_nopriv_fixture",
                    "entrypoint_type": "ajax_unauthenticated",
                    "method": "POST",
                    "request_id": "req-v0",
                    "target_plugin": "fixture",
                    "registered_inside_callback": True,
                    "parent_callback_id": "cb-fixture",
                    "parent_callback": {"callback_id": "cb-fixture"},
                },
                "cb-fixture": {
                    "callback_id": "cb-fixture",
                    "callback_repr": "fixture_callback",
                    "hook_name": "wp_ajax_nopriv_fixture",
                    "registered_inside_callback": True,
                    "parent_callback_id": "cb-fixture",
                },
            }}
            evidence = {"request_id": "req-v0", "request": request}

            first = coordinator._discover_runtime_candidates(evidence)
            second = coordinator._discover_runtime_candidates(evidence)

            self.assertEqual(len(first), 1)
            self.assertEqual(second, [])
            self.assertEqual(first[0]["callback_id"], "cb-child")
            self.assertEqual(first[0]["hook_name"], "wp_ajax_nopriv_fixture")
            self.assertEqual(first[0]["lineage"]["parent_callback_id"], "cb-fixture")

            version["callback_id"] = "cb-child"
            request["hook_coverage"] = {"registered_callbacks": {
                "cb-fixture": {
                    "callback_id": "cb-fixture",
                    "callback_repr": "fixture_callback",
                    "hook_name": "wp_ajax_nopriv_fixture",
                    "entrypoint_type": "ajax_unauthenticated",
                    "method": "POST",
                    "registered_inside_callback": True,
                    "parent_callback_id": "cb-child",
                    "parent_callback": {"callback_id": "cb-child"},
                },
            }}
            cycle = coordinator._discover_runtime_candidates(evidence)
            self.assertEqual(cycle, [])
            self.assertEqual(len(coordinator.state["candidate_queue"]), 1)
    def test_uopz_producer_contract_exports_json_status_and_cookie_names(self):
        hook_path = Path(__file__).resolve().parents[2] / "web" / "instrumentation" / "hook_coverage" / "uopz_hook_wp.php"
        source = hook_path.read_text(encoding="utf-8")
        self.assertIn("'json_params'", source)
        self.assertIn("'json_params_status'", source)
        self.assertIn("php://input", source)
        self.assertIn("json_last_error", source)
        self.assertIn("'cookies' => isset($_COOKIE) ? array_keys($_COOKIE) : []", source)

    def test_empty_buckets_and_cookie_names_preserve_fixed_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            coordinator = self.make_coordinator(root, [])
            config = config_for(seed_item())
            config["query_params"] = {
                "data": [{"name": "page", "value": "probe"}],
                "fixed": [],
                "fuzz": ["page"],
            }
            config["cookies"] = {
                "data": [{"name": "session", "value": "fixed-token"}],
                "fixed": ["session"],
                "fuzz": [],
            }
            parent_path = root / "parent.json"
            parent_path.write_text(json.dumps(config), encoding="utf-8")
            evidence = {"request_id": "r", "request": {"request_params": {
                "query_params": [],
                "body_params": [],
                "cookies": ["session"],
            }}}

            coordinator._restore_request_values(
                config, evidence, {"config_path": str(parent_path), "worker_run_id": "run-v0"}
            )

            self.assertEqual(config["query_params"]["data"][0]["value"], "probe")
            cookie = config["cookies"]["data"][0]
            self.assertEqual(cookie["value"], "fixed-token")
            self.assertIn("session", config["cookies"]["fixed"])
            self.assertNotIn("session", config["cookies"]["fuzz"])
            values = {row["name"]: row for row in config["metadata"]["online_request_seed"]["values"]}
            self.assertEqual(values["page"]["value_origin"], "empty")
            self.assertEqual(values["session"]["value_origin"], "names_only")
            self.assertNotEqual(cookie["value"], "session")

    def test_malformed_request_bucket_is_rejected_with_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            coordinator = self.make_coordinator(root, [])
            config = config_for(seed_item())
            config["query_params"] = {
                "data": [{"name": "page", "value": "probe"}],
                "fixed": [],
                "fuzz": ["page"],
            }
            parent_path = root / "parent.json"
            parent_path.write_text(json.dumps(config), encoding="utf-8")
            evidence = {"request_id": "r", "request": {"request_params": {
                "query_params": ["not-a-map"],
            }}}

            with self.assertRaisesRegex(ValueError, r"UNSUPPORTED_REQUEST_BUCKET: query_params must be an object"):
                coordinator._restore_request_values(
                    config, evidence, {"config_path": str(parent_path), "worker_run_id": "run-v0"}
                )

    def test_admission_normalizes_php_callback_scope_separator(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            parameter = {
                "name": "cfx_settings",
                "source": "POST",
                "location": "form",
                "evidence_kind": "zend_runtime",
                "request_id": "req-v0",
                "run_id": "run-v0",
                "plugin_slug": "fixture",
                "canonical_callback": "fixture_controller::save",
                "request_method": "POST",
            }
            parent = {
                "worker_run_id": "run-v0",
                "resolved_method": "POST",
                "canonical_callback": "fixture_controller->save",
            }

            self.assertTrue(coordinator._admission_complete(parameter, {"request_id": "req-v0"}, parent))
            parameter["canonical_callback"] = "other_controller::save"
            self.assertFalse(coordinator._admission_complete(parameter, {"request_id": "req-v0"}, parent))

    def test_candidate_identity_uses_one_normalized_contract_and_ignores_legacy_identity(self):
        initial = {
            "hook_name": "rest_route:demo/v1/items",
            "callback_id": "cb-shared",
            "identity": "legacy|format|must-not-be-trusted",
            "seed": {
                "entrypoint_type": "rest_route",
                "path": "/demo/v1/items/",
                "method": "get",
                "seed_variant_id": "query",
            },
        }
        runtime = {
            **initial,
            "identity": "another|legacy|format",
            "seed": {
                **initial["seed"],
                "route": "/demo/v1/items",
                "resolved_method": "GET",
            },
        }
        expected = "fixture|cb-shared|rest_route|rest_route:demo/v1/items|/demo/v1/items|GET|query"
        self.assertEqual(_batch_candidate_identity(initial, "fixture"), expected)
        self.assertEqual(_batch_candidate_identity(runtime, "fixture"), expected)
        ajax_initial = {
            "hook_name": "wp_ajax_nopriv_shared",
            "callback_id": "cb-shared",
            "seed": {"path": "/wp-admin/admin-ajax.php", "method": "POST"},
        }
        ajax_runtime = {
            **ajax_initial,
            "identity": "legacy-runtime-format",
            "seed": {
                **ajax_initial["seed"],
                "entrypoint_type": "ajax_unauthenticated",
                "seed_variant_id": "post",
            },
        }
        self.assertEqual(_batch_candidate_identity(ajax_initial, "fixture"), _batch_candidate_identity(ajax_runtime, "fixture"))

    def test_runtime_registration_enqueues_supported_child_with_parent_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            item, config, target_key = coordinator._select_v0()
            config_path = coordinator._write_config("v0", config)
            version = coordinator._new_version("v0", config, config_path, None, None, item)
            version["worker_run_id"] = "run-v0"
            coordinator._active_version = "v0"
            coordinator._target_key = target_key
            request = coordinator.load_artifact("req-v0.json")
            request["hook_coverage"] = {
                "registered_callbacks": {
                    "cb-child": {
                        "callback_id": "cb-child",
                        "callback_repr": "child_callback",
                        "hook_name": "wp_ajax_nopriv_child",
                        "entrypoint_type": "ajax_unauthenticated",
                        "method": "POST",
                        "request_id": "req-v0",
                        "target_plugin": "fixture",
                        "registered_inside_callback": True,
                        "parent_callback_id": "cb-fixture",
                        "parent_callback": {"callback_id": "cb-fixture"},
                    },
                    "cb-internal": {
                        "callback_id": "cb-internal",
                        "callback_repr": "internal_callback",
                        "hook_name": "init",
                        "request_id": "req-v0",
                        "target_plugin": "fixture",
                        "registered_inside_callback": True,
                        "parent_callback_id": "cb-fixture",
                        "parent_callback": {"callback_id": "cb-fixture"},
                    },
                }
            }
            evidence = {"request_id": "req-v0", "request": request}

            first = coordinator._discover_runtime_candidates(evidence)
            second = coordinator._discover_runtime_candidates(evidence)

            self.assertEqual(len(first), 1)
            self.assertEqual(second, [])
            child = first[0]
            self.assertEqual(child["callback_id"], "cb-child")
            self.assertEqual(child["hook_name"], "wp_ajax_nopriv_child")
            self.assertEqual(child["seed"]["method"], "POST")
            self.assertEqual(child["seed"]["seed_variant_id"], "post")
            self.assertEqual(child["lineage"]["parent_request_id"], "req-v0")
            self.assertEqual(child["lineage"]["parent_callback_id"], "cb-fixture")
            self.assertIn(child["identity"], coordinator.state["queued_candidate_ids"])
            self.assertEqual(coordinator.registry["callback_map"]["cb-child"], "child_callback")
            registry = json.loads(coordinator.registry_path.read_text(encoding="utf-8-sig"))
            self.assertEqual(registry["callback_map"]["cb-child"], "child_callback")
            blocked = [event for event in coordinator.state["events"] if event.get("callback_id") == "cb-internal"]
            self.assertEqual(len(blocked), 1)
            self.assertEqual(blocked[0]["reason"], "ACTION_EXPANSION_SETUP_REQUIRED")

    def test_runtime_registration_keeps_each_rest_method_as_distinct_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            item, config, target_key = coordinator._select_v0()
            config_path = coordinator._write_config("v0", config)
            version = coordinator._new_version("v0", config, config_path, None, None, item)
            version["worker_run_id"] = "run-v0"
            coordinator._active_version = "v0"
            coordinator._target_key = target_key
            request = coordinator.load_artifact("req-v0.json")
            request["hook_coverage"] = {"registered_callbacks": {
                "cb-rest": {
                    "callback_id": "cb-rest",
                    "callback_repr": "rest_callback",
                    "hook_name": "rest_route:demo/v1/items",
                    "entrypoint_type": "rest_route",
                    "namespace": "demo/v1",
                    "route": "/items",
                    "methods": ["GET", "POST"],
                    "request_id": "req-v0",
                    "target_plugin": "fixture",
                    "registered_inside_callback": True,
                    "parent_callback_id": "cb-fixture",
                    "parent_callback": {"callback_id": "cb-fixture"},
                }
            }}

            candidates = coordinator._discover_runtime_candidates({"request_id": "req-v0", "request": request})

            self.assertEqual([candidate["seed"]["method"] for candidate in candidates], ["GET", "POST"])
            self.assertEqual(len({candidate["identity"] for candidate in candidates}), 2)

    def test_v0_requires_registry_and_nonempty_pass2_before_fuzzing(self):
        for missing_registry in (True, False):
            with self.subTest(missing_registry=missing_registry), tempfile.TemporaryDirectory() as tmp:
                log = []
                coordinator = self.make_coordinator(Path(tmp), log)
                if missing_registry:
                    coordinator.registry = {'callback_map': {}}
                else:
                    coordinator.verify_pass2_fn = lambda *args, **kwargs: {'accepted': 0, 'total': 0}
                self.assertEqual(coordinator.run(), 2)
                self.assertNotIn('worker_start', log)
                self.assertEqual(coordinator.state['terminal_reason'],
                                 'V0_REGISTRY_MISSING' if missing_registry else 'V0_PASS2_NOT_VERIFIED')

    def test_v0_selection_matches_method_when_callback_has_multiple_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            coordinator.list_targets_fn = lambda *args, **kwargs: [
                {'hook_name': 'wp_ajax_nopriv_fixture', 'callback_id': 'cb-fixture',
                 'method': method, 'candidate_key': method} for method in ('GET', 'POST')]
            selected = coordinator._select_v0()
            self.assertIsNotNone(selected)
            self.assertEqual(selected[2], 'POST')

    def test_unverified_v0_never_starts_a_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator = self.make_coordinator(Path(tmp), log)
            coordinator.replay_runner = lambda *args, **kwargs: {'runs': []}
            self.assertNotEqual(coordinator.run(), 0)
            self.assertNotIn('worker_start', log)
            self.assertEqual(coordinator.state['terminal_reason'], 'V0_CALLBACK_NOT_REACHED')

    def test_runtime_seed_preserves_json_types_nested_form_and_fixed_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            coordinator = self.make_coordinator(root, [])
            config = config_for(seed_item())
            config['body_params'] = {
                'data': [{'name': name, 'value': 'fuzz'} for name in ('enabled', 'count', 'detail', 'missing', 'nonce')],
                'fixed': [], 'fuzz': ['enabled', 'count', 'detail', 'missing', 'nonce'],
            }
            config['headers'] = {'data': [{'name': 'Content-Type', 'value': 'application/json'}]}
            parent_config = copy.deepcopy(config)
            parent_config['body_params']['fixed'] = ['nonce']
            path = root / 'parent.json'
            path.write_text(json.dumps(parent_config), encoding='utf-8')
            parent = {'config_path': str(path), 'worker_run_id': 'run-v0'}
            evidence = {'request_id': 'r', 'request': {'request_params': {
                'body_params': {'enabled': 'wrong-transport'},
                'json_params_status': 'decoded',
                'json_params': {'enabled': False, 'count': 0, 'detail': None, 'nonce': 'runtime-token'},
            }}}
            coordinator._restore_request_values(config, evidence, parent)
            body = {row['name']: row['value'] for row in config['body_params']['data']}
            self.assertIs(body['enabled'], False)
            self.assertEqual(body['count'], 0)
            self.assertIsNone(body['detail'])
            self.assertEqual(body['nonce'], 'runtime-token')
            self.assertIn('nonce', config['body_params']['fixed'])
            self.assertNotIn('nonce', config['body_params']['fuzz'])
            replay_config = copy.deepcopy(config)
            coordinator.force_replay_only_fn(replay_config)
            replay_body = {row['name']: row['value'] for row in replay_config['body_params']['data']}
            self.assertIs(replay_body['enabled'], False)
            self.assertEqual(replay_body['count'], 0)
            self.assertIsNone(replay_body['detail'])
            values = config['metadata']['online_request_seed']['values']
            self.assertEqual(next(row for row in values if row['name'] == 'missing')['value_origin'], 'probe')
            config.pop('headers')
            config['body_params']['data'] = [{'name': 'data[detail]', 'value': 'fuzz'}]
            evidence['request']['request_params']['body_params'] = {'data': {'detail': 'nested'}}
            coordinator._restore_request_values(config, evidence, parent)
            self.assertEqual(config['body_params']['data'][0]['value'], 'nested')

    def test_json_statuses_are_distinct_without_falsifying_observed_values(self):
        for label, request_params, expected_origin in (
            ("missing", {}, "missing"),
            ("invalid", {"json_params": None, "json_params_status": "invalid", "json_params_error": "bad json"}, "invalid"),
            ("empty", {"json_params": {}, "json_params_status": "empty"}, "empty"),
        ):
            with self.subTest(status=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                coordinator = self.make_coordinator(root, [])
                config = config_for(seed_item())
                config["headers"] = {"data": [{"name": "Content-Type", "value": "application/json"}]}
                config["body_params"] = {
                    "data": [{"name": "mode", "value": "probe"}],
                    "fixed": [],
                    "fuzz": ["mode"],
                }
                parent_path = root / "parent.json"
                parent_path.write_text(json.dumps(config), encoding="utf-8")
                coordinator._restore_request_values(
                    config,
                    {"request_id": "r", "request": {"request_params": request_params}},
                    {"config_path": str(parent_path), "worker_run_id": "run-v0"},
                )
                value = config["body_params"]["data"][0]["value"]
                record = config["metadata"]["online_request_seed"]["values"][0]
                self.assertEqual(value, "probe")
                self.assertEqual(record["value_origin"], expected_origin)

    def test_json_nested_values_reach_child_and_replay_config_with_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            coordinator = self.make_coordinator(root, [])
            config = config_for(seed_item())
            config["headers"] = {"data": [{"name": "Content-Type", "value": "application/json"}]}
            config["body_params"] = {
                "data": [
                    {"name": "payload[mode]", "value": "probe"},
                    {"name": "payload[enabled]", "value": "probe"},
                ],
                "fixed": [],
                "fuzz": ["payload[mode]", "payload[enabled]"],
            }
            parent_path = root / "parent.json"
            parent_path.write_text(json.dumps(config), encoding="utf-8")
            evidence = {"request_id": "r", "request": {"request_params": {
                "json_params_status": "decoded",
                "json_params": {"payload": {"mode": "deep", "enabled": False}},
            }}}
            coordinator._restore_request_values(
                config, evidence, {"config_path": str(parent_path), "worker_run_id": "run-v0"}
            )
            values = {row["name"]: row["value"] for row in config["body_params"]["data"]}
            self.assertEqual(values["payload[mode]"], "deep")
            self.assertIs(values["payload[enabled]"], False)
            replay_config = copy.deepcopy(config)
            coordinator.force_replay_only_fn(replay_config)
            replay_values = {row["name"]: row["value"] for row in replay_config["body_params"]["data"]}
            self.assertEqual(replay_values["payload[mode]"], "deep")
            self.assertIs(replay_values["payload[enabled]"], False)

    def test_failed_child_replay_does_not_confirm_parent_parameters(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [], replay_passes=False)
            self.assertEqual(coordinator.run(), 1)
            parent, child = coordinator.state['versions']
            self.assertEqual(parent['known_parameters'], [])
            self.assertEqual(child['status'], 'replay_failed')

    def test_export_failure_retains_parent_and_reserves_attempt_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            exporter = coordinator.export_configs_fn
            coordinator.export_configs_fn = lambda *args, **kwargs: {'generated': []}
            coordinator.run()
            self.assertEqual(coordinator.state['versions'][0]['known_parameters'], [])
            self.assertEqual(coordinator.state['attempts'][0]['reason'], 'CHILD_CONFIG_EXPORT_FAILED')
            self.assertEqual(coordinator.state['attempts'][0]['version'], 'v1')
            coordinator.export_configs_fn = exporter
            coordinator._active_container = coordinator.state["workers"][0]["container_name"]
            coordinator.state["workers"][0]["status"] = "started"
            converge = coordinator.converge_fn

            def repeated_observation(**kwargs):
                self.assertEqual(kwargs['known_state']['known_parameters'], [])
                result = converge(**kwargs)
                result['request_id'] = 'retry'
                result['new_parameters'][0]['request_id'] = 'retry'
                return result

            coordinator.converge_fn = repeated_observation
            request = coordinator.load_artifact('retry.json')
            child = coordinator.advance_online_version({
                'request_name': 'retry.json', 'zend_name': 'retry.json', 'request_id': 'retry',
                'request': request, 'zend': coordinator.load_zend_artifact('retry.json'),
            })
            self.assertEqual(child['version'], 'v2')
            self.assertEqual(child['status'], 'fuzzing')
            self.assertEqual(coordinator.state['versions'][0]['known_parameters'], [])
            self.assertIsNone(coordinator.advance_online_version({'request_id': 'third'}))

    def test_convergence_failure_keeps_missing_parameter_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            coordinator.converge_fn = lambda **kwargs: {
                'status': 'REPLAY_FAILED', 'new_parameters': [],
                'missing_parameters': ['detail'], 'runtime_block_reason': 'BRANCH_NOT_REACHED',
            }
            coordinator.run()
            event = coordinator.state['events'][-1]
            self.assertEqual(event['reason'], 'BRANCH_NOT_REACHED')
            self.assertEqual(event['missing_parameters'], ['detail'])

    def test_child_replay_and_initial_seed_keep_runtime_branch_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            converge = coordinator.converge_fn
            load = coordinator.load_artifact

            def branch_request(name):
                request = load(name)
                request['request_params']['body_params'].update(mode='deep', detail='observed')
                request['request_params']['query_params'] = {'detail': 'query-only'}
                return request

            def branch_parameters(**kwargs):
                result = converge(**kwargs)
                if not result['new_parameters']:
                    return result
                template = result['new_parameters'][0]
                result['known_parameters'] = result['new_parameters'] = [
                    {**template, 'name': name, 'path': [name]} for name in ('mode', 'detail')
                ]
                return result

            def materialize(report, **kwargs):
                kwargs['candidate_key'] = canonical_identity_id(
                    candidate_from_seed_item(report['suggested_seeds'][0], plugin_slug='fixture'))
                return materialize_convergence_seeds(report, **kwargs)

            coordinator.load_artifact = branch_request
            coordinator.converge_fn = branch_parameters
            coordinator.materialize_fn = materialize
            coordinator.export_configs_fn = export_seed_configs
            self.assertEqual(coordinator.run(), 0)
            parent, child = coordinator.state['versions']
            self.assertEqual(coordinator.config_hash(Path(parent['config_path'])), parent['config_hash'])
            for path in (child['config_path'], child['replay_config_path']):
                config = json.loads(Path(path).read_text(encoding='utf-8'))
                body = {row['name']: row['value'] for row in config['body_params']['data']}
                self.assertEqual(body['mode'], 'deep')
                self.assertEqual(body['detail'], 'observed')
                self.assertEqual(body['action'], 'fixture')
            config = json.loads(Path(child['config_path']).read_text(encoding='utf-8'))
            self.assertIn('detail', config['body_params']['fuzz'])

    def test_online_linked_batch_continues_after_candidate_vulnerability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suggested = root / "suggested_seeds.json"
            suggested.write_text(json.dumps({
                "plugin_slug": "fixture",
                "suggested_seeds": [
                    {"hook_name": "wp_ajax_first", "callback_id": "cb-first", "seed": {}},
                    {"hook_name": "wp_ajax_second", "callback_id": "cb-second", "seed": {}},
                ],
            }), encoding="utf-8")
            registry = root / "registry.json"
            registry.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
            calls = []

            class FakeCoordinator:
                def __init__(self, **kwargs):
                    calls.append(kwargs)
                    self.state_path = Path(kwargs["output_root"]) / "online-linked" / kwargs["legacy_run_id"] / "state.json"
                    self.state = {
                        "terminal_status": "VULN_FOUND" if len(calls) == 1 else "BOUNDED_ONLINE_COMPLETE",
                        "terminal_reason": "VULN_FOUND" if len(calls) == 1 else "BUDGET_EXPIRED",
                        "versions": [],
                    }

                def run(self):
                    return 0

            args = SimpleNamespace(
                suggested_seeds=str(suggested),
                bootstrap_config="",
                config_root=str(root / "configs"),
                output_root=str(root / "output"),
                plugin_slug="fixture",
                legacy_run_id="run",
                max_seconds=1,
                max_versions=2,
                callback_registry=str(registry),
                service="fuzzer-wordpress-plugin",
            )
            with patch("hook_energy.seed_generation.online_linked_coordinator.OnlineLinkedCoordinator", FakeCoordinator), \
                    patch(
                        "hook_energy.seed_generation.online_linked_coordinator.export_online_linked_batch",
                        return_value=0,
                    ):
                self.assertEqual(run_online_linked(args), 0)

            self.assertEqual(len(calls), 2)
            batch_state = json.loads(
                (root / "output" / "online-linked" / "run" / "batch-state.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(batch_state["candidates"]), 2)
            self.assertEqual(batch_state["candidates"][0]["terminal_status"], "VULN_FOUND")
            self.assertEqual(batch_state["candidates"][1]["terminal_status"], "BOUNDED_ONLINE_COMPLETE")

    def test_batch_skips_failed_candidates_and_finishes_remaining_queue(self):
        for failure in (None, RuntimeError("candidate failed"), subprocess.TimeoutExpired("docker", 1)):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                suggested = root / "suggested.json"
                suggested.write_text(json.dumps({"suggested_seeds": [
                    {"hook_name": "wp_ajax_first", "callback_id": "first", "seed": {}},
                    {"hook_name": "wp_ajax_last", "callback_id": "last", "seed": {}},
                ]}), encoding="utf-8")
                registry = root / "registry.json"
                registry.write_text("{}", encoding="utf-8")
                calls = []

                class Candidate:
                    def __init__(self, **kwargs):
                        calls.append(kwargs)
                        self.state_path = root / f"state-{len(calls)}.json"
                        self.state = {
                            "terminal_status": "NOT_VERIFIED" if len(calls) == 1 else "BOUNDED_ONLINE_COMPLETE",
                            "terminal_reason": "CHILD_REPLAY_FAILED" if len(calls) == 1 else "BUDGET_EXPIRED",
                            "versions": [],
                        }

                    def run(self):
                        if len(calls) == 1:
                            if failure is not None:
                                raise failure
                            return 2
                        return 0

                args = SimpleNamespace(
                    suggested_seeds=str(suggested), bootstrap_config="", config_root=str(root / "configs"),
                    output_root=str(root / "output"), plugin_slug="fixture", legacy_run_id="run",
                    max_seconds=1, max_versions=2, callback_registry=str(registry), service="fuzzer-wordpress-plugin",
                )
                with patch("hook_energy.seed_generation.online_linked_coordinator.OnlineLinkedCoordinator", Candidate), \
                        patch(
                            "hook_energy.seed_generation.online_linked_coordinator.export_online_linked_batch",
                            return_value=0,
                        ):
                    result = run_online_linked(args)
                state = json.loads((root / "output/online-linked/run/batch-state.json").read_text())
                self.assertEqual([row["callback_id"] for row in state["candidates"]], ["first", "last"])
                self.assertEqual(state["candidates"][0]["terminal_status"], "NOT_VERIFIED")
                self.assertEqual(state["candidates"][1]["terminal_status"], "BOUNDED_ONLINE_COMPLETE")
                self.assertEqual(state["campaign_status"], "complete_with_skips")
                self.assertEqual(result, 0)

    def test_online_linked_batch_consumes_runtime_candidate_queue_with_lineage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suggested = root / "suggested_seeds.json"
            suggested.write_text(json.dumps({
                "plugin_slug": "fixture",
                "suggested_seeds": [{
                    "hook_name": "wp_ajax_nopriv_parent",
                    "callback_id": "cb-parent",
                    "callback_repr": "parent_callback",
                    "seed": {"method": "POST", "path": "/wp-admin/admin-ajax.php", "body": {"action": "parent"}},
                }],
            }), encoding="utf-8")
            registry = root / "registry.json"
            registry.write_text(json.dumps({"schema_version": 1, "callback_map": {"cb-parent": "parent_callback"}}), encoding="utf-8")
            child = {
                "identity": "fixture|cb-child|ajax_unauthenticated|wp_ajax_nopriv_child|/wp-admin/admin-ajax.php|POST|post",
                "hook_name": "wp_ajax_nopriv_child",
                "callback_id": "cb-child",
                "callback_repr": "child_callback",
                "seed": {"method": "POST", "path": "/wp-admin/admin-ajax.php", "body": {"action": "child"}},
                "lineage": {"parent_request_id": "req-parent", "parent_callback_id": "cb-parent"},
            }
            calls = []

            class FakeCoordinator:
                def __init__(self, **kwargs):
                    calls.append(kwargs)
                    self.state_path = Path(kwargs["output_root"]) / "online-linked" / kwargs["legacy_run_id"] / "state.json"
                    self.state = {
                        "terminal_status": "BOUNDED_ONLINE_COMPLETE",
                        "terminal_reason": "BUDGET_EXPIRED",
                        "versions": [],
                        "candidate_queue": [child] if len(calls) == 1 else [],
                    }

                def run(self):
                    return 0

            args = SimpleNamespace(
                suggested_seeds=str(suggested),
                bootstrap_config="",
                config_root=str(root / "configs"),
                output_root=str(root / "output"),
                plugin_slug="fixture",
                legacy_run_id="run",
                max_seconds=1,
                max_versions=2,
                max_candidates=2,
                campaign_seconds=10,
                callback_registry=str(registry),
                service="fuzzer-wordpress-plugin",
            )
            with patch("hook_energy.seed_generation.online_linked_coordinator.OnlineLinkedCoordinator", FakeCoordinator), \
                    patch(
                        "hook_energy.seed_generation.online_linked_coordinator.export_online_linked_batch",
                        return_value=0,
                    ):
                self.assertEqual(run_online_linked(args), 0)

            self.assertEqual(len(calls), 2)
            self.assertIsNotNone(calls[0]["campaign_deadline"])
            self.assertEqual(calls[0]["campaign_deadline"], calls[1]["campaign_deadline"])
            batch_state = json.loads((root / "output" / "online-linked" / "run" / "batch-state.json").read_text(encoding="utf-8"))
            self.assertEqual(batch_state["candidates"][1]["lineage"]["parent_callback_id"], "cb-parent")
            self.assertEqual(batch_state["candidates"][1]["source"], "runtime_registration")

            calls.clear()
            args.sync_registry = True
            with patch("hook_energy.seed_generation.online_linked_coordinator.OnlineLinkedCoordinator", FakeCoordinator), \
                    patch(
                        "hook_energy.seed_generation.online_linked_coordinator.export_online_linked_batch",
                        return_value=0,
                    ), \
                    patch("hook_energy.seed_generation.online_linked_coordinator._sync_callback_registry_to_web",
                          side_effect=subprocess.TimeoutExpired("docker cp", 30)):
                self.assertEqual(run_online_linked(args), 0)
            batch_state = json.loads((root / "output" / "online-linked" / "run" / "batch-state.json").read_text())
            self.assertEqual(batch_state["campaign_status"], "complete_with_skips")
            self.assertEqual(len(batch_state["candidates"]), 1)
            self.assertEqual(batch_state["candidates"][0]["terminal_status"], "BOUNDED_ONLINE_COMPLETE")
            self.assertEqual(batch_state["expansion_events"][0]["reason"], "CALLBACK_REGISTRY_REFRESH_FAILED")

    def test_online_linked_batch_does_not_sync_or_queue_after_campaign_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suggested = root / "suggested_seeds.json"
            initial = {
                "hook_name": "wp_ajax_nopriv_parent",
                "callback_id": "cb-parent",
                "callback_repr": "parent_callback",
                "seed": {"method": "POST", "path": "/wp-admin/admin-ajax.php", "body": {"action": "parent"}},
            }
            suggested.write_text(json.dumps({"plugin_slug": "fixture", "suggested_seeds": [initial]}), encoding="utf-8")
            registry = root / "registry.json"
            registry.write_text(json.dumps({"schema_version": 1, "callback_map": {"cb-parent": "parent_callback"}}), encoding="utf-8")
            child = {
                "hook_name": "wp_ajax_nopriv_child",
                "callback_id": "cb-child",
                "callback_repr": "child_callback",
                "seed": {"method": "POST", "path": "/wp-admin/admin-ajax.php", "body": {"action": "child"}},
                "lineage": {"parent_callback_id": "cb-parent"},
            }
            calls = []

            class FakeCoordinator:
                def __init__(self, **kwargs):
                    calls.append(kwargs)
                    self.state_path = Path(kwargs["output_root"]) / "state.json"
                    self.state = {
                        "terminal_status": "BOUNDED_ONLINE_COMPLETE",
                        "terminal_reason": "BUDGET_EXPIRED",
                        "versions": [],
                        "candidate_queue": [child],
                    }

                def run(self):
                    return 0

            args = SimpleNamespace(
                suggested_seeds=str(suggested), bootstrap_config="", config_root=str(root / "configs"),
                output_root=str(root / "output"), plugin_slug="fixture", legacy_run_id="run",
                max_seconds=60, max_versions=2, max_candidates=2, campaign_seconds=1,
                callback_registry=str(registry), service="fuzzer-wordpress-plugin", sync_registry=True,
            )
            with patch("hook_energy.seed_generation.online_linked_coordinator.OnlineLinkedCoordinator", FakeCoordinator), \
                    patch(
                        "hook_energy.seed_generation.online_linked_coordinator.export_online_linked_batch",
                        return_value=0,
                    ), \
                    patch("hook_energy.seed_generation.online_linked_coordinator._sync_callback_registry_to_web") as sync, \
                    patch("hook_energy.seed_generation.online_linked_coordinator.time.monotonic", side_effect=[0.0, 0.0, 2.0]):
                self.assertEqual(run_online_linked(args), 0)

            self.assertEqual(len(calls), 1)
            sync.assert_not_called()
            batch_state = json.loads((root / "output" / "online-linked" / "run" / "batch-state.json").read_text(encoding="utf-8"))
            self.assertEqual(batch_state["campaign_status"], "CAMPAIGN_BUDGET_EXPIRED")
            self.assertEqual(len(batch_state["candidates"]), 1)

    def test_batch_exports_once_after_final_batch_state_for_vulnerability_and_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suggested = root / "suggested.json"
            suggested.write_text(
                json.dumps(
                    {
                        "suggested_seeds": [
                            {"hook_name": "wp_ajax_first", "callback_id": "cb-first", "seed": {}},
                            {"hook_name": "wp_ajax_second", "callback_id": "cb-second", "seed": {}},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            registry = root / "registry.json"
            registry.write_text("{}", encoding="utf-8")
            calls = []
            export_calls = []

            class FakeCoordinator:
                def __init__(self, **kwargs):
                    calls.append(kwargs)
                    self.state_path = root / f"state-{len(calls)}.json"
                    self.state = {
                        "terminal_status": "VULN_FOUND" if len(calls) == 1 else "BOUNDED_ONLINE_COMPLETE",
                        "terminal_reason": "VULN_FOUND" if len(calls) == 1 else "BUDGET_EXPIRED",
                        "versions": [],
                    }

                def run(self):
                    return 0

            def export(batch_state_path):
                export_calls.append(
                    (
                        Path(batch_state_path),
                        json.loads(Path(batch_state_path).read_text(encoding="utf-8")),
                    )
                )
                return 0

            args = SimpleNamespace(
                suggested_seeds=str(suggested),
                bootstrap_config="",
                config_root=str(root / "configs"),
                output_root=str(root / "output"),
                plugin_slug="fixture",
                legacy_run_id="run",
                max_seconds=1,
                max_versions=2,
                max_candidates=2,
                campaign_seconds=10,
                callback_registry=str(registry),
                service="fuzzer-wordpress-plugin",
            )
            with patch("hook_energy.seed_generation.online_linked_coordinator.OnlineLinkedCoordinator", FakeCoordinator), \
                    patch("hook_energy.seed_generation.online_linked_coordinator.export_online_linked_batch",
                          create=True,
                          side_effect=export):
                self.assertEqual(run_online_linked(args), 0)

            self.assertEqual(len(calls), 2)
            self.assertEqual(len(export_calls), 1)
            self.assertTrue(export_calls[0][0].is_file())
            self.assertEqual(len(export_calls[0][1]["candidates"]), 2)

    def test_batch_export_failure_keeps_batch_state_and_returns_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suggested = root / "suggested.json"
            suggested.write_text(
                json.dumps(
                    {
                        "suggested_seeds": [
                            {"hook_name": "wp_ajax_only", "callback_id": "cb-only", "seed": {}}
                        ]
                    }
                ),
                encoding="utf-8",
            )
            registry = root / "registry.json"
            registry.write_text("{}", encoding="utf-8")

            class FakeCoordinator:
                def __init__(self, **kwargs):
                    self.state_path = root / "state.json"
                    self.state = {
                        "terminal_status": "VULN_FOUND",
                        "terminal_reason": "VULN_FOUND",
                        "versions": [],
                    }

                def run(self):
                    return 0

            args = SimpleNamespace(
                suggested_seeds=str(suggested),
                bootstrap_config="",
                config_root=str(root / "configs"),
                output_root=str(root / "output"),
                plugin_slug="fixture",
                legacy_run_id="run",
                max_seconds=1,
                max_versions=2,
                callback_registry=str(registry),
                service="fuzzer-wordpress-plugin",
            )
            error_output = io.StringIO()
            with patch("hook_energy.seed_generation.online_linked_coordinator.OnlineLinkedCoordinator", FakeCoordinator), \
                    patch(
                        "hook_energy.seed_generation.online_linked_coordinator.export_online_linked_batch",
                        create=True,
                        side_effect=OSError("disk full"),
                    ), redirect_stderr(error_output):
                result = run_online_linked(args)

            batch_path = root / "output" / "online-linked" / "run" / "batch-state.json"
            self.assertEqual(result, 2)
            self.assertTrue(batch_path.is_file())
            self.assertEqual(len(json.loads(batch_path.read_text(encoding="utf-8"))["candidates"]), 1)
            self.assertIn("EXPORT_FAILED", error_output.getvalue())
            self.assertIn("disk full", error_output.getvalue())

    def test_worker_vulnerability_exit_stops_current_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            finding = {
                "run_id": "run-v0",
                "findings": [{
                    "vuln_type": "SQLi",
                    "mutated_param_name": "album_id",
                    "payload": "PAYLOAD",
                    "coverage_id": "coverage-123",
                }],
            }
            coordinator.load_finding_artifact = lambda name: finding

            def run_command(command, **kwargs):
                if command[:2] == ["docker", "inspect"]:
                    return subprocess.CompletedProcess(command, 0, "57\n", "")
                if command[:3] == ["docker", "compose", "run"]:
                    log.append("worker_start")
                elif command[:3] == ["docker", "rm", "-f"]:
                    log.append("worker_stop")
                return subprocess.CompletedProcess(command, 0, "", "")

            coordinator.run_command = run_command
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual(coordinator.state["terminal_status"], "VULN_FOUND")
            self.assertEqual(coordinator.state["versions"][-1]["status"], "vuln_found")
            self.assertEqual(coordinator.state["versions"][-1]["finding_artifact"], finding)
            self.assertTrue(any("HOOKPHUZZ_FINDING_ARTIFACT=" in item for item in coordinator.state["workers"][0]["command"]))
            self.assertIn("worker_stop", log)

    def make_coordinator(
        self,
        root: Path,
        log: list[str],
        *,
        replay_passes: bool = True,
        discovers_parameter: bool = True,
        incomplete_parameter: bool = False,
        convergence_error: bool = False,
        replay_error: bool = False,
        request_callback_id: str | None = None,
        max_versions: int = 3,
        request_names: set[str] | None = None,
        zend_names: set[str] | None = None,
        legacy_run_id: str = "run",
        max_seconds: int = 2,
        campaign_deadline: float | None = None,
        runtime_cookie_probes: bool = False,
    ) -> OnlineLinkedCoordinator:
        item = seed_item()
        raw_report = {"plugin_slug": "fixture", "suggested_seeds": [item]}
        suggested = root / "suggested_seeds.json"
        suggested.write_text(json.dumps(raw_report), encoding="utf-8")
        registry = root / "registry.json"
        registry.write_text(json.dumps({"schema_version": 1, "callback_map": {"cb-fixture": "fixture_callback"}}), encoding="utf-8")
        clock = Clock()
        request_names = request_names if request_names is not None else {"req-v0.json"}
        zend_names = zend_names if zend_names is not None else {"req-v0.json"}
        request_id = Path(sorted(request_names)[0]).stem

        def build_config(*args, **kwargs):
            log.append("build_config")
            return "fixture", config_for(item)

        def list_targets(*args, **kwargs):
            log.append("list_targets")
            return [{
                "candidate_key": "candidate-fixture",
                "hook_name": item["hook_name"],
                "callback_id": item["callback_id"],
                "entrypoint_type": "ajax",
                "method": "POST",
                "route": "/wp-admin/admin-ajax.php",
            }]

        def list_artifacts():
            log.append("list_request_artifacts")
            return set(request_names)

        def load_artifact(name):
            log.append("load_request_artifact")
            payload = {
                "request_id": Path(name).stem,
                "legacy_run_id": f"{legacy_run_id}-v0",
                "target_plugin": "fixture",
                "http_method": "POST",
                "request_params": {"body_params": {"action": "fixture", "seed": "base"}},
            }
            if request_callback_id is not None:
                payload["callback_id"] = request_callback_id
            return payload

        def list_zend():
            log.append("list_zend_artifacts")
            return set(zend_names)

        def load_zend(name):
            log.append("load_zend_artifact")
            return {"request_id": Path(name).stem, "run_id": f"{legacy_run_id}-v0"}

        def converge(**kwargs):
            if kwargs.get("runtime_cookie_probes"):
                log.append("runtime_cookie_probes:converge")
            if kwargs['pass_run_summary']['runs'][0].get('process_status') == 'replaying':
                log.append('v0_convergence')
                return {'status': 'CONVERGED', 'new_parameters': [], 'known_parameters': []}
            log.append("converge_iteration")
            if convergence_error:
                raise RuntimeError("REPLAY_FAILED: exact candidate correlation failed")
            if not discovers_parameter:
                return {
                    "status": "CONVERGED",
                    "request_id": request_id,
                    "known_parameters": [],
                    "new_parameters": [],
                    "merged_suggested_seeds": copy.deepcopy(raw_report),
                }
            parameter = {
                "name": "new_param",
                "path": ["new_param"],
                "source": "POST",
                "location": "form",
                "helper_depth": 0,
                "observed_count": 1,
                "evidence_kind": "zend_runtime",
                "fuzzable": True,
                "run_id": f"{legacy_run_id}-v0",
                "plugin_slug": "fixture",
                "request_id": request_id,
                "canonical_callback": "fixture_callback",
                "request_method": "POST",
            }
            if incomplete_parameter:
                parameter.pop("request_id")
            self.assertEqual(kwargs["legacy_run_id"], f"{legacy_run_id}-v0")
            self.assertEqual(kwargs["candidate_key"], "candidate-fixture")
            return {
                "status": "CONTINUE",
                "request_id": request_id,
                "known_parameters": [parameter],
                "new_parameters": [parameter],
                "merged_suggested_seeds": copy.deepcopy(raw_report),
            }

        def materialize(*args, **kwargs):
            log.append("materialize_convergence_seeds")
            return copy.deepcopy(raw_report)

        def export_configs(report, *, output_config_dir, summary_path, **kwargs):
            log.append("export_seed_configs")
            output_config_dir = Path(output_config_dir)
            path = output_config_dir / "exported.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(config_for(item, include_new=True)), encoding="utf-8")
            summary = {"generated": [{
                "config_slug": "online-linked/exported",
                "config_path": str(path),
                "hook_name": item["hook_name"],
                "callback_id": item["callback_id"],
            }]}
            Path(summary_path).write_text(json.dumps(summary), encoding="utf-8")
            return summary

        def force_replay(config):
            log.append("force_replay_only" if config.get('metadata', {}).get('online_request_seed') else 'v0_force_replay')
            for section in (config.get("body_params"), config.get("query_params")):
                if isinstance(section, dict):
                    section["fuzz"] = []
            config["config_type"] = "replay_only"

        def replay_runner(*args, **kwargs):
            if kwargs['legacy_run_id'] == f'{legacy_run_id}-v0':
                log.append('v0_replay')
                return {'legacy_run_id': kwargs['legacy_run_id'], 'runs': [{
                    **args[0][0], 'callback_reached': True, 'validation_status': 'callback_reached',
                    'process_status': 'replaying', 'matched_artifact': 'v0-probe.json',
                }]}
            log.append("run_generated_configs")
            if replay_error:
                raise RuntimeError("REPLAY_FAILED: replay runner failed")
            return {"legacy_run_id": kwargs["legacy_run_id"], "runs": [{
                "hook_name": item["hook_name"],
                "callback_id": item["callback_id"],
                "callback_reached": replay_passes,
                "validation_status": "callback_reached" if replay_passes else "registered_not_executed",
                "validation_reason": "" if replay_passes else "CALLBACK_NOT_REACHED",
                "process_status": "exited",
                "matched_artifact": "replay-v1.json",
                "request_artifacts": ["replay-v1.json"],
                "resolved_method": "POST",
            }]}

        def verify_pass2(*args, **kwargs):
            if kwargs.get("runtime_cookie_probes"):
                log.append("runtime_cookie_probes:verify")
            if args[0].get('legacy_run_id') == f'{legacy_run_id}-v0':
                log.append('v0_pass2')
                return {'accepted': 1, 'total': 1}
            log.append("verify_pass2_contract")
            return {"accepted": 1, "total": 1} if replay_passes else {"accepted": 0, "total": 0}

        def run_command(command, **kwargs):
            if command[:3] == ["docker", "compose", "run"]:
                log.append("worker_start")
            elif command[:3] == ["docker", "rm", "-f"]:
                log.append("worker_stop")
            return subprocess.CompletedProcess(command, 0, "", "")

        coordinator = OnlineLinkedCoordinator(
            suggested_seeds=suggested,
            config_root=root / "configs",
            output_root=root / "output",
            plugin_slug="fixture",
            legacy_run_id=legacy_run_id,
            max_seconds=max_seconds,
            max_versions=max_versions,
            runtime_cookie_probes=runtime_cookie_probes,
            registry_path=registry,
            campaign_deadline=campaign_deadline,
            build_config_fn=build_config,
            list_targets_fn=list_targets,
            list_artifacts=list_artifacts,
            load_artifact=load_artifact,
            list_zend_artifacts=list_zend,
            load_zend_artifact=load_zend,
            converge_fn=converge,
            materialize_fn=materialize,
            export_configs_fn=export_configs,
            force_replay_only_fn=force_replay,
            replay_runner=replay_runner,
            verify_pass2_fn=verify_pass2,
            run_command=run_command,
            clock=clock,
            sleeper=clock.sleep,
        )

        def light_sender(container_name, **kwargs):
            self.assertEqual(container_name, coordinator._active_container)
            run_id = kwargs["run_id"]
            log.append(f"sender_timeout:{run_id}:{kwargs['timeout_seconds']}")
            config_payload = json.loads(
                (coordinator.config_root / f'{kwargs["config_slug"]}.json').read_text(encoding="utf-8")
            )
            metadata = config_payload.get("metadata") if isinstance(config_payload, dict) else {}
            row = {
                "config_slug": kwargs["config_slug"],
                "hook_name": kwargs["expected"]["hook_name"],
                "callback_id": kwargs["expected"]["callback_id"],
                "entrypoint_type": "ajax",
                "resolved_method": kwargs["expected"]["method"],
                "seed_variant_id": str(
                    kwargs["expected"].get("seed_variant_id")
                    or (metadata or {}).get("seed_variant_id") or ""
                ),
            }
            try:
                report = coordinator.replay_runner(
                    [row], timeout_seconds=kwargs["timeout_seconds"], service=coordinator.service,
                    legacy_run_id=run_id, run_command=coordinator.run_command,
                    list_artifacts=coordinator.list_artifacts, load_artifact=coordinator.load_artifact,
                    list_zend_artifacts=coordinator.list_zend_artifacts,
                    poll_interval_seconds=0, fuzzer_node_id=100, stop_on_callback=True,
                )
            except Exception as exc:
                return {"status": "sender_error", "error": str(exc)}
            old_row = report.get("runs", [{}])[0] if isinstance(report, dict) else {}
            reached = old_row.get("callback_reached") is True
            matched = str(old_row.get("matched_artifact") or "")
            name = str(row.get("seed_variant_id") or "").rsplit("_", 1)[-1] or "seed"
            return {
                "status": "callback_reached" if reached else "request_completed",
                "callback_reached": reached,
                "validation_status": old_row.get("validation_status"),
                "validation_reason": old_row.get("validation_reason", ""),
                "request_name": matched,
                "request": ({
                    "request_id": Path(matched).stem, "legacy_run_id": run_id,
                    "target_plugin": "fixture", "http_method": row["resolved_method"],
                    "request_params": {"body_params": {"action": "fixture", name: f"probe-{name}"}},
                } if matched else None),
                "zend_name": matched if matched else old_row.get("zend_artifact"),
                "zend": ({
                    "request_id": Path(matched).stem, "run_id": run_id,
                    "callback_summaries": [{"callback": "fixture_callback", "unique_parameters": [{
                        "source": "POST", "path": [name], "helper_depth": 5,
                        "observed_count": 1, "access_forms": ["read"],
                    }]}],
                    "events": [{"source": "POST", "path": [name], "operation": "read",
                                 "callback_context": {"attributed": True, "root_callback": "fixture_callback", "depth": 5}}],
                } if matched else None),
                "timing": {},
            }

        coordinator.probe_sender = light_sender
        return coordinator

    def test_runtime_cookie_probe_flag_reaches_injected_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), log, names=("a",), accepted=("a",), runtime_cookie_probes=True,
            )
            result = coordinator._run_pending_probe(
                parent=parent,
                evidence=evidence,
                raw_report=coordinator._reports["v0"],
                convergence=convergence,
                probe=convergence["pending_probes"][0],
                seed=parent["seed_item"],
                deadline=120.0,
            )
            self.assertIsNotNone(result)
            self.assertTrue(coordinator.runtime_cookie_probes)
            self.assertIn("runtime_cookie_probes:verify", log)

    def make_probe_context(
        self,
        root: Path,
        log: list[str],
        *,
        names: tuple[str, ...] = ("a", "b"),
        accepted: tuple[str, ...] = ("a", "b"),
        wrong_target: str | None = None,
        child_export_error: bool = False,
        runtime_cookie_probes: bool = False,
    ) -> tuple[OnlineLinkedCoordinator, dict, dict, dict]:
        coordinator = self.make_coordinator(
            root, log, max_versions=3, runtime_cookie_probes=runtime_cookie_probes,
        )
        item, config, target_key = coordinator._select_v0()
        config_path = coordinator._write_config("v0", config)
        parent = coordinator._new_version("v0", config, config_path, None, None, item)
        parent.update(worker_run_id="run-v0", known_parameters=[])
        coordinator._reports["v0"] = {"plugin_slug": "fixture", "suggested_seeds": [item]}
        coordinator._active_version = "v0"
        coordinator._target_key = target_key
        coordinator._active_container = "parent-container"
        coordinator.state["workers"].append({
            "version": "v0", "container_name": "parent-container", "run_id": "run-v0", "status": "started",
        })

        probe_items = []
        pending = []
        for name in names:
            variant = f"zend_probe_post_{name}"
            probe_item = copy.deepcopy(item)
            probe_item["seed"]["seed_variant_id"] = variant
            probe_item["seed"]["probe_variant"] = True
            probe_item["seed"]["body"][name] = f"probe-{name}"
            probe_item["seed"]["fixed_params"].append(name)
            probe_items.append(probe_item)
            pending.append({
                "name": name, "source": "POST", "location": "form", "helper_depth": 5,
                "seed_variant_id": variant, "request_id": "req-v0", "run_id": "run-v0",
                "plugin_slug": "fixture", "callback_id": "cb-fixture",
                "canonical_callback": "fixture_callback", "request_method": "POST",
            })

        base_evidence = {
            "request_id": "req-v0",
            "request": {"request_params": {"body_params": {"action": "fixture", "seed": "base"}}},
        }
        raw_report = {"plugin_slug": "fixture", "suggested_seeds": [item]}
        convergence = {
            "status": "CONTINUE", "candidate_key": "candidate-fixture",
            "pending_probes": pending, "merged_suggested_seeds": {"suggested_seeds": probe_items},
        }
        original_save = coordinator._save_replay_artifacts
        current_probe_run_id = ""

        def save_replay(row, request_dir, zend_dir):
            nonlocal current_probe_run_id
            if "-probe-" not in current_probe_run_id:
                return original_save(row, request_dir, zend_dir)
            request_name = str(row["matched_artifact"])
            request_dir.mkdir(parents=True, exist_ok=True)
            zend_dir.mkdir(parents=True, exist_ok=True)
            if row.get("request_payload") is not None and row.get("zend_payload") is not None:
                (request_dir / request_name).write_text(json.dumps(row["request_payload"]), encoding="utf-8")
                (zend_dir / str(row.get("zend_artifact") or request_name)).write_text(
                    json.dumps(row["zend_payload"]), encoding="utf-8"
                )
                return
            name = str(row["hook_name"]).split("probe-", 1)[-1]
            (request_dir / request_name).write_text(json.dumps({
                "request_id": Path(request_name).stem, "legacy_run_id": current_probe_run_id,
                "target_plugin": "fixture", "http_method": "POST",
                "request_params": {"body_params": {"action": "fixture", name: f"probe-{name}"}},
            }), encoding="utf-8")
            (zend_dir / request_name).write_text(json.dumps({
                "request_id": Path(request_name).stem, "run_id": current_probe_run_id,
                "callback_summaries": [{
                    "callback": "fixture_callback",
                    "unique_parameters": [{
                        "source": "POST", "path": [name], "helper_depth": 5,
                        "observed_count": 1, "access_forms": ["read"],
                    }],
                }],
                "events": [{
                    "source": "POST", "path": [name], "operation": "read",
                    "callback_context": {
                        "attributed": True, "root_callback": "fixture_callback", "depth": 5,
                    },
                }],
            }), encoding="utf-8")

        def replay(*args, **kwargs):
            nonlocal current_probe_run_id
            run_id = kwargs["legacy_run_id"]
            current_probe_run_id = run_id
            row = dict(args[0][0])
            if "-probe-" in run_id:
                name = str(row["seed_variant_id"]).rsplit("_", 1)[-1]
                row["hook_name"] = f"probe-{name}"
                row["matched_artifact"] = f"probe-{name}.json"
                log.append(f"probe:{name}")
                return {"legacy_run_id": run_id, "runs": [{
                    **row, "callback_reached": True, "validation_status": "callback_reached",
                    "process_status": "exited", "request_artifacts": [row["matched_artifact"]],
                }]}
            return coordinator._default_probe_child_replay(args, kwargs)

        def converge(**kwargs):
            run_id = kwargs["legacy_run_id"]
            if "-probe-" not in run_id:
                return {"status": "CONVERGED", "new_parameters": [], "known_parameters": []}
            item_seed = kwargs["raw_report"]["suggested_seeds"][0]["seed"]
            name = str(item_seed.get("seed_variant_id")).rsplit("_", 1)[-1]
            if name not in accepted:
                return {"status": "CONTINUE", "new_parameters": [], "known_parameters": []}
            target = wrong_target or name
            request_id = f"probe-{name}"
            parameter = {
                "name": target, "path": [target], "source": "POST", "location": "form",
                "helper_depth": 5, "observed_count": 1, "evidence_kind": "zend_runtime", "fuzzable": True,
                "run_id": run_id, "request_id": request_id, "plugin_slug": "fixture",
                "callback_id": "cb-fixture", "canonical_callback": "fixture_callback", "request_method": "POST",
            }
            return {
                "status": "CONTINUE", "request_id": request_id, "known_parameters": [parameter],
                "new_parameters": [parameter], "merged_suggested_seeds": {"suggested_seeds": []},
            }

        def export(report, **kwargs):
            if report["suggested_seeds"][0]["seed"].get("probe_variant"):
                return export_seed_configs(report, **kwargs)
            if child_export_error:
                raise OSError("child export failed")
            out = Path(kwargs["output_config_dir"])
            out.mkdir(parents=True, exist_ok=True)
            names_in_config = ["action", "seed", *names]
            child_config = config_for(item)
            child_config["body_params"]["data"] = [
                {"name": name, "value": "fixture" if name == "action" else "fuzz"}
                for name in names_in_config
            ]
            child_config["body_params"]["fuzz"] = list(names)
            path = out / "child.json"
            path.write_text(json.dumps(child_config), encoding="utf-8")
            Path(kwargs["summary_path"]).write_text(json.dumps({"generated": [{"config_path": str(path)}]}), encoding="utf-8")
            return {"generated": [{"config_path": str(path)}]}

        coordinator._save_replay_artifacts = save_replay
        coordinator.replay_runner = replay
        coordinator.converge_fn = converge
        coordinator.export_configs_fn = export
        coordinator._default_probe_child_replay = lambda args, kwargs: {
            "legacy_run_id": kwargs["legacy_run_id"], "runs": [{
                **args[0][0], "callback_reached": True, "validation_status": "callback_reached",
                "process_status": "exited", "matched_artifact": "replay-v1.json",
                "request_artifacts": ["replay-v1.json"],
            }]
        }
        return coordinator, parent, base_evidence, convergence

    def test_failed_probe_continues_to_next_candidate_and_dedupes_same_parent_context(self):
        for deadline in (None, 31.5):
            with self.subTest(deadline=deadline), tempfile.TemporaryDirectory() as tmp:
                log: list[str] = []
                coordinator, parent, evidence, convergence = self.make_probe_context(Path(tmp), log, accepted=("b",))

                coordinator._run_pending_probe(
                    parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                    convergence=convergence, probe=convergence["pending_probes"][0],
                    seed=parent["seed_item"], deadline=deadline,
                )
                first_attempts = list(coordinator.state["probe_attempts"])
                coordinator._run_pending_probe(
                    parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                    convergence=convergence, probe=convergence["pending_probes"][0],
                    seed=parent["seed_item"], deadline=deadline,
                )

                self.assertEqual([item["candidate"]["name"] for item in first_attempts if item["status"] == "accepted"], ["b"])
                self.assertEqual(
                    len([item for item in coordinator.state["events"] if item.get("reason") == "PROBE_ALREADY_ATTEMPTED"]),
                    2,
                )
                self.assertEqual([item for item in coordinator.state["probe_attempts"] if item["candidate"]["name"] == "a"], [first_attempts[0]])
                self.assertIn("probe:b", log)

    def test_probe_dedupe_retries_changed_inputs_not_request_ids_or_key_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), log, names=("a",), accepted=(),
            )
            cases = [
                ("initial", {"body_params": {"action": "fixture", "seed": "base"}}, 1),
                ("new-id-reordered", {"body_params": {"seed": "base", "action": "fixture"}}, 1),
                ("form-changed", {"body_params": {"action": "fixture", "seed": "deep"}}, 2),
                ("query-changed", {"body_params": {"action": "fixture", "seed": "deep"},
                                   "query_params": {"gallery_id": 42}}, 3),
                ("json-false", {"json_params": {"enabled": False}}, 4),
                ("json-zero", {"json_params": {"enabled": 0}}, 5),
                ("json-nested", {"json_params": {"payload": {"left": 1, "right": [1, 2]}}}, 6),
                ("json-nested-reordered", {"json_params": {"payload": {"right": [1, 2], "left": 1}}}, 6),
                ("json-array-reordered", {"json_params": {"payload": {"right": [2, 1], "left": 1}}}, 7),
                ("cookie-changed", {"json_params": {"payload": {"right": [2, 1], "left": 1}},
                                    "cookies": {"session": "changed"}}, 8),
            ]
            for request_id, params, expected_attempts in cases:
                with self.subTest(request_id=request_id):
                    changed = copy.deepcopy(evidence)
                    changed["request_id"] = request_id
                    changed["request"]["request_params"] = params
                    if request_id == "new-id-reordered":
                        changed["request"]["metadata"] = {"auth_context": "changed"}
                    coordinator._run_pending_probe(
                        parent=parent, evidence=changed, raw_report=coordinator._reports["v0"],
                        convergence=convergence, probe=convergence["pending_probes"][0],
                        seed=parent["seed_item"], deadline=None,
                    )
                    self.assertEqual(log.count("probe:a"), expected_attempts)
                    self.assertEqual(len(coordinator.state["probe_attempts"]), expected_attempts)
                    self.assertEqual(parent["known_parameters"], [])

    def test_probe_dedupe_respects_attempt_budget_when_inputs_keep_changing(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), [], names=("a",), accepted=(),
            )
            coordinator.MAX_PROBE_ATTEMPTS = 2

            for index in range(4):
                changed = copy.deepcopy(evidence)
                changed["request_id"] = f"changed-{index}"
                changed["request"]["request_params"] = {
                    "body_params": {"action": "fixture", "seed": f"value-{index}"},
                }
                coordinator._run_pending_probe(
                    parent=parent, evidence=changed, raw_report=coordinator._reports["v0"],
                    convergence=convergence, probe=convergence["pending_probes"][0],
                    seed=parent["seed_item"], deadline=None,
                )

            self.assertEqual(len(coordinator.state["probe_attempts"]), 2)
            self.assertIn("PROBE_BUDGET_EXHAUSTED", json.dumps(coordinator.state["events"]))
            self.assertEqual(parent["known_parameters"], [])

    def test_two_successful_probes_keep_each_value_in_child_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(Path(tmp), [], accepted=("a", "b"))
            result = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=None,
            )

            self.assertIsNotNone(result)
            child = coordinator.state["versions"][1]
            child_config = json.loads(Path(child["config_path"]).read_text())
            values = {row["name"]: row["value"] for row in child_config["body_params"]["data"]}
            self.assertEqual(values["a"], "probe-a")
            self.assertEqual(values["b"], "probe-b")
            seed_metadata = child_config["metadata"]["online_request_seed"]
            self.assertEqual(seed_metadata["evidence_request_ids"], ["req-v0", "probe-a", "probe-b"])
            self.assertEqual(
                {row["name"]: row["request_id"] for row in seed_metadata["values"] if row["name"] in {"a", "b"}},
                {"a": "probe-a", "b": "probe-b"},
            )
            self.assertEqual(parent["known_parameters"], [])

    def test_bounded_two_probes_keep_independent_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), log, accepted=("a", "b"))
            result = coordinator._run_pending_probe(
                parent=parent, evidence=evidence,
                raw_report=coordinator._reports["v0"], convergence=convergence,
                probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=120.0)
            self.assertIsNotNone(result)
            self.assertEqual([p["status"] for p in coordinator.state["probe_attempts"]],
                             ["accepted", "accepted"])
            self.assertEqual([v["version"] for v in coordinator.state["versions"]],
                             ["v0", "v1"])
            child = json.loads(Path(coordinator.state["versions"][1]["config_path"]).read_text())
            values = {p["name"]: p["value"] for p in child["body_params"]["data"]}
            self.assertEqual((values["a"], values["b"]), ("probe-a", "probe-b"))
            self.assertEqual(parent["known_parameters"], [])

    def test_accepted_probe_survives_later_probe_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), [], names=("a", "b"), accepted=("a",),
            )

            result = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=None,
            )

            self.assertIsNotNone(result)
            self.assertEqual([item["status"] for item in coordinator.state["probe_attempts"]], ["accepted", "failed"])
            child = json.loads(Path(coordinator.state["versions"][1]["config_path"]).read_text())
            values = {row["name"]: row["value"] for row in child["body_params"]["data"]}
            self.assertEqual(values["a"], "probe-a")
            self.assertEqual(parent["known_parameters"], [])

    def test_probe_target_mismatch_is_not_admitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), [], names=("a",), accepted=("a",), wrong_target="b",
            )
            result = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=None,
            )

            self.assertIsNone(result)
            self.assertEqual(len(coordinator.state["versions"]), 1)
            self.assertIn("PROBE_TARGET_MISMATCH", json.dumps(coordinator.state["events"]))
            self.assertEqual(parent["known_parameters"], [])

    def test_existing_accepted_parameter_survives_pending_probe_admission(self):
        for deadline in (None, 31.5):
            with self.subTest(deadline=deadline), tempfile.TemporaryDirectory() as tmp:
                log: list[str] = []
                coordinator, parent, evidence, convergence = self.make_probe_context(
                    Path(tmp), log, names=("a",), accepted=("a",),
                )
                existing = {
                    "name": "existing", "source": "POST", "location": "form", "helper_depth": 0,
                    "evidence_kind": "zend_runtime", "fuzzable": True, "observed_count": 1,
                    "request_id": "req-v0", "run_id": "run-v0", "plugin_slug": "fixture",
                    "canonical_callback": "fixture_callback", "request_method": "POST",
                }
                convergence["new_parameters"] = [existing]

                result = coordinator._run_pending_probe(
                    parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                    convergence=convergence, probe=convergence["pending_probes"][0],
                    seed=parent["seed_item"], deadline=deadline,
                )

                self.assertIsNotNone(result)
                child_names = {item["name"] for item in coordinator.state["versions"][1]["known_parameters"]}
                self.assertEqual(child_names, {"existing", "a"} if deadline is None else {"existing"})
                self.assertEqual(parent["known_parameters"], [])
                if deadline is None:
                    self.assertIn("probe:a", log)
                else:
                    self.assertNotIn("probe:a", log)

    def test_not_admitted_probe_preserves_candidate_and_continues_to_next_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), log, names=("a", "b"), accepted=("b",),
            )
            first_probe, second_probe = convergence["pending_probes"]
            original_converge = coordinator.converge_fn

            def converge(**kwargs):
                result = original_converge(**kwargs)
                if kwargs["legacy_run_id"].endswith("-probe-p1"):
                    pending = {
                        **first_probe, "fuzzable": False,
                        "candidate_status": "pending_probe",
                        "candidate_reason": "guard_without_correlated_read",
                    }
                    return {
                        "status": "CONTINUE", "new_parameters": [],
                        "observed_parameters": [pending],
                        "pending_probes": [second_probe],
                        "merged_suggested_seeds": convergence_report,
                    }
                return result

            convergence_report = convergence["merged_suggested_seeds"]
            coordinator.converge_fn = converge
            result = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=first_probe,
                seed=parent["seed_item"], deadline=None,
            )

            self.assertIsNotNone(result)
            self.assertEqual(
                [item["status"] for item in coordinator.state["probe_attempts"]],
                ["pending", "accepted", "accepted"],
                coordinator.state["events"],
            )
            self.assertEqual(coordinator.state["probe_attempts"][1]["request_id"], "req-v0")
            self.assertEqual(coordinator.state["probe_attempts"][2]["request_id"], "probe-a")
            self.assertEqual({item["name"] for item in result["known_parameters"]}, {"b"})
            self.assertIn("CORRELATED_CANDIDATE_NOT_ADMITTED", json.dumps(coordinator.state["events"]))

    def test_pending_queue_keeps_each_probe_report_and_source_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), log, names=("a", "b"), accepted=("b",),
            )
            first_probe, second_probe = convergence["pending_probes"]
            c_item = copy.deepcopy(convergence["merged_suggested_seeds"]["suggested_seeds"][0])
            c_item["seed"]["seed_variant_id"] = "zend_probe_post_c"
            c_item["seed"]["body"]["c"] = "probe-c"
            c_probe = {
                **first_probe, "name": "c", "seed_variant_id": "zend_probe_post_c",
            }
            sent: list[dict[str, Any]] = []
            original_sender = coordinator.probe_sender

            def capture_sender(container_name, **kwargs):
                config = json.loads(
                    (coordinator.config_root / f'{kwargs["config_slug"]}.json').read_text()
                )
                result = original_sender(container_name, **kwargs)
                sent.append({
                    "run_id": kwargs["run_id"],
                    "seed_variant_id": kwargs["expected"]["seed_variant_id"],
                    "config": config,
                    "request": result.get("request"),
                })
                return result

            coordinator.probe_sender = capture_sender
            original_converge = coordinator.converge_fn

            def converge(**kwargs):
                run_id = kwargs["legacy_run_id"]
                seed_variant = kwargs["raw_report"]["suggested_seeds"][0]["seed"]["seed_variant_id"]
                if seed_variant == "zend_probe_post_a":
                    pending_a = {
                        **first_probe, "fuzzable": False,
                        "candidate_status": "pending_probe",
                        "candidate_reason": "guard_without_correlated_read",
                    }
                    return {
                        "status": "CONTINUE", "new_parameters": [],
                        "observed_parameters": [pending_a], "pending_probes": [c_probe],
                        "merged_suggested_seeds": {"suggested_seeds": [c_item]},
                    }
                if seed_variant == "zend_probe_post_c":
                    return {
                        "status": "CONTINUE", "new_parameters": [{
                            "name": "c", "path": ["c"], "source": "POST", "location": "form",
                            "helper_depth": 5, "observed_count": 1, "evidence_kind": "zend_runtime",
                            "fuzzable": True, "run_id": run_id, "request_id": "probe-c",
                            "plugin_slug": "fixture", "callback_id": "cb-fixture",
                            "canonical_callback": "fixture_callback", "request_method": "POST",
                        }], "known_parameters": [],
                        "merged_suggested_seeds": {"suggested_seeds": [c_item]},
                    }
                return original_converge(**kwargs)

            coordinator.converge_fn = converge
            result = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=first_probe, seed=parent["seed_item"], deadline=None,
            )

            self.assertIsNotNone(result)
            attempts = coordinator.state["probe_attempts"]
            self.assertEqual([item["candidate"]["name"] for item in attempts], ["a", "b", "c"])
            self.assertEqual([item["status"] for item in attempts], ["pending", "accepted", "accepted"])
            probe_sent = [item for item in sent if "-probe-" in item["run_id"]]
            self.assertEqual([item["seed_variant_id"] for item in probe_sent], [
                "zend_probe_post_a", "zend_probe_post_b", "zend_probe_post_c",
            ])
            sent_by_variant = {item["seed_variant_id"]: item for item in probe_sent}
            b_values = {
                row["name"]: row["value"]
                for row in sent_by_variant["zend_probe_post_b"]["config"]["body_params"]["data"]
            }
            c_values = {
                row["name"]: row["value"]
                for row in sent_by_variant["zend_probe_post_c"]["config"]["body_params"]["data"]
            }
            self.assertEqual(b_values["b"], "probe-b")
            self.assertEqual(c_values["c"], "probe-c")
            b_request = sent_by_variant["zend_probe_post_b"]["request"]
            c_request = sent_by_variant["zend_probe_post_c"]["request"]
            self.assertEqual(b_request["request_params"]["body_params"]["b"], "probe-b")
            self.assertEqual(c_request["request_params"]["body_params"]["c"], "probe-c")
            self.assertEqual(
                sent_by_variant["zend_probe_post_b"]["config"]["metadata"]["online_request_seed"]["request_id"],
                "req-v0",
            )
            self.assertEqual(
                sent_by_variant["zend_probe_post_c"]["config"]["metadata"]["online_request_seed"]["request_id"],
                "probe-a",
            )

    def test_child_export_error_keeps_parent_running_without_probe_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), log, names=("a",), accepted=("a",), child_export_error=True,
            )
            coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=None,
            )

            self.assertTrue(coordinator._active_container)
            self.assertNotIn("worker_stop", log)
            self.assertNotEqual(coordinator.state.get("terminal_reason"), "BUDGET_EXPIRED")
            self.assertIn("CHILD_CONFIG_EXPORT_FAILED", json.dumps(coordinator.state["events"]))

    def test_fake_clock_reserves_child_budget_after_accepted_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), log, names=("a", "b"), accepted=("a",),
            )
            original_replay = coordinator.replay_runner

            def replay(*args, **kwargs):
                report = original_replay(*args, **kwargs)
                if kwargs["legacy_run_id"].endswith("-probe-p1"):
                    coordinator.clock.now = 0.25
                return report

            coordinator.replay_runner = replay
            result = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=3.0,
            )

            self.assertIsNotNone(result)
            self.assertEqual(
                [item["status"] for item in coordinator.state["probe_attempts"]],
                ["accepted", "failed"],
            )
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0", "v1"])
            self.assertEqual(parent["known_parameters"], [])
            accepted_event = next(event for event in coordinator.state["events"] if event.get("status") == "ACCEPTED")
            self.assertIn("verify", accepted_event["timing"])
            self.assertIn("total", accepted_event["timing"])
            self.assertTrue(coordinator.state["versions"][1]["replay_result"]["passed"])
            self.assertLessEqual(
                max(float(entry.rsplit(":", 1)[-1]) for entry in log if "-probe-" in entry),
                1.5,
            )

    def test_optional_probe_overhead_cannot_starve_accepted_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), log, names=("a", "b"), accepted=("a",),
            )
            original_replay = coordinator.replay_runner

            def replay(*args, **kwargs):
                report = original_replay(*args, **kwargs)
                run_id = kwargs["legacy_run_id"]
                if run_id.endswith("-probe-p1"):
                    coordinator.clock.now = 0.0
                elif run_id.endswith("-probe-p2"):
                    coordinator.clock.now = 15.75
                return report

            coordinator.replay_runner = replay
            result = coordinator._run_pending_probe(
                parent=parent, evidence=evidence,
                raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=31.5,
            )
            self.assertIsNotNone(result)
            self.assertEqual(
                [row["status"] for row in coordinator.state["probe_attempts"]],
                ["accepted", "failed"],
            )
            self.assertEqual(
                [row["version"] for row in coordinator.state["versions"]],
                ["v0", "v1"],
            )
            child = coordinator.state["versions"][1]
            self.assertEqual({row["name"] for row in child["known_parameters"]}, {"a"})
            self.assertTrue(child["replay_result"]["passed"])
            verification = child["replay_result"]["pass2_verification"]
            self.assertGreater(verification["total"], 0)
            self.assertEqual(verification["accepted"], verification["total"])
            self.assertEqual(coordinator._active_version, "v1")
            self.assertTrue(coordinator._active_container)
            self.assertEqual(parent["known_parameters"], [])

    def test_deadline_expiration_after_accepted_probe_does_not_start_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), log, names=("a",), accepted=("a",),
            )
            original_replay = coordinator.replay_runner

            def replay(*args, **kwargs):
                report = original_replay(*args, **kwargs)
                if kwargs["legacy_run_id"].endswith("-probe-p1"):
                    coordinator.clock.now = 31.5
                return report

            coordinator.replay_runner = replay
            result = coordinator._run_pending_probe(
                parent=parent, evidence=evidence,
                raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=31.5,
            )

            self.assertIsNone(result)
            self.assertEqual([row["status"] for row in coordinator.state["probe_attempts"]], ["failed"])
            self.assertEqual([row["version"] for row in coordinator.state["versions"]], ["v0"])
            self.assertNotIn("worker_start", log)
            self.assertIn("BUDGET_EXPIRED", json.dumps(coordinator.state["events"]))

    def test_campaign_deadline_caps_candidate_replay_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(
                Path(tmp), [], max_seconds=60, campaign_deadline=1.0,
            )
            replay_timeouts = []
            original_replay = coordinator.replay_runner

            def record_timeout(*args, **kwargs):
                replay_timeouts.append(kwargs["timeout_seconds"])
                return original_replay(*args, **kwargs)

            coordinator.replay_runner = record_timeout
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual(replay_timeouts[0], 1)
            self.assertEqual(coordinator.state["campaign_status"], "bounded")

    def test_campaign_budget_exhausted_by_v0_replay_does_not_start_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(
                Path(tmp), log, max_seconds=60, campaign_deadline=1.0,
            )
            original_replay = coordinator.replay_runner

            def exhaust_campaign(*args, **kwargs):
                report = original_replay(*args, **kwargs)
                if kwargs["legacy_run_id"] == "run-v0":
                    coordinator.clock.now = 2.0
                return report

            coordinator.replay_runner = exhaust_campaign
            self.assertNotEqual(coordinator.run(), 0)
            self.assertNotIn("worker_start", log)
            self.assertEqual(coordinator.state["terminal_reason"], "BUDGET_EXPIRED")


    def test_online_linked_calls_legacy_pipeline_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            self.assertEqual(coordinator.run(), 0)
            positions = {name: log.index(name) for name in {
                "build_config", "list_targets", "worker_start", "list_request_artifacts",
                "load_request_artifact", "list_zend_artifacts", "load_zend_artifact",
                "converge_iteration", "materialize_convergence_seeds", "export_seed_configs",
                "force_replay_only", "run_generated_configs", "verify_pass2_contract",
            }}
            self.assertLess(positions["build_config"], positions["list_targets"])
            self.assertLess(positions["list_targets"], positions["worker_start"])
            self.assertLess(positions["worker_start"], positions["converge_iteration"])
            self.assertLess(positions["converge_iteration"], positions["materialize_convergence_seeds"])
            self.assertLess(positions["materialize_convergence_seeds"], positions["export_seed_configs"])
            self.assertLess(positions["export_seed_configs"], positions["force_replay_only"])
            self.assertLess(positions["force_replay_only"], positions["run_generated_configs"])
            self.assertLess(positions["run_generated_configs"], positions["verify_pass2_contract"])

    def test_v0_selection_allows_replay_only_seed_without_fuzz_params(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log: list[str] = []
            coordinator = self.make_coordinator(root, log)

            def build_replay_config(*args, **kwargs):
                config = config_for(seed_item())
                config["config_type"] = "replay_only"
                config["body_params"]["fuzz"] = []
                return "fixture", config

            coordinator.build_config_fn = build_replay_config

            selected = coordinator._select_v0()

            self.assertIsNotNone(selected)
            _, config, _ = selected
            self.assertEqual(config["config_type"], "replay_only")
            self.assertEqual(config["body_params"]["fuzz"], [])

    def test_v0_selection_falls_back_to_replay_builder_for_blocked_seed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log: list[str] = []
            coordinator = self.make_coordinator(root, log)

            def build_blocked_then_replay(*args, **kwargs):
                if not kwargs.get("replay_only"):
                    raise SeedConfigSkip("blocked_http_method")
                config = config_for(seed_item())
                config["config_type"] = "replay_only"
                config["body_params"]["fuzz"] = []
                return "fixture", config

            coordinator.build_config_fn = build_blocked_then_replay
            selected = coordinator._select_v0()

            self.assertIsNotNone(selected)
            _, config, _ = selected
            self.assertEqual(config["config_type"], "replay_only")

    def test_replay_only_worker_is_marked_replaying(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log: list[str] = []
            coordinator = self.make_coordinator(root, log)
            config = config_for(seed_item())
            config["config_type"] = "replay_only"
            config["body_params"]["fuzz"] = []
            coordinator.run_dir.mkdir(parents=True)
            config_path = coordinator._write_config("v0", config)
            version = coordinator._new_version("v0", config, config_path, None, None, seed_item())

            self.assertTrue(coordinator._start_worker(version))
            self.assertEqual(version["status"], "replaying")

    def test_cmp_log_only_does_not_create_child_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, discovers_parameter=False)
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0"])
            self.assertNotIn("materialize_convergence_seeds", log)
            self.assertNotIn("run_generated_configs", log)

    def test_empty_new_parameters_runs_ajax_probe_before_parent_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log: list[str] = []
            coordinator = self.make_coordinator(root, log)
            original_converge = coordinator.converge_fn
            convergence_calls = 0
            probe_run_id = ""
            parameter = {
                "name": "filter_tag", "path": ["filter_tag"], "source": "POST", "location": "form",
                "helper_depth": 5, "observed_count": 1, "evidence_kind": "zend_runtime",
                "run_id": "run-v0", "request_id": "req-v0", "plugin_slug": "fixture",
                "canonical_callback": "fixture_callback", "request_method": "POST", "fuzzable": True,
            }
            probe_item = copy.deepcopy(seed_item())
            probe_item["seed"]["seed_variant_id"] = "zend_probe_post_filter_tag"
            probe_item["seed"]["probe_variant"] = True
            probe_item["seed"]["body"]["filter_tag"] = "probe"
            probe_item["seed"]["fixed_params"].append("filter_tag")
            probe_row = {
                "name": "filter_tag", "source": "POST", "location": "form", "helper_depth": 5,
                "seed_variant_id": "zend_probe_post_filter_tag", "request_id": "req-v0",
                "run_id": "run-v0", "plugin_slug": "fixture", "callback_id": "cb-fixture",
                "canonical_callback": "fixture_callback", "request_method": "POST",
            }

            def converge(**kwargs):
                nonlocal convergence_calls, probe_run_id
                if (
                    kwargs["pass_run_summary"]["runs"][0].get("process_status") == "replaying"
                    and "-probe-" not in kwargs["legacy_run_id"]
                ):
                    return original_converge(**kwargs)
                convergence_calls += 1
                if convergence_calls == 1:
                    return {
                        "status": "CONTINUE", "request_id": "req-v0", "known_parameters": [],
                        "new_parameters": [], "pending_probes": [probe_row],
                        "runtime_candidate_status": "awaiting_probe", "candidate_key": "candidate-fixture",
                        "merged_suggested_seeds": {"suggested_seeds": [probe_item]},
                    }
                self.assertEqual(kwargs["pass_run_summary"]["runs"][0]["matched_artifact"], "probe.json")
                probe_run_id = kwargs["legacy_run_id"]
                accepted = {**parameter, "run_id": probe_run_id, "request_id": "probe"}
                return {
                    "status": "CONTINUE", "request_id": "probe", "known_parameters": [accepted],
                    "new_parameters": [accepted], "candidate_key": "candidate-fixture::zend_probe_post_filter_tag",
                    "merged_suggested_seeds": {"suggested_seeds": [probe_item]},
                }

            original_save = coordinator._save_replay_artifacts

            def save_replay(row, request_dir, zend_dir):
                if row.get("matched_artifact") != "probe.json":
                    return original_save(row, request_dir, zend_dir)
                request_dir.mkdir(parents=True, exist_ok=True)
                zend_dir.mkdir(parents=True, exist_ok=True)
                (request_dir / "probe.json").write_text(json.dumps({
                    "request_id": "probe", "legacy_run_id": probe_run_id,
                    "target_plugin": "fixture", "http_method": "POST",
                    "request_params": {"body_params": {"action": "fixture", "filter_tag": "probe"}},
                }), encoding="utf-8")
                (zend_dir / "probe.json").write_text(json.dumps({
                    "request_id": "probe", "run_id": probe_run_id,
                    "callback_summaries": [{
                        "callback": "fixture_callback",
                        "unique_parameters": [{
                            "source": "POST", "path": ["filter_tag"], "helper_depth": 5,
                            "observed_count": 1, "access_forms": ["read"],
                        }],
                    }],
                    "events": [{
                        "source": "POST", "path": ["filter_tag"], "operation": "read",
                        "callback_context": {
                            "attributed": True, "root_callback": "fixture_callback", "depth": 5,
                        },
                    }],
                }), encoding="utf-8")

            original_replay = coordinator.replay_runner

            def replay(*args, **kwargs):
                nonlocal probe_run_id
                if "-probe-" in kwargs["legacy_run_id"]:
                    probe_run_id = kwargs["legacy_run_id"]
                    return {"legacy_run_id": kwargs["legacy_run_id"], "runs": [{
                        **args[0][0], "callback_reached": True, "validation_status": "callback_reached",
                        "process_status": "exited", "matched_artifact": "probe.json",
                        "request_artifacts": ["probe.json"],
                    }]}
                return original_replay(*args, **kwargs)

            fake_export = coordinator.export_configs_fn

            def export(report, **kwargs):
                item = report["suggested_seeds"][0]
                if item["seed"].get("probe_variant"):
                    return export_seed_configs(report, **kwargs)
                return fake_export(report, **kwargs)

            coordinator.converge_fn = converge
            coordinator._save_replay_artifacts = save_replay
            coordinator.export_configs_fn = export
            coordinator.replay_runner = replay
            coordinator.run()

            self.assertEqual(convergence_calls, 2)
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0", "v1"])
            self.assertEqual(coordinator.state["versions"][0]["known_parameters"], [])
            self.assertEqual(coordinator.state["versions"][1]["known_parameters"][0]["helper_depth"], 5)
            self.assertIn("PARAMETER_PROBE", json.dumps(coordinator.state["events"]))
            probe_config = json.loads(Path(coordinator.state["probe_attempts"][0]["config_path"]).read_text())
            probe_values = {row["name"]: row["value"] for row in probe_config["body_params"]["data"]}
            self.assertEqual(probe_values["action"], "fixture")
            self.assertEqual(probe_config["metadata"]["auth_context"], "guest")
            self.assertEqual(probe_config["metadata"]["zend_runtime_probe"]["value_origin"], "generated_probe")
            self.assertEqual(log.count("worker_start"), 2)

    def test_zend_parameter_creates_child_after_exact_correlation(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            self.assertEqual(coordinator.run(), 0)
            versions = coordinator.state["versions"]
            self.assertEqual([version["version"] for version in versions], ["v0", "v1"])
            self.assertEqual(versions[1]["parent_version"], "v0")
            self.assertEqual(versions[1]["replay_result"]["passed"], True)
            self.assertEqual(versions[1]["status"], "fuzzing")
            self.assertIn("new_param", json.dumps(json.loads(Path(versions[1]["config_path"]).read_text())))

    def test_failed_ajax_probe_keeps_parent_without_confirming_parameter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log: list[str] = []
            coordinator = self.make_coordinator(root, log)
            original_converge = coordinator.converge_fn
            probe_item = copy.deepcopy(seed_item())
            probe_item["seed"]["seed_variant_id"] = "zend_probe_post_filter_tag"
            probe_item["seed"]["probe_variant"] = True
            probe_item["seed"]["body"]["filter_tag"] = "probe"
            probe_item["seed"]["fixed_params"].append("filter_tag")
            probe = {
                "name": "filter_tag", "source": "POST", "location": "form", "helper_depth": 5,
                "seed_variant_id": "zend_probe_post_filter_tag", "request_id": "req-v0",
                "run_id": "run-v0", "plugin_slug": "fixture", "callback_id": "cb-fixture",
                "canonical_callback": "fixture_callback", "request_method": "POST",
            }

            def converge(**kwargs):
                if kwargs["pass_run_summary"]["runs"][0].get("process_status") == "replaying":
                    return original_converge(**kwargs)
                return {
                    "status": "CONTINUE", "request_id": "req-v0", "known_parameters": [],
                    "new_parameters": [], "pending_probes": [probe],
                    "runtime_candidate_status": "awaiting_probe", "candidate_key": "candidate-fixture",
                    "merged_suggested_seeds": {"suggested_seeds": [probe_item]},
                }

            original_replay = coordinator.replay_runner

            def replay(*args, **kwargs):
                if "-probe-" in kwargs["legacy_run_id"]:
                    return {"legacy_run_id": kwargs["legacy_run_id"], "runs": [{
                        **args[0][0], "callback_reached": False,
                        "validation_status": "registered_not_executed", "process_status": "exited",
                        "matched_artifact": "probe.json",
                    }]}
                return original_replay(*args, **kwargs)

            coordinator.converge_fn = converge
            coordinator.replay_runner = replay
            coordinator.run()

            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0"])
            self.assertEqual(coordinator.state["versions"][0]["known_parameters"], [])
            self.assertIn("PROBE_CALLBACK_NOT_REACHED", json.dumps(coordinator.state["events"]))
            self.assertEqual(log.count("worker_start"), 1)

    def test_parent_vulnerability_exit_cancels_probe_without_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(Path(tmp), [])
            coordinator.probe_sender = lambda *args, **kwargs: {
                "status": "parent_stopped", "parent_exit_code": STOP_ON_VULN_EXIT_CODE,
                "error": "PARENT_WORKER_EXITED_DURING_SENDER",
            }
            result = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=None,
            )
            self.assertIsNone(result)
            self.assertEqual(coordinator.state["terminal_status"], "VULN_FOUND")
            self.assertEqual(parent["known_parameters"], [])
            self.assertIn("PARENT_WORKER_EXITED_DURING_PROBE", json.dumps(coordinator.state["events"]))

    def test_missing_correlation_does_not_create_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(
                Path(tmp), log, request_names={"req-v0.json"}, zend_names={"prefix-req-v0.json"}
            )
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual(len(coordinator.state["versions"]), 1)
            self.assertNotIn("converge_iteration", log)

    def test_parameter_missing_correlation_is_rejected_without_child_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, incomplete_parameter=True)
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0"])
            self.assertIn("CORRELATION_OR_PROVENANCE_INCOMPLETE", json.dumps(coordinator.state["events"]))
            self.assertNotIn("export_seed_configs", log)

    def test_new_action_or_callback_is_recorded_without_child_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, request_callback_id="new-callback")
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0"])
            self.assertIn("ACTION_EXPANSION_NOT_IMPLEMENTED", json.dumps(coordinator.state["events"]))
            self.assertNotIn("converge_iteration", log)

    def test_convergence_exception_is_rejected_and_parent_continues(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, convergence_error=True)
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0"])
            self.assertIn("CORRELATION_OR_PROVENANCE_INCOMPLETE", json.dumps(coordinator.state["events"]))

    def test_replay_exception_keeps_parent_without_child_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, replay_error=True)
            self.assertNotEqual(coordinator.run(), 0)
            self.assertEqual(len(coordinator.state["versions"]), 2)
            self.assertEqual(coordinator.state["versions"][1]["status"], "replay_failed")
            self.assertEqual([item for item in coordinator.state["workers"] if item["version"] == "v1"], [])
            self.assertEqual(log.count("worker_start"), 1)

    def test_replay_failure_keeps_parent_without_child_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, replay_passes=False)
            self.assertNotEqual(coordinator.run(), 0)
            self.assertEqual(len(coordinator.state["versions"]), 2)
            self.assertEqual(coordinator.state["versions"][1]["status"], "replay_failed")
            self.assertEqual([item for item in coordinator.state["workers"] if item["version"] == "v1"], [])
            self.assertEqual(log.count("worker_start"), 1)
            state = json.loads(coordinator.state_path.read_text())
            self.assertEqual(state["terminal_status"], "NOT_VERIFIED")
            self.assertEqual(state["terminal_reason"], "CHILD_REPLAY_FAILED")

    def test_not_verified_stops_candidate_before_budget_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator = self.make_coordinator(Path(tmp), log, replay_passes=False, max_seconds=120)
            started = coordinator.clock()
            self.assertNotEqual(coordinator.run(), 0)
            self.assertLess(coordinator.clock() - started, 1)
            self.assertEqual(coordinator.state["terminal_status"], "NOT_VERIFIED")
            self.assertEqual(coordinator.state["terminal_reason"], "CHILD_REPLAY_FAILED")
            self.assertEqual(coordinator.state["workers"][0]["status"], "stopped")
            self.assertEqual(coordinator.state["workers"][0]["terminal_reason"], "CHILD_REPLAY_FAILED")

    def test_probe_admission_normalizes_instance_callback_without_weakening_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            parent = {"canonical_callback": "Fixture->handle", "resolved_method": "POST"}
            parameter = {
                "name": "task", "path": ["task"], "source": "GET", "location": "query",
                "helper_depth": 2, "observed_count": 1, "evidence_kind": "zend_runtime",
                "request_id": "probe-request", "run_id": "probe-run", "plugin_slug": "fixture",
                "canonical_callback": "Fixture::handle", "request_method": "POST",
            }
            evidence = {
                "request_id": "probe-request", "worker_run_id": "probe-run",
                "request": {"target_plugin": "fixture", "http_method": "POST",
                            "request_params": {"query_params": {"task": "probe"}}},
                "zend": {"events": [{"source": "GET", "path": ["task"], "operation": "read",
                         "callback_context": {"attributed": True, "root_callback": "Fixture::handle", "depth": 2}}]},
            }
            self.assertTrue(coordinator._probe_admission_complete(parameter, evidence, parent))
            for field, value in (("root_callback", "Other::handle"), ("attributed", False), ("depth", 3)):
                invalid = copy.deepcopy(evidence)
                invalid["zend"]["events"][0]["callback_context"][field] = value
                self.assertFalse(coordinator._probe_admission_complete(parameter, invalid, parent))
            invalid = copy.deepcopy(evidence)
            invalid["request"]["request_params"]["query_params"] = {}
            self.assertFalse(coordinator._probe_admission_complete(parameter, invalid, parent))

    def test_probe_admission_accepts_correlated_request_guard_after_transport_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            parent = {"canonical_callback": "Fixture->handle", "resolved_method": "POST"}
            parameter = {
                "name": "task", "path": ["task"], "source": "POST", "location": "form",
                "helper_depth": 2, "observed_count": 1, "evidence_kind": "zend_runtime",
                "request_id": "probe-request", "run_id": "probe-run", "plugin_slug": "fixture",
                "canonical_callback": "Fixture::handle", "request_method": "POST",
                "fuzzable": True, "access_forms": ["isset"],
            }
            evidence = {
                "request_id": "probe-request", "worker_run_id": "probe-run",
                "request": {"target_plugin": "fixture", "http_method": "POST",
                            "request_params": {"body_params": {"task": "probe"}}},
                "zend": {"events": [{"source": "REQUEST", "path": ["task"], "operation": "isset",
                         "callback_context": {"attributed": True, "root_callback": "Fixture::handle", "depth": 2}}]},
            }

            self.assertTrue(coordinator._probe_admission_complete(parameter, evidence, parent))

    def test_probe_admission_uses_registry_callback_identity_and_registration(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            coordinator.registry = {
                "schema_version": 1,
                "callback_map": {"tfa": "BaseFixture::handle", "override": "ChildFixture::handle"},
            }
            parent = {
                "callback_id": "tfa", "canonical_callback": "ChildFixture->handle",
                "hook_name": "wp_ajax_tfa", "auth_context": "authenticated", "resolved_method": "POST",
            }
            parameter = {
                "name": "task", "path": ["task"], "source": "GET", "location": "query",
                "helper_depth": 2, "observed_count": 1, "evidence_kind": "zend_runtime",
                "request_id": "probe-request", "run_id": "probe-run", "plugin_slug": "fixture",
                "callback_id": "tfa", "canonical_callback": "BaseFixture::handle", "request_method": "POST",
            }
            evidence = {
                "request_id": "probe-request", "worker_run_id": "probe-run",
                "request": {
                    "target_plugin": "fixture", "http_method": "POST", "hook_name": "wp_ajax_tfa",
                    "callback_id": "tfa", "auth_context": "authenticated",
                    "request_params": {"query_params": {"task": "probe"}},
                },
                "zend": {"events": [{"source": "GET", "path": ["task"], "operation": "read",
                         "callback_context": {"attributed": True, "root_callback": "BaseFixture::handle", "depth": 2}}]},
            }
            self.assertTrue(coordinator._probe_admission_complete(parameter, evidence, parent))

            for field, value in (
                ("callback_id", "other"), ("hook_name", "wp_ajax_other"),
                ("auth_context", "guest"),
            ):
                invalid = copy.deepcopy(evidence)
                invalid["request"][field] = value
                self.assertFalse(coordinator._probe_admission_complete(parameter, invalid, parent), field)

            for field, value in (("plugin_slug", "other"), ("request_id", "other"), ("run_id", "other"),
                                 ("request_method", "GET"), ("canonical_callback", "OtherFixture::handle")):
                invalid = copy.deepcopy(parameter)
                invalid[field] = value
                self.assertFalse(coordinator._probe_admission_complete(invalid, evidence, parent), field)

            override_parent = {**parent, "callback_id": "override", "canonical_callback": "ChildFixture->handle"}
            override_parameter = {**parameter, "callback_id": "override", "canonical_callback": "ChildFixture::handle"}
            override_evidence = copy.deepcopy(evidence)
            override_evidence["request"]["callback_id"] = "override"
            override_evidence["zend"]["events"][0]["callback_context"]["root_callback"] = "ChildFixture::handle"
            self.assertTrue(coordinator._probe_admission_complete(override_parameter, override_evidence, override_parent))

            unrelated = {**parameter, "canonical_callback": "OtherFixture::handle"}
            self.assertFalse(coordinator._probe_admission_complete(unrelated, evidence, parent))

    def test_replay_artifact_payloads_are_saved_without_reload_and_classify_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            request = {"request_id": "probe-r", "legacy_run_id": "probe-run"}
            zend = {"request_id": "probe-r", "run_id": "probe-run"}
            coordinator = object.__new__(OnlineLinkedCoordinator)
            coordinator.load_artifact = lambda _name: (_ for _ in ()).throw(
                AssertionError("unexpected request reload"))
            coordinator.load_zend_artifact = lambda _name: (_ for _ in ()).throw(
                AssertionError("unexpected Zend reload"))
            row = coordinator._sender_runner_row({}, {
                "status": "callback_reached", "request_name": "probe-r.json", "request": request,
                "zend_name": "probe-r.json", "zend": zend,
            }, "probe-run")
            coordinator._save_replay_artifacts(row, root / "request", root / "zend")
            self.assertEqual(json.loads((root / "request/probe-r.json").read_text()), request)
            self.assertEqual(json.loads((root / "zend/probe-r.json").read_text()), zend)

            def expect_stage(result, stage):
                with self.assertRaises(RuntimeError) as caught:
                    error_root = root / stage
                    coordinator._save_replay_artifacts(result, error_root / "request", error_root / "zend")
                self.assertEqual(getattr(caught.exception, "stage", ""), stage)

            missing_request = dict(row, request_payload=None)
            coordinator.load_artifact = lambda _name: None
            expect_stage(missing_request, "sender_payload")

            missing_zend = dict(row, zend_payload=None)
            coordinator.load_zend_artifact = lambda _name: None
            expect_stage(missing_zend, "sender_payload")

            mismatch = dict(row, request_payload={"request_id": "other", "legacy_run_id": "probe-run"})
            expect_stage(mismatch, "id_correlation")

            coordinator._copy_json = lambda *_args: (_ for _ in ()).throw(OSError("write failed"))
            expect_stage(row, "request_write")

    def test_stop_waits_for_in_progress_removal_and_fails_closed(self):
        for outcome in ("removed", "stuck", "daemon_error"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as tmp:
                coordinator, parent, _, _ = self.make_probe_context(Path(tmp), [])
                inspected = []

                def remove(command, **kwargs):
                    self.assertGreater(kwargs["timeout"], 0)
                    self.assertLessEqual(kwargs["timeout"], 30)
                    if command[:3] == ["docker", "rm", "-f"]:
                        return subprocess.CompletedProcess(command, 1, "", "removal of container parent-container is already in progress")
                    self.assertEqual(command[:3], ["docker", "container", "inspect"])
                    self.assertEqual(command[-1], "parent-container")
                    inspected.append(command)
                    if outcome == "daemon_error":
                        return subprocess.CompletedProcess(command, 1, "", "daemon unavailable")
                    if outcome == "removed" and len(inspected) > 1:
                        return subprocess.CompletedProcess(command, 1, "", "Error response from daemon: No such container: parent-container")
                    return subprocess.CompletedProcess(command, 0, "removing", "")

                coordinator.run_command = remove
                self.assertEqual(coordinator._stop_worker(parent, "PARAMETER_PROBE"), outcome == "removed")
                self.assertTrue(inspected)
                self.assertLessEqual(coordinator.clock(), 30)
                if outcome == "removed":
                    self.assertEqual(coordinator._active_container, "")
                    self.assertEqual(parent["worker_status"], "stopped")
                    self.assertIsNone(coordinator.state["terminal_status"])
                else:
                    self.assertEqual(coordinator._active_container, "parent-container")
                    self.assertEqual(coordinator.state["terminal_reason"], "WORKER_STOP_FAILED")

    def test_stop_failure_blocks_handoff_after_replay_and_preserves_worker_identity(self):
        for raises in (False, True):
            with self.subTest(raises=raises), tempfile.TemporaryDirectory() as tmp:
                log: list[str] = []
                coordinator = self.make_coordinator(Path(tmp), log)
                run_command = coordinator.run_command

                def fail_stop(command, **kwargs):
                    if command[:3] == ["docker", "rm", "-f"]:
                        if raises:
                            raise subprocess.TimeoutExpired(command, 30)
                        return subprocess.CompletedProcess(command, 1, "", "daemon unavailable")
                    return run_command(command, **kwargs)

                coordinator.run_command = fail_stop
                self.assertNotEqual(coordinator.run(), 0)
                self.assertIn("run_generated_configs", log)
                self.assertEqual(log.count("worker_start"), 1)
                self.assertEqual(coordinator._active_container, coordinator.state["workers"][0]["container_name"])
                state = json.loads(coordinator.state_path.read_text())
                self.assertEqual(state["terminal_status"], "NOT_VERIFIED")
                self.assertEqual(state["terminal_reason"], "WORKER_STOP_FAILED")
                self.assertEqual(state["workers"][0]["status"], "stop_failed")

    def test_shutdown_failure_does_not_report_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [], discovers_parameter=False)
            run_command = coordinator.run_command

            def fail_stop(command, **kwargs):
                if command[:3] == ["docker", "rm", "-f"]:
                    return subprocess.CompletedProcess(command, 1, "", "daemon unavailable")
                return run_command(command, **kwargs)

            coordinator.run_command = fail_stop
            self.assertNotEqual(coordinator.run(), 0)
            self.assertEqual(coordinator.state["terminal_status"], "NOT_VERIFIED")
            self.assertEqual(coordinator.state["terminal_reason"], "WORKER_STOP_FAILED")

    def test_child_start_failure_is_reported_after_parent_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            run_command = coordinator.run_command

            def fail_child(command, **kwargs):
                if command[:3] == ["docker", "compose", "run"] and "HOOKPHUZZ_LEGACY_RUN_ID=run-v1" in command:
                    return subprocess.CompletedProcess(command, 1, "", "child failed")
                return run_command(command, **kwargs)

            coordinator.run_command = fail_child
            self.assertNotEqual(coordinator.run(), 0)
            self.assertEqual([w["version"] for w in coordinator.state["workers"]], ["v0"])
            self.assertEqual(coordinator.state["terminal_status"], "NOT_VERIFIED")
            self.assertEqual(coordinator.state["terminal_reason"], "CHILD_WORKER_START_FAILED")

    def test_expired_evidence_does_not_create_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            list_artifacts = coordinator.list_artifacts

            def slow_evidence():
                coordinator.sleeper(3)
                return list_artifacts()

            coordinator.list_artifacts = slow_evidence
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual([v["version"] for v in coordinator.state["versions"]], ["v0"])
            self.assertNotIn("run_generated_configs", log)

    def test_pass2_failure_does_not_use_successful_callback_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            replay_runner = coordinator.replay_runner

            def reached_callback(*args, **kwargs):
                report = replay_runner(*args, **kwargs)
                report["runs"][0]["validation_reason"] = "Expected callback id was found in executed_callbacks"
                return report

            coordinator.replay_runner = reached_callback
            coordinator.verify_pass2_fn = lambda *args, **kwargs: {
                "accepted": int(args[0].get('legacy_run_id') == 'run-v0'), "total": 1}
            self.assertNotEqual(coordinator.run(), 0)
            self.assertEqual(coordinator.state["terminal_status"], "NOT_VERIFIED")
            self.assertEqual(coordinator.state["versions"][1]["terminal_reason"], "PASS2_VERIFICATION_FAILED")

    def test_cookie_probe_admission_is_opt_in_and_reaches_child_config(self):
        for enabled, admitted in ((False, False), (True, True)):
            with self.subTest(runtime_cookie_probes=enabled), tempfile.TemporaryDirectory() as tmp:
                coordinator, parent, _, _ = self.make_probe_context(
                    Path(tmp), [], names=("fixture_cookie",), accepted=(),
                    runtime_cookie_probes=enabled,
                )
                cookie_item = copy.deepcopy(parent["seed_item"])
                cookie_item["seed"].update({
                    "body": {"action": "fixture"},
                    "cookies": {"fixture_cookie": "FUZZ"},
                    "fixed_params": ["action"],
                    "fuzzable_params": ["fixture_cookie"],
                    "input_params": [{
                        "name": "fixture_cookie", "path": ["fixture_cookie"],
                        "source": "COOKIE", "location": "cookie", "fuzzable": True,
                        "evidence_kind": "zend_runtime",
                    }],
                })
                coordinator.materialize_fn = lambda *args, **kwargs: {
                    "plugin_slug": "fixture", "suggested_seeds": [cookie_item],
                }
                coordinator.export_configs_fn = export_seed_configs
                parameter = {
                    "name": "fixture_cookie", "path": ["fixture_cookie"],
                    "source": "COOKIE", "location": "cookie", "helper_depth": 1,
                    "observed_count": 1, "evidence_kind": "zend_runtime",
                    "fuzzable": True, "request_id": "req-v0", "run_id": "run-v0",
                    "plugin_slug": "fixture", "callback_id": "cb-fixture",
                    "canonical_callback": "fixture_callback", "request_method": "POST",
                }
                evidence = {
                    "request_id": "req-v0", "worker_run_id": "run-v0",
                    "request": {
                        "target_plugin": "fixture", "http_method": "POST",
                        "hook_name": parent["hook_name"], "callback_id": "cb-fixture",
                        "auth_context": parent["auth_context"],
                        "request_params": {"cookies": {"fixture_cookie": "source-cookie"}},
                    },
                    "zend": {"events": [{
                        "source": "COOKIE", "path": ["fixture_cookie"], "operation": "read",
                        "callback_context": {
                            "attributed": True, "root_callback": "fixture_callback", "depth": 1,
                        },
                    }]},
                }
                result = coordinator._handle_convergence_result(
                    parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                    result={
                        "status": "CONTINUE", "request_id": "req-v0",
                        "known_parameters": [parameter], "new_parameters": [parameter],
                    }, seed=parent["seed_item"], deadline=None,
                )
                if not admitted:
                    self.assertIsNone(result)
                    self.assertEqual(len(coordinator.state["versions"]), 1)
                    continue
                self.assertIsNotNone(result)
                child = json.loads(Path(coordinator.state["versions"][1]["config_path"]).read_text())
                cookie_rows = {row["name"]: row for row in child["cookies"]["data"]}
                self.assertEqual(cookie_rows["fixture_cookie"]["value"], "source-cookie")
                self.assertIn("fixture_cookie", child["cookies"]["fuzz"])
                invalid_cases = []
                unsupported_operation = copy.deepcopy(evidence)
                unsupported_operation["zend"]["events"][0]["operation"] = "write"
                invalid_cases.append(("unsupported operation", parameter, unsupported_operation))
                absent_cookie = copy.deepcopy(evidence)
                absent_cookie["request"]["request_params"]["cookies"] = {}
                invalid_cases.append(("cookie absent", parameter, absent_cookie))
                for field, value in (("request_id", "other-request"), ("run_id", "other-run")):
                    wrong_identity = copy.deepcopy(parameter)
                    wrong_identity[field] = value
                    invalid_cases.append((f"wrong {field}", wrong_identity, evidence))
                wrong_callback = copy.deepcopy(parameter)
                wrong_callback["canonical_callback"] = "other_callback"
                invalid_cases.append(("wrong callback", wrong_callback, evidence))
                for label, invalid_parameter, invalid_evidence in invalid_cases:
                    self.assertFalse(
                        coordinator._probe_admission_complete(invalid_parameter, invalid_evidence, parent),
                        label,
                    )

    def test_child_handoff_failure_is_terminal_without_parent_restart(self):
        for replay_passes in (True, False):
            with self.subTest(replay_passes=replay_passes), tempfile.TemporaryDirectory() as tmp:
                coordinator = self.make_coordinator(Path(tmp), [], replay_passes=replay_passes)
                run_command = coordinator.run_command
                starts = 0

                def fail_after_v0(command, **kwargs):
                    nonlocal starts
                    if command[:3] == ["docker", "compose", "run"]:
                        starts += 1
                        if starts > 1:
                            return subprocess.CompletedProcess(command, 1, "", "start failed")
                    return run_command(command, **kwargs)

                coordinator.run_command = fail_after_v0
                self.assertNotEqual(coordinator.run(), 0)
                self.assertEqual(coordinator.state["terminal_status"], "NOT_VERIFIED")
                self.assertEqual(
                    coordinator.state["terminal_reason"],
                    "CHILD_WORKER_START_FAILED" if replay_passes else "CHILD_REPLAY_FAILED",
                )
                self.assertEqual(len(coordinator.state["workers"]), 1)

    def test_budget_spent_after_replay_prevents_or_allows_child_start(self):
        for elapsed in (1.5, 3):
            with self.subTest(elapsed=elapsed), tempfile.TemporaryDirectory() as tmp:
                log: list[str] = []
                coordinator = self.make_coordinator(Path(tmp), log)
                run_command = coordinator.run_command

                def slow_stop(command, **kwargs):
                    if command[:3] == ["docker", "rm", "-f"]:
                        coordinator.sleeper(elapsed)
                    return run_command(command, **kwargs)

                coordinator.run_command = slow_stop
                self.assertEqual(coordinator.run(), 0)
                self.assertIn("run_generated_configs", log)
                self.assertEqual(log.count("worker_start"), 1 if elapsed >= 3 else 2)
                if elapsed >= 3:
                    self.assertEqual(coordinator.state["versions"][1]["worker_status"], "not_started_budget_expired")

    def test_budget_spent_replaying_prevents_child_or_parent_start(self):
        for replay_passes in (True, False):
            with self.subTest(replay_passes=replay_passes), tempfile.TemporaryDirectory() as tmp:
                log: list[str] = []
                coordinator = self.make_coordinator(Path(tmp), log, replay_passes=replay_passes)
                replay_runner = coordinator.replay_runner

                def slow_replay(*args, **kwargs):
                    if kwargs['legacy_run_id'] != 'run-v0':
                        coordinator.sleeper(3)
                    return replay_runner(*args, **kwargs)

                coordinator.replay_runner = slow_replay
                self.assertEqual(coordinator.run(), 1)
                self.assertEqual(log.count("worker_start"), 1)
                self.assertFalse(coordinator.state["versions"][1]["replay_result"]["passed"])
                self.assertEqual(coordinator.state["terminal_status"], "NOT_VERIFIED")

    def test_replay_pass_starts_child_only_after_parent_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            self.assertEqual(coordinator.run(), 0)
            stop_index = log.index("worker_stop")
            replay_index = log.index("run_generated_configs")
            child_start_index = log.index("worker_start", log.index("worker_start") + 1)
            self.assertLess(replay_index, stop_index)
            self.assertLess(replay_index, child_start_index)
            replay_event = [event for event in coordinator.state["events"] if event.get("kind") == "CHILD_REPLAY"][-1]
            self.assertEqual(replay_event["timing"], coordinator.state["versions"][1]["replay_result"]["timing"])

    def test_online_max_versions_includes_v0(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, max_versions=1)
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0"])
            self.assertIn("VERSION_LIMIT_REACHED", json.dumps(coordinator.state["events"]))
            self.assertNotIn("run_generated_configs", log)

    def test_no_worker_versions_run_concurrently(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            self.assertEqual(coordinator.run(), 0)
            starts = [index for index, value in enumerate(log) if value == "worker_start"]
            stops = [index for index, value in enumerate(log) if value == "worker_stop"]
            self.assertEqual(len(starts), 2)
            self.assertEqual(len(stops), 2)
            self.assertLess(starts[0], stops[0])
            self.assertLess(stops[0], starts[1])

    def test_config_files_are_immutable_and_hashed_per_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            self.assertEqual(coordinator.run(), 0)
            for version in coordinator.state["versions"]:
                config_path = Path(version["config_path"])
                self.assertTrue(config_path.is_file())
                self.assertEqual(version["config_hash"], coordinator.config_hash(config_path))
                self.assertNotEqual(version["config_path"], version.get("replay_config_path"))

    def test_config_paths_are_grouped_by_plugin_with_readable_filenames(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            self.assertEqual(coordinator.run(), 0)

            for version in coordinator.state["versions"]:
                config_path = Path(version["config_path"])
                replay_path = Path(version["replay_config_path"])
                relative_parts = config_path.relative_to(coordinator.config_root).parts
                self.assertEqual(relative_parts[:2], ("online-linked", "fixture"))
                self.assertEqual(config_path.name, f"{version['version']}-config.json")
                self.assertEqual(replay_path.name, f"{version['version']}-replay.json")

    def test_runtime_evidence_is_saved_under_run_specific_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            self.assertEqual(coordinator.run(), 0)
            run_dir = coordinator.run_dir
            self.assertTrue((run_dir / "state.json").is_file())
            self.assertTrue((run_dir / "events.jsonl").is_file())
            self.assertTrue((run_dir / "versions" / "v0").is_dir())

    def test_long_run_id_preserves_evidence_and_resolvable_worker_configs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / ("workspace-" + "x" * 45)
            root.mkdir()
            run_id = "plugin-20260906T121044Z-candidate-001-wp_ajax_nopriv_" + "upload_file_" * 5
            coordinator = self.make_coordinator(
                root, [], legacy_run_id=run_id,
                request_names={"1788671490-f70d334e-44a4-46f8-85e6-95b571434eec.json"},
                zend_names={"1788671490-f70d334e-44a4-46f8-85e6-95b571434eec.json"},
            )
            coordinator.export_configs_fn = export_seed_configs
            replay_runner = coordinator.replay_runner

            def replay_with_existing_config(rows, **kwargs):
                config = coordinator.config_root / (rows[0]["config_slug"] + ".json")
                self.assertTrue(config.is_file(), config)
                self.assertEqual(json.loads(config.read_text())["config_type"], "replay_only")
                return replay_runner(rows, **kwargs)

            coordinator.replay_runner = replay_with_existing_config
            self.assertEqual(coordinator.run(), 0, coordinator.state["terminal_reason"])
            self.assertEqual([v["version"] for v in coordinator.state["versions"]], ["v0", "v1"])
            self.assertTrue(coordinator.state["versions"][1]["replay_result"]["passed"])
            state = json.loads(coordinator.state_path.read_text())
            self.assertEqual(state["legacy_run_id"], run_id)
            evidence = next((coordinator.run_dir / "versions/v0/observation/request").glob("*.json"))
            self.assertEqual(json.loads(evidence.read_text())["legacy_run_id"], run_id + "-v0")
            for worker in state["workers"]:
                slug = next(arg.split("=", 1)[1] for arg in worker["command"] if arg.startswith("FUZZER_CONFIG="))
                self.assertTrue((coordinator.config_root / (slug + ".json")).is_file())
            for path in root.rglob("*.json"):
                self.assertLess(len(str(path.resolve())), 260, path)


if __name__ == "__main__":
    unittest.main()
