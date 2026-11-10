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
from collections.abc import Mapping
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
from typing import Any


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(FUZZER_DIR))

from online_linked.coordination.campaign import run_online_linked
from online_linked.coordination.candidate_identity import _batch_candidate_identity, _candidate_context_key
from online_linked.coordinator import OnlineLinkedCoordinator, OnlineLinkedError
from hook_energy.seed_generation.generated_config_runner import STOP_ON_VULN_EXIT_CODE
from core import online_handoff as handoff
from online_linked.probe_sender import ParentInspectionTimeout
from seed_generation.config.config_exporter import SeedConfigSkip, export_seed_configs, build_config_for_seed_item
from seed_generation.skeleton.candidate_generator import ZendRuntimeSeedGenerator
from hook_energy.seed_generation.zend_runtime.bridge_cli import converge_iteration, _materialize_ajax_runtime_probes
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


def worker_env(worker: Mapping[str, Any]) -> dict[str, str]:
    command = worker["command"]
    return dict(command[i + 1].split("=", 1) for i, arg in enumerate(command) if arg == "-e")


class OnlineLinkedCoordinatorTests(unittest.TestCase):
    def test_verified_probe_renews_before_checkpoint_and_large_guard_queue_reaches_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            c, parent, evidence, convergence = self.make_probe_context(Path(tmp), [], names=('a',))
            c.max_seconds = 30
            c._candidate_deadline()
            c.clock.now = 15
            sender = c.probe_sender
            converge = c.converge_fn
            write_state = c._write_state
            checkpoints = []
            admission_time = []
            baseline_inputs = []
            handle = c._handle_convergence_result

            def admit_near_deadline(*args, **kwargs):
                result = sender(*args, **kwargs)
                if kwargs['run_id'].endswith('-probe-p1'):
                    c.clock.now = 22
                return result

            def discover_guards(**kwargs):
                result = converge(**kwargs)
                if '-probe-' in kwargs['legacy_run_id']:
                    admission_time.append(c.clock())
                    result['pending_probes'] = [
                        {**convergence['pending_probes'][0], 'name': f'guard-{i:03d}'}
                        for i in range(100)
                    ]
                return result

            def slow_checkpoint():
                if admission_time:
                    checkpoints.append((c.clock(), len(c._progress_keys)))
                    c.clock.sleep(0.1)
                write_state()

            def baseline(**kwargs):
                baseline_inputs.append((c.clock(), kwargs['result']['new_parameters'], len(checkpoints)))
                return handle(**kwargs)

            c.probe_sender = admit_near_deadline
            c.converge_fn = discover_guards
            with patch.object(c, '_write_state', side_effect=slow_checkpoint), \
                 patch.object(c, '_handle_convergence_result', side_effect=baseline):
                result = c._run_pending_probe(parent=parent, evidence=evidence,
                    raw_report=c._reports['v0'], convergence=convergence,
                    probe=convergence['pending_probes'][0], seed=parent['seed_item'], deadline=30)
            self.assertIsNotNone(result)
            self.assertTrue(checkpoints)
            self.assertEqual(checkpoints[0][1], 1, 'verified input must earn time before its accepted checkpoint')
            self.assertEqual(len(c.state['budget_progress']), 1)
            self.assertEqual(c.state['budget_progress'][0]['at'], admission_time[0])
            self.assertLess(baseline_inputs[0][0], c._deadline)
            self.assertEqual([p['name'] for p in baseline_inputs[0][1]], ['a'])
            self.assertEqual(len(c.state['pending_probe_queue']), 100)
            self.assertLessEqual(baseline_inputs[0][2], 5, 'checkpoint a queue batch, not each guard/event')
            self.assertNotIn('replay_input_trials', c.state)
            self.assertTrue(result['replay_result']['passed'])
            saved = json.loads(c.state_path.read_text())
            self.assertEqual(len(saved['pending_probe_queue']), 100)
            events = [json.loads(line) for line in c.events_path.read_text().splitlines()]
            self.assertEqual(sum(e.get('status') == 'DEFERRED' for e in events), 100)

    def test_idle_completion_with_pending_probes_exports_partial_from_real_state(self):
        from online_linked.export import export_online_linked_batch
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            c = self.make_coordinator(root, [])
            probe = {'name': 'b', 'source': 'POST', 'location': 'form'}

            def stop_at_deadline(version, *, deadline):
                c.state['pending_probe_queue'] = [{
                    'parent_version': version['version'], 'candidate': probe,
                    'convergence': {'pending_probes': [probe]},
                    'evidence': {'request_id': 'pending-b'},
                }]
                c.clock.now = deadline

            with patch.object(c, '_consume_gate_evidence', side_effect=stop_at_deadline):
                self.assertEqual(c.run(), 0)
            self.assertEqual(c.state['terminal_status'], 'PARTIAL')
            self.assertEqual(c.state['terminal_reason'], 'NO_NEW_PROGRESS')
            destination = root / 'export/final-configs'
            batch = root / 'batch-state.json'
            batch.write_text(json.dumps({'plugin_slug': 'fixture', 'candidates': [{
                'identity': 'fixture', 'state_path': str(c.state_path), 'run_id': c.legacy_run_id,
                'hook_name': c.state['versions'][0]['hook_name'],
            }]}))
            self.assertEqual(export_online_linked_batch(batch, destination), 1)
            partials = list(destination.parent.glob('partial-configs/*.partial.json'))
            self.assertEqual(len(partials), 1)
            partial = json.loads(partials[0].read_text())
            self.assertFalse(partial['metadata']['fuzzing_ready'])
            self.assertEqual(partial['metadata']['partial_export']['pending_parameters'],
                [{'name': 'b', 'source': 'POST', 'location': 'form'}])
            before = partials[0].read_bytes()
            export_online_linked_batch(batch, destination)
            self.assertEqual(partials[0].read_bytes(), before)

    def test_uncapped_resume_preserves_time_credit_and_rejects_old_policy(self):
        for old_policy in (False, True):
            with self.subTest(old_policy=old_policy), tempfile.TemporaryDirectory() as tmp:
                c, parent, evidence, convergence = self.make_probe_context(Path(tmp), [])
                c.max_seconds = c.state['max_seconds'] = 30
                c._candidate_deadline()
                c.clock.now = 20
                c._extend_progress_budget('verified_parameter', 'a')
                c.state.update(terminal_status='PARTIAL', terminal_reason='NO_NEW_PROGRESS')
                c._write_state()
                self.assertIsNone(c.state['budget']['hard_remaining_seconds'])
                saved_at = c.state['budget']['saved_at']
                if old_policy:
                    saved = json.loads(c.state_path.read_text())
                    saved.pop('budget_policy', None)
                    c.state_path.write_text(json.dumps(saved))
                restored = self.make_coordinator(Path(tmp), [], max_seconds=30)
                restored.clock.now = 1000
                with patch('online_linked.coordinator.time.time', return_value=saved_at + 5):
                    if old_policy:
                        with self.assertRaisesRegex(ValueError, 'policy.*new run'):
                            restored._load_checkpoint()
                        continue
                    restored._load_checkpoint()
                self.assertEqual(restored._candidate_deadline(), 1025)
                self.assertIsNone(restored._hard_deadline)
                self.assertEqual(restored._extend_progress_budget('verified_parameter', 'a'), 1025)

    def test_explicit_candidate_cap_survives_resume_and_offline_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            c, _, _, _ = self.make_probe_context(root, [])
            c.max_seconds = c.state['max_seconds'] = 30
            c.hard_seconds = c.state['hard_seconds'] = 100
            self.assertEqual(c._candidate_deadline(), 30)
            c.clock.now = 20
            self.assertEqual(c._extend_progress_budget('verified_parameter', 'a'), 50)
            c.state.update(terminal_status='PARTIAL', terminal_reason='NO_NEW_PROGRESS')
            c._write_state()
            saved_at = c.state['budget']['saved_at']

            restored = self.make_coordinator(root, [], max_seconds=30)
            restored.hard_seconds = restored.state['hard_seconds'] = 100
            restored.clock.now = 1000
            with patch('online_linked.coordinator.time.time', return_value=saved_at + 5):
                restored._load_checkpoint()
            self.assertEqual(restored._candidate_deadline(), 1025)
            self.assertEqual(restored._hard_deadline, 1075)
            restored.clock.now = 1020
            self.assertEqual(restored._extend_progress_budget('verified_parameter', 'b'), 1050)
            restored.clock.now = 1040
            self.assertEqual(restored._extend_progress_budget('verified_parameter', 'c'), 1070)
            restored.clock.now = 1060
            self.assertEqual(restored._extend_progress_budget('verified_parameter', 'd'), 1075)
            restored.clock.now = 1075
            self.assertEqual(restored._extend_progress_budget('verified_parameter', 'late'), 1075)


    def test_slow_error_probe_refreshes_guard_budget_before_strict_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            c, parent, evidence, convergence = self.make_probe_context(Path(tmp), [], names=('a',))
            c.max_seconds = 30
            c._candidate_deadline()
            calls = []
            def probe_once(**kwargs):
                calls.append((kwargs['probe']['name'], kwargs['deadline']))
                name = kwargs['probe']['name']
                c.clock.now = 14 if name == 'a' else 26
                c._sender_seconds = 12
                c._extend_progress_budget('verified_parameter', json.dumps([parent['callback_id'], [name, 'POST', 'form']]))
                guard = {**convergence['pending_probes'][0], 'name': 'b'}
                return dict(status='accepted', parameter={**kwargs['probe'], 'fuzzable': True},
                    evidence={'request_id': name, 'request': {'response': {'status_code': 400 if name == 'a' else 200}}},
                    result={'pending_probes': [guard] if name == 'a' else []})
            with patch.object(c, '_run_pending_probe_once', side_effect=probe_once), \
                 patch.object(c, '_handle_convergence_result', return_value=None):
                c._run_pending_probe(parent=parent, evidence=evidence, raw_report=c._reports['v0'],
                    convergence=convergence, probe=convergence['pending_probes'][0], seed=parent['seed_item'], deadline=30)
            self.assertEqual([name for name, _ in calls], ['a', 'b'])
            self.assertGreater(calls[1][1], 26)
            self.assertGreaterEqual(c._deadline, 80)

    def test_error_probe_refreshes_guard_allowance_at_explicit_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            c, parent, evidence, convergence = self.make_probe_context(Path(tmp), [], names=('a',))
            c.max_seconds = c.hard_seconds = 30
            c._candidate_deadline()
            calls = []

            def probe_once(**kwargs):
                name = kwargs['probe']['name']
                calls.append(name)
                c.clock.now = 14 if name == 'a' else 26
                c._sender_seconds = 1
                c._extend_progress_budget('verified_parameter', name)
                return {'status': 'accepted', 'parameter': kwargs['probe'],
                    'evidence': {'request_id': name, 'request': {'response': {'status_code': 400 if name == 'a' else 200}}},
                    'result': {'pending_probes': [{**kwargs['probe'], 'name': 'b'}] if name == 'a' else []}}

            with patch.object(c, '_run_pending_probe_once', side_effect=probe_once), \
                 patch.object(c, '_handle_convergence_result', return_value=None):
                c._run_pending_probe(parent=parent, evidence=evidence, raw_report=c._reports['v0'],
                    convergence=convergence, probe=convergence['pending_probes'][0], seed=parent['seed_item'], deadline=30)
            self.assertEqual(calls, ['a', 'b'])
            self.assertEqual(c._deadline, 30)

    def test_live_loop_services_probe_queue_after_publication_without_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            c, parent, evidence, convergence = self.make_probe_context(Path(tmp), log)
            c.max_seconds = 30
            # Begin from selection, so removing live drain from run() strands B.
            Path(parent['config_path']).unlink()
            (c.run_dir / 'versions/v0/v0-config.json').unlink()
            c.state['versions'] = []
            c.state['workers'] = []
            c._active_container = ''
            def initial_probe(version, **kwargs):
                c._run_pending_probe(parent=version, evidence=evidence,
                    raw_report=c._reports['v0'], convergence=convergence,
                    probe=convergence['pending_probes'][0], seed=version['seed_item'], deadline=kwargs['deadline'])
            replay = c.replay_runner
            def reactivation(rows, **kwargs):
                run_id = kwargs['legacy_run_id']
                if '-activation-' in run_id and '-probe-' not in run_id:
                    return {'legacy_run_id': run_id, 'runs': [{**rows[0],
                        'callback_reached': True, 'validation_status': 'callback_reached', 'process_status': 'replaying',
                        'matched_artifact': 'fresh-gate.json', 'zend_artifact': 'fresh-gate.json',
                        'request_payload': {'request_id': 'fresh-gate', 'legacy_run_id': run_id,
                            'target_plugin': 'fixture', 'http_method': 'POST',
                            "hook_name": rows[0]["hook_name"], "callback_id": rows[0]["callback_id"],
                            "auth_context": next(v["auth_context"] for v in c.state["versions"] if v.get("worker_run_id") == run_id),
                            'response': {'status_code': 200},
                            'request_params': {'body_params': {'action': 'fixture', 'seed': 'base'}}},
                        'zend_payload': {'request_id': 'fresh-gate', 'run_id': run_id}}]}
                return replay(rows, **kwargs)
            c.replay_runner = reactivation
            gate = c._gate_v0
            def fresh_gate(version, config, **kwargs):
                log.append('gate:' + version['version'])
                if not version.get('readiness_history'):
                    return True
                return gate(version, config, **kwargs)
            with patch.object(c, '_gate_v0', side_effect=fresh_gate), \
                 patch.object(c, 'read_new_runtime_evidence', return_value=[]), \
                 patch.object(c, '_consume_gate_evidence', side_effect=initial_probe):
                self.assertEqual(c.run(), 0, c.state['terminal_reason'])
            self.assertEqual([p['candidate']['name'] for p in c.state['probe_attempts']], ['a', 'b'])
            self.assertLess(log.index('gate:v0'), log.index('probe:b'))
            self.assertFalse(c.state['pending_probe_queue'])
            self.assertTrue(c.state['versions'][-1]['replay_result']['passed'])


    def test_pending_same_parent_needs_no_extra_gate_and_missing_parent_fails_closed(self):
        for missing in (False, True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as tmp:
                c, parent, evidence, convergence = self.make_probe_context(Path(tmp), [], names=('a',))
                c._candidate_deadline()
                c.state['pending_probe_queue'] = [dict(parent_version='missing' if missing else 'v0',
                    candidate=convergence['pending_probes'][0], evidence=evidence, convergence=convergence)]
                with patch.object(c, '_gate_v0') as gate, patch.object(c, '_run_pending_probe') as probe:
                    c._drain_pending_probes()
                gate.assert_not_called()
                self.assertEqual(probe.call_count, 0 if missing else 1)
                if missing:
                    self.assertEqual(c.state['terminal_status'], 'NOT_VERIFIED')
                    self.assertTrue(c.state['pending_probe_queue'])

    def test_drain_skips_probe_removed_after_snapshot_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            c, _, evidence, convergence = self.make_probe_context(Path(tmp), [])
            c._candidate_deadline()
            rows = [dict(parent_version='v0', candidate=probe, convergence=convergence, evidence=evidence)
                    for probe in convergence['pending_probes']]
            c.state['pending_probe_queue'] = rows[:]
            processed = []

            def handoff(**kwargs):
                name = kwargs['probe']['name']
                processed.append(name)
                if name == 'a':
                    c.state['pending_probe_queue'].remove(rows[1])

            with patch.object(c, '_run_pending_probe', side_effect=handoff):
                c._drain_pending_probes()
            self.assertEqual(processed, ['a'])

    def test_verified_progress_uses_rolling_window_beyond_old_120_second_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [], max_seconds=30)
            self.assertEqual(coordinator._candidate_deadline(), 30)
            self.assertIsNone(coordinator.hard_seconds)
            for now, expected in ((20, 50), (45, 75), (70, 100), (95, 125), (120, 150)):
                coordinator.clock.now = now
                self.assertEqual(coordinator._extend_progress_budget("verified_parameter", str(now)), expected)

    def test_pending_names_and_same_time_burst_do_not_bank_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [], max_seconds=30)
            coordinator._candidate_deadline()
            coordinator.clock.now = 20
            for index in range(100):
                self.assertEqual(coordinator._extend_progress_budget("pending_verification", str(index)), 30)
            for index in range(100):
                self.assertEqual(coordinator._extend_progress_budget("verified_parameter", str(index)), 50)
            coordinator.clock.now = 40
            self.assertEqual(coordinator._extend_progress_budget("verified_parameter", "0"), 50)
            coordinator.clock.now = 50
            self.assertEqual(coordinator._extend_progress_budget("verified_parameter", "late"), 50)

    def test_progress_reserve_respects_explicit_and_campaign_caps(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [], max_seconds=30, campaign_deadline=115)
            coordinator.hard_seconds = 120
            coordinator._candidate_deadline()
            coordinator._sender_seconds = 20
            coordinator.clock.now = 20
            self.assertEqual(coordinator._extend_progress_budget("verified_parameter", "a"), 90)
            coordinator.clock.now = 50
            self.assertEqual(coordinator._extend_progress_budget("verified_parameter", "b"), 115)
            coordinator.clock.now = 115
            self.assertEqual(coordinator._extend_progress_budget("verified_parameter", "c"), 115)

    def test_get_bootstrap_post_probe_baseline_before_new_worker(self):
        for method_only, post_action, error_replay, get_only in (
            (False, False, None, False), (True, False, None, False), (True, True, None, False),
            (False, False, 302, False), (False, False, 403, False), (False, False, 500, False),
            (True, False, None, True),
        ):
            with self.subTest(method_only=method_only, post_action=post_action, error_replay=error_replay,
                              get_only=get_only), tempfile.TemporaryDirectory() as tmp:
                coordinator, parent, _, _ = self.make_probe_context(Path(tmp), [], names=("body_key",))
                raw = copy.deepcopy(parent["seed_item"])
                raw["seed"].update({
                    "method": "GET", "resolved_method": "GET", "method_source": "bootstrap_probe",
                    "method_confidence": "bootstrap_probe", "seed_variant_id": "get", "body": {},
                    "query_params": {"action": "fixture"}, "fixed_params": ["action"],
                    "fuzzable_params": [], "input_params": [],
                })
                parent.update(resolved_method="GET", seed_variant_id="get", seed_item=raw, entrypoint_type="ajax")
                Path(parent["config_path"]).write_text(json.dumps(build_config_for_seed_item(raw)[1]), encoding="utf-8")
                original = Path(parent["config_path"]).read_bytes()
                report = {"suggested_seeds": [raw]}
                coordinator._reports["v0"] = report
                pending = {
                    "name": "" if method_only else "body_key", "source": "POST", "location": "form",
                    "method_probe": method_only, "request_method": "GET", "request_id": "req-v0",
                }
                probe_report = copy.deepcopy(report)
                if post_action:
                    probe_report["suggested_seeds"][0]["seed"]["body"]["action"] = "fixture"
                merged, probes = _materialize_ajax_runtime_probes(probe_report, [pending])
                coordinator.converge_fn = converge_iteration
                coordinator.materialize_fn = materialize_convergence_seeds
                coordinator.export_configs_fn = export_seed_configs
                methods = []
                def sender(container_name, **kwargs):
                    config = json.loads((coordinator.config_root / (kwargs["config_slug"] + ".json")).read_text())
                    method = config["methods"][0]
                    methods.append((method, kwargs["expected"]["method"]))
                    query = {row["name"]: row["value"] for row in config["query_params"]["data"]}
                    body = {row["name"]: row["value"] for row in config.get("body_params", {}).get("data", [])}
                    self.assertEqual(query["action"], "fixture")
                    if post_action:
                        self.assertEqual(body["action"], "fixture")
                    else:
                        self.assertNotIn("action", body)
                    request_id, run_id = kwargs["request_id"], kwargs["run_id"]
                    candidate_item = copy.deepcopy(raw)
                    candidate_item["seed"]["method"] = candidate_item["seed"]["resolved_method"] = method
                    candidate = candidate_from_seed_item(candidate_item, plugin_slug="fixture")
                    request = {
                        "request_id": request_id, "run_id": run_id, "legacy_run_id": run_id,
                        "target_plugin": "fixture", "http_method": method,
                        "response": {"status_code": error_replay or (400 if not method_only and "not_sent" not in body else 200)},
                        "hook_name": parent["hook_name"], "callback_id": parent["callback_id"],
                        "auth_context": "guest", "auth_variant": "unauthenticated",
                        "canonical_identity_id": canonical_identity_id(candidate),
                        "request_params": {"query_params": query, "body_params": body, "headers": (
                            {"Content-Type": "application/x-www-form-urlencoded"} if method == "POST" else {}
                        )},
                        "hook_coverage": {"executed_callbacks": {parent["callback_id"]: {"callback_id": parent["callback_id"]}}},
                    }
                    zend = {
                        "schema_version": 3, "request_id": request_id, "run_id": run_id, "request_method": method,
                        "target_loading": {"load_status": "loaded", "file_target_count": 1},
                        "callback_summaries": [{"callback": "fixture_callback", "unique_parameters": [{
                            "source": "POST", "path": ["body_key"], "helper_depth": 0,
                            "observed_count": 1, "access_forms": ["read"],
                        }]}],
                        "events": [{"source": "POST", "path": ["body_key"], "operation": "read",
                                    "callback_context": {"attributed": True, "root_callback": "fixture_callback", "depth": 0}}],
                    }
                    if get_only:
                        # The POST trace touches no POST field; only an absent GET guard.
                        zend["callback_summaries"][0]["unique_parameters"] = [{
                            "source": "GET", "path": ["page"], "helper_depth": 0,
                            "observed_count": 1, "access_forms": ["isset"],
                        }]
                        zend["events"] = [{"source": "GET", "path": ["page"], "operation": "isset",
                                           "callback_context": {"attributed": True, "root_callback": "fixture_callback", "depth": 0}}]
                    elif method_only:
                        # Guards on keys the probe never sent, one inside a helper.
                        for name, depth, operation in (("notice_action", 0, "empty"), ("save_options", 3, "isset")):
                            zend["callback_summaries"][0]["unique_parameters"].append({
                                "source": "POST", "path": [name], "helper_depth": depth,
                                "observed_count": 1, "access_forms": [operation],
                            })
                            zend["events"].append({
                                "source": "POST", "path": [name], "operation": operation,
                                "callback_context": {"attributed": True, "root_callback": "fixture_callback", "depth": depth},
                            })
                    if not method_only:
                        zend["callback_summaries"][0]["unique_parameters"].append({
                            "source": "POST", "path": ["not_sent"], "helper_depth": 0,
                            "observed_count": 1, "access_forms": ["read"],
                        })
                        zend["events"].append({
                            "source": "POST", "path": ["not_sent"], "operation": "read",
                            "callback_context": {"attributed": True, "root_callback": "fixture_callback", "depth": 0},
                        })
                    from online_linked.probe_sender import send_and_wait
                    requests = Path(tmp) / "http-requests"
                    zend_dir = Path(tmp) / "http-zend"
                    requests.mkdir(exist_ok=True); zend_dir.mkdir(exist_ok=True)
                    (requests / (request_id + ".json")).write_text(json.dumps(request))
                    (zend_dir / (request_id + ".json")).write_text(json.dumps(zend))
                    class Session:
                        def __enter__(self): return self
                        def __exit__(self, *args): return False
                        def send(self, prepared, timeout, allow_redirects):
                            self_test.assertFalse(allow_redirects)
                            return type("Response", (), {"status_code": request["response"]["status_code"]})()
                    self_test = self
                    return send_and_wait(
                        coordinator.config_root / (kwargs["config_slug"] + ".json"),
                        request_id=request_id, run_id=run_id, timeout_seconds=2,
                        expected=kwargs["expected"], session_factory=Session,
                        request_dir=requests, zend_dir=zend_dir,
                    )
                coordinator.probe_sender = sender
                child = coordinator._run_pending_probe(
                    parent=parent, evidence={"request_id": "req-v0", "request": {"request_params": {"query_params": {"action": "fixture"}}}},
                    raw_report=report, convergence={"pending_probes": probes, "merged_suggested_seeds": merged},
                    probe=probes[0], seed=raw, deadline=None,
                )
                if get_only:
                    # GET reads alone never prove that the callback takes POST.
                    self.assertIsNone(child)
                    self.assertEqual(len(coordinator.state["versions"]), 1)
                    continue
                self.assertIsNotNone(child, coordinator.state)
                self.assertEqual(child["resolved_method"], "POST")
                self.assertNotIn("pass2_verification", child["replay_result"])
                if error_replay:
                    # The status stays a diagnostic; the trace proves the new field.
                    self.assertTrue(child["replay_result"]["passed"])
                    self.assertEqual(child["replay_result"]["response_status"], error_replay)
                    self.assertEqual(child["replay_result"]["runner"]["runs"][0]["response_status"], error_replay)
                else:
                    self.assertTrue(child["replay_result"]["passed"])
                self.assertEqual(Path(parent["config_path"]).read_bytes(), original)
                final = json.loads(Path(child["config_path"]).read_text())
                self.assertEqual(final["methods"], ["POST"])
                self.assertIn("body_key", final["body_params"]["fuzz"])
                if post_action:
                    self.assertNotIn("action", final["body_params"]["fixed"])
                    self.assertIn("action", final["body_params"]["fuzz"])
                if not method_only:
                    # The first 400 exposes this key; only a later correlated
                    # probe and strict replay may promote it alongside body_key.
                    self.assertIn("not_sent", final["body_params"]["fuzz"])
                else:
                    self.assertNotIn("not_sent", {row["name"] for row in final["body_params"]["data"]})
                    # One POST method probe plus one callback baseline, never one per field.
                    self.assertEqual(len(methods), 2)
                    self.assertEqual(len(coordinator.state["probe_attempts"]), 1)
                    self.assertEqual([v["version"] for v in coordinator.state["versions"]], ["v0", "v1"])
                    self.assertTrue({"body_key", "notice_action", "save_options"} <= set(final["body_params"]["fuzz"]))
                    discovery = next(event for event in coordinator.state["events"]
                                     if event.get("kind") == "PARAMETER_DISCOVERY" and event.get("status") == "ACCEPTED")
                    self.assertEqual({p["name"] for p in discovery["parameters"]},
                                     {"body_key", "notice_action", "save_options"})
                    self.assertEqual(discovery["evidence_run_id"], "run-v0-probe-p1")
                self.assertNotIn("probe_variant", final["metadata"])
                self.assertTrue(all(actual == expected == "POST" for actual, expected in methods))

    def _guard_chain_campaign(
        self, root: Path, *, guards=("cn_param", "cn_nonce"), nonce_callback="fixture_callback",
        probe_status=200, deadline=None, send_cost=0.0, version_cap=None, v2_replay_unread=(),
        send_cost_by_run_id=None,
    ):
        """Cookie Notice shape: PHP evaluates isset(action, cn_param, cn_nonce) left to right
        and stops at the first absent field, so each request reveals one more guard."""
        log: list[str] = []
        coordinator, parent, _, _ = self.make_probe_context(root, log, names=("cn_param",))
        if version_cap is not None:
            coordinator.max_versions = coordinator.hard_versions = version_cap
        raw = copy.deepcopy(parent["seed_item"])
        raw["seed"].update({
            "method": "POST", "resolved_method": "POST", "query_params": {"action": "fixture"},
            "body": {"action": "fixture"}, "fixed_params": ["action"], "fuzzable_params": [],
            "input_params": [], "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        })
        parent.update(seed_item=raw, entrypoint_type="ajax", resolved_method="POST")
        Path(parent["config_path"]).write_text(json.dumps(build_config_for_seed_item(raw)[1]), encoding="utf-8")
        coordinator._reports["v0"] = {"suggested_seeds": [raw]}
        coordinator.converge_fn = converge_iteration
        coordinator.materialize_fn = materialize_convergence_seeds
        coordinator.export_configs_fn = export_seed_configs
        from hook_energy.seed_generation.zend_runtime.bridge_cli import _candidate_iteration_key
        coordinator._target_key = _candidate_iteration_key(raw, plugin_slug="fixture", legacy_run_id="run-v0")
        identity = canonical_identity_id(candidate_from_seed_item(raw, plugin_slug="fixture"))
        sends: list[dict] = []

        def php(request_id, run_id, method, query, body, auth_context, status):
            touched = []
            # A tuple is one PHP expression whose guards are all evaluated together.
            for group in ("action", *guards):
                names = group if isinstance(group, tuple) else (group,)
                touched.extend(names)
                if any(name not in body for name in names):
                    break
            request = {
                "request_id": request_id, "run_id": run_id, "legacy_run_id": run_id,
                "target_plugin": "fixture", "http_method": method, "response": {"status_code": status},
                "hook_name": parent["hook_name"], "callback_id": parent["callback_id"],
                "auth_context": auth_context, "canonical_identity_id": identity,
                "request_params": {"query_params": query, "body_params": body,
                                   "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
                "hook_coverage": {"executed_callbacks": {parent["callback_id"]: {"callback_id": parent["callback_id"]}}},
            }
            if run_id.endswith("-v2-replay"):
                touched = [name for name in touched if name not in v2_replay_unread]
            owner = {name: (nonce_callback if name == "cn_nonce" else "fixture_callback") for name in touched}
            zend = {
                "schema_version": 3, "request_id": request_id, "run_id": run_id, "request_method": method,
                "target_loading": {"load_status": "loaded", "file_target_count": 1},
                "callback_summaries": [{"callback": callback, "unique_parameters": [{
                    "source": "POST", "path": [name], "helper_depth": 0,
                    "observed_count": 1, "access_forms": ["isset"],
                } for name in touched if owner[name] == callback]} for callback in sorted(set(owner.values()))],
                "events": [{"source": "POST", "path": [name], "operation": "isset",
                            "callback_context": {"attributed": True, "root_callback": owner[name], "depth": 0}}
                           for name in touched],
            }
            return request, zend

        def sender(container_name, **kwargs):
            from urllib.parse import parse_qsl, urlsplit
            from online_linked.probe_sender import send_and_wait
            request_id, run_id = kwargs["request_id"], kwargs["run_id"]
            requests_dir, zend_dir = root / "http-requests", root / "http-zend"
            requests_dir.mkdir(exist_ok=True)
            zend_dir.mkdir(exist_ok=True)
            test = self

            class Session:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def send(self, prepared, timeout, allow_redirects):
                    test.assertFalse(allow_redirects)
                    raw_body = prepared.body or ""
                    raw_body = raw_body.decode() if isinstance(raw_body, bytes) else raw_body
                    query = dict(parse_qsl(urlsplit(prepared.url).query))
                    body = dict(parse_qsl(raw_body))
                    status = probe_status if "cn_nonce" in body else 200
                    sends.append({"run_id": run_id, "query": query, "body": body, "status": status})
                    coordinator.clock.now += (send_cost_by_run_id or {}).get(run_id, send_cost)
                    log.append(f"send:{run_id}")
                    request, zend = php(request_id, run_id, prepared.method, query, body,
                                        str(kwargs["expected"].get("auth_context") or ""), status)
                    (requests_dir / f"{request_id}.json").write_text(json.dumps(request), encoding="utf-8")
                    (zend_dir / f"{request_id}.json").write_text(json.dumps(zend), encoding="utf-8")
                    return type("Response", (), {"status_code": status})()

            return send_and_wait(
                coordinator.config_root / (kwargs["config_slug"] + ".json"),
                request_id=request_id, run_id=run_id, timeout_seconds=2, expected=kwargs["expected"],
                session_factory=Session, request_dir=requests_dir, zend_dir=zend_dir,
            )

        coordinator.probe_sender = sender
        # v0 worker request: correct action only, so the trace stops at isset(cn_param).
        request, zend = php("req-v0", "run-v0", "POST", {"action": "fixture"}, {"action": "fixture"},
                            parent["auth_context"], 200)
        evidence = {"request_name": "req-v0.json", "request": request, "zend_name": "req-v0.json",
                    "zend": zend, "request_id": "req-v0", "worker_run_id": "run-v0"}
        coordinator.advance_online_version(evidence, deadline=deadline)
        return coordinator, log, sends

    def test_ajax_child_replay_probes_missing_guard_before_worker_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, log, sends = self._guard_chain_campaign(Path(tmp))
            versions = {version["version"]: version for version in coordinator.state["versions"]}
            # v1 replay sends action + cn_param and reveals isset(cn_nonce) for an unsent field.
            v1_replay = [send for send in sends if send["run_id"].endswith("-v1-replay")]
            self.assertEqual(len(v1_replay), 1)
            self.assertEqual(set(v1_replay[0]["body"]), {"action", "cn_param"})
            # Exactly one probe adds the field, with the right POST action, before any worker start.
            probes = [send for send in sends if "-probe-" in send["run_id"]]
            self.assertEqual(len(probes), 1, sends)
            self.assertEqual(set(probes[0]["body"]), {"action", "cn_param", "cn_nonce"})
            self.assertEqual(probes[0]["body"]["action"], "fixture")
            self.assertEqual(probes[0]["query"]["action"], "fixture")
            self.assertLess(log.index(f"send:{probes[0]['run_id']}"), log.index("worker_start"))
            self.assertEqual(log.count("worker_start"), 1)
            # The nonce child keeps its link to v1 and passes its own callback baseline.
            self.assertEqual(versions["v2"]["parent_version"], "v1")
            self.assertTrue(versions["v2"]["replay_result"]["passed"])
            v2_replay = [send for send in sends if send["run_id"].endswith("-v2-replay")]
            self.assertEqual(set(v2_replay[0]["body"]), {"action", "cn_param", "cn_nonce"})
            self.assertEqual(coordinator._active_version, "v2")
            self.assertEqual(versions["v2"]["worker_status"], "started")
            self.assertNotEqual(versions["v1"]["worker_status"], "started")
            final = json.loads(Path(versions["v2"]["config_path"]).read_text(encoding="utf-8"))
            self.assertIn("action", final["query_params"]["fixed"])
            self.assertIn("cn_nonce", final["body_params"]["fixed"])
            self.assertTrue({"action", "cn_param"} <= set(final["body_params"]["fuzz"]))
            self.assertNotIn("cn_nonce", final["body_params"]["fuzz"])
            # cn_nonce is proven but fixed in v2: only cn_param gets priority attempts.
            descriptor = json.loads(worker_env(coordinator.state["workers"][-1])["HOOKPHUZZ_PRIORITY_SEED"])
            self.assertEqual(descriptor["targets"], [["body_params", "cn_param"]])

    def test_guard_revealed_by_probe_trace_gets_its_own_probe(self):
        # p(cn_nonce) passes isset(cn_nonce) and only then reaches isset(next_guard): seeing that
        # guard proves the access, so next_guard enters a config only after a probe that sent it.
        for deadline in (None, 100.0):
            with self.subTest(deadline=deadline), tempfile.TemporaryDirectory() as tmp:
                coordinator, log, sends = self._guard_chain_campaign(
                    Path(tmp), guards=("cn_param", "cn_nonce", "next_guard"), deadline=deadline,
                )
                probes = [send for send in sends if "-probe-" in send["run_id"]]
                self.assertEqual([sorted(send["body"]) for send in probes], [
                    ["action", "cn_nonce", "cn_param"],
                    ["action", "cn_nonce", "cn_param", "next_guard"],
                ])
                events = coordinator.state["events"]
                next_guard_probe = next(
                    index for index, event in enumerate(events)
                    if event.get("kind") == "PARAMETER_PROBE" and event.get("status") == "ACCEPTED"
                    and (event.get("candidate") or {}).get("name") == "next_guard"
                )
                first_admission = next(
                    index for index, event in enumerate(events)
                    if event.get("kind") == "PARAMETER_DISCOVERY" and event.get("status") == "ACCEPTED"
                    and any(p.get("name") == "next_guard" for p in event.get("parameters") or [])
                )
                # No config carries next_guard before the probe that sent it was accepted.
                self.assertLess(next_guard_probe, first_admission)
                active = coordinator._version(coordinator._active_version)
                self.assertTrue(active["replay_result"]["passed"])
                self.assertEqual({p["name"] for p in active["known_parameters"]}, {"cn_param", "cn_nonce", "next_guard"})
                self.assertEqual(log.count("worker_start"), 1)
                self.assertLess(log.index(f"send:{probes[1]['run_id']}"), log.index("worker_start"))

    def assert_v1_handoff_without_nonce(self, coordinator, log, sends):
        versions = {version["version"]: version for version in coordinator.state["versions"]}
        self.assertEqual(coordinator._active_version, "v1")
        self.assertEqual(versions["v1"]["worker_status"], "started")
        self.assertEqual(log.count("worker_start"), 1)
        config = json.loads(Path(versions["v1"]["config_path"]).read_text(encoding="utf-8"))
        self.assertNotIn("cn_nonce", {row["name"] for row in config["body_params"]["data"]})
        return versions

    def test_replay_trace_without_new_guard_keeps_plain_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, log, sends = self._guard_chain_campaign(Path(tmp), guards=("cn_param",))
            self.assertEqual([send for send in sends if "-probe-" in send["run_id"]], [])
            self.assert_v1_handoff_without_nonce(coordinator, log, sends)
            self.assertFalse([e for e in coordinator.state["events"] if e.get("kind") == "REPLAY_GUARD_DISCOVERY"])

    def test_replay_guard_on_other_callback_does_not_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, log, sends = self._guard_chain_campaign(Path(tmp), nonce_callback="other_callback")
            self.assertEqual([send for send in sends if "-probe-" in send["run_id"]], [])
            self.assert_v1_handoff_without_nonce(coordinator, log, sends)

    def test_replay_guard_already_probed_is_not_sent_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, log, sends = self._guard_chain_campaign(Path(tmp))
            versions = {version["version"]: version for version in coordinator.state["versions"]}
            replay_dir = coordinator.run_dir / "versions" / "v1" / "replay"
            (request_path,) = (replay_dir / "request").glob("*.json")
            evidence = {
                "version": "v1", "worker_run_id": "run-v1-replay", "request_name": request_path.name,
                "request_id": request_path.stem, "zend_name": request_path.name,
                "request": json.loads(request_path.read_text(encoding="utf-8")),
                "zend": json.loads((replay_dir / "zend" / request_path.name).read_text(encoding="utf-8")),
                "evidence_origin": "child_replay",
            }
            before = len(sends)
            # Re-entering with the same replay trace (e.g. after resume) must not resend the probe.
            target = coordinator._discover_replay_guards(versions["v1"], evidence, deadline=None)
            self.assertIs(target, versions["v1"])
            self.assertEqual(len(sends), before)
            self.assertTrue(any(
                event.get("kind") == "PARAMETER_PROBE" and event.get("reason") == "PROBE_ALREADY_ATTEMPTED"
                for event in coordinator.state["events"]
            ))

    def test_replay_guard_probe_error_status_is_diagnostic_when_trace_proves_nonce(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, log, sends = self._guard_chain_campaign(Path(tmp), probe_status=403)
            self.assertEqual(len([send for send in sends if "-probe-" in send["run_id"]]), 1)
            versions = {version["version"]: version for version in coordinator.state["versions"]}
            replay = versions["v2"]["replay_result"]
            self.assertTrue(replay["passed"])
            self.assertEqual(replay["response_status"], 403)
            # The last descendant proves the whole batch over the running v0, in its own replay.
            self.assertEqual({row["name"] for row in replay["verified_parameters"]}, {"cn_param", "cn_nonce"})
            self.assertEqual(coordinator._active_version, "v2")
            self.assertEqual(log.count("worker_start"), 1)
            self.assertTrue(coordinator.state["probe_attempts"][-1]["config_path"])
            self.assertIsNone(coordinator.state["terminal_status"])
            # The failed guard child is a rejected probe, not a batch v1's next update must replay.
            self.assertEqual(coordinator._failed_batch_parameters(
                versions["v1"], versions["v1"]["known_parameters"]), [])

    def test_version_cap_during_replay_guard_discovery_still_fuzzes_v1(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, log, sends = self._guard_chain_campaign(Path(tmp), version_cap=2)
            self.assertEqual(len([send for send in sends if "-probe-" in send["run_id"]]), 1)
            self.assert_v1_handoff_without_nonce(coordinator, log, sends)
            # The cap keeps the verified nonce as a pending candidate instead of ending v1's run.
            self.assertIsNone(coordinator.state["terminal_status"])
            self.assertIn("cn_nonce", json.dumps(coordinator.state["pending_runtime_candidates"]))

    def test_guards_deferred_on_superseded_version_do_not_restart_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, log, sends = self._guard_chain_campaign(
                Path(tmp), guards=("cn_param", ("cn_nonce", "cn_extra")), deadline=100.0,
            )
            versions = {version["version"]: version for version in coordinator.state["versions"]}
            active = coordinator._active_version
            final = json.loads(Path(versions[active]["config_path"]).read_text(encoding="utf-8"))
            self.assertTrue({"cn_nonce", "cn_extra"} <= {row["name"] for row in final["body_params"]["data"]})
            coordinator._drain_pending_probes()
            # The started descendant covers every deferred guard: it keeps running, v1 never starts.
            self.assertEqual(coordinator._active_version, active)
            self.assertEqual(log.count("worker_stop"), 1)
            self.assertEqual(log.count("worker_start"), 1)
            self.assertNotEqual(versions["v1"]["worker_status"], "started")

    def test_replay_guard_probe_deferred_when_budget_is_short(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, log, sends = self._guard_chain_campaign(Path(tmp), deadline=10.0, send_cost=4.0)
            self.assertEqual([send for send in sends if "-probe-" in send["run_id"]], [])
            self.assert_v1_handoff_without_nonce(coordinator, log, sends)
            deferred = [event for event in coordinator.state["events"]
                        if event.get("kind") == "PARAMETER_PROBE" and event.get("status") == "DEFERRED"]
            self.assertEqual([event["candidate"]["name"] for event in deferred], ["cn_nonce"])
            self.assertEqual([row["candidate"]["name"] for row in coordinator.state["pending_probe_queue"]], ["cn_nonce"])

    def test_non_ajax_child_replay_keeps_plain_handoff(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch("online_linked.coordinator._is_ajax", return_value=False), \
                patch("online_linked.coordination.probe_runner._is_ajax", return_value=False), \
                patch("online_linked.coordination.worker_runner._is_ajax", return_value=False):
            coordinator, log, sends = self._guard_chain_campaign(Path(tmp))
            self.assertEqual([send for send in sends if "-probe-" in send["run_id"]], [])
            self.assert_v1_handoff_without_nonce(coordinator, log, sends)

    def test_hard_budget_inputs_reject_zero_negative_bool_and_fraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            for value in (0, -1, True, 2.5):
                for name in ("hard_seconds", "hard_versions"):
                    with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                        OnlineLinkedCoordinator(
                            suggested_seeds=coordinator.suggested_seeds,
                            config_root=coordinator.config_root, output_root=coordinator.output_root,
                            plugin_slug="fixture", legacy_run_id="invalid", max_seconds=2,
                            max_versions=2, registry=coordinator.registry, **{name: value})

    def test_callback_burst_buys_separate_turns_and_duplicates_buy_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [], campaign_deadline=2.0)
            coordinator._candidate_deadline()
            coordinator.clock.now = 1.9
            first = coordinator._extend_progress_budget("runtime_callback", "a")
            second = coordinator._extend_progress_budget("runtime_callback", "b")
            self.assertEqual(second, first)
            campaign = coordinator.campaign_deadline
            self.assertEqual(coordinator._extend_progress_budget("runtime_callback", "b"), second)
            self.assertEqual(coordinator.campaign_deadline, campaign)
            self.assertEqual(second, 2.0)

    def test_child_only_proposal_cannot_buy_parent_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(Path(tmp), [])
            coordinator._candidate_deadline()
            evidence["request"]["callback_id"] = "cb-child"
            before = coordinator._deadline
            with patch.object(coordinator, "_run_pending_probe", return_value=None):
                coordinator._handle_convergence_result(parent=parent, evidence=evidence,
                    raw_report=coordinator._reports["v0"], result=convergence,
                    seed=parent["seed_item"], deadline=before)
            self.assertEqual(coordinator._deadline, before)
            self.assertFalse(coordinator._progress_keys)

    def test_worker_start_cannot_spend_more_than_remaining_candidate_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, _, _ = self.make_probe_context(Path(tmp), [])
            coordinator._active_container = ""
            calls = []
            def run(command, **kwargs):
                calls.append(kwargs["timeout"])
                return subprocess.CompletedProcess(command, 0, "", "")
            coordinator.run_command = run
            coordinator.clock.now = 1.9
            self.assertTrue(coordinator._start_worker(parent, deadline=2.0))
            self.assertAlmostEqual(calls[0], 0.1)

    def test_callback_burst_reserves_campaign_turns_until_real_hard_cap(self):
        for hard_seconds, expected_runs in ((9, 5), (4, 4)):
            with self.subTest(hard_seconds=hard_seconds), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                suggested = root / "suggested.json"
                suggested.write_text(json.dumps({"suggested_seeds": [seed_item()]}))
                registry = root / "registry.json"
                registry.write_text("{}")
                children = [{**seed_item(), "callback_id": f"cb-{i}", "hook_name": f"wp_ajax_fixture_{i}",
                             "lineage": {"parent_callback_id": "cb-fixture", "parent_request_id": "request"}}
                            for i in range(4)]
                now = [0.0]
                calls = []
                class Candidate:
                    def __init__(self, **kwargs):
                        calls.append(kwargs)
                        self.kwargs = kwargs
                        self.state_path = root / "state.json"
                        self.state = {"terminal_status": "BOUNDED_ONLINE_COMPLETE", "versions": [],
                                      "candidate_queue": children + children if len(calls) == 1 else []}
                    def run(self):
                        if len(calls) == 1:
                            now[0] = 0.9
                            for child in children:
                                self.kwargs["progress_callback"]("runtime_callback", _candidate_context_key(child, "fixture"))
                        else:
                            now[0] = min(self.kwargs["campaign_deadline"], now[0] + 1.5)
                        return 0
                args = SimpleNamespace(suggested_seeds=str(suggested), bootstrap_config="",
                    config_root=str(root / "configs"), output_root=str(root / "output"), plugin_slug="fixture",
                    legacy_run_id="run", max_seconds=2, max_versions=2, max_candidates=1,
                    hard_max_candidates=5, campaign_seconds=1, hard_campaign_seconds=hard_seconds,
                    callback_registry=str(registry), service="fixture")
                with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", Candidate), \
                        patch("online_linked.coordination.campaign.time.monotonic", side_effect=lambda: now[0]), \
                        patch("online_linked.coordination.campaign.export_online_linked_batch", return_value=0):
                    run_online_linked(args)
                state = json.loads((root / "output/online-linked/run/batch-state.json").read_text())
                self.assertEqual(len(calls), expected_runs)
                self.assertEqual(len(state["budget"]["progress_keys"]), 4)
                self.assertLessEqual(now[0], hard_seconds)
                if hard_seconds == 4:
                    self.assertEqual(state["campaign_status"], "PARTIAL")
                    self.assertEqual(state["terminal_reason"], "HARD_CAMPAIGN_TIME_CAP")
                    self.assertEqual(len(state["pending_candidates"]), 1)
                else:
                    self.assertEqual(state["campaign_status"], "complete")
                    self.assertFalse(state["pending_candidates"])

    def test_partial_candidate_keeps_campaign_partial_with_specific_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suggested = root / "suggested.json"
            suggested.write_text(json.dumps({"suggested_seeds": [seed_item()]}))
            registry = root / "registry.json"
            registry.write_text("{}")
            class Candidate:
                def __init__(self, **kwargs):
                    self.state_path = root / "candidate-state.json"
                    self.state = {"terminal_status": "PARTIAL", "terminal_reason": "HARD_VERSION_CAP",
                                  "versions": [], "candidate_queue": []}
                def run(self):
                    return 0
            args = SimpleNamespace(suggested_seeds=str(suggested), bootstrap_config="",
                config_root=str(root / "configs"), output_root=str(root / "output"), plugin_slug="fixture",
                legacy_run_id="run", max_seconds=2, max_versions=2, callback_registry=str(registry), service="fixture")
            with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", Candidate), \
                    patch("online_linked.coordination.campaign.export_online_linked_batch", return_value=0):
                run_online_linked(args)
            state = json.loads((root / "output/online-linked/run/batch-state.json").read_text())
            self.assertEqual(state["campaign_status"], "PARTIAL")
            self.assertEqual(state["terminal_reason"], "HARD_VERSION_CAP")
            self.assertEqual(state["pending_candidates"][0]["state_path"], str(root / "candidate-state.json"))

    def test_all_campaign_budget_inputs_validate_before_reading_files(self):
        for name in ("hard_candidate_seconds", "hard_max_versions", "hard_max_candidates", "hard_campaign_seconds"):
            for value in (0, -1, True, 2.5):
                args = SimpleNamespace(suggested_seeds="missing.json", max_seconds=2, max_versions=2,
                                       max_candidates=32, campaign_seconds=1, **{name: value})
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    run_online_linked(args)

    def test_progress_callback_can_renew_campaign_but_explicit_candidate_cap_still_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [], campaign_deadline=2.0)
            coordinator.hard_seconds = 8
            coordinator.progress_callback = lambda kind, key: 20.0
            coordinator._candidate_deadline()
            coordinator.clock.now = 1.9
            deadline = coordinator._extend_progress_budget("verified_parameter", "body:new")
            self.assertEqual(deadline, 3.9)
            self.assertEqual(coordinator.campaign_deadline, 20)
            coordinator.clock.now = 2.1
            self.assertEqual(coordinator._extend_progress_budget("verified_parameter", "body:new"), deadline)
            for index in range(20):
                coordinator.clock.now = min(coordinator._deadline - 0.1, 7.9)
                coordinator._extend_progress_budget("verified_parameter", str(index))
            self.assertEqual(coordinator._deadline, 8)

    def test_runtime_callback_33_runs_beyond_initial_budget_or_is_preserved_at_hard_cap(self):
        for hard_cap in (32, 33):
            with self.subTest(hard_cap=hard_cap), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                items = [{**seed_item(), "callback_id": f"cb-{i}",
                          "hook_name": f"wp_ajax_fixture_{i}"} for i in range(32)]
                suggested = root / "suggested.json"
                suggested.write_text(json.dumps({"suggested_seeds": items}))
                registry = root / "registry.json"
                registry.write_text("{}")
                child = {**seed_item(), "callback_id": "cb-33", "hook_name": "wp_ajax_fixture_33",
                         "lineage": {"parent_callback_id": "cb-31", "parent_request_id": "req-31"}}
                calls = []
                now = [0.0]
                class FakeCoordinator:
                    def __init__(self, **kwargs):
                        calls.append(kwargs)
                        self.kwargs = kwargs
                        self.state_path = root / "state.json"
                        self.state = {"terminal_status": "BOUNDED_ONLINE_COMPLETE", "versions": [],
                                      "candidate_queue": [child, child] if len(calls) == 32 else []}
                    def run(self):
                        if len(calls) == 32:
                            now[0] = 0.9
                            callback = self.kwargs["progress_callback"]
                            deadline = callback("runtime_callback", _candidate_context_key(child, "fixture"))
                            now[0] = 1.1
                            self.state["campaign_deadline"] = deadline
                        return 0
                args = SimpleNamespace(suggested_seeds=str(suggested), bootstrap_config="",
                    config_root=str(root / "configs"), output_root=str(root / "output"),
                    plugin_slug="fixture", legacy_run_id="run", max_seconds=2, max_versions=2,
                    max_candidates=32, hard_max_candidates=hard_cap, campaign_seconds=1,
                    hard_campaign_seconds=4, callback_registry=str(registry), service="fixture")
                with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator), \
                        patch("online_linked.coordination.campaign.time.monotonic", side_effect=lambda: now[0]), \
                        patch("online_linked.coordination.campaign.export_online_linked_batch", return_value=0):
                    self.assertEqual(run_online_linked(args), 0)
                state = json.loads((root / "output/online-linked/run/batch-state.json").read_text())
                self.assertEqual(len(calls), hard_cap)
                self.assertGreater(state["campaign_deadline"], 1.0)
                self.assertEqual(len(state["budget"]["progress_keys"]), 1)
                if hard_cap == 32:
                    self.assertEqual(state["campaign_status"], "PARTIAL")
                    self.assertEqual(len(state["pending_candidates"]), 1)
                    self.assertEqual(state["pending_candidates"][0]["item"]["lineage"], child["lineage"])
                else:
                    self.assertFalse(state["pending_candidates"])


    def test_initial_candidate_queue_uses_available_slots_without_time_credit(self):
        cases = (
            # name, unique inputs, duplicate input, discoveries, expire after,
            # processed, effective slots, pending, stop reason
            ("all_90", 90, False, False, None, 90, 90, 0, None),
            ("dedupe", 90, True, False, None, 90, 90, 0, None),
            ("new_and_duplicate_callbacks", 90, False, True, None, 92, 92, 0, None),
            ("hard_cap", 130, False, False, None, 128, 128, 2, "HARD_CANDIDATE_COUNT_CAP"),
            ("time_cap", 90, False, False, 40, 40, 90, 50, "CAMPAIGN_BUDGET_EXPIRED"),
            ("below_initial", 3, False, False, None, 3, 32, 0, None),
        )
        for name, count, duplicates, discoveries, expire_after, processed, slots, pending, reason in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                items = [{**seed_item(), "callback_id": f"cb-{i}",
                          "hook_name": f"wp_ajax_fixture_{i}"} for i in range(count)]
                children = [{**seed_item(), "callback_id": f"new-{i}",
                             "hook_name": f"wp_ajax_new_{i}",
                             "lineage": {"parent_callback_id": "cb-89", "parent_request_id": "req-89"}}
                            for i in range(2)] if discoveries else []
                suggested = root / "suggested.json"
                # Non-object rows and duplicates must not reserve candidate slots.
                suggested.write_text(json.dumps({"suggested_seeds": [None, "invalid"] + items
                                                 + (items if duplicates else [])}))
                registry = root / "registry.json"
                registry.write_text("{}")
                now = [0.0]
                seen = []
                growth = []

                class FakeCoordinator:
                    def __init__(self, **kwargs):
                        self.kwargs = kwargs
                        item = json.loads(Path(kwargs["suggested_seeds"]).read_text())["suggested_seeds"][0]
                        seen.append(item["callback_id"])
                        self.state_path = root / "candidate-state.json"
                        self.state = {"terminal_status": "BOUNDED_ONLINE_COMPLETE", "versions": [],
                                      "candidate_queue": children + children + [items[0]]
                                      if discoveries and len(seen) == count else []}

                    def run(self):
                        if discoveries and len(seen) == count:
                            callback = self.kwargs["progress_callback"]
                            callback("runtime_callback", _candidate_context_key(items[0], "fixture"))
                            for child in children + children:
                                callback("runtime_callback", _candidate_context_key(child, "fixture"))
                                state = json.loads((root / "output/online-linked/run/batch-state.json").read_text())
                                growth.append(state["effective_max_candidates"])
                        if len(seen) == expire_after:
                            now[0] = 10.0
                        return 0

                args = SimpleNamespace(suggested_seeds=str(suggested), bootstrap_config="",
                    config_root=str(root / "configs"), output_root=str(root / "output"),
                    plugin_slug="fixture", legacy_run_id="run", max_seconds=2, max_versions=2,
                    max_candidates=32, hard_max_candidates=128, campaign_seconds=10,
                    hard_campaign_seconds=20, callback_registry=str(registry), service="fixture")
                with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator), \
                        patch("online_linked.coordination.campaign.time.monotonic", side_effect=lambda: now[0]), \
                        patch("online_linked.coordination.campaign.export_online_linked_batch", return_value=0), \
                        patch("sys.stdout", new=io.StringIO()):
                    self.assertEqual(run_online_linked(args), 0)
                state = json.loads((root / "output/online-linked/run/batch-state.json").read_text())
                expected_ids = [item["callback_id"] for item in items + children]
                self.assertEqual(seen, expected_ids[:processed])
                self.assertEqual([row["callback_id"] for row in state["candidates"]], seen)
                self.assertEqual([row["item"]["callback_id"] for row in state["pending_candidates"]],
                                 expected_ids[processed:])
                self.assertEqual(len(state["pending_candidates"]), pending)
                self.assertEqual(state["effective_max_candidates"], slots)
                self.assertEqual(state["max_candidates"], 32)
                self.assertEqual(args.max_candidates, 32)
                self.assertEqual(state["resume_context"]["budgets"][4], 32)
                self.assertEqual(state["campaign_status"], "PARTIAL" if reason else "complete")
                self.assertEqual(state.get("terminal_reason"), reason)
                self.assertEqual(len(state["budget"]["progress_keys"]), 2 if discoveries else 0)
                self.assertEqual(state["campaign_deadline"], 14.0 if discoveries else 10.0)
                if discoveries:
                    self.assertEqual(growth, [91, 92, 92, 92])

    def test_request_artifact_names_stay_short_and_preserve_correlation(self):
        from online_linked.coordinator import _request_id

        run = "custom-fonts-20260928T140526Z-candidate-001-wp_ajax_astra-notice-dismiss-v0"
        ids = set()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            # Match the failing Windows directory depth without requiring long-path support.
            root = root / ("x" * max(1, 180 - len(str(root)) - 1))
            coordinator = object.__new__(OnlineLinkedCoordinator)
            for suffix in ("-probe-p1", "-probe-p2", "-replay", "-replay-input-a1-t1"):
                run_id = run + suffix
                request_id = _request_id(run_id)
                self.assertEqual(request_id, _request_id(run_id))
                self.assertNotIn(request_id, ids)
                ids.add(request_id)
                name = request_id + ".json"
                self.assertLess(len(str(root / "request" / name)), 260)
                request = {"request_id": request_id, "legacy_run_id": run_id}
                zend = {"request_id": request_id, "run_id": run_id}
                row = coordinator._sender_runner_row({}, {
                    "status": "callback_reached", "request_name": name, "request": request,
                    "zend_name": name, "zend": zend,
                }, run_id)
                coordinator._save_replay_artifacts(row, root / "request", root / "zend")
                self.assertEqual(json.loads((root / "request" / name).read_text()), request)
                self.assertEqual(json.loads((root / "zend" / name).read_text()), zend)

    def test_poll_deadline_is_bounded_without_losing_verified_version(self):
        for outcome in ("timeout", "late_output", "before_poll", "early_timeout", "docker_error"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as tmp:
                coordinator, parent, _, _ = self.make_probe_context(Path(tmp), [])
                parent["status"] = "fuzzing"
                parent["known_parameters"] = [{"name": "verified"}]
                original = copy.deepcopy(parent["known_parameters"])
                def reader(**kwargs):
                    coordinator.clock.now = 1.0 if outcome == "early_timeout" else 10.0
                    if outcome in ("timeout", "early_timeout"):
                        from online_linked.evidence import RuntimeBatchTimeout
                        raise RuntimeBatchTimeout("RUNTIME_BATCH_TIMEOUT")
                    if outcome == "docker_error":
                        raise RuntimeError("docker failed")
                    return {"pairs": [{
                        "request_name": "late.json", "zend_name": "late.json",
                        "request": {"request_id": "late", "run_id": parent["worker_run_id"],
                                    "target_plugin": "fixture"},
                        "zend": {"request_id": "late", "run_id": parent["worker_run_id"]},
                    }], "stats": {}}
                coordinator.runtime_batch_reader = reader
                if outcome == "before_poll":
                    coordinator.clock.now = 10.0
                self.assertEqual(coordinator.read_new_runtime_evidence(deadline=10.0), [])
                failed = outcome in ("early_timeout", "docker_error")
                self.assertEqual(coordinator.state["terminal_status"],
                                 "NOT_VERIFIED" if failed else "BOUNDED_ONLINE_COMPLETE")
                self.assertEqual(coordinator._failure, failed)
                self.assertEqual(parent["known_parameters"], original)
                self.assertFalse(coordinator._seen_pairs)
                if not failed:
                    self.assertEqual(parent["status"], "fuzzing")
                    self.assertEqual(coordinator.state["terminal_reason"], "BUDGET_EXPIRED")
                    self.assertFalse(coordinator.state["evidence_scan"]["last_attempt_complete"])

    def test_runtime_poll_uses_injected_batch_reader_and_preserves_exact_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, _, _ = self.make_probe_context(Path(tmp), [])
            calls = []
            pair = {
                "request_name": "req-v0.json",
                "request": {
                    "request_id": "req-v0",
                    "legacy_run_id": "run-v0",
                    "target_plugin": "fixture",
                    "http_method": "POST",
                    "request_params": {"body_params": {"action": "fixture", "seed": "base"}},
                },
                "zend_name": "req-v0.json",
                "zend": {"request_id": "req-v0", "run_id": "run-v0"},
            }

            def batch_reader(**kwargs):
                calls.append(kwargs)
                return {"pairs": [pair], "stats": {"file_count": 601, "paired_count": 1}}

            coordinator.runtime_batch_reader = batch_reader
            coordinator.list_artifacts = lambda: self.fail("legacy request listing used")
            coordinator.load_artifact = lambda _name: self.fail("legacy request loader used")
            coordinator.list_zend_artifacts = lambda: self.fail("legacy Zend listing used")
            coordinator.load_zend_artifact = lambda _name: self.fail("legacy Zend loader used")

            evidence = coordinator.read_new_runtime_evidence(deadline=10.0)

            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["run_id"], parent["worker_run_id"])
            self.assertEqual(calls[0]["plugin_slug"], "fixture")
            self.assertLessEqual(calls[0]["timeout"], 10.0)
            self.assertEqual([item["request_id"] for item in evidence], ["req-v0"])
            self.assertEqual(evidence[0]["request"]["request_params"]["body_params"]["seed"], "base")
            self.assertEqual(evidence[0]["evidence_origin"], "worker_poll")
            self.assertEqual(coordinator.state["evidence_scan"]["paired_count"], 1)

    def test_evidence_runner_sees_reader_replaced_after_construction(self):
        """The evidence read must use the reader on the coordinator at call time; a missing host
        member would be swallowed by the read's except branch as RUNTIME_BATCH_READ_FAILED."""
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, _, _, _ = self.make_probe_context(Path(tmp), [])
            coordinator.runtime_batch_reader = lambda **kwargs: {"pairs": [], "stats": {}}

            self.assertEqual(coordinator.read_new_runtime_evidence(deadline=10.0), [])

            self.assertEqual(coordinator.state["evidence_scan"]["paired_count"], 0)
            self.assertIsNone(coordinator.state["terminal_status"])
            self.assertNotIn("RUNTIME_BATCH_READ_FAILED", [
                event.get("reason") for event in coordinator.state["events"]
            ])

    def test_runtime_poll_discovers_through_coordinator_method(self):
        """Runtime discovery on the poll path must go through the coordinator method, so a patch
        on the instance still intercepts it; a runner calling its own method would bypass it."""
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, _, _, _ = self.make_probe_context(Path(tmp), [])
            coordinator.runtime_batch_reader = lambda **kwargs: {"pairs": [{
                "request_name": "req-v0.json",
                "request": {
                    "request_id": "req-v0", "legacy_run_id": "run-v0", "target_plugin": "fixture",
                    "http_method": "POST",
                    "request_params": {"body_params": {"action": "fixture", "seed": "base"}},
                },
                "zend_name": "req-v0.json",
                "zend": {"request_id": "req-v0", "run_id": "run-v0"},
            }], "stats": {}}

            with patch.object(coordinator, "_discover_runtime_candidates", return_value=[]) as discover:
                evidence = coordinator.read_new_runtime_evidence(deadline=10.0)

            self.assertEqual([item["request_id"] for item in evidence], ["req-v0"])
            discover.assert_called_once()
            self.assertEqual(discover.call_args.args[0]["request_id"], "req-v0")
            self.assertEqual(discover.call_args.kwargs, {"deadline": 10.0})

    def test_runtime_poll_retries_missing_zend_and_dedupes_only_after_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, _, _, _ = self.make_probe_context(Path(tmp), [])
            pair = {
                "request_name": "req-v0.json",
                "request": {
                    "request_id": "req-v0",
                    "legacy_run_id": "run-v0",
                    "target_plugin": "fixture",
                    "http_method": "POST",
                    "request_params": {"body_params": {}},
                },
                "zend_name": "req-v0.json",
                "zend": {"request_id": "req-v0", "run_id": "run-v0"},
            }
            responses = [
                {"pairs": [], "stats": {"missing_zend": 1, "paired_count": 0}},
                {"pairs": [
                    {**pair, "request": {**pair["request"], "request_id": "other"}},
                    pair,
                ], "stats": {"paired_count": 2}},
                {"pairs": [pair], "stats": {"paired_count": 1}},
            ]

            def batch_reader(**kwargs):
                return responses.pop(0)

            coordinator.runtime_batch_reader = batch_reader
            first = coordinator.read_new_runtime_evidence(deadline=10.0)
            self.assertEqual(first, [])
            self.assertNotIn(("v0", "req-v0"), coordinator._seen_pairs)

            second = coordinator.read_new_runtime_evidence(deadline=10.0)
            self.assertEqual([item["request_id"] for item in second], ["req-v0"])
            self.assertIn(("v0", "req-v0"), coordinator._seen_pairs)

            third = coordinator.read_new_runtime_evidence(deadline=10.0)
            self.assertEqual(third, [])

    def test_runtime_batch_read_clock_sequence(self):
        """Pins the number of clock() reads so moving the body cannot drop or add deadline checks."""
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, _, _, _ = self.make_probe_context(Path(tmp), [])
            calls = []

            def counting_clock():
                calls.append(len(calls))
                return float(len(calls) - 1)

            coordinator.clock = counting_clock
            coordinator.runtime_batch_reader = lambda **kwargs: {"pairs": [{
                "request_name": "req-v0.json",
                "request": {
                    "request_id": "req-v0", "legacy_run_id": "run-v0", "target_plugin": "fixture",
                    "http_method": "POST",
                    "request_params": {"body_params": {"action": "fixture", "seed": "base"}},
                },
                "zend_name": "req-v0.json",
                "zend": {"request_id": "req-v0", "run_id": "run-v0"},
            }], "stats": {}}

            evidence = coordinator.read_new_runtime_evidence(deadline=1000.0)

            self.assertEqual(len(evidence), 1)
            # 6 = value measured at 2df598ea (wave 4 BASE).
            self.assertEqual(len(calls), 6)

    def test_runtime_batch_read_failure_reasons(self):
        """An expired budget is a bounded stop; any other read error is a failure, not a timeout."""
        from online_linked.evidence import RuntimeBatchTimeout
        cases = (
            ("timeout", RuntimeBatchTimeout("RUNTIME_BATCH_TIMEOUT"), "BUDGET_EXPIRED", False),
            ("value_error", ValueError("bad batch"), "RUNTIME_BATCH_READ_FAILED", True),
        )
        for label, error, reason, failed in cases:
            with self.subTest(label), tempfile.TemporaryDirectory() as tmp:
                coordinator, _, _, _ = self.make_probe_context(Path(tmp), [])

                def reader(**kwargs):
                    coordinator.clock.now = 10.0
                    raise error

                coordinator.runtime_batch_reader = reader
                self.assertEqual(coordinator.read_new_runtime_evidence(deadline=10.0), [])
                self.assertEqual(coordinator.state["terminal_reason"], reason)
                self.assertIs(coordinator._failure, failed)

    def test_scan_event_written_before_next_counter_fails(self):
        """Each EVIDENCE_SCAN event is written before the next counter is read; a bad counter must not lose it."""
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, _, _, _ = self.make_probe_context(Path(tmp), [])
            coordinator.runtime_batch_reader = lambda **kwargs: {
                "pairs": [], "stats": {"missing_zend": 1, "invalid_payloads": "bad"},
            }

            with self.assertRaises(ValueError):
                coordinator.read_new_runtime_evidence(deadline=10.0)

            written = [
                json.loads(line)
                for line in coordinator.events_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertIn(
                ("EVIDENCE_SCAN", "ZEND_ARTIFACT_MISSING"),
                [(event.get("kind"), event.get("reason")) for event in written],
            )

    def _reconcile_fixture(self, root: Path, second_row: dict):
        coordinator, parent, _, _ = self.make_probe_context(root, [])
        first_row = {"name": "a", "source": "POST", "location": "form",
                     "request_id": "req-old", "run_id": "run-old"}
        coordinator.state["pending_runtime_candidates"] = [first_row, second_row]
        snapshots = []
        record = coordinator._record_event

        def recording(event, **kwargs):
            if event.get("kind") == "PENDING_RUNTIME_CANDIDATE":
                snapshots.append((event["status"], event["parameter"],
                                  len(coordinator.state["pending_runtime_candidates"])))
            return record(event, **kwargs)

        coordinator._record_event = recording
        evidence = {"request_id": "req-new", "worker_run_id": "run-new"}
        result = {
            "status": "CONTINUE",
            "new_parameters": [{"name": "a", "source": "POST", "location": "form"}],
            "runtime_block_reason": "TEST_STOP",
        }

        def call():
            return coordinator._handle_convergence_result(
                parent=parent, evidence=evidence, raw_report={}, result=result, seed={}, deadline=None,
            )

        return coordinator, snapshots, call

    def test_reconcile_records_events_before_replacing_pending(self):
        """Each pending-row event checkpoints while the old list is still in place; the list is replaced last."""
        with tempfile.TemporaryDirectory() as tmp:
            second = {"name": "b", "source": "POST", "location": "form",
                      "request_id": "req-old", "run_id": "run-old"}
            coordinator, snapshots, call = self._reconcile_fixture(Path(tmp), second)

            self.assertIsNone(call())

            self.assertEqual(snapshots, [("REQUEUED", "a", 2), ("RETIRED", "b", 2)])
            self.assertEqual(coordinator.state["pending_runtime_candidates"], [])

    def test_reconcile_interrupted_keeps_first_event_and_old_pending(self):
        """An error while reading row 2 must leave row 1's event and checkpoint, with the old list intact."""

        class ExplodingRow(dict):
            def get(self, key, default=None):
                if key == "request_id":
                    raise RuntimeError("boom")
                return super().get(key, default)

        with tempfile.TemporaryDirectory() as tmp:
            second = ExplodingRow(name="b", source="POST", location="form",
                                  request_id="req-old", run_id="run-old")
            coordinator, snapshots, call = self._reconcile_fixture(Path(tmp), second)

            with self.assertRaisesRegex(RuntimeError, "boom"):
                call()

            self.assertEqual(snapshots, [("REQUEUED", "a", 2)])
            self.assertEqual(len(coordinator.state["pending_runtime_candidates"]), 2)
            checkpoint = json.loads(coordinator.state_path.read_text(encoding="utf-8"))
            self.assertEqual(len(checkpoint["pending_runtime_candidates"]), 2)
            self.assertIn("REQUEUED", [
                event.get("status") for event in checkpoint["events"]
                if event.get("kind") == "PENDING_RUNTIME_CANDIDATE"
            ])

    def test_bounded_parent_inspection_rejects_failed_or_invalid_output(self):
        coordinator = object.__new__(OnlineLinkedCoordinator)
        coordinator._active_container = "parent"
        for code, output in ((1, ""), (0, "invalid")):
            with self.subTest(code=code, output=output):
                coordinator.run_command = lambda *args, **kwargs: SimpleNamespace(
                    returncode=code, stdout=output)
                with self.assertRaisesRegex(RuntimeError, "PARENT_INSPECT_FAILED"):
                    coordinator._worker_exit_code(timeout=1)

    def test_gate_terminal_failure_stops_started_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            def reject(version, *, deadline):
                coordinator._reject_runtime_batch(version, "PARENT_CHECK_TIMEOUT")
            coordinator._consume_gate_evidence = reject
            self.assertEqual(coordinator.run(), 1)
            self.assertFalse(coordinator._active_container)
            self.assertEqual(coordinator.state["workers"][0]["status"], "stopped")

    def test_gate_discovers_siblings_even_at_hard_version_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            coordinator.max_versions = 1
            coordinator.hard_versions = 1
            with patch.object(coordinator, "_handle_convergence_result") as handle, patch.object(
                coordinator, "_discover_runtime_candidates", return_value=[]
            ) as discover:
                coordinator.run()
            self.assertTrue(handle.called)
            self.assertTrue(any(call.args[0].get("evidence_origin") == "v0_gate"
                                for call in discover.call_args_list))

    def test_verified_gate_evidence_starts_probe_after_worker_start_without_new_poll_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(
                Path(tmp), log, max_seconds=2,
                request_names={"req-v0.json", "v0-probe.json"},
                zend_names={"req-v0.json", "v0-probe.json"},
            )
            gate_request_id = "v0-probe"
            probe_items = []
            pending = []
            for name in ("a",):
                variant = f"zend_probe_post_{name}"
                item = copy.deepcopy(seed_item())
                item["seed"]["seed_variant_id"] = variant
                item["seed"]["probe_variant"] = True
                item["seed"]["body"][name] = f"probe-{name}"
                probe_items.append(item)
                pending.append({
                    "name": name,
                    "source": "POST",
                    "location": "form",
                    "helper_depth": 5,
                    "seed_variant_id": variant,
                    "request_id": gate_request_id,
                    "run_id": "run-v0",
                    "plugin_slug": "fixture",
                    "callback_id": "cb-fixture",
                    "canonical_callback": "fixture_callback",
                    "request_method": "POST",
                })

            original_converge = coordinator.converge_fn

            def gate_then_probe(**kwargs):
                if kwargs["legacy_run_id"] == "run-v0":
                    log.append("gate_convergence")
                    return {
                        "status": "CONTINUE",
                        "request_id": gate_request_id,
                        "known_parameters": [],
                        "new_parameters": [],
                        "pending_probes": pending,
                        "merged_suggested_seeds": {"suggested_seeds": probe_items},
                    }
                if "-probe-" in kwargs["legacy_run_id"]:
                    log.append("probe_convergence")
                    probe_run_id = kwargs["legacy_run_id"]
                    return {
                        "status": "CONTINUE",
                        "request_id": "replay-v1",
                        "new_parameters": [{
                            "name": "a",
                            "path": ["a"],
                            "source": "POST",
                            "location": "form",
                            "helper_depth": 5,
                            "observed_count": 1,
                            "access_forms": ["read"],
                            "evidence_kind": "zend_runtime",
                            "fuzzable": True,
                            "request_id": "replay-v1",
                            "run_id": probe_run_id,
                            "plugin_slug": "fixture",
                            "callback_id": "cb-fixture",
                            "canonical_callback": "fixture_callback",
                            "request_method": "POST",
                        }],
                        "known_parameters": [],
                        "merged_suggested_seeds": {"suggested_seeds": probe_items},
                    }
                return original_converge(**kwargs)

            coordinator.converge_fn = gate_then_probe
            coordinator.runtime_batch_reader = lambda **kwargs: {
                "pairs": [],
                "stats": {"file_count": 603, "paired_count": 0},
            }

            self.assertEqual(coordinator.run(), 0)
            probe_start = next(i for i, item in enumerate(log) if item.startswith("sender_timeout:run-v0-probe-p1:"))
            self.assertLess(log.index("worker_start"), probe_start)
            self.assertEqual(coordinator.state["probe_attempts"][0]["request_id"], gate_request_id)
            self.assertEqual(coordinator.state["probe_attempts"][0]["status"], "accepted")
            self.assertEqual(coordinator.state["probe_attempts"][0]["probe_request_id"], "replay-v1")
            self.assertEqual(coordinator.state["probe_attempts"][0]["evidence_origin"], "v0_gate")
            self.assertGreater(coordinator.state["probe_attempts"][0]["remaining_budget_seconds"], 0)
            self.assertIsNotNone(coordinator.state["probe_attempts"][0]["first_probe_delay_seconds"])
            self.assertEqual(coordinator.state["evidence_scan"]["paired_count"], 0)

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

    def test_same_callback_is_queued_once_per_distinct_runtime_context(self):
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
            self.assertEqual(len(cycle), 1)
            self.assertEqual(cycle[0]["callback_id"], "cb-fixture")
            self.assertNotEqual(cycle[0]["context_key"], first[0]["context_key"])
            self.assertEqual(coordinator._discover_runtime_candidates(evidence), [])
            self.assertEqual(len(coordinator.state["candidate_queue"]), 2)
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

    def test_candidate_context_key_deduplicates_provenance_and_fuzzable_values(self):
        self.assertEqual(
            _candidate_context_key(seed_item(), "fixture"),
            "8b7b3ed1b0fcaf9eeeaeeea7577e5f8e0245214074a65c13b09a0829b5fc2570",
        )
        item = {
            "hook_name": "wp_ajax_nopriv_context",
            "callback_id": "cb-context",
            "request_id": "req-1",
            "executed_count": 4,
            "observed_at": "2026-10-20T00:00:00Z",
            "seed": {
                "entrypoint_type": "ajax_unauthenticated",
                "path": "/wp-admin/admin-ajax.php",
                "method": "POST",
                "content_type": "application/x-www-form-urlencoded",
                "auth_mode": "unauth-capable",
                "query_params": {"page": 1},
                "body": {"action": "context", "mode": "list", "payload": "first"},
                "headers": {"X-Trace": "fixed", "X-Nonce": "nonce-1"},
                "cookies": {"session": "fixed-cookie"},
                "fixed_params": ["action", "mode", "page", "X-Trace", "session"],
                "fuzzable_params": ["payload"],
                "input_params": [
                    {"name": "payload", "source": "POST", "role": "application_data", "fuzzable": True},
                    {"name": "X-Nonce", "source": "HEADER", "role": "security_nonce", "fuzzable": False},
                ],
            },
        }
        reordered = copy.deepcopy(item)
        reordered["request_id"] = "req-2"
        reordered["executed_count"] = 99
        reordered["observed_at"] = "later"
        reordered["seed"]["body"]["payload"] = "second"
        reordered["seed"]["headers"]["X-Nonce"] = "nonce-2"
        reordered["seed"]["body"] = dict(reversed(list(reordered["seed"]["body"].items())))
        reordered["seed"]["headers"] = dict(reversed(list(reordered["seed"]["headers"].items())))

        self.assertEqual(_candidate_context_key(item, "fixture"), _candidate_context_key(reordered, "fixture"))

    def test_candidate_context_key_keeps_auth_transport_and_fixed_selectors_distinct(self):
        item = {
            "hook_name": "wp_ajax_nopriv_context",
            "callback_id": "cb-context",
            "seed": {
                "entrypoint_type": "ajax_unauthenticated",
                "path": "/wp-admin/admin-ajax.php",
                "method": "POST",
                "content_type": "application/x-www-form-urlencoded",
                "auth_mode": "unauth-capable",
                "body": {"action": "context", "mode": "list", "payload": "first"},
                "fixed_params": ["action", "mode"],
                "fuzzable_params": ["payload"],
            },
        }
        base = _candidate_context_key(item, "fixture")
        for section, key, value in (
            ("body", "mode", "preview"),
            ("auth_mode", None, "authenticated"),
            ("method", None, "GET"),
            ("content_type", None, "application/json"),
        ):
            changed = copy.deepcopy(item)
            if key is None:
                changed["seed"][section] = value
            else:
                changed["seed"][section][key] = value
            self.assertNotEqual(base, _candidate_context_key(changed, "fixture"), section)

    def test_candidate_context_key_keeps_unclassified_nonce_values_fixed(self):
        item = {
            "hook_name": "wp_ajax_nopriv_context",
            "callback_id": "cb-context",
            "seed": {"path": "/wp-admin/admin-ajax.php", "method": "POST",
                     "headers": {"X-Nonce": "nonce-1"}},
        }
        changed = copy.deepcopy(item)
        changed["seed"]["headers"]["X-Nonce"] = "nonce-2"
        self.assertNotEqual(_candidate_context_key(item, "fixture"), _candidate_context_key(changed, "fixture"))

    def test_candidate_context_key_matches_exporter_section_fuzz_rules(self):
        item = {
            "hook_name": "wp_ajax_nopriv_context",
            "callback_id": "cb-context",
            "seed": {
                "path": "/wp-admin/admin-ajax.php", "method": "POST",
                "auth_mode": "unauth-capable",
                "body": {"action": "demo", "payload": "fuzz"},
                "query_params": {"payload": "list"},
                "headers": {"payload": "header-fixed"},
                "cookies": {"payload": "cookie-fixed"},
                "fixed_params": ["action"], "fuzzable_params": ["payload"],
                "input_params": [{
                    "name": "payload", "source": "POST", "location": "form", "fuzzable": True,
                }],
            },
        }
        _, config = build_config_for_seed_item(item)
        self.assertEqual(config["body_params"]["fuzz"], ["action", "payload"])
        self.assertIn("payload", config["query_params"]["fixed"])
        self.assertEqual(config["headers"]["fuzz"], [])
        self.assertEqual(config["cookies"]["fuzz"], [])

        body_value_changed = copy.deepcopy(item)
        body_value_changed["seed"]["body"]["payload"] = "different-fuzz-input"
        self.assertEqual(_candidate_context_key(item, "fixture"),
                         _candidate_context_key(body_value_changed, "fixture"))

        for section, value in (("query_params", "preview"), ("headers", "header-changed"),
                               ("cookies", "cookie-changed")):
            with self.subTest(section=section):
                changed = copy.deepcopy(item)
                changed["seed"][section]["payload"] = value
                self.assertNotEqual(_candidate_context_key(item, "fixture"),
                                    _candidate_context_key(changed, "fixture"))

    def test_candidate_context_key_respects_fixed_priority_and_top_level_export_fields(self):
        conflict = {
            "hook_name": "wp_ajax_nopriv_context",
            "callback_id": "cb-context",
            "seed": {
                "path": "/wp-admin/admin-ajax.php", "method": "POST",
                "auth_mode": "unauth-capable",
                "body": {"payload": "fixed-value"},
                "fixed_params": ["payload"], "fuzzable_params": ["payload"],
                "input_params": [{
                    "name": "payload", "source": "POST", "location": "form", "fuzzable": True,
                }],
            },
        }
        _, config = build_config_for_seed_item(conflict)
        self.assertEqual(config["body_params"]["fuzz"], [])
        self.assertIn("payload", config["body_params"]["fixed"])
        changed_conflict = copy.deepcopy(conflict)
        changed_conflict["seed"]["body"]["payload"] = "another-fixed-value"
        self.assertNotEqual(_candidate_context_key(conflict, "fixture"),
                            _candidate_context_key(changed_conflict, "fixture"))

        nested = copy.deepcopy(conflict)
        nested["seed"].update({
            "body": {"action": "demo", "id": "fuzz", "options": {"id": "list"}},
            "fixed_params": ["action", "options"], "fuzzable_params": ["id"],
            "input_params": [],
        })
        _, config = build_config_for_seed_item(nested)
        self.assertIn("options", config["body_params"]["fixed"])
        self.assertIn("id", config["body_params"]["fuzz"])
        changed_nested = copy.deepcopy(nested)
        changed_nested["seed"]["body"]["options"]["id"] = "preview"
        self.assertNotEqual(_candidate_context_key(nested, "fixture"),
                            _candidate_context_key(changed_nested, "fixture"))

    def test_candidate_context_key_canonicalizes_role_metadata_as_sets(self):
        item = {
            "hook_name": "wp_ajax_nopriv_context",
            "callback_id": "cb-context",
            "seed": {
                "path": "/wp-admin/admin-ajax.php", "method": "POST",
                "body": {"action": "demo", "mode": "list", "payload": "fuzz"},
                "fixed_params": ["action", "mode"],
                "fuzzable_params": ["payload", "nonce"],
                "input_params": [
                    {"name": "payload", "source": "POST", "location": "form", "fuzzable": True},
                    {"name": "nonce", "source": "POST", "location": "form", "fuzzable": True},
                ],
            },
        }
        reordered = copy.deepcopy(item)
        reordered["seed"]["fixed_params"] = ["mode", "action", "mode"]
        reordered["seed"]["fuzzable_params"] = ["nonce", "payload", "nonce"]
        reordered["seed"]["input_params"] = list(reversed(reordered["seed"]["input_params"]))
        reordered["seed"]["input_params"].append(copy.deepcopy(reordered["seed"]["input_params"][0]))
        self.assertEqual(_candidate_context_key(item, "fixture"),
                         _candidate_context_key(reordered, "fixture"))

    def test_candidate_context_key_preserves_fixed_value_types_and_array_order(self):
        item = {
            "hook_name": "wp_ajax_nopriv_context",
            "callback_id": "cb-context",
            "seed": {"path": "/wp-admin/admin-ajax.php", "method": "POST",
                     "body": {"action": "context", "choices": [1, "1"]},
                     "fixed_params": ["action", "choices"]},
        }
        reordered = copy.deepcopy(item)
        reordered["seed"]["body"]["choices"] = ["1", 1]
        self.assertNotEqual(_candidate_context_key(item, "fixture"), _candidate_context_key(reordered, "fixture"))

    def test_candidate_context_key_tolerates_missing_optional_role_lists(self):
        for field in ("fixed_params", "fuzzable_params", "input_params"):
            item = {
                "hook_name": "wp_ajax_nopriv_context",
                "callback_id": "cb-context",
                "seed": {"path": "/wp-admin/admin-ajax.php", "method": "POST", field: None},
            }
            with self.subTest(field=field):
                self.assertRegex(_candidate_context_key(item, "fixture"), r"^[0-9a-f]{64}$")

    def test_batch_deduplicates_by_context_across_initial_and_runtime_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def item(mode, payload, request_id):
                result = copy.deepcopy(seed_item())
                result["request_id"] = request_id
                result["executed_count"] = int(request_id.rsplit("-", 1)[-1])
                result["seed"].update(
                    content_type="application/x-www-form-urlencoded",
                    body={"action": "fixture", "mode": mode, "seed": payload},
                    fixed_params=["action", "mode"],
                    fuzzable_params=["seed"],
                )
                return result

            initial = [item("list", "first", "req-1"), item("list", "next", "req-2"),
                       item("preview", "first", "req-3")]
            rediscovered = [item("list", "later", "req-4"), item("preview", "later", "req-5"),
                            item("edit", "first", "req-6")]
            suggested = root / "suggested.json"
            suggested.write_text(json.dumps({"suggested_seeds": initial}), encoding="utf-8")
            registry = root / "registry.json"
            registry.write_text("{}", encoding="utf-8")
            calls = []

            class FakeCoordinator:
                def __init__(self, **kwargs):
                    self.kwargs = kwargs
                    self.state_path = root / f"candidate-{len(calls) + 1}.json"
                    current = json.loads(Path(kwargs["suggested_seeds"]).read_text())["suggested_seeds"][0]
                    calls.append(current)
                    self.state = {
                        "terminal_status": "BOUNDED_ONLINE_COMPLETE",
                        "terminal_reason": "BUDGET_EXPIRED",
                        "versions": [],
                        "candidate_queue": rediscovered if len(calls) == 1 else [],
                    }

                def run(self):
                    return 0

            args = SimpleNamespace(
                suggested_seeds=str(suggested), bootstrap_config="", config_root=str(root / "configs"),
                output_root=str(root / "output"), plugin_slug="fixture", legacy_run_id="context-campaign",
                max_seconds=2, max_versions=2, max_candidates=1, hard_max_candidates=4,
                campaign_seconds=20, hard_campaign_seconds=40, callback_registry=str(registry), service="fixture",
            )
            with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator), \
                    patch("online_linked.coordination.campaign.export_online_linked_batch", return_value=0), \
                    patch("sys.stdout", new=io.StringIO()):
                self.assertEqual(run_online_linked(args), 0)

            state = json.loads((root / "output/online-linked/context-campaign/batch-state.json").read_text())
            self.assertEqual([row["seed"]["body"]["mode"] for row in calls], ["list", "preview", "edit"])
            self.assertEqual(len({row["identity"] for row in state["candidates"]}), 1)
            self.assertEqual(len({row["context_key"] for row in state["candidates"]}), 3)
            self.assertEqual(len(state["queued_context_keys"]), 3)
            self.assertEqual(len(state["budget"]["progress_keys"]), 1)

    def test_covered_bootstrap_report_exports_replay_only_and_deduplicates_queue(self):
        hook_name = "wp_ajax_nopriv_hookphuzz_online_discovery_mode"
        coverage = {"data": {
            "registered_callbacks": {"cb-mode": {
                "callback_id": "cb-mode", "hook_name": hook_name,
                "callback_repr": "hookphuzz_online_discovery_mode_ajax", "is_active": True,
                "status": "covered",
            }},
            "executed_callbacks": {"cb-mode": {
                "callback_id": "cb-mode", "hook_name": hook_name,
                "executed_count": 5,
            }},
        }}
        gap_report, seed_report = ZendRuntimeSeedGenerator().build_reports(coverage)
        item = seed_report["suggested_seeds"][0]
        self.assertEqual(item["status"], "covered")
        self.assertTrue(item["discovery_eligible"])
        self.assertEqual(gap_report["callbacks"][0]["execute_count"], 5)
        self.assertEqual(gap_report["summary"]["discovery_eligible_callbacks"], 1)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export = export_seed_configs(
                seed_report, output_config_dir=root / "configs", replay_only=True,
            )
            self.assertEqual(len(export["generated"]), 1)
            config = json.loads(Path(export["generated"][0]["config_path"]).read_text())
            self.assertEqual(config["config_type"], "replay_only")
            self.assertFalse(config["metadata"]["fuzzing_ready"])

            duplicate = copy.deepcopy(item)
            duplicate["request_id"] = "bootstrap-request-2"
            duplicate["executed_count"] = 8
            suggested = root / "suggested.json"
            suggested.write_text(json.dumps({"suggested_seeds": [item, duplicate]}), encoding="utf-8")
            registry = root / "registry.json"
            registry.write_text("{}", encoding="utf-8")

            class FakeCoordinator:
                def __init__(self, **kwargs):
                    self.state_path = root / "candidate-state.json"
                    self.state = {
                        "terminal_status": "BOUNDED_ONLINE_COMPLETE",
                        "versions": [],
                        "candidate_queue": [copy.deepcopy(item)],
                    }

                def run(self):
                    return 0

            args = SimpleNamespace(
                suggested_seeds=str(suggested), bootstrap_config="",
                config_root=str(root / "online-configs"), output_root=str(root / "output"),
                plugin_slug="fixture", legacy_run_id="covered-bootstrap", max_seconds=2,
                max_versions=2, max_candidates=1, hard_max_candidates=4,
                campaign_seconds=20, hard_campaign_seconds=40,
                callback_registry=str(registry), service="fixture",
            )
            with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator), \
                    patch("online_linked.coordination.campaign.export_online_linked_batch", return_value=0), \
                    patch("sys.stdout", new=io.StringIO()):
                self.assertEqual(run_online_linked(args), 0)

            state = json.loads((root / "output/online-linked/covered-bootstrap/batch-state.json").read_text())
            self.assertEqual(len(state["candidates"]), 1)
            self.assertEqual(len(state["queued_context_keys"]), 1)
            self.assertEqual(state["budget"]["progress_keys"], [])

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

    def test_v0_requires_callback_registry_before_fuzzing(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator = self.make_coordinator(Path(tmp), log)
            coordinator.registry = {"callback_map": {}}
            self.assertEqual(coordinator.run(), 2)
            self.assertNotIn("worker_start", log)
            self.assertEqual(coordinator.state["terminal_reason"], "V0_REGISTRY_MISSING")

    def test_v0_error_response_blocks_fuzz_ready_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator = self.make_coordinator(Path(tmp), log)
            replay = coordinator.replay_runner
            def replay_403(*args, **kwargs):
                report = replay(*args, **kwargs)
                report['runs'][0]['request_payload']['response'] = {'status_code': 403}
                return report
            coordinator.replay_runner = replay_403
            coordinator.run()
            version = coordinator.state['versions'][0]
            self.assertEqual(version["readiness"]["verification_policy"], "callback_baseline_v1")
            self.assertFalse(version['readiness']['passed'])
            self.assertEqual(coordinator.state['terminal_reason'], 'GUARD_SATISFACTION_UNKNOWN')
            self.assertNotIn('worker_start', log)

    def test_v0_successful_responses_keep_existing_fuzz_gate(self):
        for status in (200, 201, 204):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                log = []
                coordinator = self.make_coordinator(Path(tmp), log)
                replay = coordinator.replay_runner
                def replay_success(*args, **kwargs):
                    report = replay(*args, **kwargs)
                    if kwargs['legacy_run_id'].endswith('-v0'):
                        report['runs'][0]['request_payload']['response'] = {'status_code': status}
                    return report
                coordinator.replay_runner = replay_success
                coordinator.run()
                self.assertTrue(coordinator.state['versions'][0]['readiness']['passed'])
                self.assertIn('worker_start', log)

    def test_v0_error_response_keeps_replay_only_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator = self.make_coordinator(Path(tmp), log)
            def build_replay(*args, **kwargs):
                config = config_for(seed_item())
                config['config_type'] = 'replay_only'
                config['body_params']['fuzz'] = []
                return 'fixture', config
            coordinator.build_config_fn = build_replay
            replay = coordinator.replay_runner
            def replay_403(*args, **kwargs):
                report = replay(*args, **kwargs)
                if kwargs['legacy_run_id'].endswith('-v0'):
                    report['runs'][0]['request_payload']['response'] = {'status_code': 403}
                return report
            coordinator.replay_runner = replay_403
            coordinator.run()
            self.assertTrue(coordinator.state['versions'][0]['readiness']['probe_only'])
            self.assertIn('worker_start', log)

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
            self.assertEqual(coordinator.run(), 0)
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
            self.assertEqual(coordinator.state['attempts'], [])
            self.assertIn("CHILD_CONFIG_EXPORT_FAILED", json.dumps(coordinator.state["events"]))
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
            self.assertEqual(child['version'], 'v1')
            self.assertEqual(child['status'], 'fuzzing')
            self.assertEqual(coordinator.state['versions'][0]['known_parameters'], [])
            with self.assertRaises(OnlineLinkedError):
                coordinator.advance_online_version({'request_id': 'third'})

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
            child_config = json.loads(Path(child['config_path']).read_text(encoding='utf-8'))
            child_body = {row['name']: row['value'] for row in child_config['body_params']['data']}
            self.assertEqual(child_body['mode'], 'fuzz')
            self.assertEqual(child_body['detail'], 'fuzz')
            self.assertEqual(child_body['action'], 'fixture')
            self.assertIn('detail', child_config['body_params']['fuzz'])
            replay_config = json.loads(Path(child['replay_config_path']).read_text(encoding='utf-8'))
            replay_body = {row['name']: row['value'] for row in replay_config['body_params']['data']}
            self.assertEqual(replay_body['mode'], 'deep')
            self.assertEqual(replay_body['detail'], 'observed')
            self.assertEqual(replay_body['action'], 'fixture')

    def test_batch_prioritizes_ajax_including_runtime_children_with_stable_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hooks = ["rest_route:demo/v1/items", "wp_ajax_first", "admin_post_save", "wp_ajax_nopriv_second"]
            suggested = root / "suggested.json"
            suggested.write_text(json.dumps({"suggested_seeds": [
                {"hook_name": hook, "callback_id": hook, "seed": {}} for hook in hooks
            ]}), encoding="utf-8")
            registry = root / "registry.json"
            registry.write_text("{}", encoding="utf-8")
            calls = []

            class Candidate:
                def __init__(self, **kwargs):
                    item = json.loads(Path(kwargs["suggested_seeds"]).read_text(encoding="utf-8"))["suggested_seeds"][0]
                    calls.append(item["hook_name"])
                    self.state_path = root / f"state-{len(calls)}.json"
                    self.state = {
                        "terminal_status": "BOUNDED_ONLINE_COMPLETE", "versions": [],
                        "candidate_queue": [{
                            "hook_name": "wp_ajax_child", "callback_id": "child", "seed": {},
                        }] if len(calls) == 1 else [],
                    }

                def run(self):
                    return 0

            args = SimpleNamespace(
                suggested_seeds=str(suggested), bootstrap_config="", config_root=str(root / "configs"),
                output_root=str(root / "output"), plugin_slug="fixture", legacy_run_id="run",
                max_seconds=1, max_versions=2, callback_registry=str(registry), service="fuzzer-wordpress-plugin",
            )
            with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", Candidate), \
                    patch("online_linked.coordination.campaign.export_online_linked_batch", return_value=0):
                self.assertEqual(run_online_linked(args), 0)
            self.assertEqual(calls, [hooks[1], hooks[3], "wp_ajax_child", hooks[0], hooks[2]])

    def test_batch_skips_items_without_http_seed_before_spending_candidate_slots(self):
        # A seedless item (e.g. admin_enqueue_scripts) can never build a v0
        # config, so it must not consume a max_candidates slot that a real
        # HTTP entrypoint needs, nor mark the campaign as complete_with_skips.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suggested = root / "suggested.json"
            suggested.write_text(json.dumps({"suggested_seeds": [
                {"hook_name": "admin_enqueue_scripts", "callback_id": "a", "direct_http_supported": False},
                {"hook_name": "add_meta_boxes", "callback_id": "b", "seed": None},
                {"hook_name": "wp_ajax_real", "callback_id": "c", "seed": {}},
            ]}), encoding="utf-8")
            registry = root / "registry.json"
            registry.write_text("{}", encoding="utf-8")
            calls = []

            class Candidate:
                def __init__(self, **kwargs):
                    item = json.loads(Path(kwargs["suggested_seeds"]).read_text(encoding="utf-8"))["suggested_seeds"][0]
                    calls.append(item["hook_name"])
                    self.state_path = root / f"state-{len(calls)}.json"
                    self.state = {"terminal_status": "BOUNDED_ONLINE_COMPLETE", "versions": [], "candidate_queue": []}

                def run(self):
                    return 0

            args = SimpleNamespace(
                suggested_seeds=str(suggested), bootstrap_config="", config_root=str(root / "configs"),
                output_root=str(root / "output"), plugin_slug="fixture", legacy_run_id="run",
                max_seconds=1, max_versions=2, max_candidates=1, hard_max_candidates=1,
                callback_registry=str(registry), service="fuzzer-wordpress-plugin",
            )
            with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", Candidate), \
                    patch("online_linked.coordination.campaign.export_online_linked_batch", return_value=0):
                self.assertEqual(run_online_linked(args), 0)
            self.assertEqual(calls, ["wp_ajax_real"])
            state = json.loads((root / "output" / "online-linked" / "run" / "batch-state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["campaign_status"], "complete")
            self.assertEqual([row["hook_name"] for row in state["candidates"]], ["wp_ajax_real"])
            self.assertEqual(
                [(row["hook_name"], row["reason"]) for row in state["non_http_skipped"]],
                [("admin_enqueue_scripts", "missing_seed"), ("add_meta_boxes", "missing_seed")],
            )

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
            with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator), \
                    patch(
                        "online_linked.coordination.campaign.export_online_linked_batch",
                        return_value=0,
                    ):
                self.assertEqual(run_online_linked(args), 0)

            self.assertEqual(len(calls), 2)
            self.assertTrue(all(call["campaign_dir"] == root / "output/online-linked/run" for call in calls))
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
                with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", Candidate), \
                        patch(
                            "online_linked.coordination.campaign.export_online_linked_batch",
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
            with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator), \
                    patch(
                        "online_linked.coordination.campaign.export_online_linked_batch",
                        return_value=0,
                    ):
                self.assertEqual(run_online_linked(args), 0)

            self.assertEqual(len(calls), 2)
            self.assertIsNotNone(calls[0]["campaign_deadline"])
            self.assertEqual(calls[1]["campaign_deadline"] - calls[0]["campaign_deadline"], args.max_seconds)
            batch_state = json.loads((root / "output" / "online-linked" / "run" / "batch-state.json").read_text(encoding="utf-8"))
            self.assertEqual(batch_state["candidates"][1]["lineage"]["parent_callback_id"], "cb-parent")
            self.assertEqual(batch_state["candidates"][1]["source"], "runtime_registration")

            calls.clear()
            args.sync_registry = True
            with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator), \
                    patch(
                        "online_linked.coordination.campaign.export_online_linked_batch",
                        return_value=0,
                    ), \
                    patch("online_linked.coordination.campaign._sync_callback_registry_to_web",
                          side_effect=subprocess.TimeoutExpired("docker cp", 30)):
                self.assertEqual(run_online_linked(args), 0)
            batch_state = json.loads((root / "output" / "online-linked" / "run" / "batch-state.json").read_text())
            self.assertEqual(batch_state["campaign_status"], "PARTIAL")
            self.assertEqual(batch_state["terminal_reason"], "CALLBACK_REGISTRY_REFRESH_FAILED")
            self.assertEqual(len(batch_state["pending_candidates"]), 1)
            self.assertEqual(len(batch_state["candidates"]), 1)
            self.assertEqual(batch_state["candidates"][0]["terminal_status"], "BOUNDED_ONLINE_COMPLETE")
            self.assertEqual(batch_state["expansion_events"][0]["reason"], "CALLBACK_REGISTRY_REFRESH_FAILED")
            args.resume = True
            old_budget = batch_state["budget"]
            with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator), \
                    patch("online_linked.coordination.campaign.export_online_linked_batch", return_value=0), \
                    patch("online_linked.coordination.campaign._sync_callback_registry_to_web") as sync, \
                    patch("online_linked.coordination.campaign.time.monotonic", return_value=10000.0), \
                    patch("online_linked.coordination.campaign.time.time", return_value=old_budget["saved_at"]):
                self.assertEqual(run_online_linked(args), 0)
            resumed = json.loads((root / "output/online-linked/run/batch-state.json").read_text())
            self.assertEqual(len(calls), 2, "completed parent must not run again")
            self.assertEqual(calls[-1]["campaign_deadline"], 10000 + old_budget["remaining_seconds"])
            self.assertEqual(resumed["budget"]["progress_keys"], old_budget["progress_keys"])
            self.assertFalse(resumed["pending_candidates"])
            self.assertEqual(resumed["campaign_status"], "complete")
            self.assertEqual(resumed["effective_max_candidates"], batch_state["effective_max_candidates"])
            sync.assert_called_once()
            args.hard_max_candidates = 129
            with self.assertRaisesRegex(ValueError, "context or budgets changed"):
                run_online_linked(args)
            args.hard_max_candidates = None
            batch_path = root / "output/online-linked/run/batch-state.json"
            old_policy = json.loads(batch_path.read_text(encoding="utf-8"))
            for field in ("context_key_version", "queued_context_keys"):
                with self.subTest(missing_checkpoint_field=field):
                    missing_context = copy.deepcopy(old_policy)
                    missing_context.pop(field)
                    batch_path.write_text(json.dumps(missing_context), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "context-key"):
                        run_online_linked(args)
            old_policy["resume_context"].pop("budget_policy")
            batch_path.write_text(json.dumps(old_policy), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "policy.*new run"):
                run_online_linked(args)

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
            with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator), \
                    patch(
                        "online_linked.coordination.campaign.export_online_linked_batch",
                        return_value=0,
                    ), \
                    patch("online_linked.coordination.campaign._sync_callback_registry_to_web") as sync, \
                    patch("online_linked.coordination.campaign.time.monotonic", side_effect=lambda: 2.0 if calls else 0.0):
                self.assertEqual(run_online_linked(args), 0)

            self.assertEqual(len(calls), 1)
            sync.assert_not_called()
            batch_state = json.loads((root / "output" / "online-linked" / "run" / "batch-state.json").read_text(encoding="utf-8"))
            self.assertEqual(batch_state["campaign_status"], "PARTIAL")
            self.assertEqual(batch_state["terminal_reason"], "CAMPAIGN_BUDGET_EXPIRED")
            self.assertEqual(len(batch_state["pending_candidates"]), 1)
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
            with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator), \
                    patch("online_linked.coordination.campaign.export_online_linked_batch",
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
            with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator), \
                    patch(
                        "online_linked.coordination.campaign.export_online_linked_batch",
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
        runtime_batch_reader=None,
        campaign_dir: Path | None = None,
        pause_ack=None,
    ) -> OnlineLinkedCoordinator:
        item = seed_item()
        control_root = root / "handoff-control"
        if pause_ack is None:
            # A worker that stops at attempt 10 of a 20-attempt round and scored the request at 31.
            pause_ack = lambda request: {**request, "round_id": 1, "allocated_energy": 20, "attempts_used": 9,
                                         "seed_phuzz_energy": 31}
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

        def default_batch_reader(*, run_id, plugin_slug, timeout, run_command):
            log.append("runtime_batch_reader")
            request_names_snapshot = coordinator.list_artifacts()
            zend_names_snapshot = coordinator.list_zend_artifacts()
            pairs = []
            for name in sorted(request_names_snapshot):
                if name not in zend_names_snapshot:
                    continue
                pairs.append({
                    "request_name": name,
                    "request": coordinator.load_artifact(name),
                    "zend_name": name,
                    "zend": coordinator.load_zend_artifact(name),
                })
            return {
                "pairs": pairs,
                "stats": {
                    "file_count": len(request_names_snapshot),
                    "run_plugin_matches": len(pairs),
                    "paired_count": len(pairs),
                    "missing_zend": len(request_names_snapshot - zend_names_snapshot),
                },
            }

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
            materialized = copy.deepcopy(raw_report)
            items = materialized.get("suggested_seeds")
            known_parameters = kwargs.get("known_parameters")
            if isinstance(items, list) and items and isinstance(items[0], Mapping):
                seed = items[0].setdefault("seed", {})
                if isinstance(seed, dict) and isinstance(known_parameters, list):
                    body = seed.setdefault("body", {})
                    if isinstance(body, dict):
                        for parameter in known_parameters:
                            if not isinstance(parameter, Mapping):
                                continue
                            name = str(parameter.get("name") or "")
                            if name and str(parameter.get("source") or "").upper() == "POST":
                                body.setdefault(name, "fuzz")
            return materialized

        def export_configs(report, *, output_config_dir, summary_path, **kwargs):
            log.append("export_seed_configs")
            output_config_dir = Path(output_config_dir)
            path = output_config_dir / "exported.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            config = config_for(item, include_new=True)
            report_items = report.get("suggested_seeds") if isinstance(report, Mapping) else None
            report_seed = report_items[0].get("seed") if isinstance(report_items, list) and report_items else None
            if isinstance(report_seed, Mapping) and isinstance(report_seed.get("body"), Mapping):
                existing_names = {
                    str(row.get("name") or "")
                    for row in config["body_params"]["data"]
                    if isinstance(row, Mapping)
                }
                for name, value in report_seed["body"].items():
                    if str(name) and str(name) not in existing_names:
                        config["body_params"]["data"].append({"name": str(name), "value": value})
                        config["body_params"]["fuzz"].append(str(name))
            path.write_text(json.dumps(config), encoding="utf-8")
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
                    'zend_artifact': 'v0-probe.json',
                    'request_payload': {
                        'request_id': 'v0-probe',
                        'legacy_run_id': kwargs['legacy_run_id'],
                        'target_plugin': 'fixture',
                        'hook_name': item['hook_name'], 'callback_id': item['callback_id'],
                        'auth_context': next((v['auth_context'] for v in coordinator.state['versions'] if v.get('worker_run_id') == kwargs['legacy_run_id']), 'authenticated'),
                        'http_method': args[0][0]['resolved_method'],
                        'response': {'status_code': 200},
                        'request_params': {'body_params': {'action': 'fixture', 'seed': 'base'}},
                    },
                    'zend_payload': {
                        'request_id': 'v0-probe',
                        'run_id': kwargs['legacy_run_id'],
                    },
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


        def run_command(command, **kwargs):
            if command[:2] == ["docker", "inspect"]:
                return subprocess.CompletedProcess(command, 0, "running", "")
            if command[:2] == ["docker", "exec"] and command[3:6] == ["python", "-m", "core.online_handoff"]:
                # Fake worker: the container's shared tmpfs is a local folder.
                out = io.StringIO()
                with redirect_stdout(out):
                    code = handoff.main(command[6:], root=control_root)
                if command[6] == "request":
                    log.append("pause_requested")
                    ack = pause_ack({"token": command[8], "worker_run_id": command[9],
                                     **({"request_id": command[10]} if len(command) > 10 else {})})
                    if ack is not None:
                        handoff.write_ack(command[7], ack, root=control_root)
                elif command[6] == "ack" and json.loads(out.getvalue() or "null") is not None:
                    log.append("pause_ack")
                elif command[6] == "release":
                    log.append("pause_released")
                return subprocess.CompletedProcess(command, code, out.getvalue(), "")
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
            campaign_dir=campaign_dir,
            build_config_fn=build_config,
            list_targets_fn=list_targets,
            list_artifacts=list_artifacts,
            load_artifact=load_artifact,
            list_zend_artifacts=list_zend,
            load_zend_artifact=load_zend,
            runtime_batch_reader=runtime_batch_reader or default_batch_reader,
            converge_fn=converge,
            materialize_fn=materialize,
            export_configs_fn=export_configs,
            force_replay_only_fn=force_replay,
            replay_runner=replay_runner,
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
            is_probe = "-probe-" in run_id
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
            name = str(row.get("seed_variant_id") or "").split("zend_probe_post_", 1)[-1] or "seed"
            artifact_name = str(old_row.get("matched_artifact") or (
                f"probe-{name}.json" if is_probe else f"{kwargs['request_id']}.json"
            ))
            artifact_id = Path(artifact_name).stem
            body = (
                {"action": "fixture", name: f"probe-{name}"}
                if is_probe
                else {
                    str(item.get("name")): item.get("value")
                    for item in config_payload.get("body_params", {}).get("data", [])
                    if isinstance(item, Mapping) and str(item.get("name") or "")
                }
            )
            auth_context = str(kwargs["expected"].get("auth_context") or "authenticated")
            helper_depth = 5 if "-probe-" in run_id else 0
            return {
                "status": "callback_reached" if reached else "request_completed",
                "callback_reached": reached,
                "validation_status": "callback_reached" if reached else old_row.get("validation_status"),
                "validation_reason": "" if reached else old_row.get("validation_reason", ""),
                "request_name": artifact_name if reached else "",
                "request": ({
                    "request_id": artifact_id, "legacy_run_id": run_id, "run_id": run_id,
                    "target_plugin": "fixture", "hook_name": kwargs["expected"]["hook_name"],
                    "callback_id": kwargs["expected"]["callback_id"], "auth_context": auth_context,
                    "http_method": row["resolved_method"],
                    "request_params": {"body_params": body, "headers": {
                        "X-HookPhuzz-Auth-Context": auth_context,
                    }},
                    "response": {"status_code": 200},
                } if reached else None),
                "zend_name": artifact_name if reached else "",
                "zend": ({
                    "request_id": artifact_id, "run_id": run_id,
                    "request_method": row["resolved_method"],
                    "callback_summaries": [{"callback": "fixture_callback", "unique_parameters": [{
                        "name": item_name, "source": "POST", "path": [item_name], "helper_depth": helper_depth,
                        "observed_count": 1, "access_forms": ["read"],
                    } for item_name in body if item_name != "action"]}],
                    "events": [{"source": "POST", "path": [item_name], "operation": "read",
                                 "callback_context": {"attributed": True, "root_callback": "fixture_callback", "depth": helper_depth}}
                                for item_name in body if item_name != "action"],
                } if reached else None),
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
            self.assertEqual(result["replay_result"]["verification_policy"], "parameter_replay_v1")

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
        parent.update(worker_run_id="run-v0", known_parameters=[], handoff_key="key-v0")
        parent["auth_context"] = "guest"
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
                name = str(row["seed_variant_id"]).split("zend_probe_post_", 1)[-1]
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
            name = str(item_seed.get("seed_variant_id")).split("zend_probe_post_", 1)[-1]
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
            report_seed = report["suggested_seeds"][0].get("seed", {})
            report_body_names = (
                [str(name) for name in report_seed.get("body", {}) if str(name)]
                if isinstance(report_seed, Mapping) and isinstance(report_seed.get("body"), Mapping)
                else []
            )
            names_in_config = list(dict.fromkeys(["action", "seed", *names, *report_body_names]))
            child_config = config_for(item)
            child_config["body_params"]["data"] = [
                {"name": name, "value": "fixture" if name == "action" else "fuzz"}
                for name in names_in_config
            ]
            child_config["body_params"]["fuzz"] = [
                name for name in names_in_config if name not in {"action", "seed"}
            ]
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

    def test_probe_artifact_failure_keeps_stage(self):
        """The stage tells operators whether the write or the correlation step failed.
        ReplayArtifactError subclasses RuntimeError, so reordering the except branches
        would silently report every write failure as id_correlation. A save that succeeds
        but leaves artifacts from another run must also be reported, not raised: the
        correlation check runs inside the same guarded step as the write."""
        from online_linked.coordination.errors import ReplayArtifactError

        def save_from_other_run(row, request_dir, zend_dir):
            name = str(row["matched_artifact"])
            request_dir.mkdir(parents=True, exist_ok=True)
            zend_dir.mkdir(parents=True, exist_ok=True)
            stem = Path(name).stem
            (request_dir / name).write_text(json.dumps(
                {"request_id": stem, "legacy_run_id": row["legacy_run_id"]}), encoding="utf-8")
            (zend_dir / name).write_text(json.dumps(
                {"request_id": stem, "run_id": "another-run"}), encoding="utf-8")

        cases = (
            ("write", ReplayArtifactError("request_write", "boom"), "request_write"),
            ("runtime", RuntimeError("boom"), "id_correlation"),
            ("mismatched_run", None, "id_correlation"),
        )
        for case, error, stage in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                log: list[str] = []
                coordinator, parent, evidence, convergence = self.make_probe_context(
                    Path(tmp), log, names=("a",), accepted=("a",),
                )

                def failing_save(row, request_dir, zend_dir, error=error):
                    raise error

                coordinator._save_replay_artifacts = save_from_other_run if error is None else failing_save
                outcome = coordinator._run_pending_probe_once(
                    parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                    convergence=convergence, probe=convergence["pending_probes"][0],
                    seed=parent["seed_item"], deadline=None,
                )

                self.assertIsNone(outcome)
                event = coordinator.state["events"][-1]
                self.assertEqual((event["status"], event["reason"], event["artifact_stage"]),
                                 ("REJECTED", "PROBE_ARTIFACT_CORRELATION_FAILED", stage))

    def test_probe_runner_sees_instance_overrides_made_after_construction(self):
        """Tests and campaign wiring replace limits and dependencies on a built coordinator;
        the probe code must read them when it runs, not capture them when it is created."""
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), log, names=("a",), accepted=("a",),
            )
            coordinator.MAX_PROBE_ATTEMPTS = 0

            outcome = coordinator._run_pending_probe_once(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=None,
            )

            self.assertIsNone(outcome)
            self.assertEqual(coordinator.state["events"][-1]["reason"], "PROBE_BUDGET_EXHAUSTED")
            self.assertNotIn("probe:a", log)

    def test_finish_probe_pending_timing_and_order(self):
        """Fake clocks advance on every call, so the number and order of clock() reads is part
        of the recorded timing; the event must be written before the checkpoint that saves it."""
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator, parent, evidence, _ = self.make_probe_context(Path(tmp), log, names=("a",))
            ticks = iter([10.0, 11.0, 12.0, 13.0])
            clock_calls: list[float] = []

            def clock():
                clock_calls.append(next(ticks))
                return clock_calls[-1]

            calls: list[str] = []
            coordinator.clock = clock
            coordinator._record_event = lambda event, checkpoint=True: calls.append("record_event") or dict(event)
            coordinator._write_state = lambda: calls.append("write_state")
            attempt = {"_verify_started_at": 3, "_started_at": 1, "probe_id": "p1", "candidate": {"name": "a"}}

            outcome = coordinator._probes._finish_probe_pending(
                parent, evidence, attempt, {"request_id": "probe-a"}, {"status": "CONTINUE"}, {"name": "a"},
            )

            self.assertEqual(outcome["status"], "pending")
            self.assertEqual(attempt["timing"], {"verify": 7.0, "total": 11.0})
            self.assertEqual(len(clock_calls), 4)
            self.assertEqual(calls, ["record_event", "write_state"])
            self.assertNotIn("_verify_started_at", attempt)
            self.assertNotIn("_started_at", attempt)

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

    def test_non_success_baseline_with_parameter_proof_hands_off(self):
        for status in (301, 302, 303, 304, 307, 308, 400, 403, 404, 500):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                log = []
                coordinator, parent, evidence, convergence = self.make_probe_context(
                    Path(tmp), log, names=("a",), accepted=("a",),
                )
                original = coordinator.probe_sender
                def sender(container, **kwargs):
                    result = original(container, **kwargs)
                    result["response_status"] = status
                    result["request"]["response"]["status_code"] = status
                    return result
                coordinator.probe_sender = sender
                child = coordinator._run_pending_probe(
                    parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                    convergence=convergence, probe=convergence["pending_probes"][0],
                    seed=parent["seed_item"], deadline=None,
                )
                self.assertIsNotNone(child)
                replay = child["replay_result"]
                self.assertNotIn("pass2_verification", replay)
                self.assertEqual(replay["runner"]["runs"][0]["response_status"], status)
                self.assertEqual(replay["verification_policy"], "parameter_replay_v1")
                self.assertTrue(replay["passed"])
                self.assertIn("worker_start", log)

    def test_disconnect_after_callback_cannot_prove_child_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), log, names=('a',), accepted=('a',),
            )
            original = coordinator.probe_sender
            def sender(container, **kwargs):
                result = original(container, **kwargs)
                if '-replay' in kwargs['run_id'] and 'replay-input' not in kwargs['run_id']:
                    result['error'] = 'connection closed after callback'
                return result
            coordinator.probe_sender = sender
            child = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports['v0'],
                convergence=convergence, probe=convergence['pending_probes'][0],
                seed=parent['seed_item'], deadline=None,
            )
            self.assertNotIn("pass2_verification", child["replay_result"])
            self.assertFalse(child['replay_result']['passed'])
            self.assertEqual(child['replay_result']['runner']['runs'][0]['http_error'], 'connection closed after callback')
            self.assertEqual(child['terminal_reason'], 'REPLAY_TRANSPORT_NOT_VERIFIED')
            self.assertNotIn('worker_start', log)

    def test_disagreeing_response_statuses_cannot_prove_child_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), log, names=('a',), accepted=('a',),
            )
            original = coordinator.probe_sender
            def sender(container, **kwargs):
                result = original(container, **kwargs)
                if '-replay' in kwargs['run_id'] and 'replay-input' not in kwargs['run_id']:
                    result['response_status'] = 200
                    result['request']['response']['status_code'] = 403
                return result
            coordinator.probe_sender = sender
            child = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports['v0'],
                convergence=convergence, probe=convergence['pending_probes'][0],
                seed=parent['seed_item'], deadline=None,
            )
            self.assertFalse(child['replay_result']['passed'])
            self.assertEqual(child['terminal_reason'], 'REPLAY_TRANSPORT_NOT_VERIFIED')
            self.assertNotIn('worker_start', log)

    def test_two_successful_probes_use_fuzz_values_in_child_but_keep_replay_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(Path(tmp), [], accepted=("a", "b"))
            result = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=None,
            )

            self.assertIsNotNone(result, json.dumps(coordinator.state, default=str))
            child = coordinator.state["versions"][1]
            child_config = json.loads(Path(child["config_path"]).read_text())
            values = {row["name"]: row["value"] for row in child_config["body_params"]["data"]}
            self.assertEqual(values["a"], "fuzz")
            self.assertEqual(values["b"], "fuzz")
            replay_config = json.loads(Path(child["replay_config_path"]).read_text())
            replay_values = {row["name"]: row["value"] for row in replay_config["body_params"]["data"]}
            self.assertEqual(replay_values["a"], "probe-a")
            self.assertEqual(replay_values["b"], "probe-b")
            seed_metadata = child_config["metadata"]["online_request_seed"]
            self.assertEqual(set(seed_metadata["evidence_request_ids"]), {"probe-a", "probe-b"})
            self.assertEqual(
                {row["name"]: row["request_id"] for row in seed_metadata["values"] if row["name"] in {"a", "b"}},
                {"a": "probe-a", "b": "probe-b"},
            )
            self.assertEqual(parent["known_parameters"], [])

    def test_error_probe_discovers_next_guard_before_strict_child_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), [], names=("a",), accepted=("a", "b"),
            )
            original_sender = coordinator.probe_sender
            original_converge = coordinator.converge_fn
            policies = []

            def sender(container, **kwargs):
                result = original_sender(container, **kwargs)
                is_probe = "-probe-" in kwargs["run_id"]
                policies.append((is_probe, kwargs["expected"].get("allow_error_responses", False)))
                config = json.loads((coordinator.config_root / (kwargs["config_slug"] + ".json")).read_text())
                body = {row["name"]: row["value"] for row in config["body_params"]["data"]}
                result["request"]["request_params"]["body_params"] = body
                if is_probe and "b" not in body:
                    result["request"]["response"]["status_code"] = 400
                elif not is_probe and "b" not in body:
                    return {"status": "timeout", "error": "STRICT_REPLAY_REQUIRES_B"}
                return result

            def converge(**kwargs):
                result = original_converge(**kwargs)
                item = kwargs["raw_report"]["suggested_seeds"][0]
                if item["seed"].get("seed_variant_id") == "zend_probe_post_a":
                    next_guard = {**convergence["pending_probes"][0], "name": "b",
                                  "request_id": "probe-a", "run_id": kwargs["legacy_run_id"]}
                    merged, pending = _materialize_ajax_runtime_probes(
                        {"suggested_seeds": [item]}, [next_guard],
                    )
                    result.update(merged_suggested_seeds=merged, pending_probes=pending)
                return result

            coordinator.probe_sender = sender
            coordinator.converge_fn = converge
            child = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=120.0,
            )
            self.assertEqual([p["candidate"]["name"] for p in coordinator.state["probe_attempts"]], ["a", "b"])
            self.assertIsNotNone(child)
            self.assertEqual({p["name"] for p in child["known_parameters"]}, {"a", "b"})
            self.assertTrue(child["replay_result"]["passed"])
            self.assertTrue(policies)
            self.assertTrue(all(discovery == is_probe for is_probe, discovery in policies))

    def test_parameter_replay_accepts_non_2xx_only_with_exact_batch_evidence(self):
        # HTTP status is a diagnostic: a 302/500 replay that proves the new field
        # hands off, while a 200 replay on the wrong branch or identity does not.
        def replay_case(mutate):
            tmp = tempfile.TemporaryDirectory()
            self.addCleanup(tmp.cleanup)
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp.name), log)
            sender = coordinator.probe_sender

            def edited(container, **kwargs):
                result = sender(container, **kwargs)
                if kwargs["run_id"].endswith("-replay") and result.get("request"):
                    mutate(result)
                return result

            coordinator.probe_sender = edited
            coordinator.run()
            return coordinator, log

        def status(code):
            def apply(result):
                result["response_status"] = code
                result["request"]["response"]["status_code"] = code
            return apply

        def events_for(result, name):
            return [event for event in result["zend"]["events"] if event["path"] == [name]]

        for code in (302, 500):
            with self.subTest(status=code):
                coordinator, log = replay_case(status(code))
                replay = coordinator.state["versions"][1]["replay_result"]
                self.assertTrue(replay["passed"], replay)
                self.assertEqual(replay["verification_policy"], "parameter_replay_v1")
                self.assertEqual(replay["response_status"], code)
                self.assertEqual([(row["bucket"], row["name"]) for row in replay["verified_parameters"]],
                                 [("body_params", "new_param")])
                self.assertEqual(log.count("worker_start"), 2)

        def drop_read(result):
            result["zend"]["events"] = [e for e in result["zend"]["events"] if e["path"] != ["new_param"]]

        def wrong_run(result):
            result["zend"]["run_id"] = "other-run"

        def wrong_callback(result):
            for event in events_for(result, "new_param"):
                event["callback_context"]["root_callback"] = "other_callback"

        def missing_key(result):
            result["request"]["request_params"]["body_params"].pop("new_param")

        def query_read(result):
            for event in events_for(result, "new_param"):
                event["source"] = "GET"

        for name, mutate in (("missing_read", drop_read), ("wrong_run", wrong_run),
                             ("wrong_callback", wrong_callback), ("missing_key", missing_key),
                             ("query_read_for_body_target", query_read)):
            with self.subTest(case=name):
                coordinator, log = replay_case(mutate)
                child = coordinator.state["versions"][1]
                self.assertFalse(child["replay_result"]["passed"])
                self.assertEqual(child["status"], "replay_failed")
                self.assertEqual(log.count("worker_start"), 1)
                self.assertIn("pause_released", log)

        # A batch is all-or-nothing: one unproven field rejects the whole replay.
        for drop in ((), ("b",)):
            with self.subTest(batch_drop=drop), tempfile.TemporaryDirectory() as tmp:
                coordinator, parent, evidence, convergence = self.make_probe_context(
                    Path(tmp), [], names=("a", "b"), accepted=("a", "b"),
                )
                sender = coordinator.probe_sender

                def partial(container, _sender=sender, _drop=drop, **kwargs):
                    result = _sender(container, **kwargs)
                    if kwargs["run_id"].endswith("-replay") and result.get("zend"):
                        result["zend"]["events"] = [e for e in result["zend"]["events"] if e["path"][0] not in _drop]
                    return result

                coordinator.probe_sender = partial
                child = coordinator._run_pending_probe(
                    parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                    convergence=convergence, probe=convergence["pending_probes"][0],
                    seed=parent["seed_item"], deadline=None,
                )
                self.assertIsNotNone(child)
                replay = child["replay_result"]
                self.assertEqual(sorted(row["name"] for row in replay["verified_parameters"]), ["a", "b"])
                self.assertEqual(replay["passed"], not drop)

    def test_admitted_probe_parameters_enter_one_callback_baseline(self):
        for names in (("nonce", "notice_id", "repeat_notice_after"),
                      ("repeat_notice_after", "notice_id", "nonce")):
            with self.subTest(names=names), tempfile.TemporaryDirectory() as tmp:
                coordinator, parent, evidence, convergence = self.make_probe_context(
                    Path(tmp), [], names=names, accepted=names,
                )
                child = coordinator._run_pending_probe(
                    parent=parent, evidence=evidence,
                    raw_report=coordinator._reports["v0"], convergence=convergence,
                    probe=convergence["pending_probes"][0], seed=parent["seed_item"], deadline=None,
                )
                self.assertIsNotNone(child)
                self.assertEqual(
                    [p["name"] for p in child["known_parameters"]],
                    ["nonce", "notice_id", "repeat_notice_after"],
                )
                self.assertTrue(child["replay_result"]["passed"])
                self.assertNotIn("replay_input_trials", coordinator.state)
                config = json.loads(Path(child["config_path"]).read_text())
                provenance = config["metadata"]["online_request_seed"]
                self.assertEqual(set(provenance["evidence_request_ids"]), {"probe-" + name for name in names})
                self.assertEqual({row["name"]: row["request_id"] for row in provenance["values"] if row["name"] in names},
                                 {name: "probe-" + name for name in names})
                self.assertEqual(coordinator.state["pending_runtime_candidates"], [])

    def test_baseline_does_not_require_missing_historical_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(Path(tmp), [])
            old = {"name": "old", "path": ["old"], "source": "POST", "location": "form",
                   "helper_depth": 0, "fuzzable": True, "observed_count": 1,
                   "evidence_kind": "zend_runtime", "canonical_callback": "fixture_callback",
                   "callback_id": "cb-fixture", "request_method": "POST"}
            parent["known_parameters"] = [old]
            original_converge = coordinator.converge_fn

            def converge(**kwargs):
                result = original_converge(**kwargs)
                if "-probe-" in kwargs["legacy_run_id"]:
                    result.update(status="REPLAY_FAILED", missing_parameters=[old],
                                  observed_parameters=result["new_parameters"])
                return result

            coordinator.converge_fn = converge
            child = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=None,
            )
            self.assertIsNotNone(child)
            self.assertTrue(child["replay_result"]["passed"])
            self.assertEqual({p["name"] for p in child["known_parameters"]}, {"old", "a", "b"})
            self.assertEqual(coordinator.state["pending_runtime_candidates"], [])

    def test_baseline_rejects_batch_when_admitted_parameter_is_not_read_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(Path(tmp), [])
            original_sender = coordinator.probe_sender

            def sender(container_name, **kwargs):
                result = original_sender(container_name, **kwargs)
                if kwargs["run_id"].endswith("-replay"):
                    # This callback cannot read a and b in the same request.
                    result["zend"]["events"] = [e for e in result["zend"]["events"] if e["path"] != ["a"]]
                    result["zend"]["callback_summaries"][0]["unique_parameters"] = [
                        p for p in result["zend"]["callback_summaries"][0]["unique_parameters"]
                        if p["name"] != "a"
                    ]
                return result

            coordinator.probe_sender = sender
            child = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=None,
            )
            self.assertIsNotNone(child)
            self.assertEqual({p["name"] for p in child["known_parameters"]}, {"a", "b"})
            self.assertFalse(child["replay_result"]["passed"])
            self.assertEqual(child["terminal_reason"], "PARAMETER_REPLAY_NOT_VERIFIED")
            self.assertEqual([row["name"] for row in child["replay_result"]["unverified_parameters"]], ["a"])
            self.assertNotIn("replay_input_trials", coordinator.state)

    def test_equivalent_branch_proposal_does_not_create_version_but_new_input_does(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, _ = self.make_probe_context(
                Path(tmp), [], names=("a",), accepted=(),
            )
            coordinator.handoff_to_next_worker = lambda *args, **kwargs: True
            coordinator.max_versions = 4
            current_nonce = "valid-a"
            original_export = coordinator.export_configs_fn

            def export_with_fixed_nonce(report, **kwargs):
                generated = original_export(report, **kwargs)
                path = Path(str(generated["generated"][0]["config_path"]))
                child_config = json.loads(path.read_text(encoding="utf-8"))
                section = child_config["body_params"]
                section["data"].append({"name": "nonce", "value": current_nonce})
                section["fixed"].append("nonce")
                section["fuzz"].append("nonce")
                path.write_text(json.dumps(child_config), encoding="utf-8")
                return generated

            coordinator.export_configs_fn = export_with_fixed_nonce

            def branch(name, request_id, run_id):
                parameter = {
                    "name": name, "path": [name], "source": "POST", "location": "form",
                    "helper_depth": 0, "observed_count": 1, "evidence_kind": "zend_runtime",
                    "fuzzable": True, "request_id": request_id, "run_id": run_id,
                    "plugin_slug": "fixture", "callback_id": "cb-fixture",
                    "canonical_callback": "fixture_callback", "request_method": "POST",
                }
                current_evidence = copy.deepcopy(evidence)
                current_evidence["request_id"] = request_id
                current_evidence["worker_run_id"] = run_id
                current_evidence["request"] = {
                    "request_id": request_id, "legacy_run_id": run_id,
                    "target_plugin": "fixture", "http_method": "POST",
                    "request_params": {"body_params": {"action": "fixture", name: "probe"}},
                }
                return current_evidence, {
                    "status": "REPLAY_FAILED",
                    "missing_parameters": [{"name": "guard", "source": "GET", "location": "query"}],
                    "observed_parameters": [parameter], "new_parameters": [], "known_parameters": [],
                }

            first_evidence, first_result = branch("a", "request-a", "run-a")
            first = coordinator._handle_convergence_result(
                parent=parent, evidence=first_evidence,
                raw_report=coordinator._reports["v0"], result=first_result,
                seed=parent["seed_item"], deadline=None,
            )
            self.assertIsNotNone(first)
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0", "v1"])

            duplicate_evidence, duplicate_result = branch("a", "request-a-new", "run-a-new")
            duplicate = coordinator._handle_convergence_result(
                parent=parent, evidence=duplicate_evidence,
                raw_report=coordinator._reports["v0"], result=duplicate_result,
                seed=parent["seed_item"], deadline=None,
            )
            self.assertIsNone(duplicate)
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0", "v1"])
            self.assertIn("NO_SEMANTIC_PROGRESS", json.dumps(coordinator.state["events"]))

            current_nonce = "valid-b"
            fixed_changed_evidence, fixed_changed_result = branch("a", "request-a-fixed", "run-a-fixed")
            fixed_changed = coordinator._handle_convergence_result(
                parent=parent, evidence=fixed_changed_evidence,
                raw_report=coordinator._reports["v0"], result=fixed_changed_result,
                seed=parent["seed_item"], deadline=None,
            )
            self.assertIsNotNone(fixed_changed)
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0", "v1", "v2"])

            repeated_fixed_evidence, repeated_fixed_result = branch(
                "a", "request-a-fixed-new", "run-a-fixed-new",
            )
            repeated_fixed = coordinator._handle_convergence_result(
                parent=parent, evidence=repeated_fixed_evidence,
                raw_report=coordinator._reports["v0"], result=repeated_fixed_result,
                seed=parent["seed_item"], deadline=None,
            )
            self.assertIsNone(repeated_fixed)

            distinct_evidence, distinct_result = branch("b", "request-b", "run-b")
            distinct = coordinator._handle_convergence_result(
                parent=parent, evidence=distinct_evidence,
                raw_report=coordinator._reports["v0"], result=distinct_result,
                seed=parent["seed_item"], deadline=None,
            )
            self.assertIsNotNone(distinct)
            self.assertEqual(
                [version["version"] for version in coordinator.state["versions"]],
                ["v0", "v1", "v2", "v3"],
            )

    def _ajax_runtime_row(self, name):
        return {
            "name": name, "path": [name], "source": "POST", "location": "form",
            "helper_depth": 0, "observed_count": 1, "evidence_kind": "zend_runtime",
            "fuzzable": True, "request_id": "req-v0", "run_id": "run-v0",
            "plugin_slug": "fixture", "callback_id": "cb-fixture",
            "canonical_callback": "fixture_callback", "request_method": "POST",
        }

    def test_ajax_trace_missing_known_field_keeps_union_and_resume_adds_no_version(self):
        # A saved REPLAY_FAILED result (older checkpoint shape) must not shrink
        # the AJAX config to the fields this one request touched.
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, _ = self.make_probe_context(Path(tmp), [], names=("a",), accepted=())
            handoffs = []
            coordinator.handoff_to_next_worker = lambda *args, **kwargs: handoffs.append(args[1]["version"]) or True
            coordinator.max_versions = 4
            parent["known_parameters"] = [self._ajax_runtime_row("a"), self._ajax_runtime_row("b")]
            saved = {
                "status": "REPLAY_FAILED", "missing_parameters": [self._ajax_runtime_row("b")],
                "observed_parameters": [self._ajax_runtime_row("a"), self._ajax_runtime_row("c")],
                "new_parameters": [], "known_parameters": [],
            }

            child = coordinator._handle_convergence_result(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                result=copy.deepcopy(saved), seed=parent["seed_item"], deadline=None,
            )

            self.assertIsNotNone(child)
            self.assertEqual({p["name"] for p in child["known_parameters"]}, {"a", "b", "c"})
            discovery = next(event for event in coordinator.state["events"]
                             if event.get("kind") == "PARAMETER_DISCOVERY" and event.get("status") == "ACCEPTED")
            self.assertEqual([p["name"] for p in discovery["parameters"]], ["c"])
            self.assertEqual([p["name"] for p in discovery["unobserved_known_parameters"]], ["b"])
            self.assertNotIn("MISSING_PARAMETERS", json.dumps(coordinator.state["events"]))

            again = coordinator._handle_convergence_result(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                result=copy.deepcopy(saved), seed=parent["seed_item"], deadline=None,
            )
            self.assertIsNone(again)
            self.assertEqual([v["version"] for v in coordinator.state["versions"]], ["v0", "v1"])
            self.assertEqual(handoffs, ["v1"])

    def test_legacy_per_field_probe_queue_skips_field_admitted_from_earlier_trace(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator, parent, evidence, convergence = self.make_probe_context(Path(tmp), log)
            original_sender, original_converge = coordinator.probe_sender, coordinator.converge_fn

            def sender(container, **kwargs):
                result = original_sender(container, **kwargs)
                if kwargs["run_id"].endswith("-probe-p1"):
                    # The trace of probe a also checks isset() on b, which was never sent.
                    result["request"].setdefault("request_params", {})["headers"] = {
                        "Content-Type": "application/x-www-form-urlencoded",
                    }
                    result["zend"]["callback_summaries"][0]["unique_parameters"].append({
                        "name": "b", "source": "POST", "path": ["b"], "helper_depth": 5,
                        "observed_count": 1, "access_forms": ["isset"],
                    })
                    result["zend"]["events"].append({
                        "source": "POST", "path": ["b"], "operation": "isset",
                        "callback_context": {"attributed": True, "root_callback": "fixture_callback", "depth": 5},
                    })
                return result

            def converge(**kwargs):
                result = original_converge(**kwargs)
                if kwargs["legacy_run_id"].endswith("-probe-p1"):
                    extra = {**result["new_parameters"][0], "name": "b", "path": ["b"]}
                    result["new_parameters"] = result["new_parameters"] + [extra]
                    result["known_parameters"] = result["new_parameters"]
                return result

            coordinator.probe_sender, coordinator.converge_fn = sender, converge
            child = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=None,
            )

            self.assertIsNotNone(child)
            self.assertEqual(log.count("probe:a"), 1)
            self.assertNotIn("probe:b", log)
            self.assertEqual({p["name"] for p in child["known_parameters"]}, {"a", "b"})
            self.assertEqual([v["version"] for v in coordinator.state["versions"]], ["v0", "v1"])

    def test_field_admitted_in_get_context_does_not_skip_post_context_probe(self):
        # Method is part of the context, so a GET proof never stands in for POST.
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), log, names=("b",), accepted=("b",),
            )
            convergence = {**convergence, "new_parameters": [
                {**self._ajax_runtime_row("b"), "source": "POST", "request_method": "GET"},
            ]}
            coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=None,
            )
            self.assertIn("probe:b", log)
            self.assertNotIn("ADMITTED_FROM_TRACE", json.dumps(coordinator.state["events"]))

    def test_batch_from_failed_child_baseline_joins_next_ajax_update(self):
        # A failed baseline must not drop its batch: the parent keeps fuzzing,
        # so the next update has to carry {a, b} together with the new field.
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, _ = self.make_probe_context(Path(tmp), [], names=("a",), accepted=())
            coordinator.max_versions = 4
            original = coordinator.probe_sender
            replays = []

            def sender(container, **kwargs):
                result = original(container, **kwargs)
                if kwargs["run_id"].endswith("-replay"):
                    replays.append(kwargs["run_id"])
                    if len(replays) == 1:
                        result["request"]["callback_id"] = "other-callback"
                return result

            coordinator.probe_sender = sender

            def trace(*names):
                rows = [self._ajax_runtime_row(name) for name in names]
                return {"status": "CONTINUE", "new_parameters": rows, "known_parameters": rows,
                        "observed_parameters": rows}

            failed = coordinator._handle_convergence_result(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                result=trace("a", "b"), seed=parent["seed_item"], deadline=None,
            )
            self.assertFalse(failed["replay_result"]["passed"])
            self.assertEqual(coordinator._active_container, "parent-container")

            child = coordinator._handle_convergence_result(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                result=trace("d"), seed=parent["seed_item"], deadline=None,
            )

            self.assertEqual(child["version"], "v2")
            self.assertTrue(child["replay_result"]["passed"])
            self.assertEqual({p["name"] for p in child["known_parameters"]}, {"a", "b", "d"})
            config = json.loads(Path(child["config_path"]).read_text(encoding="utf-8"))
            self.assertTrue({"a", "b", "d"} <= set(config["body_params"]["fuzz"]))
            discovery = [event for event in coordinator.state["events"]
                         if event.get("kind") == "PARAMETER_DISCOVERY" and event.get("status") == "ACCEPTED"][-1]
            self.assertEqual([p["name"] for p in discovery["parameters"]], ["d"])
            self.assertEqual({p["name"] for p in discovery["carried_parameters"]}, {"a", "b"})

    def test_failed_baseline_of_grouped_trace_keeps_full_draft_and_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(Path(tmp), [])
            original = coordinator.probe_sender

            def sender(container, **kwargs):
                result = original(container, **kwargs)
                if kwargs["run_id"].endswith("-replay"):
                    result["request"]["callback_id"] = "other-callback"
                return result

            coordinator.probe_sender = sender
            child = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=None,
            )
            self.assertFalse(child["replay_result"]["passed"])
            self.assertTrue(child["terminal_reason"])
            self.assertEqual({p["name"] for p in child["known_parameters"]}, {"a", "b"})
            draft = json.loads(Path(child["config_path"]).read_text(encoding="utf-8"))
            self.assertTrue({"a", "b"} <= set(draft["body_params"]["fuzz"]))
            self.assertEqual(coordinator._active_container, "parent-container")
            self.assertEqual({p["name"] for p in coordinator.state["pending_runtime_candidates"]}, {"a", "b"})

    def test_semantic_progress_keeps_fixed_input_and_transport_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, _, _ = self.make_probe_context(
                Path(tmp), [], names=("a",), accepted=(),
            )
            config = config_for(parent["seed_item"])
            config["body_params"]["data"].append({"name": "mode", "value": "one"})
            config["body_params"]["fixed"].append("mode")
            config_path = coordinator._write_config("v1", config)
            published = coordinator._new_version(
                "v1", config, config_path, parent, None, parent["seed_item"],
            )
            published["known_parameters"] = [{
                "name": "a", "source": "POST", "location": "form",
            }]

            known = published["known_parameters"]
            self.assertEqual(
                coordinator._published_config_with_same_request(copy.deepcopy(config), known)["version"],
                "v1",
            )

            changed_value = copy.deepcopy(config)
            changed_value["body_params"]["data"][-1]["value"] = "two"
            self.assertIsNone(coordinator._published_config_with_same_request(changed_value, known))

            changed_transport = copy.deepcopy(config)
            changed_transport["query_params"] = {
                "data": [{"name": "a", "value": "fuzz"}],
                "fixed": [], "fuzz": ["a"], "weight": 1,
            }
            self.assertIsNone(coordinator._published_config_with_same_request(
                changed_transport,
                [{"name": "a", "source": "GET", "location": "query"}],
            ))

    def test_config_request_key_matches_fixed_priority_and_selector_patterns(self):
        def config(*, nonce_value="valid-a", fuzz_value="one", query=False):
            section = {
                "data": [
                    {"name": "nonce", "value": nonce_value},
                    {"name": "fuzz_token", "value": fuzz_value},
                ],
                "fixed": ["nonce"],
                "fuzz": ["nonce", "fuzz_.*"],
                "weight": 1,
            }
            result = {
                "target": "http://web/wp-admin/admin-ajax.php",
                "methods": ["POST"],
                "body_params": section,
            }
            if query:
                result["query_params"] = result.pop("body_params")
            return result

        fixed_changed = config(nonce_value="valid-b")
        self.assertNotEqual(
            OnlineLinkedCoordinator._config_request_key(config()),
            OnlineLinkedCoordinator._config_request_key(fixed_changed),
        )
        fuzz_changed = config(fuzz_value="two")
        self.assertEqual(
            OnlineLinkedCoordinator._config_request_key(config()),
            OnlineLinkedCoordinator._config_request_key(fuzz_changed),
        )
        self.assertNotEqual(
            OnlineLinkedCoordinator._config_request_key(config()),
            OnlineLinkedCoordinator._config_request_key(config(query=True)),
        )

    def test_request_matching_keys_are_stable(self):
        """Published-config dedupe, priority-seed reuse and probe dedupe compare these keys
        against values stored in earlier checkpoints, so moving code must not change them."""
        from online_linked.coordination.request_matching import _coherent_evidence_key, probe_context_key
        from online_linked.coordinator import _parameter_key, _request_payload_hash

        config = {
            "target": "http://web/wp-admin/admin-ajax.php",
            "methods": ["POST"],
            "body_params": {
                "data": [{"name": "nonce", "value": "valid-a"}, {"name": "fuzz_token", "value": "one"}],
                "fixed": ["nonce"],
                "fuzz": ["nonce", "fuzz_.*"],
                "weight": 1,
            },
        }
        self.assertEqual(
            OnlineLinkedCoordinator._config_request_key(config),
            '{"body_params":{"data":[{"name":"nonce","value":"valid-a"},'
            '{"name":"fuzz_token","value":"<fuzzable>"}]},"entrypoint_type":null,'
            '"methods":["POST"],"target":"http://web/wp-admin/admin-ajax.php"}',
        )
        request = {
            "http_method": "post",
            "http_target": "http://web/wp-admin/admin-ajax.php?action=x",
            "endpoint": "admin-ajax",
            "request_params": {
                "query_params": {"action": "x"},
                "body_params": {"nonce": "a"},
                "cookies": {"c": "1"},
                "headers": {"User-Agent": "UA", "X-Fuzzer-Id": "9"},
            },
        }
        self.assertEqual(
            _request_payload_hash(request),
            "e6636f58129fb96e9ccb7ac95ed1f23e34d26fd056e650de7d7003d0c03a0b83",
        )
        self.assertEqual(
            _coherent_evidence_key({"request_id": "r1", "run_id": "w1", "request": request}),
            ("r1", "w1", "7400a83139b97a74252c7b291cd13aa949ca18412226ea69583499ffa0ce4a85"),
        )
        self.assertEqual(_parameter_key({"name": "n", "source": "post", "location": "form"}), ("n", "POST", "form"))
        # Stored in checkpoints to skip probes already tried; value captured at 87da6907.
        parent = {"version": "v2", "worker_run_id": "run-v2", "callback_id": "cb1", "hook_name": "wp_ajax_x",
                  "entrypoint_type": "ajax", "canonical_callback": "Plugin::handle", "resolved_method": "post"}
        probe_evidence = {"request": {"request_params": {
            "query_params": {"action": "x"}, "body_params": {"n": [1, "a"]},
            "cookies": {"c": "1"}, "headers": {"X-Ignored": "1"},
        }}}
        self.assertEqual(
            probe_context_key(parent, {"name": "n", "source": "post", "location": "form"}, probe_evidence,
                              plugin_slug="fixture"),
            '["v2","run-v2","cb1","wp_ajax_x","ajax","n","POST","form","cb1","fixture","Plugin::handle","POST",'
            '"f0a7440e2b4b1053c7b9aa938ec69adf3a67846ee206504f2bd7f42563690cb1"]',
        )
        # Probe and handoff request IDs are matched against worker artifacts; value captured after wave 2.
        from online_linked.coordinator import _request_id
        self.assertEqual(_request_id("run-v1-probe-p1"), "r-d97f3ba0aeffe293249595c2")

    def test_resume_reports_first_incompatible_field(self):
        """Users read the first resume error to learn why a run cannot continue, so the check
        order is part of the contract: budget policy is reported before candidate context."""
        from online_linked.coordination.checkpoint import validate_resume_checkpoint

        expected = {
            "plugin_slug": "fixture", "legacy_run_id": "run", "max_seconds": 60, "hard_seconds": 120,
            "hard_versions": 4, "runtime_cookie_probes": False, "initial_max_versions": 2,
        }
        saved = {
            **expected, "budget_policy": "progress_idle_v1", "context_key_version": 1,
            "queued_candidate_context_keys": [], "terminal_status": "PARTIAL",
            "checkpoint": {"context_key_version": 1},
        }
        validate_resume_checkpoint(saved, expected=expected)
        with self.assertRaisesRegex(ValueError, "^resume budget policy incompatible"):
            validate_resume_checkpoint(
                {**saved, "budget_policy": "old", "plugin_slug": "other"}, expected=expected)
        with self.assertRaisesRegex(ValueError, "^resume candidate context changed: plugin_slug$"):
            validate_resume_checkpoint({**saved, "plugin_slug": "other"}, expected=expected)

    def test_replay_failed_branch_still_services_independent_pending_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), [], names=("body_candidate",), accepted=("body_candidate",),
            )
            failed_branch = {
                **convergence,
                "status": "REPLAY_FAILED",
                "missing_parameters": [{"name": "guard_value", "source": "GET", "location": "query"}],
                "new_parameters": [],
                "known_parameters": [],
                "observed_parameters": [{
                    **convergence["pending_probes"][0],
                    "fuzzable": False,
                    "candidate_status": "pending_probe",
                }],
            }

            coordinator._handle_convergence_result(
                parent=parent, evidence=evidence,
                raw_report=coordinator._reports["v0"], result=failed_branch,
                seed=parent["seed_item"], deadline=None,
            )

            self.assertEqual(
                [item["candidate"]["name"] for item in coordinator.state["probe_attempts"]],
                ["body_candidate"],
            )

    def test_failed_baseline_preserves_runtime_candidates_and_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(Path(tmp), [])
            original = coordinator.probe_sender
            def sender(container, **kwargs):
                result = original(container, **kwargs)
                if kwargs["run_id"].endswith("-replay"):
                    result["request"]["auth_context"] = "other"
                return result
            coordinator.probe_sender = sender
            child = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=None,
            )
            self.assertFalse(child["replay_result"]["passed"])
            self.assertEqual(coordinator._active_container, "parent-container")
            self.assertEqual({p["name"] for p in coordinator.state["pending_runtime_candidates"]}, {"a", "b"})

    def test_unbounded_two_probes_keep_independent_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), log, accepted=("a", "b"))
            result = coordinator._run_pending_probe(
                parent=parent, evidence=evidence,
                raw_report=coordinator._reports["v0"], convergence=convergence,
                probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=None)
            self.assertIsNotNone(result)
            self.assertEqual([p["status"] for p in coordinator.state["probe_attempts"]],
                             ["accepted", "accepted"])
            self.assertEqual([v["version"] for v in coordinator.state["versions"]],
                             ["v0", "v1"])
            child = json.loads(Path(coordinator.state["versions"][1]["config_path"]).read_text())
            values = {p["name"]: p["value"] for p in child["body_params"]["data"]}
            self.assertEqual((values["a"], values["b"]), ("fuzz", "fuzz"))
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
            self.assertEqual(values["a"], "fuzz")
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
                    "name": "existing", "path": ["existing"], "source": "POST", "location": "form", "helper_depth": 0,
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
                self.assertEqual(child_names, {"a", "existing"} if deadline is None else {"existing"})
                if deadline is None:
                    self.assertEqual(coordinator.state["pending_runtime_candidates"], [])
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
                ["pending", "accepted"],
                coordinator.state["events"],
            )
            self.assertEqual(coordinator.state["probe_attempts"][1]["request_id"], "req-v0")
            # b is already admitted, so the re-queued probe under probe-a is not sent again.
            self.assertIn("ADMITTED_FROM_TRACE", json.dumps(coordinator.state["events"]))
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
                seed_variant = kwargs["raw_report"]["suggested_seeds"][0]["seed"].get("seed_variant_id")
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

    def test_measured_sender_cost_reserves_time_for_baseline_and_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(Path(tmp), [])
            coordinator.hard_seconds = 5
            original_sender = coordinator.probe_sender

            def sender(container_name, **kwargs):
                result = original_sender(container_name, **kwargs)
                coordinator.sleeper(1.0)
                return result

            coordinator.probe_sender = sender
            child = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=5.0,
            )
            self.assertIsNotNone(child)
            self.assertTrue(child["replay_result"]["passed"])
            self.assertEqual([p["candidate"]["name"] for p in coordinator.state["probe_attempts"]], ["a"])
            deferred = [e for e in coordinator.state["events"] if e.get("status") == "DEFERRED"]
            self.assertEqual(deferred[0]["candidate"]["name"], "b")
            self.assertLess(coordinator.clock(), 5.0)

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
                ["accepted"],
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

            self.assertEqual([row["candidate"]["name"] for row in coordinator.state["pending_probe_queue"]], ["b"])

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
                ["accepted"],
            )
            self.assertEqual(
                [row["version"] for row in coordinator.state["versions"]],
                ["v0", "v1"],
            )
            child = coordinator.state["versions"][1]
            self.assertEqual({row["name"] for row in child["known_parameters"]}, {"a"})
            self.assertTrue(child["replay_result"]["passed"])
            self.assertEqual(child["replay_result"]["verification_policy"], "parameter_replay_v1")
            self.assertEqual(coordinator._active_version, "v1")
            self.assertTrue(coordinator._active_container)
            self.assertEqual(parent["known_parameters"], [])

            self.assertEqual([row["candidate"]["name"] for row in coordinator.state["pending_probe_queue"]], ["b"])

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
                "force_replay_only", "run_generated_configs",
            }}
            self.assertLess(positions["build_config"], positions["list_targets"])
            self.assertLess(positions["list_targets"], positions["worker_start"])
            self.assertLess(positions["worker_start"], positions["converge_iteration"])
            self.assertLess(positions["converge_iteration"], positions["materialize_convergence_seeds"])
            self.assertLess(positions["materialize_convergence_seeds"], positions["export_seed_configs"])
            self.assertLess(positions["export_seed_configs"], positions["force_replay_only"])
            self.assertLess(positions["force_replay_only"], positions["run_generated_configs"])
            self.assertNotIn("verify_pass2_contract", log)

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


    def test_child_baseline_sends_once_without_trials_or_pass2(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), [], names=("a",), accepted=("a",),
            )
            sends = []
            original_sender = coordinator.probe_sender

            def sender(container, **kwargs):
                sends.append(kwargs["run_id"])
                return original_sender(container, **kwargs)

            coordinator.probe_sender = sender
            coordinator.verify_pass2_fn = lambda *args, **kwargs: (_ for _ in ()).throw(
                AssertionError("online-linked baseline must not call Pass 2")
            )
            child = coordinator._run_pending_probe(
                parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                convergence=convergence, probe=convergence["pending_probes"][0],
                seed=parent["seed_item"], deadline=None,
            )

            self.assertIsNotNone(child)
            self.assertEqual(len([run for run in sends if run.endswith("-replay")]), 1)
            self.assertFalse(any("replay-input" in run for run in sends))
            result = child["replay_result"]
            self.assertEqual(result["verification_policy"], "parameter_replay_v1")
            self.assertTrue(result["passed"])
            self.assertEqual(set(result["baseline_evidence"]), {
                "request_id", "run_id", "plugin_slug", "callback_id",
                "http_method", "auth_context", "seed_variant_id",
            })
            self.assertNotIn("pass2_verification", result)
            self.assertNotIn("replay_input_trials", coordinator.state)

    def test_baseline_identity_mismatches_block_child(self):
        for field, value in (
            ("callback_id", "other"), ("request_id", "other"), ("run_id", "other"),
            ("target_plugin", "other"), ("http_method", "GET"),
            ("auth_context", "other"), ("seed_variant_id", "other"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                coordinator, parent, evidence, convergence = self.make_probe_context(
                    Path(tmp), [], names=("a",), accepted=("a",),
                )
                original_sender = coordinator.probe_sender

                def sender(container, **kwargs):
                    result = original_sender(container, **kwargs)
                    if result.get("request") and kwargs["run_id"].endswith("-replay"):
                        result["request"] = dict(result["request"])
                        if field in {"request_id", "run_id", "target_plugin", "callback_id", "auth_context", "http_method"}:
                            result["request"][field] = value
                        elif field == "seed_variant_id":
                            result["request"][field] = value
                    return result

                coordinator.probe_sender = sender
                child = coordinator._run_pending_probe(
                    parent=parent, evidence=evidence, raw_report=coordinator._reports["v0"],
                    convergence=convergence, probe=convergence["pending_probes"][0],
                    seed=parent["seed_item"], deadline=None,
                )
                self.assertIsNotNone(child)
                self.assertFalse(child["replay_result"]["passed"])
                self.assertNotEqual(child["worker_status"], "started")

    def test_v0_baseline_allows_missing_historical_parameter(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [], discovers_parameter=False)
            coordinator.converge_fn = lambda **kwargs: {
                "status": "REPLAY_FAILED", "missing_parameters": [{"name": "old"}],
                "new_parameters": [], "known_parameters": [],
            }
            self.assertEqual(coordinator.run(), 0)
            readiness = coordinator.state["versions"][0]["readiness"]
            self.assertTrue(readiness["passed"])
            self.assertEqual(readiness["verification_policy"], "callback_baseline_v1")
            self.assertEqual(readiness["baseline_evidence"]["plugin_slug"], "fixture")


    def test_baseline_identity_accepts_201_but_rejects_auth_or_callback_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, _, _ = self.make_probe_context(Path(tmp), [])
            request = {
                "request_id": "baseline", "run_id": parent["worker_run_id"],
                "target_plugin": "fixture", "hook_name": parent["hook_name"],
                "callback_id": parent["callback_id"], "auth_context": parent["auth_context"],
                "http_method": "POST", "response": {"status_code": 201},
            }
            zend = {"request_method": "POST", "request_id": "baseline", "run_id": parent["worker_run_id"]}

            self.assertTrue(coordinator._baseline_identity_complete(request, zend, parent))
            for field, value in (("auth_context", "authenticated"), ("callback_id", "other-callback")):
                with self.subTest(field=field):
                    mismatched = {**request, field: value}
                    self.assertFalse(coordinator._baseline_identity_complete(mismatched, zend, parent))


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
            self.assertEqual(coordinator.run(), 0, coordinator.state["terminal_reason"])
            self.assertIn("pause_released", log)
            self.assertEqual(len(coordinator.state["versions"]), 2)
            self.assertEqual(coordinator.state["versions"][1]["status"], "replay_failed")
            self.assertEqual([item for item in coordinator.state["workers"] if item["version"] == "v1"], [])
            self.assertEqual(log.count("worker_start"), 1)

    def test_replay_failure_keeps_parent_without_child_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, replay_passes=False, max_versions=2)
            self.assertEqual(coordinator.run(), 0, coordinator.state["terminal_reason"])
            self.assertEqual(len(coordinator.state["versions"]), 2)
            self.assertEqual(coordinator.state["versions"][1]["status"], "replay_failed")
            self.assertEqual([item for item in coordinator.state["workers"] if item["version"] == "v1"], [])
            self.assertEqual(log.count("worker_start"), 1)
            state = json.loads(coordinator.state_path.read_text())
            self.assertNotEqual(state["terminal_reason"], "CHILD_REPLAY_FAILED")
            self.assertEqual(state["versions"][1]["terminal_reason"], "REPLAY_PROCESS_FAILED")
            self.assertIn("pause_released", log)

    def test_not_verified_stops_candidate_before_budget_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator = self.make_coordinator(Path(tmp), log, max_seconds=120)
            run_command = coordinator.run_command

            def fail_child(command, **kwargs):
                if command[:3] == ["docker", "compose", "run"] and "HOOKPHUZZ_LEGACY_RUN_ID=run-v1" in command:
                    return subprocess.CompletedProcess(command, 1, "", "child failed")
                return run_command(command, **kwargs)

            coordinator.run_command = fail_child
            started = coordinator.clock()
            self.assertNotEqual(coordinator.run(), 0)
            self.assertLess(coordinator.clock() - started, 1)
            self.assertEqual(coordinator.state["terminal_status"], "NOT_VERIFIED")
            self.assertEqual(coordinator.state["terminal_reason"], "CHILD_WORKER_START_FAILED")
            self.assertEqual(coordinator.state["workers"][0]["status"], "stopped")

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
                # The old worker is still the one running: do not leave it paused.
                self.assertIn("pause_released", log)

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
                if admitted:
                    def cookie_sender(container_name, **kwargs):
                        config_path = coordinator.config_root / f'{kwargs["config_slug"]}.json'
                        config = json.loads(config_path.read_text(encoding="utf-8"))
                        cookies = {
                            row["name"]: row["value"]
                            for row in config.get("cookies", {}).get("data", [])
                            if isinstance(row, Mapping) and row.get("name")
                        }
                        request_id = kwargs["request_id"]
                        run_id = kwargs["run_id"]
                        return {
                            "status": "callback_reached",
                            "callback_reached": True,
                            "validation_status": "callback_reached",
                            "request_name": f"{request_id}.json",
                            "request": {
                                "request_id": request_id,
                                "legacy_run_id": run_id,
                                "target_plugin": "fixture",
                                "hook_name": parent["hook_name"],
                                "callback_id": parent["callback_id"],
                                "auth_context": parent["auth_context"],
                                "http_method": "POST",
                                "request_params": {"body_params": {"action": "fixture"}, "cookies": cookies},
                            },
                            "zend_name": f"{request_id}.json",
                            "zend": {
                                "request_id": request_id,
                                "run_id": run_id,
                                "request_method": "POST",
                                "callback_summaries": [{
                                    "callback": "fixture_callback",
                                    "unique_parameters": [{
                                        "name": "fixture_cookie", "source": "COOKIE",
                                        "path": ["fixture_cookie"], "helper_depth": 1,
                                        "observed_count": 1, "access_forms": ["read"],
                                    }],
                                }],
                                "events": [{
                                    "source": "COOKIE", "path": ["fixture_cookie"],
                                    "operation": "read",
                                    "callback_context": {
                                        "attributed": True, "root_callback": "fixture_callback", "depth": 1,
                                    },
                                }],
                            },
                            "timing": {},
                        }
                    coordinator.probe_sender = cookie_sender
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
                self.assertEqual(cookie_rows["fixture_cookie"]["value"], "fuzz")
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
                if replay_passes:
                    self.assertNotEqual(coordinator.run(), 0)
                    self.assertEqual(coordinator.state["terminal_status"], "NOT_VERIFIED")
                    self.assertEqual(coordinator.state["terminal_reason"], "CHILD_WORKER_START_FAILED")
                else:
                    # A rejected baseline resumes the paused parent instead of ending the callback.
                    self.assertEqual(coordinator.run(), 0, coordinator.state["terminal_reason"])
                    self.assertNotEqual(coordinator.state["terminal_reason"], "CHILD_REPLAY_FAILED")
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
                coordinator.hard_seconds = coordinator.max_seconds
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
                coordinator.hard_seconds = coordinator.max_seconds
                replay_runner = coordinator.replay_runner

                def slow_replay(*args, **kwargs):
                    if kwargs['legacy_run_id'] != 'run-v0':
                        coordinator.sleeper(3)
                    return replay_runner(*args, **kwargs)

                coordinator.replay_runner = slow_replay
                self.assertEqual(coordinator.run(), 0, coordinator.state["terminal_reason"])
                self.assertEqual(log.count("worker_start"), 1)
                self.assertFalse(coordinator.state["versions"][1]["replay_result"]["passed"])
                self.assertEqual(coordinator.state["terminal_status"], "PARTIAL")
                self.assertEqual(coordinator.state["terminal_reason"], "HARD_CANDIDATE_TIME_CAP")
                child = coordinator.state["versions"][1]
                self.assertEqual(child["terminal_reason"], "CANDIDATE_BUDGET_EXPIRED")
                replay = child["replay_result"]
                self.assertEqual(replay["runner"]["runs"][0]["callback_reached"], replay_passes)
                self.assertTrue(replay["budget_expired"])

    def test_deadline_spent_verifying_baseline_does_not_admit_a_late_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            coordinator.hard_seconds = coordinator.max_seconds
            original = coordinator._baseline_identity_complete
            def verify(request, zend, version):
                result = original(request, zend, version)
                if str(version.get("worker_run_id", "")).endswith("-v1-replay"):
                    coordinator.sleeper(3)
                return result
            coordinator._baseline_identity_complete = verify
            coordinator.run()
            child = coordinator.state["versions"][1]
            self.assertFalse(child["replay_result"]["passed"])
            self.assertEqual(child["terminal_reason"], "CANDIDATE_BUDGET_EXPIRED")
            self.assertTrue(child["replay_result"]["runner"]["runs"][0]["callback_reached"])

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
            initial, child = coordinator.state["workers"]
            self.assertNotIn("HOOKPHUZZ_PRIORITY_SEED", worker_env(initial))
            self.assertIn("HOOKPHUZZ_PRIORITY_SEED", worker_env(child))
            self.assertFalse(any("NEW_PARAMETER_ENERGY_BONUS" in arg for arg in initial["command"] + child["command"]))
            replay_event = [event for event in coordinator.state["events"] if event.get("kind") == "CHILD_REPLAY"][-1]
            self.assertEqual(replay_event["timing"], coordinator.state["versions"][1]["replay_result"]["timing"])

    def test_priority_descriptor_follows_verified_targets_and_is_granted_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            coordinator.priority_energy_mode = "carryover"
            self.assertEqual(coordinator.run(), 0, coordinator.state["terminal_reason"])
            initial, started = (worker_env(worker) for worker in coordinator.state["workers"])
            child = coordinator.state["versions"][1]
            descriptor = json.loads(started["HOOKPHUZZ_PRIORITY_SEED"])
            self.assertEqual(descriptor, {
                "replay_slug": Path(child["replay_config_path"]).relative_to(coordinator.config_root)
                .with_suffix("").as_posix(),
                "replay_hash": child["replay_config_hash"],
                "targets": [["body_params", "new_param"]],
                "mode": "carryover", "allocated_energy": 20, "attempts_used": 9,
            })
            # Each immutable config gets its own sync namespace.
            self.assertNotEqual(initial["HOOKPHUZZ_SYNC_NAMESPACE"], started["HOOKPHUZZ_SYNC_NAMESPACE"])
            event = next(e for e in coordinator.state["events"] if e.get("kind") == "PRIORITY_SEED")
            self.assertEqual((event["status"], event["discovery_request_id"], event["pause_round_id"]),
                             ("GRANTED", "req-v0", 1))
            # A restarted worker of an activated config never gets the round again.
            coordinator._stop_worker(child, "TEST_RESTART")
            self.assertTrue(coordinator._start_worker(child, priority_seed=descriptor))
            self.assertNotIn("HOOKPHUZZ_PRIORITY_SEED", worker_env(coordinator.state["workers"][-1]))

    def test_seed_energy_is_carried_only_for_the_verified_request(self):
        # Energy 31 belongs to the old worker's request; it is the seed's only if the replay sends that payload.
        same_body = {"action": "fixture", "seed": "base", "new_param": "fuzz"}
        other = lambda request: {**request, "request_id": "another-request", "round_id": 1,
                                 "allocated_energy": 20, "attempts_used": 9, "seed_phuzz_energy": 31}

        def shape(request, run, *, cookie="old", feature="on", agent="Desktop", accept="text/html"):
            # Same request as sent, except the fuzzer's own per-request tracking headers.
            request["http_target"] = "http://web/wp-admin/admin-ajax.php"
            request["request_params"].update(
                body_params=dict(same_body), cookies={"profile": cookie},
                headers={"Content-Type": "application/x-www-form-urlencoded", "X-Feature": feature,
                         "User-Agent": agent, "Accept": accept,  # WordPress reads both (wp_is_mobile)
                         "X-Fuzzer-Covid": run, "X-HookPhuzz-Run-ID": run, "X-HookPhuzz-Request-ID": run},
            )

        for case, pause_ack, replay_shape, expected in (
                ("other_request", other, None, None), ("payload_changed", None, None, None),
                ("same_payload", None, {}, 31), ("cookie_changed", None, {"cookie": "new"}, None),
                ("header_changed", None, {"feature": "off"}, None),
                ("user_agent_changed", None, {"agent": "Mobile"}, None),
                ("accept_changed", None, {"accept": "application/json"}, None)):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                coordinator = self.make_coordinator(Path(tmp), [], pause_ack=pause_ack)
                if replay_shape is not None:
                    load, sender = coordinator.load_artifact, coordinator.probe_sender

                    def load_same(name, _load=load):
                        payload = _load(name)
                        shape(payload, "worker")
                        return payload

                    def send_same(container, _sender=sender, _replay=replay_shape, **kwargs):
                        result = _sender(container, **kwargs)
                        if kwargs["run_id"].endswith("-replay") and result.get("request"):
                            shape(result["request"], "replay-run", **_replay)
                        return result

                    coordinator.load_artifact, coordinator.probe_sender = load_same, send_same
                self.assertEqual(coordinator.run(), 0, coordinator.state["terminal_reason"])
                descriptor = json.loads(worker_env(coordinator.state["workers"][-1])["HOOKPHUZZ_PRIORITY_SEED"])
                self.assertEqual(descriptor.get("seed_phuzz_energy"), expected)

    def test_handoff_without_new_fuzzable_field_keeps_parent(self):
        # The plan switches config only for a new fuzzable param: a batch that is all fixed keeps v0.
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            export = coordinator.export_configs_fn

            def export_fixed(report, **kwargs):
                summary = export(report, **kwargs)
                path = Path(summary["generated"][0]["config_path"])
                config = json.loads(path.read_text(encoding="utf-8"))
                config["body_params"]["fixed"].append("new_param")
                path.write_text(json.dumps(config), encoding="utf-8")
                return summary

            coordinator.export_configs_fn = export_fixed
            coordinator.run()
            child = coordinator.state["versions"][1]
            self.assertTrue(child["replay_result"]["passed"] is False)
            self.assertEqual(child["terminal_reason"], "NO_NEW_FUZZABLE_TARGET")
            self.assertEqual(log.count("worker_start"), 1)
            self.assertNotIn("worker_stop", log[:log.index("pause_released")])

    def test_nested_selector_targets_and_missing_config_field_block_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            self.assertEqual(coordinator.run(), 0, coordinator.state["terminal_reason"])
            parent, child = coordinator.state["versions"]
            nested = Path(tmp) / "nested.json"
            nested.write_text(json.dumps({"body_params": {
                "data": [{"name": "cfx_settings[alert_emails]", "value": "fuzz"},
                         {"name": "cfx_settings[mode]", "value": "x"}],
                "fixed": ["cfx_settings\\[mode\\]"], "fuzz": ["cfx_settings\\[alert_emails\\]"],
            }}), encoding="utf-8")
            child = {**child, "config_path": str(nested)}
            replay = {"verification_policy": "parameter_replay_v1",
                      "verified_parameters": [{"bucket": "body_params", "name": "cfx_settings"}]}
            descriptor, blocked = coordinator._priority_seed(parent, child, replay)
            self.assertIsNone(blocked)
            self.assertEqual(descriptor["targets"], [["body_params", "cfx_settings[alert_emails]"]])
            replay["verified_parameters"] = [{"bucket": "body_params", "name": "other"}]
            self.assertEqual(coordinator._priority_seed(parent, child, replay), (None, "VERIFIED_FIELD_NOT_IN_CONFIG"))
            # A nested selector the parent config already fuzzes is not new: no target, no handoff.
            parent_path = Path(tmp) / "parent.json"
            parent_path.write_text(nested.read_text(encoding="utf-8"), encoding="utf-8")
            replay["verified_parameters"] = [{"bucket": "body_params", "name": "cfx_settings"}]
            self.assertEqual(coordinator._priority_seed({**parent, "config_path": str(parent_path)}, child, replay),
                             (None, "NO_NEW_FUZZABLE_TARGET"))

    def test_bootstrap_discovery_keeps_callback_baseline_policy(self):
        for origin, policy in (("v0_gate", "callback_baseline_v1"), ("worker_poll", "parameter_replay_v1")):
            with self.subTest(origin=origin), tempfile.TemporaryDirectory() as tmp:
                coordinator, parent, evidence, convergence = self.make_probe_context(
                    Path(tmp), [], names=("a",), accepted=("a",),
                )
                child = coordinator._run_pending_probe(
                    parent=parent, evidence={**evidence, "evidence_origin": origin},
                    raw_report=coordinator._reports["v0"], convergence=convergence,
                    probe=convergence["pending_probes"][0], seed=parent["seed_item"], deadline=None,
                )
                self.assertEqual(child["replay_result"]["verification_policy"], policy)
                started = worker_env(coordinator.state["workers"][-1])
                self.assertEqual("HOOKPHUZZ_PRIORITY_SEED" in started, origin == "worker_poll")

    def test_resume_gate_keeps_parameter_replay_policy_and_handoff_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            sender = coordinator.probe_sender

            def server_error(container, **kwargs):
                result = sender(container, **kwargs)
                if kwargs["run_id"].endswith("-replay") and result.get("request"):
                    result["response_status"] = 500
                    result["request"]["response"]["status_code"] = 500
                return result

            coordinator.probe_sender = server_error
            self.assertEqual(coordinator.run(), 0, coordinator.state["terminal_reason"])
            child = coordinator.state["versions"][1]
            handoff_proof = (child["replay_config_path"], child["replay_config_hash"])
            self.assertTrue(child["replay_result"]["passed"])
            # Reactivate v1 the way _load_checkpoint does, against a live 500 response.
            coordinator.resume = True
            coordinator.state["terminal_status"] = None
            child["worker_run_id"] = "run-v1-resume-1"
            child.setdefault("readiness_history", []).append(None)
            body = {"action": "fixture", "seed": "base", "new_param": "fuzz"}

            def gate(rows, **kwargs):
                run_id = kwargs["legacy_run_id"]
                return {"legacy_run_id": run_id, "runs": [{
                    **rows[0], "callback_reached": True, "validation_status": "callback_reached",
                    "process_status": "replaying", "matched_artifact": "resume-gate.json",
                    "zend_artifact": "resume-gate.json",
                    "request_payload": {
                        "request_id": "resume-gate", "legacy_run_id": run_id, "target_plugin": "fixture",
                        "hook_name": child["hook_name"], "callback_id": child["callback_id"],
                        "auth_context": child["auth_context"], "http_method": "POST",
                        "response": {"status_code": 500}, "request_params": {"body_params": body},
                    },
                    "zend_payload": {
                        "request_id": "resume-gate", "run_id": run_id, "request_method": "POST",
                        "events": [{"source": "POST", "path": ["new_param"], "operation": "read",
                                    "callback_context": {"attributed": True, "root_callback": "fixture_callback",
                                                         "depth": 0}}],
                    },
                }]}

            coordinator.replay_runner = gate
            config = json.loads(Path(child["replay_config_path"]).read_text(encoding="utf-8"))
            self.assertTrue(coordinator._gate_v0(child, config, deadline=coordinator.clock() + 100),
                            child.get("readiness"))
            self.assertEqual(child["readiness"]["verification_policy"], "parameter_replay_v1")
            # The reactivation replay is stored apart; the handoff proof the exporter rechecks is intact.
            self.assertEqual((child["replay_config_path"], child["replay_config_hash"]), handoff_proof)
            self.assertNotEqual(child["readiness"]["config_path"], handoff_proof[0])

    def test_priority_energy_mode_is_fixed_in_batch_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            coordinator = self.make_coordinator(root, [])
            registry = root / "registry.json"
            registry.write_text(json.dumps(coordinator.registry), encoding="utf-8")
            args = SimpleNamespace(suggested_seeds=str(coordinator.suggested_seeds), bootstrap_config="",
                config_root=str(root / "configs"), output_root=str(root / "output"), plugin_slug="fixture",
                legacy_run_id="campaign", max_seconds=10, max_versions=3, max_candidates=2,
                campaign_seconds=100, callback_registry=str(registry), service="fuzzer-wordpress-plugin")
            modes: list[str] = []

            class FakeCoordinator:
                def __init__(self, **kwargs):
                    modes.append(kwargs["priority_energy_mode"])
                    self.state_path = root / "candidate-state.json"
                    self.state = {"legacy_run_id": kwargs["legacy_run_id"], "plugin_slug": "fixture",
                                  "terminal_status": "PARTIAL", "terminal_reason": "PENDING_RUNTIME_VERIFICATION",
                                  "versions": [], "candidate_queue": []}

                def run(self):
                    self.state_path.write_text(json.dumps(self.state), encoding="utf-8")
                    return 0

            batch_path = root / "output/online-linked/campaign/batch-state.json"
            with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator):
                with patch.dict(os.environ, {"HOOKPHUZZ_PRIORITY_ENERGY_MODE": "bogus"}):
                    with self.assertRaisesRegex(ValueError, "HOOKPHUZZ_PRIORITY_ENERGY_MODE"):
                        run_online_linked(args)
                with patch.dict(os.environ, {"HOOKPHUZZ_PRIORITY_ENERGY_MODE": "carryover"}):
                    run_online_linked(args)
                saved = json.loads(batch_path.read_text())
                self.assertEqual(saved["priority_energy_mode"], "carryover")
                args.resume = True
                legacy = copy.deepcopy(saved)
                legacy.pop("priority_energy_mode")
                for checkpoint, env_mode in ((saved, "seed-plus-bonus"), (legacy, "carryover")):
                    batch_path.write_text(json.dumps(checkpoint), encoding="utf-8")
                    with patch.dict(os.environ, {"HOOKPHUZZ_PRIORITY_ENERGY_MODE": env_mode}), \
                            patch("online_linked.coordination.campaign.time.time", return_value=saved["budget"]["saved_at"]):
                        run_online_linked(args)
            # Resume keeps the saved mode; a checkpoint without one uses the default.
            self.assertEqual(modes, ["carryover", "carryover", "seed-plus-bonus"])

    def test_resume_releases_pause_when_worker_inspection_fails(self):
        # An inspect error is not proof the worker is gone: still send the token-guarded release.
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, replay_passes=False)
            run_command, failed = coordinator.run_command, []

            def flaky(command, **kwargs):
                if command[:2] == ["docker", "inspect"] and kwargs.get("timeout") == 10.0 and not failed:
                    failed.append(command)
                    return subprocess.CompletedProcess(command, 1, "", "daemon busy")
                return run_command(command, **kwargs)

            coordinator.run_command = flaky
            coordinator.run()
            self.assertTrue(failed)
            self.assertIn("pause_released", log)

    def test_pause_state_does_not_leak_when_pause_request_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            record = coordinator._record_event

            def failing(event, **kwargs):
                if event.get("kind") == "WORKER_PAUSE" and event.get("status") == "REQUESTED":
                    raise OSError("disk full")
                return record(event, **kwargs)

            coordinator._record_event = failing
            coordinator.run()
            self.assertIsNone(coordinator._pause)

    def test_late_pause_ack_defers_and_retains_discovery(self):
        # The ACK wait spends the candidate budget; a late ACK must keep the batch, not drop it.
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            coordinator._sender_seconds = 0.5
            run_command = coordinator.run_command

            def slow_ack(command, **kwargs):
                # The ACK is read just after it lands, with less than the reserve left.
                if command[:2] == ["docker", "exec"] and command[6:7] == ["ack"]:
                    coordinator.clock.now = coordinator._deadline - 0.6
                return run_command(command, **kwargs)

            coordinator.run_command = slow_ack
            coordinator.run()
            self.assertFalse(any(entry.startswith("sender_timeout:run-v1-replay") for entry in log))
            deferred = [e for e in coordinator.state["events"] if e.get("kind") == "PARAMETER_DISCOVERY"
                        and e.get("status") == "DEFERRED"]
            self.assertEqual([e["reason"] for e in deferred], ["INSUFFICIENT_VERIFICATION_BUDGET"])
            self.assertTrue(coordinator.state["pending_runtime_candidates"])
            self.assertIn("pause_released", log)

    def test_descendant_failing_batch_recheck_keeps_verified_ancestor(self):
        # v2 proves cn_nonce but not cn_param in its own replay: hand off v1, which passed.
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, log, sends = self._guard_chain_campaign(Path(tmp), v2_replay_unread=("cn_param",))
            versions = {version["version"]: version for version in coordinator.state["versions"]}
            self.assertEqual(versions["v2"]["terminal_reason"], "PARAMETER_REPLAY_NOT_VERIFIED")
            self.assertEqual(coordinator._active_version, "v1")
            self.assertEqual(versions["v1"]["worker_status"], "started")

    def test_runtime_parameter_triggers_handoff_without_new_coverage(self):
        # The coordinator never asks PHUZZ for new paths: one admitted Zend field
        # is enough, while a trace with only known fields must not pause anyone.
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            self.assertEqual(coordinator.run(), 0, coordinator.state["terminal_reason"])
            accepted = [event for event in coordinator.state["events"]
                        if event.get("kind") == "PARAMETER_DISCOVERY" and event.get("status") == "ACCEPTED"]
            self.assertEqual(len(accepted), 1)
            self.assertEqual(log.count("pause_requested"), 1)
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator = self.make_coordinator(Path(tmp), log, discovers_parameter=False)
            coordinator.run()
            self.assertNotIn("pause_requested", log)
            self.assertEqual(log.count("worker_start"), 1)

    def _trace_docker(self, coordinator, *, fail=None) -> list[tuple]:
        trace = []
        run_command = coordinator.run_command
        starts = 0

        def traced(command, **kwargs):
            nonlocal starts
            if command[:2] == ["docker", "exec"] and command[3:6] == ["python", "-m", "core.online_handoff"]:
                trace.append(("exec", command[6], command[2], *command[7:9]))
            elif command[:3] == ["docker", "rm", "-f"]:
                trace.append(("rm", command[3]))
                if fail == "rm":
                    return subprocess.CompletedProcess(command, 1, "", "boom")
            elif command[:3] == ["docker", "compose", "run"]:
                trace.append(("run", command[command.index("--name") + 1]))
                starts += 1
                if fail == "child_run" and starts == 2:
                    return subprocess.CompletedProcess(command, 1, "", "start boom")
            return run_command(command, **kwargs)

        coordinator.run_command = traced
        return trace

    def test_handoff_docker_order_pause_ack_stop_then_start(self):
        """Start only after removing the parent, and release only if the parent survives."""
        for failure in (None, "rm", "child_run"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                coordinator = self.make_coordinator(Path(tmp), [])
                trace = self._trace_docker(coordinator, fail=failure)
                coordinator.run()
                parent = coordinator.state["workers"][0]["container_name"]
                child_start = ("run", "hookphuzz-online-linked-run-v1")
                request = next(row for row in trace if row[:2] == ("exec", "request"))
                key, token = request[3:]
                ack = ("exec", "ack", parent, key)
                release = ("exec", "release", parent, key, token)
                releases = [row for row in trace if row[:2] == ("exec", "release")]
                last = release if failure == "rm" else child_start
                start = trace.index(request)
                self.assertEqual(trace[start:start + 4], [("exec", "request", parent, key, token),
                                                           ack, ("rm", parent), last])
                self.assertIsNone(coordinator._pause)
                if failure == "rm":
                    self.assertNotIn(child_start, trace)
                    self.assertEqual(coordinator.state["versions"][1]["worker_status"],
                                     "not_started_parent_stop_failed")
                    self.assertEqual(coordinator.state["terminal_reason"], "WORKER_STOP_FAILED")
                else:
                    self.assertEqual(releases, [])
                    if failure == "child_run":
                        self.assertEqual(coordinator.state["terminal_reason"], "CHILD_WORKER_START_FAILED")
                    else:
                        pause_statuses = [e["status"] for e in coordinator.state["events"]
                                          if e["kind"] == "WORKER_PAUSE"]
                        self.assertEqual(pause_statuses, ["REQUESTED", "ACKNOWLEDGED"])

    def test_pause_ack_with_foreign_run_id_is_ignored_and_released(self):
        """An ACK from another run must not authorize replay, even with the correct token."""
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator = self.make_coordinator(
                Path(tmp), log, pause_ack=lambda r: {**r, "worker_run_id": "other-run", "round_id": 1,
                                                     "allocated_energy": 20, "attempts_used": 9},
            )
            trace = self._trace_docker(coordinator)
            coordinator.run()
            self.assertFalse(any(entry.startswith("sender_timeout:run-v1-replay") for entry in log))
            self.assertEqual(log.count("worker_start"), 1)
            self.assertNotIn("pause_ack", coordinator.state["versions"][0])
            pause = [(e["status"], e["reason"]) for e in coordinator.state["events"] if e["kind"] == "WORKER_PAUSE"]
            self.assertLess(pause.index(("REJECTED", "PAUSE_ACK_TIMEOUT")), pause.index(("RELEASED", "PAUSE_RELEASED")))
            _, _, parent, key, token = next(row for row in trace if row[:2] == ("exec", "request"))
            self.assertIn(("exec", "release", parent, key, token), trace)
            self.assertIsNone(coordinator._pause)

    def test_rejected_handoff_releases_same_pause_token(self):
        """Replay or priority rejection must release the exact paused parent before polling again."""
        for fixed in (False, True):
            with self.subTest(fixed=fixed), tempfile.TemporaryDirectory() as tmp:
                coordinator = self.make_coordinator(Path(tmp), [], replay_passes=fixed)
                if fixed:
                    export = coordinator.export_configs_fn

                    def export_fixed(report, **kwargs):
                        summary = export(report, **kwargs)
                        path = Path(summary["generated"][0]["config_path"])
                        config = json.loads(path.read_text(encoding="utf-8"))
                        config["body_params"]["fixed"].append("new_param")
                        path.write_text(json.dumps(config), encoding="utf-8")
                        return summary

                    coordinator.export_configs_fn = export_fixed
                trace = self._trace_docker(coordinator)
                coordinator.run()
                events = [(e["kind"], e["status"], e["reason"]) for e in coordinator.state["events"]]
                self.assertEqual([e[1:] for e in events if e[0] == "WORKER_PAUSE"][:3], [
                    ("REQUESTED", "PARAMETER_HANDOFF"), ("ACKNOWLEDGED", "PAUSE_ACK"), ("RELEASED", "PAUSE_RELEASED"),
                ])
                _, _, parent, key, token = next(row for row in trace if row[:2] == ("exec", "request"))
                release = next(row for row in trace if row[:2] == ("exec", "release"))
                self.assertEqual(release, ("exec", "release", parent, key, token))
                self.assertNotIn(("rm", parent), trace[:trace.index(release)])
                self.assertIsNone(coordinator._pause)
                released = events.index(("WORKER_PAUSE", "RELEASED", "PAUSE_RELEASED"))
                if fixed:
                    reason = "NO_NEW_FUZZABLE_TARGET"
                    priority = events.index(("PRIORITY_SEED", "REJECTED", reason))
                    rejected = events.index(("CHILD_REPLAY", "REJECTED", reason))
                    self.assertLess(priority, rejected)
                else:
                    rejected = next(i for i, e in enumerate(events) if e[:2] == ("CHILD_REPLAY", "REJECTED"))
                    self.assertNotEqual(coordinator.state["terminal_reason"], "CHILD_REPLAY_FAILED")
                self.assertLess(rejected, released)

    def test_priority_seed_is_recorded_once_and_never_overwritten(self):
        """A restart must retain the descriptor of the first verified activation."""
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            self.assertEqual(coordinator.run(), 0)
            child = coordinator.state["versions"][1]
            descriptor = json.loads(worker_env(coordinator.state["workers"][-1])["HOOKPHUZZ_PRIORITY_SEED"])
            keys = ["replay_slug", "replay_hash", "targets", "mode", "allocated_energy", "attempts_used"]
            self.assertEqual(child["priority_seed"], descriptor)
            self.assertEqual(list(child["priority_seed"]), keys)
            saved = json.loads(coordinator.state_path.read_text(encoding="utf-8"))
            self.assertEqual(list(saved["versions"][1]["priority_seed"]), keys)

            def grants():
                return sum(e["kind"] == "PRIORITY_SEED" and e["status"] == "GRANTED"
                           for e in coordinator.state["events"])

            self.assertEqual(grants(), 1)
            self.assertTrue(coordinator._stop_worker(child, "TEST_RESTART"))
            replacement = {**descriptor, "targets": [["body_params", "other"]]}
            self.assertTrue(coordinator._start_worker(child, priority_seed=replacement))
            self.assertEqual(child["priority_seed"], descriptor)
            self.assertNotIn("HOOKPHUZZ_PRIORITY_SEED", worker_env(coordinator.state["workers"][-1]))
            self.assertEqual(grants(), 1)

    def test_guard_target_handoff_event_describes_started_version(self):
        """The event must use the activated descendant's version and distinct replay timing."""
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, _, _ = self._guard_chain_campaign(
                Path(tmp), probe_status=403, send_cost_by_run_id={"run-v1-replay": 0.25, "run-v2-replay": 0.5},
            )
            versions = {v["version"]: v for v in coordinator.state["versions"]}
            v1_timing = versions["v1"]["replay_result"]["timing"]
            v2_timing = versions["v2"]["replay_result"]["timing"]
            self.assertEqual([v1_timing["total"], v2_timing["total"]], [0.25, 0.5])
            events = [e for e in coordinator.state["events"] if e["kind"] == "CHILD_REPLAY" and e["status"] == "PASS"
                      and e["reason"] in {"PARAMETER_REPLAY_VERIFIED", "CALLBACK_BASELINE_VERIFIED"}]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["version"], "v2")
            self.assertEqual(events[0]["timing"], v2_timing)
            self.assertIn("handoff", v2_timing)

    def test_handoff_waits_for_matching_pause_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            self.assertEqual(coordinator.run(), 0, coordinator.state["terminal_reason"])
            baseline = next(i for i, entry in enumerate(log) if entry.startswith("sender_timeout:run-v1-replay"))
            self.assertLess(log.index("pause_requested"), log.index("pause_ack"))
            self.assertLess(log.index("pause_ack"), baseline)
            self.assertLess(baseline, log.index("worker_stop"))
            self.assertEqual(log.count("worker_start"), 2)
            snapshot = coordinator.state["versions"][0]["pause_ack"]
            self.assertEqual((snapshot["allocated_energy"], snapshot["attempts_used"]), (20, 9))
            self.assertIn("HOOKPHUZZ_HANDOFF_KEY=" + coordinator.state["versions"][0]["handoff_key"],
                          coordinator.state["workers"][0]["command"])
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            stale = lambda request: {**request, "token": "stale", "round_id": 1, "allocated_energy": 20, "attempts_used": 9}
            coordinator = self.make_coordinator(Path(tmp), log, pause_ack=stale)
            coordinator.run()
            self.assertFalse(any(entry.startswith("sender_timeout:run-v1-replay") for entry in log))
            self.assertEqual(log.count("worker_start"), 1)
            self.assertNotIn("worker_stop", log[:log.index("pause_released")])
            pause = [event for event in coordinator.state["events"] if event.get("kind") == "WORKER_PAUSE"]
            self.assertIn(("REJECTED", "PAUSE_ACK_TIMEOUT"), [(e["status"], e["reason"]) for e in pause])

    def test_replay_rejection_resumes_paused_parent_and_keeps_polling(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, replay_passes=False)
            coordinator.run()
            child = coordinator.state["versions"][1]
            self.assertEqual(child["status"], "replay_failed")
            self.assertNotEqual(coordinator.state["terminal_reason"], "CHILD_REPLAY_FAILED")
            self.assertEqual(log.count("worker_start"), 1)
            released = log.index("pause_released")
            self.assertLess(log.index("run_generated_configs"), released)
            self.assertNotIn("worker_stop", log[:released])
            # Back to polling the same parent instead of a terminal state.
            self.assertIn("runtime_batch_reader", log[released:])

    def test_online_max_versions_includes_v0(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, max_versions=1)
            coordinator.hard_versions = 1
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0"])
            self.assertEqual(coordinator.state["terminal_status"], "PARTIAL")
            self.assertEqual(coordinator.state["terminal_reason"], "HARD_VERSION_CAP")
            self.assertTrue(coordinator.state["pending_runtime_candidates"])
            self.assertNotIn("run_generated_configs", log)

    def test_soft_version_limit_includes_v0_but_verified_progress_can_grow(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [], max_versions=1)
            coordinator.hard_versions = 2
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual([row["version"] for row in coordinator.state["versions"]], ["v0", "v1"])
            self.assertEqual(coordinator.max_versions, 2)
            self.assertTrue(coordinator.state["versions"][1]["replay_result"]["passed"])

    def test_candidate_checkpoint_preserves_pending_and_budget_across_clock_epochs(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            item, config, key = coordinator._select_v0()
            path = coordinator._write_config("v0", config)
            parent = coordinator._new_version("v0", config, path, None, None, item)
            parent["worker_run_id"] = "run-v0"
            coordinator._active_version = "v0"
            coordinator._target_key = key
            coordinator._reports["v0"] = copy.deepcopy(coordinator._raw_report)
            coordinator._candidate_deadline()
            coordinator._extend_progress_budget("runtime_callback", "child")
            coordinator.clock.now = 0.5
            coordinator._retain_pending_runtime_candidates(
                [{"parameters": [{"name": "a", "source": "POST", "location": "form", "payload": "probe"}],
                  "evidence": {"request_id": "old", "request": {"request_params": {"body_params": {"a": "probe"}}}}}], parent)
            coordinator.state.update(terminal_status="PARTIAL", terminal_reason="PENDING_RUNTIME_VERIFICATION")
            coordinator._write_state()
            original = json.loads(coordinator.state_path.read_text())
            self.assertEqual(original["context_key_version"], 1)
            self.assertEqual(original["checkpoint"]["candidate_context_key"],
                             _candidate_context_key(item, "fixture"))
            restored = self.make_coordinator(Path(tmp), [])
            legacy = copy.deepcopy(original)
            legacy.pop("context_key_version")
            legacy["checkpoint"].pop("context_key_version")
            restored.state_path.write_text(json.dumps(legacy), encoding="utf-8")
            rejected = self.make_coordinator(Path(tmp), [])
            with self.assertRaisesRegex(ValueError, "candidate context-key version"):
                rejected._load_checkpoint()
            restored.state_path.write_text(json.dumps(original), encoding="utf-8")
            restored.resume = True
            restored.clock.now = 1000
            with patch("online_linked.coordinator.time.time", return_value=original["budget"]["saved_at"]):
                restored._load_checkpoint()
            self.assertEqual(restored._deadline, 1000 + original["budget"]["remaining_seconds"])
            self.assertIsNone(restored._hard_deadline)
            self.assertEqual(restored.state["pending_runtime_candidates"], original["pending_runtime_candidates"])
            self.assertEqual(restored.state["queued_candidate_context_keys"], original["queued_candidate_context_keys"])
            self.assertEqual(restored.state["pending_runtime_candidates"][0]["parameter"]["payload"], "probe")
            self.assertEqual(restored._extend_progress_budget("runtime_callback", "child"), restored._deadline)
            self.assertEqual(len(restored.state["versions"]), 1)
            self.assertIn("resume-1", restored._version("v0")["worker_run_id"])
            path.write_text("{}")
            rejected = self.make_coordinator(Path(tmp), [])
            with self.assertRaisesRegex(ValueError, "config hash changed"):
                rejected._load_checkpoint()

    def test_partial_campaign_resume_uses_real_exporter_with_existing_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            coordinator = self.make_coordinator(root, [])
            registry = root / "registry.json"
            registry.write_text(json.dumps(coordinator.registry), encoding="utf-8")
            args = SimpleNamespace(suggested_seeds=str(coordinator.suggested_seeds), bootstrap_config="",
                config_root=str(root / "configs"), output_root=str(root / "output"), plugin_slug="fixture",
                legacy_run_id="campaign", max_seconds=10, max_versions=3, max_candidates=2,
                campaign_seconds=100, callback_registry=str(registry), service="fuzzer-wordpress-plugin")
            class FakeCoordinator:
                def __init__(self, **kwargs):
                    self.state_path = root / "candidate-state.json"
                    self.state = {"legacy_run_id": kwargs["legacy_run_id"], "plugin_slug": "fixture",
                        "terminal_status": "BOUNDED_ONLINE_COMPLETE" if kwargs["resume"] else "PARTIAL",
                        "terminal_reason": None if kwargs["resume"] else "PENDING_RUNTIME_VERIFICATION",
                        "versions": [], "candidate_queue": []}
                def run(self):
                    self.state_path.write_text(json.dumps(self.state), encoding="utf-8")
                    return 0
            batch_path = root / "output/online-linked/campaign/batch-state.json"
            with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator):
                self.assertEqual(run_online_linked(args), 0)
                saved = json.loads(batch_path.read_text())
                self.assertEqual(saved["campaign_status"], "PARTIAL")
                self.assertEqual(saved["context_key_version"], 1)
                self.assertTrue((batch_path.parent / "final-configs").is_dir())
                legacy = copy.deepcopy(saved)
                legacy.pop("context_key_version")
                batch_path.write_text(json.dumps(legacy), encoding="utf-8")
                args.resume = True

                class NeverCoordinator:
                    def __init__(self, **kwargs):
                        raise AssertionError("worker must not start for a legacy context checkpoint")

                with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", NeverCoordinator):
                    with self.assertRaisesRegex(ValueError, "batch context-key version"):
                        run_online_linked(args)
                batch_path.write_text(json.dumps(saved), encoding="utf-8")
                args.resume = True
                with patch("online_linked.coordination.campaign.time.time", return_value=saved["budget"]["saved_at"]):
                    self.assertEqual(run_online_linked(args), 0)
            self.assertEqual(json.loads(batch_path.read_text())["campaign_status"], "complete")

    def test_campaign_resume_after_runtime_registry_merge_retains_integrity(self):
        for interrupt_before_publish in (False, True):
            with self.subTest(interrupt_before_publish=interrupt_before_publish), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                coordinator, parent, _, _ = self.make_probe_context(root, [])
                registry = root / "registry.json"
                registry.write_text(json.dumps(coordinator.registry), encoding="utf-8")
                args = SimpleNamespace(suggested_seeds=str(coordinator.suggested_seeds), bootstrap_config="",
                    config_root=str(root / "configs"), output_root=str(root / "output"), plugin_slug="fixture",
                    legacy_run_id="campaign", max_seconds=10, max_versions=3, max_candidates=2,
                    campaign_seconds=100, callback_registry=str(registry), service="fuzzer-wordpress-plugin")
                calls = []
                class FakeCoordinator:
                    def __init__(self, **kwargs):
                        self.kwargs = kwargs
                        calls.append(kwargs)
                        self.state_path = root / "candidate-state.json"
                        self.state = {"legacy_run_id": kwargs["legacy_run_id"], "plugin_slug": "fixture",
                                      "terminal_status": "BOUNDED_ONLINE_COMPLETE", "versions": [], "candidate_queue": []}
                    def run(self):
                        if self.kwargs.get("resume"):
                            return 0
                        self.state_path.write_text(json.dumps(self.state), encoding="utf-8")
                        coordinator.registry_path = self.kwargs["registry_path"]
                        coordinator.progress_callback = self.kwargs["progress_callback"]
                        coordinator.registry_checkpoint_callback = self.kwargs.get("registry_checkpoint_callback")
                        original_merge = coordinator._merge_runtime_registry
                        def merge(callback):
                            original_merge(callback)
                            raise KeyboardInterrupt
                        coordinator._merge_runtime_registry = merge
                        coordinator._discover_runtime_candidates({"request_id": "runtime-child", "request": {
                            "hook_coverage": {"registered_callbacks": {"cb-child": {
                                "callback_id": "cb-child", "callback_repr": "child_callback",
                                "hook_name": "wp_ajax_nopriv_child", "method": "POST",
                                "registered_inside_callback": True, "parent_callback_id": parent["callback_id"],
                            }}}}})
                        return 0
                from online_linked.coordination.campaign import _write_json
                def write_json(path, content):
                    if interrupt_before_publish and path.name == "callback-registry.json":
                        raise KeyboardInterrupt
                    return _write_json(path, content)
                with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator), \
                        patch("online_linked.coordination.campaign._write_json", write_json):
                    with self.assertRaises(KeyboardInterrupt):
                        run_online_linked(args)
                batch_path = root / "output/online-linked/campaign/batch-state.json"
                saved = json.loads(batch_path.read_text())
                self.assertTrue(saved["pending_candidates"])
                args.resume = True
                with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator), \
                        patch("online_linked.coordination.campaign.time.time", return_value=saved["budget"]["saved_at"]):
                    self.assertEqual(run_online_linked(args), 0)
                published = root / "output/online-linked/campaign/callback-registry.json"
                self.assertEqual(json.loads(published.read_text())["callback_map"]["cb-child"], "child_callback")
                self.assertTrue(calls[-1]["resume"])
                published.write_text(published.read_text() + " ", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "registry snapshot changed"):
                    run_online_linked(args)

    def test_resume_pending_probe_rechecks_gate_then_sends_fresh_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator, parent, evidence, convergence = self.make_probe_context(Path(tmp), log, names=("a",))
            coordinator._candidate_deadline()
            coordinator._run_pending_probe(parent=parent, evidence=evidence,
                raw_report=coordinator._reports["v0"], convergence=convergence,
                probe=convergence["pending_probes"][0], seed=parent["seed_item"], deadline=0)
            self.assertEqual(len(coordinator.state["pending_probe_queue"]), 1)
            coordinator.state.update(terminal_status="PARTIAL", terminal_reason="PENDING_RUNTIME_VERIFICATION")
            coordinator._write_state()
            saved_at = coordinator.state["budget"]["saved_at"]
            coordinator.resume = True
            coordinator.clock.now = 1000
            old_replay = coordinator.replay_runner
            def replay(rows, **kwargs):
                run_id = kwargs["legacy_run_id"]
                if run_id.endswith("resume-1"):
                    log.append("fresh_gate")
                    return {"legacy_run_id": run_id, "runs": [{**rows[0],
                        "callback_reached": True, "validation_status": "callback_reached", "process_status": "replaying",
                        "matched_artifact": "fresh-gate.json", "zend_artifact": "fresh-gate.json",
                        "request_payload": {"request_id": "fresh-gate", "legacy_run_id": run_id,
                            "target_plugin": "fixture", "http_method": "POST",
                            "hook_name": rows[0]["hook_name"], "callback_id": rows[0]["callback_id"],
                            "auth_context": next(v["auth_context"] for v in coordinator.state["versions"] if v.get("worker_run_id") == run_id),
                            "response": {"status_code": 200},
                            "request_params": {"body_params": {"action": "fixture", "seed": "base"}}},
                        "zend_payload": {"request_id": "fresh-gate", "run_id": run_id}}]}
                return old_replay(rows, **kwargs)
            coordinator.replay_runner = replay
            with patch("online_linked.coordinator.time.time", return_value=saved_at):
                coordinator.run()
            self.assertTrue(coordinator.state["versions"][0]["readiness"]["passed"])
            self.assertLess(log.index("fresh_gate"), log.index("probe:a"))
            self.assertIn("resume-1-probe", coordinator.state["probe_attempts"][0]["probe_run_id"])
            self.assertEqual(len(coordinator.state["probe_attempts"]), 1)
            self.assertFalse(coordinator.state["pending_probe_queue"])
            self.assertLessEqual(coordinator.clock(), coordinator._deadline)

    def test_resume_deferred_probe_from_ancestor_revalidates_saved_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = []
            coordinator, parent, evidence, convergence = self.make_probe_context(
                Path(tmp), log, names=("a", "b", "c"), accepted=("a", "b", "c"))
            coordinator.max_seconds = coordinator.state["max_seconds"] = 10
            coordinator.hard_seconds = coordinator.state["hard_seconds"] = 30
            coordinator._candidate_deadline()
            old_sender = coordinator.probe_sender
            def slow_sender(*args, **kwargs):
                result = old_sender(*args, **kwargs)
                coordinator.sleeper(1)
                return result
            coordinator.probe_sender = slow_sender
            child = coordinator._run_pending_probe(parent=parent, evidence=evidence,
                raw_report=coordinator._reports["v0"], convergence=convergence,
                probe=convergence["pending_probes"][0], seed=parent["seed_item"], deadline=5)
            self.assertIsNotNone(child)
            self.assertEqual(coordinator._active_version, "v1")
            self.assertEqual([(row["parent_version"], row["candidate"]["name"])
                              for row in coordinator.state["pending_probe_queue"]], [("v0", "b"), ("v0", "c")])
            coordinator.state.update(terminal_status="PARTIAL", terminal_reason="PENDING_RUNTIME_VERIFICATION")
            coordinator._write_state()
            saved_at = coordinator.state["budget"]["saved_at"]
            coordinator.resume = True
            coordinator.clock.now = 1000
            coordinator.probe_sender = old_sender
            old_replay = coordinator.replay_runner
            def replay(rows, **kwargs):
                run_id = kwargs["legacy_run_id"]
                if "-resume-1" in run_id and "-probe-" not in run_id:
                    return {"legacy_run_id": run_id, "runs": [{**rows[0],
                        "callback_reached": True, "validation_status": "callback_reached", "process_status": "replaying",
                        "matched_artifact": "fresh-gate.json", "zend_artifact": "fresh-gate.json",
                        "request_payload": {"request_id": "fresh-gate", "legacy_run_id": run_id,
                            "target_plugin": "fixture", "http_method": "POST",
                            "hook_name": rows[0]["hook_name"], "callback_id": rows[0]["callback_id"],
                            "auth_context": next(v["auth_context"] for v in coordinator.state["versions"] if v.get("worker_run_id") == run_id),
                            "response": {"status_code": 200},
                            # v1's replay config sends its proven field a; the trace reads it again.
                            "request_params": {"body_params": {"action": "fixture", "seed": "base", "a": "probe-a"}}},
                        "zend_payload": {"request_id": "fresh-gate", "run_id": run_id, "events": [{
                            "source": "POST", "path": ["a"], "operation": "read",
                            "callback_context": {"attributed": True, "root_callback": "fixture_callback", "depth": 0},
                        }]}}]}
                return old_replay(rows, **kwargs)
            coordinator.replay_runner = replay
            old_gate = coordinator._gate_v0
            def gate(version, config, **kwargs):
                log.append("fresh_gate:" + version["version"])
                return old_gate(version, config, **kwargs)
            coordinator._gate_v0 = gate
            with patch("online_linked.coordinator.time.time", return_value=saved_at):
                coordinator.run()
            self.assertLess(log.index("fresh_gate:v1"), log.index("fresh_gate:v0"))
            self.assertLess(log.index("fresh_gate:v0"), log.index("probe:b"))
            self.assertFalse(coordinator.state["pending_probe_queue"])
            resumed_attempts = coordinator.state["probe_attempts"][1:]
            self.assertEqual([row["candidate"]["name"] for row in resumed_attempts], ["b", "c"])
            self.assertEqual({row["parent_version"] for row in resumed_attempts}, {"v0"})
            self.assertEqual(len({row["probe_run_id"] for row in resumed_attempts}), 2)
            self.assertTrue(all("resume-1-activation-" in row["probe_run_id"] for row in resumed_attempts))
            self.assertTrue(all(row["status"] == "accepted" for row in resumed_attempts))
            self.assertEqual([row["version"] for row in coordinator.state["versions"]], ["v0", "v1", "v2", "v3"])
            for version, parameter in zip(coordinator.state["versions"][2:], ("b", "c")):
                self.assertTrue(version["replay_result"]["passed"])
                self.assertIn(parameter, {row["name"] for row in version["known_parameters"]})

    def test_resume_ancestor_gate_restores_method_and_seed_variant_filter(self):
        from hook_energy.seed_generation.zend_runtime.bridge_cli import _filter_iteration_inputs
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, parent, evidence, convergence = self.make_probe_context(Path(tmp), [], names=("a",))
            coordinator._candidate_deadline()
            coordinator._run_pending_probe(parent=parent, evidence=evidence,
                raw_report=coordinator._reports["v0"], convergence=convergence,
                probe=convergence["pending_probes"][0], seed=parent["seed_item"], deadline=0)
            parent["seed_item"]["seed"].update(method="GET", resolved_method="GET", seed_variant_id="get-parent")
            parent.update(resolved_method="GET", seed_variant_id="get-parent")
            coordinator._reports["v0"]["suggested_seeds"] = [copy.deepcopy(parent["seed_item"])]
            child_item = copy.deepcopy(parent["seed_item"])
            child_item["seed"].update(method="POST", resolved_method="POST", seed_variant_id="post-child")
            child_config = config_for(child_item)
            child_path = coordinator._write_config("v1", child_config)
            child = coordinator._new_version("v1", child_config, child_path, parent, None, child_item)
            child.update(worker_run_id="run-v1", known_parameters=[])
            coordinator._reports["v1"] = {"plugin_slug": "fixture", "suggested_seeds": [child_item]}
            coordinator._active_version = "v1"
            coordinator._target_key = canonical_identity_id(candidate_from_seed_item(child_item, plugin_slug="fixture")) + "::post-child"
            coordinator.state.update(terminal_status="PARTIAL", terminal_reason="PENDING_RUNTIME_VERIFICATION")
            coordinator._write_state()
            saved_at = coordinator.state["budget"]["saved_at"]
            coordinator.resume = True
            gated = []
            def gate(version, config, **kwargs):
                raw = coordinator._reports[version["version"]]
                row = {"hook_name": version["hook_name"], "callback_id": version["callback_id"],
                       "resolved_method": version["resolved_method"], "seed_variant_id": version["seed_variant_id"]}
                filtered, summary = _filter_iteration_inputs(raw, {"runs": [row]}, plugin_slug="fixture",
                    legacy_run_id=version["worker_run_id"], candidate_key=coordinator._target_key)
                self.assertEqual(len(filtered["suggested_seeds"]), 1)
                self.assertEqual(summary["runs"], [row])
                gated.append((version["version"], filtered["suggested_seeds"][0]["seed"]["method"]))
                return True
            def pending(**kwargs):
                self.assertEqual(kwargs["parent"]["version"], "v0")
                coordinator.state["pending_probe_queue"] = []
                coordinator.state.update(terminal_status="BOUNDED_ONLINE_COMPLETE", terminal_reason="BUDGET_EXPIRED")
            with patch.object(coordinator, "_gate_v0", side_effect=gate), \
                    patch.object(coordinator, "_consume_gate_evidence"), \
                    patch.object(coordinator, "_run_pending_probe", side_effect=pending), \
                    patch("online_linked.coordinator.time.time", return_value=saved_at):
                self.assertEqual(coordinator.run(), 0)
            self.assertEqual(gated, [("v1", "POST"), ("v0", "GET")])

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

    def test_candidate_evidence_is_grouped_under_owning_campaign(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign_dir = root / "output/online-linked/fixture-20260928T120000Z"
            coordinator = self.make_coordinator(root, [], campaign_dir=campaign_dir)
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual(coordinator.run_dir.parent, campaign_dir / "campaigns")
            self.assertTrue(coordinator.state_path.is_file())
            self.assertTrue((coordinator.run_dir / "versions/v0").is_dir())
            self.assertFalse((root / "output/online-linked" / coordinator.run_dir.name).exists())

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
            materialize = coordinator.materialize_fn

            def materialize_fuzzable(*args, **kwargs):
                # As the real materializer: a verified new field is declared fuzzable, not only given a value.
                report = materialize(*args, **kwargs)
                seed = report["suggested_seeds"][0]["seed"]
                seed["fuzzable_params"] = sorted({*seed.get("fuzzable_params", []),
                                                  *(str(p["name"]) for p in kwargs.get("known_parameters") or [])})
                return report

            coordinator.materialize_fn = materialize_fuzzable
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

    def _gate_ready_v0(self, tmp) -> tuple[OnlineLinkedCoordinator, dict[str, Any], dict[str, Any]]:
        """Prepare v0 exactly as run() does before its first _gate_v0 call."""
        coordinator = self.make_coordinator(Path(tmp), [])
        item, config, target_key = coordinator._select_v0()
        path = coordinator._write_config("v0", config)
        version = coordinator._new_version("v0", config, path, None, None, item)
        version["worker_run_id"] = f"{coordinator.legacy_run_id}-v0"
        version["known_parameters"] = []
        coordinator._reports["v0"] = copy.deepcopy(coordinator._raw_report or {})
        coordinator._target_key = target_key
        return coordinator, version, config

    def test_gate_v0_budget_check_runs_after_gate_evidence_is_stored(self):
        """The gate's last budget check sits after the evidence is stored and before the baseline.

        A gate that runs out of budget there keeps its correlated evidence, unconsumed, but
        never records a baseline. The clock moves inside _baseline_identity_complete, so this
        also pins that the gate calls that check on the coordinator.
        """
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, version, config = self._gate_ready_v0(tmp)
            deadline = coordinator.clock() + 100
            original = coordinator._baseline_identity_complete

            def verify_then_expire(request, zend, parent):
                result = original(request, zend, parent)
                coordinator.sleeper(deadline - coordinator.clock())
                return result

            coordinator._baseline_identity_complete = verify_then_expire
            self.assertFalse(coordinator._gate_v0(version, config, deadline=deadline))
            self.assertEqual(coordinator.state["terminal_reason"], "BUDGET_EXPIRED")
            self.assertIsNotNone(coordinator._gate_evidence)
            self.assertIs(version["gate_evidence"]["consumed"], False)
            self.assertNotIn("baseline_evidence", version["readiness"])

    def test_gate_v0_failure_reason_tracks_stage(self):
        """A plain error is reported with the stage the gate had reached when it failed.

        ``reason`` advances inside the gate's try block (callback, then provenance) and the
        except clause reports it for errors that are not OnlineLinkedError. Splitting the try
        body into several functions must not lose that value.
        """
        def boom(*args, **kwargs):
            raise ValueError("boom")

        cases = (
            ("replay", "replay_runner", boom, "V0_CALLBACK_NOT_REACHED"),
            ("converge", "converge_fn", boom, "V0_PROVENANCE_NOT_VERIFIED"),
            ("blocked", "converge_fn", lambda **kwargs: {"runtime_block_reason": "BLOCKED_X"}, "BLOCKED_X"),
        )
        for stage, attribute, replacement, expected in cases:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp:
                coordinator, version, config = self._gate_ready_v0(tmp)
                setattr(coordinator, attribute, replacement)
                self.assertFalse(coordinator._gate_v0(version, config, deadline=coordinator.clock() + 100))
                self.assertEqual(coordinator.state["terminal_status"], "NOT_VERIFIED")
                self.assertEqual(coordinator.state["terminal_reason"], expected)
                if stage == "replay":
                    self.assertEqual(version["readiness"]["reason"], "boom")
                if stage == "blocked":
                    rejected = [event for event in coordinator.state["events"]
                                if event.get("kind") == "V0_READINESS" and event.get("status") == "REJECTED"]
                    self.assertEqual([event["reason"] for event in rejected], ["BLOCKED_X"])

    def test_gate_v0_row_error_after_replay_config_is_recorded(self):
        """The gate records replay_config_* before it builds the row, and readiness only after.

        A config outside config_root fails while the row is built: the replay config is already
        on the version, but the version must not claim a readiness record.
        """
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, version, config = self._gate_ready_v0(tmp)
            # config_dir was derived from the old root, so relative_to() fails on the replay path.
            coordinator.config_root = Path(tmp) / "elsewhere"
            with self.assertRaises(ValueError) as raised:
                coordinator._gate_v0(version, config, deadline=coordinator.clock() + 100)
            self.assertIn("elsewhere", str(raised.exception))
            self.assertTrue(Path(version["replay_config_path"]).is_file())
            self.assertNotIn("readiness", version)

    def _guard_round(self, tmp, *, running_parent=None, child_parameters=(), child_fields=None):
        """One replay-guard round: v0 is current, its replay reports one unsent guard.

        Returns (coordinator, v0, discover). discover(probe=...) calls _discover_replay_guards
        with _run_pending_probe patched to ``probe``; the default builds v1 with
        ``child_parameters`` and ``child_fields`` and a passing replay. ``running_parent`` is
        a set of overrides on a copy of v0, the version whose worker is running.
        """
        coordinator, v0, config = self._gate_ready_v0(tmp)
        v0["replay_config_path"] = str(coordinator._write_config("v0", config, replay=True))
        coordinator._active_container = "c1"
        evidence = {"worker_run_id": v0["worker_run_id"], "request_name": "req-v0.json", "request_id": "req-v0"}
        guard = {"name": "g", "source": "POST", "location": "form"}
        coordinator.converge_fn = lambda **kwargs: {
            "status": "CONVERGED",
            "observed_parameters": [{**guard, "candidate_reason": "unsent_guard"}],
            "pending_probes": [dict(guard)],
        }
        running = None if running_parent is None else {**copy.deepcopy(v0), **running_parent}

        def make_child(**kwargs):
            child = coordinator._new_version(
                "v1", config, Path(v0["config_path"]), v0, "REPLAY_GUARD_DISCOVERY", v0["seed_item"],
            )
            child["known_parameters"] = [dict(parameter) for parameter in child_parameters]
            child["replay_result"] = {"passed": True, "runner": {"runs": [{
                "request_payload": {"request_id": "req-v1", "http_method": "POST",
                                    "request_params": {"body_params": {"action": "fixture", "seed": "base"}}},
                "zend_payload": {"request_id": "req-v1", "events": []},
            }]}}
            child.update(child_fields or {})
            coordinator._replay_evidence["v1"] = {
                "version": "v1", "worker_run_id": "run-v1-replay",
                "request_name": "req-v1.json", "request_id": "req-v1",
            }
            return child

        def discover(probe=make_child):
            with patch.object(coordinator, "_run_pending_probe", side_effect=probe):
                return coordinator._discover_replay_guards(v0, evidence, deadline=None, running_parent=running)

        return coordinator, v0, discover

    def test_guard_round_skips_covered_queue_rows_one_checkpoint_at_a_time(self):
        """Each skipped queue row is its own checkpoint, and it saves the remaining rows in order.

        A resume after any of these checkpoints reads this queue. Comparing only lengths would
        miss a reversed walk: the first checkpoint would then keep ["a", "d"], not ["b", "d"].
        """
        def parameter(name):
            return {"name": name, "source": "POST", "location": "form", "request_id": "req-v0"}

        with tempfile.TemporaryDirectory() as tmp:
            coordinator, v0, discover = self._guard_round(tmp, child_parameters=[parameter("a"), parameter("b")])
            coordinator.state["pending_probe_queue"] = [
                {"parent_version": "v0", "candidate": parameter(name)} for name in ("a", "b", "d")
            ]
            original = coordinator._write_state
            snapshots = []

            def snap():
                # _record_event appends before it checkpoints: events[-1] caused this write.
                event = coordinator.state["events"][-1]
                snapshots.append((event["kind"], event["status"], (event.get("candidate") or {}).get("name"),
                                  [row["candidate"]["name"] for row in coordinator.state["pending_probe_queue"]]))
                original()

            with patch.object(coordinator, "_write_state", side_effect=snap):
                target = discover()
            self.assertEqual([shot for shot in snapshots if shot[0] in {"PARAMETER_PROBE", "CHILD_REPLAY"}], [
                ("PARAMETER_PROBE", "SKIPPED", "a", ["b", "d"]),
                ("PARAMETER_PROBE", "SKIPPED", "b", ["d"]),
                ("CHILD_REPLAY", "PASS", None, ["d"]),
            ])
            self.assertEqual([row["candidate"]["name"] for row in coordinator.state["pending_probe_queue"]], ["d"])
            self.assertEqual(target["version"], "v1")
            self.assertEqual(v0["worker_status"], "not_started_superseded")

    def test_guard_round_resets_discovery_flag_when_probe_raises(self):
        """A failing guard probe still clears the discovery flag (the finally clause).

        The probe sees the flag set, so this also pins that the guard round calls
        _run_pending_probe on the coordinator, where the patch applies.
        """
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, v0, discover = self._guard_round(tmp)

            def failing_probe(**kwargs):
                self.assertIs(coordinator._replay_discovery_active, True)
                raise RuntimeError("boom")

            with self.assertRaises(RuntimeError):
                discover(failing_probe)
            self.assertIs(coordinator._replay_discovery_active, False)
            kinds = [(event.get("kind"), event.get("status")) for event in coordinator.state["events"]]
            self.assertIn(("REPLAY_GUARD_DISCOVERY", "PENDING"), kinds)
            self.assertNotIn("CHILD_REPLAY", [kind for kind, _ in kinds])

    def test_guard_round_keeps_ancestor_when_descendant_misses_batch_field(self):
        """A worker-poll descendant whose own replay does not prove a new field is rejected.

        The running parent lacks ``n``; v1 adds it but its replay never sends it, so the verified
        ancestor stays the handoff target. This is the only test through the descendant batch
        check, so it fails if a refactor reaches that check through a host that lacks it.
        """
        new_field = {"name": "n", "source": "POST", "location": "form", "request_id": "req-v1"}
        with tempfile.TemporaryDirectory() as tmp:
            coordinator, v0, discover = self._guard_round(
                tmp, running_parent={"known_parameters": []}, child_parameters=[new_field],
                child_fields={"evidence_origin": "worker_poll"},
            )
            worker_status = v0["worker_status"]
            target = discover()
            self.assertIs(target, v0)
            child = coordinator._version("v1")
            self.assertIs(child["replay_result"]["passed"], False)
            self.assertEqual(child["terminal_reason"], "PARAMETER_REPLAY_NOT_VERIFIED")
            self.assertTrue(any(
                event.get("kind") == "CHILD_REPLAY" and event.get("status") == "REJECTED"
                for event in coordinator.state["events"]
            ))
            self.assertEqual(v0["worker_status"], worker_status)

    def test_select_v0_keeps_raw_report_when_builder_raises(self):
        """_select_v0 stores the raw report before building, and targets and state only after.

        A builder error leaves the report it read in place, with no targets listed and no
        candidate queued in the state.
        """
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = self.make_coordinator(Path(tmp), [])
            payload = json.loads(Path(coordinator.suggested_seeds).read_text(encoding="utf-8"))
            queued = {key: copy.deepcopy(coordinator.state[key])
                      for key in ("queued_candidate_ids", "queued_candidate_context_keys")}

            def failing_builder(*args, **kwargs):
                raise RuntimeError("boom")

            coordinator.build_config_fn = failing_builder
            with self.assertRaises(RuntimeError):
                coordinator._select_v0()
            self.assertEqual(coordinator._raw_report, payload)
            self.assertEqual(coordinator._targets, [])
            self.assertEqual({key: coordinator.state[key] for key in queued}, queued)


if __name__ == "__main__":
    unittest.main()
