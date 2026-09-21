import http.server
import io
import json
import importlib
import sys
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path

from unittest.mock import patch

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

try:
    fuzzer = importlib.import_module("fuzzer.fuzzer")
except ModuleNotFoundError as exc:
    if "'fuzzer' is not a package" not in str(exc):
        raise
    fuzzer = importlib.import_module("fuzzer")
from hook_energy.seed_generation import generated_config_runner
from online_linked import probe_sender
from seed_generation.config.config_exporter import export_seed_configs


class ProbeSenderTests(unittest.TestCase):
    def test_container_sender_uses_exec_and_explicit_ids(self):
        calls = []

        class Process:
            stdout = io.StringIO('{"status":"callback_reached","request_id":"request-1"}\n')
            stderr = io.StringIO()

            def poll(self):
                return 0

        def factory(command, **kwargs):
            calls.append((list(command), kwargs))
            return Process()

        run_in_container = getattr(probe_sender, "run_in_container", None)
        self.assertIsNotNone(run_in_container)
        result = run_in_container(
            "parent-container",
            config_slug="online-linked/v1/replay",
            request_id="request-1",
            run_id="probe-run",
            timeout_seconds=5,
            expected={"plugin_slug": "fixture", "hook_name": "wp_ajax_fixture", "callback_id": "cb", "method": "POST", "auth_context": "guest"},
            process_factory=factory,
            parent_exit_code=lambda _timeout: None,
        )

        command = calls[0][0]
        self.assertEqual(command[:2], ["docker", "exec"])
        self.assertIn("HOOKPHUZZ_LEGACY_RUN_ID=probe-run", command)
        self.assertIn("online_linked.probe_sender", command)
        self.assertNotIn("/app/fuzzer.py", command)
        self.assertEqual(command[command.index("python") + 1:command.index("python") + 3],
                         ["-m", "online_linked.probe_sender"])
        self.assertIn("--request-id", command)
        self.assertIn("request-1", command)
        self.assertIn("--config-path", command)
        self.assertIn("/app/configs/online-linked/v1/replay.json", command)
        self.assertNotIn("compose", command)
        self.assertNotIn("rm", command)
        self.assertEqual(result["status"], "callback_reached")

    def test_sender_cancels_when_parent_exits_without_starting_another_worker(self):
        calls = []

        class Process:
            stdout = io.StringIO()
            stderr = io.StringIO()

            def poll(self):
                return None

            def terminate(self):
                calls.append("terminate")

            def wait(self, timeout=None):
                calls.append("wait")

        def factory(command, **kwargs):
            return Process()

        result = probe_sender.run_in_container(
            "parent-container", config_slug="versions/v1/replay", request_id="request-1",
            run_id="probe-run", timeout_seconds=5, expected={}, process_factory=factory,
            parent_exit_code=lambda _timeout: 1337,
        )
        self.assertEqual(result["status"], "parent_stopped")
        self.assertEqual(result["parent_exit_code"], 1337)
        self.assertEqual(calls, ["terminate", "wait"])

    def test_sender_deadline_wins_over_slow_parent_check_and_cleans_sender(self):
        class Clock:
            value = 0.0

            def __call__(self):
                return self.value

        calls = []
        clock = Clock()

        class Process:
            stdout = io.StringIO('{"status":"callback_reached"}\n')
            stderr = io.StringIO()

            def poll(self):
                return 0

            def terminate(self):
                calls.append("terminate")

            def wait(self, timeout=None):
                calls.append("wait")

        def parent_check(remaining):
            self.assertLessEqual(remaining, 0.05)
            clock.value += 0.3
            return None

        result = probe_sender.run_in_container(
            "parent-container", config_slug="versions/v1/replay", request_id="late-result",
            run_id="probe-run", timeout_seconds=0.05, expected={},
            process_factory=lambda *args, **kwargs: Process(),
            parent_exit_code=parent_check, clock=clock, sleeper=lambda _delay: None,
        )
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(result["error"], "SENDER_TIMEOUT")
        self.assertEqual(calls, ["terminate", "wait"])

    def test_sender_does_not_start_parent_check_after_budget_expiry(self):
        class Clock:
            calls = 0

            def __call__(self):
                self.calls += 1
                return 0.0 if self.calls == 1 else 0.05

        calls = []

        class Process:
            stdout = io.StringIO('{"status":"callback_reached"}\n')
            stderr = io.StringIO()

            def poll(self):
                return 0

            def terminate(self):
                calls.append("terminate")

            def wait(self, timeout=None):
                calls.append("wait")

        result = probe_sender.run_in_container(
            "parent-container", config_slug="versions/v1/replay", request_id="expired",
            run_id="probe-run", timeout_seconds=0.05, expected={},
            process_factory=lambda *args, **kwargs: Process(),
            parent_exit_code=lambda _timeout: (_ for _ in ()).throw(
                AssertionError("inspect must not run")
            ),
            clock=Clock(), sleeper=lambda _delay: None,
        )
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(calls, ["terminate", "wait"])

    def test_sender_parent_check_timeout_is_not_parent_exit(self):
        class Process:
            stdout = io.StringIO('{"status":"callback_reached"}\n')
            stderr = io.StringIO()

            def poll(self):
                return 0

            def terminate(self):
                return None

            def wait(self, timeout=None):
                return None

        result = probe_sender.run_in_container(
            "parent-container", config_slug="versions/v1/replay", request_id="inspect-timeout",
            run_id="probe-run", timeout_seconds=5, expected={},
            process_factory=lambda *args, **kwargs: Process(),
            parent_exit_code=lambda _timeout: (_ for _ in ()).throw(
                probe_sender.ParentInspectionTimeout()
            ),
            sleeper=lambda _delay: None,
        )
        self.assertEqual(result["status"], "parent_check_timeout")
        self.assertNotIn("parent_exit_code", result)

    def test_container_sender_drains_large_stdout_and_stderr_with_real_subprocess(self):
        script = (
            "import sys; "
            "sys.stderr.write('e' * (1024 * 1024)); sys.stderr.flush(); "
            "sys.stdout.write('{\"status\":\"callback_reached\",\"request_id\":\"request-large\",\"blob\":\"'); "
            "sys.stdout.write('x' * (1024 * 1024)); sys.stdout.write('\"}\\n'); sys.stdout.flush()"
        )

        def factory(_command, **kwargs):
            return subprocess.Popen([sys.executable, "-c", script], **kwargs)

        result = probe_sender.run_in_container(
            "parent-container", config_slug="versions/v1/replay", request_id="request-large",
            run_id="probe-run", timeout_seconds=5, expected={}, process_factory=factory,
        )
        self.assertEqual(result["status"], "callback_reached")
        self.assertEqual(len(result["blob"]), 1024 * 1024)

    def test_container_sender_timeout_terminates_real_subprocess(self):
        def factory(_command, **kwargs):
            return subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(10)"], **kwargs
            )

        started = time.monotonic()
        result = probe_sender.run_in_container(
            "parent-container", config_slug="versions/v1/replay", request_id="request-timeout",
            run_id="probe-run", timeout_seconds=0.2, expected={}, process_factory=factory,
        )
        self.assertEqual(result["status"], "timeout")
        self.assertLess(time.monotonic() - started, 3)

    def test_container_sender_parent_exit_terminates_real_subprocess(self):
        def factory(_command, **kwargs):
            return subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(10)"], **kwargs
            )

        result = probe_sender.run_in_container(
            "parent-container", config_slug="versions/v1/replay", request_id="request-parent-exit",
            run_id="probe-run", timeout_seconds=5, expected={}, process_factory=factory,
            parent_exit_code=lambda _timeout: 1337,
        )
        self.assertEqual(result["status"], "parent_stopped")
        self.assertEqual(result["parent_exit_code"], 1337)

    def test_request_preparation_uses_explicit_ids_without_constructing_fuzzer(self):
        config = {
            "target": "http://web/wp-admin/admin-ajax.php?existing=1",
            "methods": ["POST"],
            "metadata": {
                "hook_name": "wp_ajax_nopriv_fixture",
                "auth_context": "guest",
            },
            "headers": {
                "data": [
                    {"name": "Content-Type", "value": "application/json"},
                    {"name": "X-HookPhuzz-Auth-Context", "value": "authenticated"},
                ]
            },
            "cookies": {
                "data": [
                    {"name": "wordpress_logged_in_test", "value": "secret"},
                    {"name": "visitor", "value": "guest"},
                ]
            },
            "query_params": {"data": [{"name": "page", "value": 0}]},
            "body_params": {
                "data": [{"name": "enabled", "value": False}, {"name": "count", "value": 0}]
            },
        }

        prepare = getattr(probe_sender, "prepare_request_from_config", None)
        self.assertIsNotNone(prepare)
        with patch.object(fuzzer, "Fuzzer", side_effect=AssertionError("sender must not construct Fuzzer")):
            prepared = prepare(config, request_id="probe-request", run_id="probe-run")

        self.assertEqual(prepared.method, "POST")
        self.assertIn("existing=1", prepared.url)
        self.assertIn("page=0", prepared.url)
        self.assertEqual(prepared.headers["X-HookPhuzz-Request-ID"], "probe-request")
        self.assertEqual(prepared.headers["X-HookPhuzz-Run-ID"], "probe-run")
        self.assertEqual(prepared.headers["X-HookPhuzz-Auth-Context"], "guest")
        self.assertNotIn("wordpress_logged_in_test", prepared.headers.get("Cookie", ""))
        self.assertIn("visitor=guest", prepared.headers.get("Cookie", ""))
        self.assertEqual(json.loads(prepared.body), {"enabled": False, "count": 0})

    def test_authenticated_form_sender_preserves_query_types_cookies_and_explicit_run_id(self):
        config = {
            "target": "http://web/admin-ajax.php?existing=1",
            "methods": ["POST"],
            "metadata": {"hook_name": "wp_ajax_fixture", "auth_context": "authenticated"},
            "headers": {
                "data": [
                    {"name": "Content-Type", "value": "application/x-www-form-urlencoded"},
                    {"name": "X-HookPhuzz-Run-ID", "value": "stale"},
                ]
            },
            "cookies": {"data": [{"name": "wordpress_logged_in_test", "value": "secret"}]},
            "query_params": {"data": [{"name": "page", "value": 0}]},
            "body_params": {"data": [{"name": "enabled", "value": False}, {"name": "count", "value": 0}]},
        }
        with patch.object(fuzzer, "Fuzzer", side_effect=AssertionError("sender must not construct Fuzzer")):
            prepared = probe_sender.prepare_request_from_config(config, request_id="request-2", run_id="run-2")
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(prepared.url).query))
        body = dict(urllib.parse.parse_qsl(prepared.body))
        self.assertEqual(query, {"existing": "1", "page": "0"})
        self.assertEqual(body, {"enabled": "False", "count": "0"})
        self.assertIn("wordpress_logged_in_test=secret", prepared.headers["Cookie"])
        self.assertEqual(prepared.headers["X-HookPhuzz-Run-ID"], "run-2")
        self.assertEqual(prepared.headers["X-HookPhuzz-Request-ID"], "request-2")

    def test_send_and_wait_sends_once_and_returns_correlated_timing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.json"
            config_path.write_text(json.dumps({
                "target": "http://web/admin-ajax.php", "methods": ["POST"],
                "metadata": {"hook_name": "wp_ajax_fixture", "auth_context": "authenticated"},
                "body_params": {"data": [{"name": "action", "value": "fixture"}]},
            }), encoding="utf-8")
            request_dir = root / "requests"
            zend_dir = root / "zend"
            sent = []

            class Session:
                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

                def send(self, prepared, timeout, allow_redirects):
                    sent.append((prepared, timeout, allow_redirects))
                    request_dir.mkdir()
                    zend_dir.mkdir()
                    (request_dir / "request-3.json").write_text(json.dumps({
                        "request_id": "request-3", "legacy_run_id": "run-3", "target_plugin": "fixture",
                        "hook_name": "wp_ajax_fixture", "callback_id": "cb-fixture", "http_method": "POST",
                        "auth_context": "authenticated", "response": {"status_code": 200},
                        "hook_coverage": {"executed_callbacks": {"cb-fixture": {"hook_name": "wp_ajax_fixture"}}},
                    }), encoding="utf-8")
                    return type("Response", (), {"status_code": 200})()

            def write_zend(_delay):
                (zend_dir / "request-3.json").write_text(json.dumps({
                    "request_id": "request-3", "run_id": "run-3", "events": [],
                }), encoding="utf-8")

            result = probe_sender.send_and_wait(
                config_path, request_id="request-3", run_id="run-3", timeout_seconds=2,
                expected={"plugin_slug": "fixture", "hook_name": "wp_ajax_fixture",
                          "callback_id": "cb-fixture", "method": "POST", "auth_context": "authenticated"},
                session_factory=Session, request_dir=request_dir, zend_dir=zend_dir, sleeper=write_zend,
            )
            self.assertEqual(len(sent), 1)
            self.assertFalse(sent[0][2])
            self.assertEqual(result["status"], "callback_reached")
            self.assertEqual(result["validation_status"], "callback_reached")
            self.assertIn("send_http", result["timing"])
            self.assertIn("wait_artifacts", result["timing"])
            self.assertIn("total", result["timing"])

    def test_send_and_wait_does_not_follow_redirect_and_preserves_request_identity(self):
        hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append((self.path, self.headers.get("X-HookPhuzz-Request-ID"),
                             self.headers.get("X-HookPhuzz-Run-ID")))
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/target")
                    self.end_headers()
                else:
                    self.send_response(500)
                    self.end_headers()

            def log_message(self, *_args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                config_path = root / "config.json"
                config_path.write_text(json.dumps({
                    "target": f"http://127.0.0.1:{server.server_port}/redirect",
                    "methods": ["POST"],
                    "metadata": {"hook_name": "wp_ajax_fixture", "auth_context": "guest"},
                    "body_params": {"data": [{"name": "action", "value": "fixture"}]},
                }), encoding="utf-8")
                result = probe_sender.send_and_wait(
                    config_path, request_id="redirect-request", run_id="redirect-run",
                    # Test redirect handling, not sub-second scheduling on a busy host.
                    timeout_seconds=2,
                    expected={"hook_name": "wp_ajax_fixture", "callback_id": "cb-fixture",
                              "method": "POST", "auth_context": "guest"},
                    request_dir=root / "requests", zend_dir=root / "zend",
                )
                self.assertEqual(result["response_status"], 302, result)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(hits, [("/redirect", "redirect-request", "redirect-run")])

    def test_cookie_export_prepare_and_sender_round_trip_uses_cookie_bucket(self):
        hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8")
                hits.append((self.headers.get("Cookie", ""), body))
                self.send_response(204)
                self.end_headers()

            def log_message(self, *_args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                report = {"suggested_seeds": [{
                    "plugin_slug": "fixture",
                    "entrypoint_type": "ajax",
                    "hook_name": "wp_ajax_nopriv_fixture",
                    "callback_id": "cb-fixture",
                    "callback_repr": "fixture_callback",
                    "seed": {
                        "auth_mode": "unauth-capable",
                        "method": "POST",
                        "resolved_method": "POST",
                        "method_status": "resolved",
                        "path": "/wp-admin/admin-ajax.php",
                        "body": {"action": "fixture", "fixture_cookie": "body"},
                        "query_params": {},
                        "headers": {},
                        "cookies": {"fixture_cookie": "HOOKPHUZZ_COOKIE_PROBE"},
                        "fixed_params": ["action", "fixture_cookie"],
                        "fuzzable_params": [],
                        "probe_variant": True,
                    },
                }]}
                config_dir = root / "configs"
                export_seed_configs(
                    report,
                    output_config_dir=config_dir,
                    target_base=f"http://127.0.0.1:{server.server_port}",
                )
                config_path = next(config_dir.glob("*.json"))
                result = probe_sender.send_and_wait(
                    config_path,
                    request_id="cookie-roundtrip-request",
                    run_id="cookie-roundtrip-run",
                    timeout_seconds=0.2,
                    expected={"hook_name": "wp_ajax_nopriv_fixture", "callback_id": "cb-fixture",
                              "method": "POST", "auth_context": "guest"},
                    request_dir=root / "requests", zend_dir=root / "zend",
                )
                self.assertEqual(result["status"], "timeout")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(len(hits), 1)
        cookie_header, body = hits[0]
        self.assertIn("fixture_cookie=HOOKPHUZZ_COOKIE_PROBE", cookie_header)
        self.assertIn("fixture_cookie=body", body)

    def test_send_and_wait_timing_separates_http_and_artifact_wait(self):
        class Clock:
            value = 0.0

            def __call__(self):
                return self.value

            def sleep(self, delay):
                self.value += 3.0
                zend_dir.mkdir(parents=True, exist_ok=True)
                zend_dir.joinpath("timing-request.json").write_text(json.dumps({
                    "request_id": "timing-request", "run_id": "timing-run", "events": [],
                }), encoding="utf-8")

        class Session:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def send(self, prepared, timeout, allow_redirects):
                self.assertions = (prepared, timeout, allow_redirects)
                clock.value = 2.0
                request_dir.mkdir(parents=True, exist_ok=True)
                (request_dir / "timing-request.json").write_text(json.dumps({
                    "request_id": "timing-request", "legacy_run_id": "timing-run",
                    "target_plugin": "fixture", "hook_name": "wp_ajax_fixture",
                    "callback_id": "cb-fixture", "http_method": "POST",
                    "auth_context": "authenticated", "response": {"status_code": 200},
                    "hook_coverage": {"executed_callbacks": {
                        "cb-fixture": {"hook_name": "wp_ajax_fixture"},
                    }},
                }), encoding="utf-8")
                return type("Response", (), {"status_code": 200})()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.json"
            config_path.write_text(json.dumps({
                "target": "http://web/admin-ajax.php", "methods": ["POST"],
                "metadata": {"hook_name": "wp_ajax_fixture", "auth_context": "authenticated"},
                "body_params": {"data": [{"name": "action", "value": "fixture"}]},
            }), encoding="utf-8")
            request_dir = root / "requests"
            zend_dir = root / "zend"
            clock = Clock()
            result = probe_sender.send_and_wait(
                config_path, request_id="timing-request", run_id="timing-run", timeout_seconds=10,
                expected={"plugin_slug": "fixture", "hook_name": "wp_ajax_fixture",
                          "callback_id": "cb-fixture", "method": "POST",
                          "auth_context": "authenticated"}, session_factory=Session,
                request_dir=request_dir, zend_dir=zend_dir, clock=clock, sleeper=clock.sleep,
            )
            self.assertEqual(result["status"], "callback_reached")
            self.assertEqual(result["timing"]["send_http"], 2.0)
            self.assertEqual(result["timing"]["wait_artifacts"], 3.0)
            self.assertEqual(result["timing"]["verify"], 0.0)
            self.assertEqual(result["timing"]["total"], 5.0)

    def test_artifact_pair_requires_exact_ids_and_waits_for_zend(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            request_dir = root / "requests"
            zend_dir = root / "zend"
            request_dir.mkdir()
            zend_dir.mkdir()
            request_payload = {
                "request_id": "probe-request",
                "legacy_run_id": "probe-run",
                "target_plugin": "fixture",
                "hook_name": "wp_ajax_fixture",
                "callback_id": "cb-fixture",
                "http_method": "POST",
                "response": {"status_code": 200},
            }
            (request_dir / "probe-request.json.tmp").write_text(json.dumps(request_payload), encoding="utf-8")
            (request_dir / "probe-request.tmp.json").write_text(json.dumps(request_payload), encoding="utf-8")
            (request_dir / "other.json").write_text(json.dumps({**request_payload, "request_id": "other"}), encoding="utf-8")
            (request_dir / "probe-request.json").write_text(json.dumps(request_payload), encoding="utf-8")

            read_pair = getattr(generated_config_runner, "read_correlated_artifact_pair", None)
            self.assertIsNotNone(read_pair)
            with patch.object(Path, "glob", side_effect=AssertionError("correlated read must not scan")):
                pair = read_pair(
                    request_dir,
                    zend_dir,
                    request_id="probe-request",
                    run_id="probe-run",
                    expected={
                        "plugin_slug": "fixture",
                        "hook_name": "wp_ajax_fixture",
                        "callback_id": "cb-fixture",
                        "method": "POST",
                    },
                )
            self.assertIsNone(pair)

            (zend_dir / "probe-request.json").write_text(
                json.dumps({"request_id": "probe-request", "run_id": "probe-run", "events": []}),
                encoding="utf-8",
            )
            pair = read_pair(
                request_dir,
                zend_dir,
                request_id="probe-request",
                run_id="probe-run",
                expected={
                    "plugin_slug": "fixture",
                    "hook_name": "wp_ajax_fixture",
                    "callback_id": "cb-fixture",
                    "method": "POST",
                },
            )
            self.assertEqual(pair["request"]["request_id"], "probe-request")
            self.assertEqual(pair["zend"]["run_id"], "probe-run")

            for invalid_request_id in ("../probe-request", "..\\probe-request", "probe-request.tmp"):
                self.assertIsNone(read_pair(
                    request_dir, zend_dir, request_id=invalid_request_id, run_id="probe-run",
                    expected={"plugin_slug": "fixture"},
                ))

            nested = dict(request_payload)
            nested.pop("hook_name")
            nested.pop("callback_id")
            nested["hook_coverage"] = {
                "registered_callbacks": {
                    "cb-fixture": {"callback_id": "cb-fixture", "hook_name": "wp_ajax_fixture"}
                }
            }
            (request_dir / "probe-request.json").write_text(json.dumps(nested), encoding="utf-8")
            self.assertIsNotNone(read_pair(
                request_dir, zend_dir, request_id="probe-request", run_id="probe-run",
                expected={"plugin_slug": "fixture", "hook_name": "wp_ajax_fixture",
                          "callback_id": "cb-fixture", "method": "POST"},
            ))

            for field, bad_value in (("target_plugin", "other"), ("hook_name", "other_hook"),
                                     ("callback_id", "other_callback"), ("http_method", "GET"),
                                     ("auth_context", "guest")):
                bad = dict(request_payload)
                bad[field] = bad_value
                (request_dir / "probe-request.json").write_text(json.dumps(bad), encoding="utf-8")
                self.assertIsNone(read_pair(
                    request_dir, zend_dir, request_id="probe-request", run_id="probe-run",
                    expected={"plugin_slug": "fixture", "hook_name": "wp_ajax_fixture",
                              "callback_id": "cb-fixture", "method": "POST", "auth_context": "authenticated"},
                ), field)


if __name__ == "__main__":
    unittest.main()
