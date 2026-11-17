import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from online_linked.coordination.parallel_start import (
    clear_parallel_start,
    run_parallel_start,
    settle_parallel_start,
)
from online_linked.coordination.worker import (
    container_running,
    matching_pause_ack,
    remove_container,
    parallel_node_id,
    parallel_node_name,
    worker_container_name,
    worker_start_command,
)


class WorkerHelpersTests(unittest.TestCase):
    def test_parallel_start_receipt_survives_coordinator_kill(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt, ready, release = (Path(tmp) / name for name in ("receipt.json", "ready", "release"))
            command = [sys.executable, "-c", (
                "import sys, time; from pathlib import Path\n"
                "Path(sys.argv[1]).touch()\n"
                "deadline = time.monotonic() + 15\n"
                "while not Path(sys.argv[2]).exists() and time.monotonic() < deadline: time.sleep(0.01)\n"
            ), str(ready), str(release)]
            driver = (
                "import subprocess, sys; from pathlib import Path; "
                "from online_linked.coordination.parallel_start import run_parallel_start; "
                "run_parallel_start(Path(sys.argv[1]), sys.argv[2:], timeout=20, run_command=subprocess.run)"
            )

            def wait_for(path):
                deadline = time.monotonic() + 10
                while not path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(path.exists(), path)

            with subprocess.Popen([sys.executable, "-c", driver, str(receipt), *command]) as coordinator:
                try:
                    wait_for(ready)
                    coordinator.kill()
                    coordinator.wait(timeout=10)
                    self.assertFalse(settle_parallel_start(receipt))
                finally:
                    release.touch()
                    if ready.exists():
                        wait_for(receipt)
            self.assertTrue(settle_parallel_start(receipt))

    def test_parallel_start_can_be_cancelled_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt = Path(tmp) / "receipt.json"
            created = Path(tmp) / "container"
            self.assertTrue(settle_parallel_start(receipt))
            result = run_parallel_start(
                receipt, [sys.executable, "-c", "import sys; from pathlib import Path; Path(sys.argv[1]).touch()", str(created)],
                timeout=10, run_command=subprocess.run,
            )
            self.assertEqual(result.stderr, "PARALLEL_START_CANCELLED")
            self.assertFalse(created.exists())

    def test_parallel_start_straggler_outliving_compose_cannot_create_later(self):
        """P1: a Compose child that outlives the CLI must be dead before the launch counts as settled."""
        with tempfile.TemporaryDirectory() as tmp:
            receipt, marker = Path(tmp) / "receipt.json", Path(tmp) / "late-container"
            straggler = "import sys, time; time.sleep(7); open(sys.argv[1], 'w').close()"
            # The CLI exits at once and leaves a child that would "create the container" 7s later.
            cli = ("import subprocess, sys; "
                   f"subprocess.Popen([sys.executable, '-c', {straggler!r}, sys.argv[1]])")
            started = time.monotonic()
            run_parallel_start(receipt, [sys.executable, "-c", cli, str(marker)],
                               timeout=20, run_command=subprocess.run)
            deadline = time.monotonic() + 10
            while not settle_parallel_start(receipt) and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertTrue(settle_parallel_start(receipt))
            time.sleep(max(0.0, started + 9 - time.monotonic()))
            self.assertFalse(marker.exists(), "a settled launch must not create anything afterwards")

    def test_parallel_start_launch_timeout_kills_hung_compose(self):
        """A hung Compose is killed with its tree, then recorded, instead of blocking cleanup forever."""
        with tempfile.TemporaryDirectory() as tmp:
            receipt = Path(tmp) / "receipt.json"
            result = run_parallel_start(
                receipt, [sys.executable, "-c", "import time; time.sleep(30)"],
                timeout=20, run_command=subprocess.run, launch_timeout=1,
            )
            self.assertEqual((result.returncode, result.stderr), (-1, "PARALLEL_START_TIMEOUT"))
            self.assertTrue(settle_parallel_start(receipt))

    def test_late_launcher_still_sees_cancellation_after_cleanup(self):
        """Cleanup that ran before the launcher claimed must not erase the only thing that stops it."""
        with tempfile.TemporaryDirectory() as tmp:
            receipt, worker = Path(tmp) / "receipt.json", Path(tmp) / "worker-created"
            self.assertTrue(settle_parallel_start(receipt))
            clear_parallel_start(receipt)  # done by _remove once the container is confirmed absent
            result = run_parallel_start(
                receipt, [sys.executable, "-c", "import sys; open(sys.argv[1], 'w').close()", str(worker)],
                timeout=20, run_command=subprocess.run,
            )
            self.assertEqual(result.stderr, "PARALLEL_START_CANCELLED")
            self.assertFalse(worker.exists(), "a cancelled launch must not create a worker")

    def test_cleanup_keeps_cancellation_while_launcher_is_mid_claim(self):
        """Launcher wrote `.started` but has not read `.cancelled` yet: cleanup must not erase the marker."""
        with tempfile.TemporaryDirectory() as tmp:
            receipt, ready, release = (Path(tmp) / name for name in ("receipt.json", "ready", "release"))
            # A guarded launcher paused between the two halves of its claim.
            launcher = "\n".join([
                "import sys, time; from pathlib import Path",
                "from online_linked.coordination.launch_guard import open_guard",
                "from online_linked.coordination.parallel_start import GUARDED_CLAIM",
                "receipt, ready, release = map(Path, sys.argv[1:4])",
                "guard = open_guard(receipt)",
                "receipt.with_suffix('.started').write_text(GUARDED_CLAIM, encoding='utf-8')",
                "ready.touch()",
                "deadline = time.monotonic() + 15",
                "while not release.exists() and time.monotonic() < deadline: time.sleep(0.01)",
                "sys.exit(0 if receipt.with_suffix('.cancelled').exists() else 3)",
            ])
            self.assertTrue(settle_parallel_start(receipt))  # before the claim: nothing to wait for
            with subprocess.Popen([sys.executable, "-c", launcher, str(receipt), str(ready), str(release)],
                                  cwd=Path(__file__).resolve().parents[1]) as process:
                deadline = time.monotonic() + 10
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                clear_parallel_start(receipt)  # cleanup after `docker rm` found nothing
                release.touch()
                self.assertEqual(process.wait(timeout=20), 0, "the launcher must still see its cancellation")

    def test_unguarded_claim_from_older_launcher_is_never_assumed_ended(self):
        """A 39ec0808 launcher left `.started` empty and held no guard; only its receipt proves it ended."""
        with tempfile.TemporaryDirectory() as tmp:
            receipt = Path(tmp) / "receipt.json"
            receipt.with_suffix(".started").touch()
            with self.assertRaisesRegex(ValueError, "PARALLEL_START_LEGACY_UNCONFIRMED"):
                settle_parallel_start(receipt)
            receipt.write_text('{"returncode": 0, "stderr": ""}', encoding="utf-8")
            self.assertTrue(settle_parallel_start(receipt))

    def test_parallel_start_settles_when_launch_never_ran(self):
        """No claim means nothing was launched, so cleanup may proceed."""
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(settle_parallel_start(Path(tmp) / "receipt.json"))

    def test_parallel_start_records_normal_compose_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt = Path(tmp) / "receipt.json"
            result = run_parallel_start(
                receipt, [sys.executable, "-c", "raise SystemExit(125)"],
                timeout=10, run_command=subprocess.run,
            )
            self.assertEqual(result.returncode, 125)
            self.assertTrue(settle_parallel_start(receipt))

    def test_worker_container_name_sanitizes_run_id(self):
        """Compose start and subsequent stop must use the same Docker-safe name."""
        for run_id, version, expected in [
            ("run", "v1", "hookphuzz-online-linked-run-v1"),
            ("a b/c", "v2", "hookphuzz-online-linked-a-b-c-v2"),
            ("///", "v0", "hookphuzz-online-linked-online-linked-v0"),
        ]:
            with self.subTest(run_id=run_id):
                self.assertEqual(worker_container_name(run_id, version), expected)

    def test_matching_pause_ack_requires_token_and_run_id(self):
        """Only this pause and worker run can unlock replay and supply round progress."""
        matching = {"token": "t", "worker_run_id": "r", "allocated_energy": 20}
        for ack in (None, {}, {**matching, "token": "old"}, {**matching, "worker_run_id": "foreign"}):
            with self.subTest(ack=ack):
                self.assertIsNone(matching_pause_ack(ack, token="t", run_id="r"))
        snapshot = matching_pause_ack(matching, token="t", run_id="r")
        self.assertEqual(snapshot, {"round_id": None, "allocated_energy": 20, "attempts_used": None,
                                    "request_id": None, "seed_phuzz_energy": None})
        self.assertEqual(list(snapshot), ["round_id", "allocated_energy", "attempts_used", "request_id", "seed_phuzz_energy"])

    def test_parallel_node_id_keeps_gate_replay_id_free(self):
        """FUZZER_NODE_ID 100 belongs to gate replay; v0 nodes 1..50 must never reach it."""
        self.assertEqual(parallel_node_id("v0", 1), 1)
        self.assertEqual(parallel_node_id("v0", 50), 50)
        self.assertEqual(parallel_node_id("v1", 1), 101)
        self.assertEqual(parallel_node_id("v2", 10), 210)
        for node_index in (0, 51):
            with self.subTest(node_index=node_index), self.assertRaises(ValueError):
                parallel_node_id("v0", node_index)

    def test_parallel_node_name_keeps_node_one_identity(self):
        """Node 1 is the existing worker; extra nodes must not collide with it."""
        self.assertEqual(parallel_node_name("run-v0", 1), "run-v0")
        self.assertEqual(parallel_node_name("run-v0", 3), "run-v0-n3")

    def test_worker_start_command_node_id_override(self):
        """Default numbering stays 1 + version_index; parallel mode passes its own id."""
        version = {"version": "v1", "worker_run_id": "run-v1", "handoff_key": "k", "config_hash": "abc"}
        kwargs = {"container_name": "c", "runtime_slug": "slug", "service": "fuzzer", "priority_seed": None}
        self.assertIn("FUZZER_NODE_ID=2", worker_start_command(version, **kwargs))
        command = worker_start_command(version, **kwargs, fuzzer_node_id=105)
        self.assertIn("FUZZER_NODE_ID=105", command)
        self.assertNotIn("FUZZER_NODE_ID=2", command)

    def test_remove_container_only_accepts_confirmed_absence(self):
        target = "worker"
        absent = f"Error response from daemon: No such container: {target}"
        removing = f"Error response from daemon: removal of container {target} is already in progress"
        daemon_error = "Cannot connect to the Docker daemon"
        for first, inspection, expected in (
            (absent, None, True),
            (removing, f"Error: No such container: {target}", True),
            (absent + "-other", None, False),
            (removing, absent + "-other", False),
            (daemon_error, None, False),
            (removing, daemon_error, False),
            (subprocess.TimeoutExpired("docker", 30), None, False),
            (removing, subprocess.TimeoutExpired("docker", 30), False),
        ):
            with self.subTest(first=first, inspection=inspection):
                responses = iter((first, inspection))

                def run(command, **kwargs):
                    response = next(responses)
                    if isinstance(response, Exception):
                        raise response
                    return subprocess.CompletedProcess(command, 1, "", response)

                stopped, error = remove_container(target, clock=lambda: 0, sleeper=lambda _: None, run_command=run)
                self.assertEqual(stopped, expected)
                if not stopped:
                    self.assertTrue(error)

    def test_container_running_true_only_for_running(self):
        """The parallel clock may start only when Docker positively reports the node running."""
        def runner(stdout=None, error=None):
            def run(command, **kwargs):
                if error is not None:
                    raise error
                return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")
            return run
        self.assertTrue(container_running("c", timeout=5, run_command=runner("true\n")))
        self.assertFalse(container_running("c", timeout=5, run_command=runner("false")))
        self.assertFalse(container_running(
            "c", timeout=5, run_command=runner(error=subprocess.TimeoutExpired("docker", 5))))
