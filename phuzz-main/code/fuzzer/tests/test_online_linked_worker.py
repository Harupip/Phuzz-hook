import subprocess
import unittest

from online_linked.coordination.worker import (
    container_running,
    matching_pause_ack,
    parallel_node_id,
    parallel_node_name,
    worker_container_name,
    worker_start_command,
)


class WorkerHelpersTests(unittest.TestCase):
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
