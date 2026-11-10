import unittest

from online_linked.coordination.worker import matching_pause_ack, worker_container_name


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
