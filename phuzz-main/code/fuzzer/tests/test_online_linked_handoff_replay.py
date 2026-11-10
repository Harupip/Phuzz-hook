import unittest
from pathlib import Path

from online_linked.coordination.handoff_replay import handoff_replay_row, replay_failure_reason


class HandoffReplayTests(unittest.TestCase):
    def test_handoff_replay_row_key_order_and_raw_variant(self):
        """Replay diagnostics keep their field order and raw seed variant."""
        root = Path("configs")
        replay = root / "online-linked" / "replay.json"
        child = {"hook_name": "hook", "callback_id": "callback", "entrypoint_type": "ajax", "resolved_method": "POST"}
        row = handoff_replay_row(child, replay, config_root=root)
        self.assertEqual(list(row), [
            "config_slug", "hook_name", "callback_id", "entrypoint_type", "resolved_method", "seed_variant_id",
        ])
        self.assertEqual(row, {"config_slug": "online-linked/replay", **child, "seed_variant_id": ""})
        self.assertEqual(handoff_replay_row({**child, "seed_variant_id": 7}, replay, config_root=root)["seed_variant_id"], 7)
        with self.assertRaises(ValueError):
            handoff_replay_row(child, Path("elsewhere/replay.json"), config_root=root)

    def test_replay_failure_reason_precedence(self):
        """The first applicable failure is kept in the checkpoint when reasons overlap."""
        def reason(*, artifact_error="", report_error="", process_status="", validation_status="callback_reached",
                   validation_reason="", transport_error=False, unverified_parameters=None):
            return replay_failure_reason(
                artifact_error=artifact_error,
                replay_report={"error": report_error} if report_error else {},
                replay_row={"process_status": process_status, "validation_status": validation_status,
                            "validation_reason": validation_reason},
                replay_result={"transport_error": transport_error, "unverified_parameters": unverified_parameters},
            )

        precedence = [
            ({"artifact_error": "x"}, "REPLAY_ARTIFACT_SAVE_FAILED"),
            ({"process_status": "failed"}, "REPLAY_PROCESS_FAILED"),
            ({"validation_status": "callback_not_reached"}, "CALLBACK_NOT_REACHED"),
            ({"transport_error": True}, "REPLAY_TRANSPORT_NOT_VERIFIED"),
            ({"unverified_parameters": [{}]}, "PARAMETER_REPLAY_NOT_VERIFIED"),
        ]
        self.assertEqual(reason(), "CALLBACK_BASELINE_NOT_VERIFIED")
        for fields, expected in precedence + [
            ({"report_error": "e"}, "REPLAY_PROCESS_FAILED"),
            ({"process_status": "runner_error"}, "REPLAY_PROCESS_FAILED"),
            ({"validation_status": "callback_not_reached", "validation_reason": "R"}, "R"),
        ]:
            with self.subTest(fields=fields):
                self.assertEqual(reason(**fields), expected)
        for (first, expected), (second, _) in zip(precedence, precedence[1:]):
            with self.subTest(first=first, second=second):
                self.assertEqual(reason(**first, **second), expected)
