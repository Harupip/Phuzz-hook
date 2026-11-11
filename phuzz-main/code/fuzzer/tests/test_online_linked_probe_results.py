import unittest

from online_linked.coordination.probe_results import (
    ajax_branch_continuation,
    match_probe_parameters,
    replay_verdict,
)
from online_linked.coordination.request_matching import _parameter_key


def param(name, source="POST", location="form", fuzzable=True):
    return {"name": name, "source": source, "location": location, "fuzzable": fuzzable}


class AjaxBranchContinuationTests(unittest.TestCase):
    def test_ajax_branch_failure_keeps_accumulated_parameters(self):
        """An AJAX request that skipped a known field only describes its own path, so the
        version continues with the union instead of being rejected as a branch failure."""
        a, b, c = param("a"), param("b"), param("c")
        result = ajax_branch_continuation(
            {"status": "REPLAY_FAILED", "known_parameters": [a], "observed_parameters": [b],
             "missing_parameters": [c]},
            {"known_parameters": []},
        )
        self.assertEqual(result["status"], "CONTINUE")
        self.assertEqual({_parameter_key(p) for p in result["known_parameters"]}, {_parameter_key(a), _parameter_key(b)})
        self.assertEqual(result["unobserved_known_parameters"], [c])
        self.assertEqual(result["missing_parameters"], [])
        self.assertEqual(result["new_parameters"], [b])

    def test_ajax_branch_failure_tolerates_missing_fields(self):
        """Results saved by older checkpoints may carry only a status; resume must not crash."""
        result = ajax_branch_continuation({"status": "REPLAY_FAILED"}, {})
        self.assertEqual(result["new_parameters"], [])
        self.assertEqual(result["known_parameters"], [])
        self.assertEqual(result["status"], "CONTINUE")


class MatchProbeParametersTests(unittest.TestCase):
    def test_method_probe_only_matches_fuzzable_post_fields(self):
        """A method probe proves POST only through a POST field, never through a GET read."""
        get_read, post_read = param("q", "GET", "query"), param("p", "POST", "form")
        match = match_probe_parameters(
            {"name": "x", "source": "POST", "location": "form", "method_probe": True},
            [get_read, post_read], [get_read, post_read], ajax=False,
        )
        self.assertEqual(match.matching, [post_read])

    def test_non_ajax_trace_equals_matching(self):
        """Only AJAX traces pull unrelated accesses into the proposal."""
        target, other = param("t"), param("o")
        match = match_probe_parameters(param("t"), [target, other], [target, other], ajax=False)
        self.assertEqual(match.trace_parameters, match.matching)
        self.assertEqual(match.matching, [target])
        self.assertEqual(match.unexpected, [other])

    def test_ajax_trace_joins_other_fuzzable_accesses(self):
        target, other = param("t"), param("o")
        match = match_probe_parameters(param("t"), [target, other], [target, other], ajax=True)
        self.assertEqual(match.trace_parameters, [target, other])

    def test_non_fuzzable_target_read_is_pending(self):
        pending = param("t", fuzzable=False)
        match = match_probe_parameters(param("t"), [pending], [pending], ajax=False)
        self.assertEqual(match.matching, [])
        self.assertEqual(match.pending_matching, [pending])


def replay_row(status_code=200):
    return {
        "validation_status": "callback_reached",
        "process_status": "ok",
        "request_payload": {"response": {"status_code": status_code}},
    }


class ReplayVerdictTests(unittest.TestCase):
    def test_replay_verdict_status_mismatch_is_transport_failure(self):
        """With parameter replay, HTTP status is diagnostic, but a sender/artifact mismatch
        means the batch reached the server differently and cannot prove the fields."""
        verified = [{"name": "a", "bucket": "body_params"}]
        verdict = replay_verdict(
            replay_row=replay_row(500), sender_result={"response_status": 200}, baseline=None,
            verified_parameters=verified, deadline_expired=False, artifact_error="",
        )
        self.assertTrue(verdict.transport_failed)
        self.assertFalse(verdict.passed)
        self.assertEqual(verdict.parameter_failures, verified)

    def test_replay_verdict_non_numeric_status_is_not_success(self):
        verdict = replay_verdict(
            replay_row=replay_row("abc"), sender_result={"response_status": "abc"}, baseline={"request": {}, "zend": {}},
            verified_parameters=[], deadline_expired=False, artifact_error="",
        )
        self.assertFalse(verdict.passed)

    def test_replay_verdict_callback_reached_2xx_passes(self):
        verdict = replay_verdict(
            replay_row=replay_row(200), sender_result={"response_status": 200}, baseline={"request": {}, "zend": {}},
            verified_parameters=[], deadline_expired=False, artifact_error="",
        )
        self.assertTrue(verdict.passed)
        self.assertEqual(verdict.response_status, 200)

    def test_reached_callback_with_302_passes_without_parameter_replay(self):
        """Callbacks such as Ninja Forms OAuth can complete with an expected redirect."""
        verdict = replay_verdict(
            replay_row=replay_row(302), sender_result={"response_status": 302}, baseline={"request": {}, "zend": {}},
            verified_parameters=[], deadline_expired=False, artifact_error="",
        )
        self.assertTrue(verdict.callback_passed)
        self.assertFalse(verdict.non_success_response)
        self.assertTrue(verdict.passed)

    def test_302_still_requires_callback_baseline_and_matching_transport(self):
        cases = [
            ({"validation_status": "registered_not_executed"}, {"response_status": 302}, {"request": {}, "zend": {}}),
            ({}, {"response_status": 302}, None),
            ({}, {"response_status": 200}, {"request": {}, "zend": {}}),
            ({}, {"response_status": 302, "error": "connection closed"}, {"request": {}, "zend": {}}),
        ]
        for row_changes, sender, baseline in cases:
            with self.subTest(row_changes=row_changes, sender=sender, baseline=baseline):
                verdict = replay_verdict(
                    replay_row={**replay_row(302), **row_changes}, sender_result=sender, baseline=baseline,
                    verified_parameters=[], deadline_expired=False, artifact_error="",
                )
                self.assertFalse(verdict.passed)

    def test_other_non_2xx_responses_keep_guard_unverified(self):
        for status in (301, 303, 304, 307, 308, 400, 403, 404, 500):
            with self.subTest(status=status):
                verdict = replay_verdict(
                    replay_row=replay_row(status), sender_result={"response_status": status},
                    baseline={"request": {}, "zend": {}}, verified_parameters=[],
                    deadline_expired=False, artifact_error="",
                )
                self.assertTrue(verdict.callback_passed)
                self.assertTrue(verdict.non_success_response)
                self.assertFalse(verdict.passed)

    def test_replay_verdict_uses_artifact_status_when_sender_has_none(self):
        verdict = replay_verdict(
            replay_row=replay_row(204), sender_result={}, baseline={"request": {}, "zend": {}},
            verified_parameters=[], deadline_expired=False, artifact_error="",
        )
        self.assertTrue(verdict.passed)
        self.assertEqual(verdict.response_status, 204)

    def test_expired_deadline_never_passes(self):
        verdict = replay_verdict(
            replay_row=replay_row(200), sender_result={"response_status": 200}, baseline={"request": {}, "zend": {}},
            verified_parameters=[], deadline_expired=True, artifact_error="",
        )
        self.assertFalse(verdict.passed)


if __name__ == "__main__":
    unittest.main()
