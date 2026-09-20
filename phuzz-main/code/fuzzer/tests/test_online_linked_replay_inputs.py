import copy
import sys
import unittest
from pathlib import Path


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from online_linked.replay_inputs import propose_replay_inputs


def request_params() -> dict:
    return {
        "query_params": {"unrelated": "query-value"},
        "body_params": {
            "action": "fixture",
            "post_category": "probe",
            "post_id": "probe",
            "post_type": "probe",
        },
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    }


def comparison_event(**overrides) -> dict:
    event = {
        "request_id": "request-1",
        "run_id": "run-1",
        "callback": "fixture_callback",
        "opcode": "IS_EQUAL",
        "source": "REQUEST",
        "path": ["post_type"],
        "runtime_value": "probe",
        "comparison_value": "post",
    }
    event.update(overrides)
    return event


def zend_artifact(*events: dict, **overrides) -> dict:
    artifact = {
        "request_id": "request-1",
        "run_id": "run-1",
        "comparison_events": list(events),
    }
    artifact.update(overrides)
    return artifact


PARAMETER_TRANSPORTS = [
    {"name": "post_category", "source": "POST", "location": "form"},
    {"name": "post_id", "source": "POST", "location": "form"},
    {"name": "post_type", "source": "POST", "location": "form"},
]


class ReplayInputProposalTests(unittest.TestCase):
    def test_request_hint_changes_one_allowed_value_on_full_context(self):
        original = request_params()

        proposals = propose_replay_inputs(
            original,
            zend_artifact(comparison_event()),
            parameter_transports=PARAMETER_TRANSPORTS,
            expected_request_id="request-1",
            expected_run_id="run-1",
            expected_callback="fixture_callback",
        )

        self.assertEqual(len(proposals), 1)
        self.assertEqual(
            proposals[0]["request_params"]["body_params"],
            {
                "action": "fixture",
                "post_category": "probe",
                "post_id": "probe",
                "post_type": "post",
            },
        )
        self.assertEqual(original, request_params())
        provenance = proposals[0]["hint_provenance"]
        self.assertEqual(provenance["request_id"], "request-1")
        self.assertEqual(provenance["run_id"], "run-1")
        self.assertEqual(provenance["callback"], "fixture_callback")
        self.assertEqual(provenance["parameter"], "post_type")
        self.assertEqual(provenance["source"], "REQUEST")

    def test_request_hint_rejects_conflicting_actual_buckets_but_accepts_unique_post(self):
        params = {
            "query_params": {"a": "query"},
            "body_params": {"a": "probe"},
        }
        event = comparison_event(path=["a"])
        self.assertEqual(
            propose_replay_inputs(
                params,
                zend_artifact(event),
                parameter_transports=[{"name": "a", "source": "POST", "location": "form"}],
                expected_request_id="request-1",
                expected_run_id="run-1",
                expected_callback="fixture_callback",
            ),
            [],
        )

        unique = {"body_params": {"a": "probe"}}
        proposals = propose_replay_inputs(
            unique,
            zend_artifact(event),
            parameter_transports=[{"name": "a", "source": "POST", "location": "form"}],
            expected_request_id="request-1",
            expected_run_id="run-1",
            expected_callback="fixture_callback",
        )
        self.assertEqual(proposals[0]["request_params"]["body_params"]["a"], "post")

    def test_rejects_unrelated_or_unsafe_hints(self):
        cases = [
            ("wrong request", zend_artifact(comparison_event(request_id="other"))),
            ("wrong run", zend_artifact(comparison_event(), run_id="other")),
            ("wrong callback", zend_artifact(comparison_event(callback="other_callback"))),
            ("sensitive", zend_artifact(comparison_event(path=["nonce"]))),
            ("stale value", zend_artifact(comparison_event(runtime_value="stale"))),
            ("not allowed", zend_artifact(comparison_event(path=["action"]))),
        ]
        for name, artifact in cases:
            with self.subTest(name=name):
                self.assertEqual(
                    propose_replay_inputs(
                        request_params(), artifact,
                        parameter_transports=PARAMETER_TRANSPORTS,
                        expected_request_id="request-1",
                        expected_run_id="run-1",
                        expected_callback="fixture_callback",
                    ),
                    [],
                )

    def test_rejects_ambiguous_request_transport_and_deduplicates_repeated_hints(self):
        ambiguous = propose_replay_inputs(
            request_params(),
            zend_artifact(comparison_event()),
            parameter_transports=[
                {"name": "post_type", "source": "POST", "location": "form"},
                {"name": "post_type", "source": "GET", "location": "query"},
            ],
            expected_request_id="request-1",
            expected_run_id="run-1",
            expected_callback="fixture_callback",
        )
        self.assertEqual(ambiguous, [])

        repeated = propose_replay_inputs(
            request_params(),
            zend_artifact(comparison_event(), comparison_event()),
            parameter_transports=PARAMETER_TRANSPORTS,
            expected_request_id="request-1",
            expected_run_id="run-1",
            expected_callback="fixture_callback",
        )
        self.assertEqual(len(repeated), 1)

    def test_preserves_false_and_zero_values_when_building_context(self):
        params = {"body_params": {"enabled": False, "count": 0}}
        artifact = zend_artifact(
            comparison_event(
                path=["enabled"], runtime_value=False, comparison_value=True,
            ),
            comparison_event(
                path=["count"], runtime_value=0, comparison_value=1,
            ),
        )

        proposals = propose_replay_inputs(
            params,
            artifact,
            parameter_transports=[
                {"name": "enabled", "source": "POST", "location": "form"},
                {"name": "count", "source": "POST", "location": "form"},
            ],
            expected_request_id="request-1",
            expected_run_id="run-1",
            expected_callback="fixture_callback",
        )

        self.assertEqual(
            [item["request_params"]["body_params"] for item in proposals],
            [{"enabled": True, "count": 0}, {"enabled": False, "count": 1}],
        )


if __name__ == "__main__":
    unittest.main()
