import unittest

from online_linked.coordination.pending_candidates import (
    append_pending_rows,
    failed_batch_parameters,
    fresh_runtime_candidates,
    pending_key,
    without_discarded,
)


def param(name, **fields):
    return {"name": name, "source": "POST", "location": "form", **fields}


class FailedBatchParametersTests(unittest.TestCase):
    def test_failed_batch_parameters_carries_only_failed_same_context(self):
        """Only fields of a child whose baseline failed in the same callback and method are
        replayed again; carrying anything else would mix proven or foreign fields into the union."""
        parent = {"callback_id": "cb", "resolved_method": "post"}
        same = {"callback_id": "cb", "resolved_method": "POST"}
        versions = [
            "not-a-mapping",
            {"version": "v0", **same, "known_parameters": [param("from_v0")]},
            {"version": "g1", **same, "discovery_origin": "replay_guard", "known_parameters": [param("guard")]},
            {"version": "p1", **same, "replay_result": {"passed": True}, "known_parameters": [param("passed")]},
            {"version": "o1", "callback_id": "other", "resolved_method": "POST",
             "known_parameters": [param("other_callback")]},
            {"version": "m1", "callback_id": "cb", "resolved_method": "GET", "known_parameters": [param("get")]},
            {"version": "v1", **same, "replay_result": {"passed": False}, "known_parameters": [
                param("seen"), param("carried"), param("get_only", request_method="GET"), "bad",
                param("carried"),
            ]},
            {"version": "v2", **same, "known_parameters": [param("later", request_method="post")]},
        ]
        carried = failed_batch_parameters(parent, [param("seen"), "bad"], versions=versions)
        self.assertEqual([item["name"] for item in carried], ["carried", "later"])
        self.assertIsNot(carried[0], versions[6]["known_parameters"][1])


class PendingRowsTests(unittest.TestCase):
    def test_pending_key_normalizes_source_and_location(self):
        """Retain and discard must agree on one key, or a discarded row would survive."""
        self.assertEqual(
            pending_key({"name": "a", "source": "post", "location": "FORM", "request_id": 1, "run_id": None}),
            ("a", "POST", "form", "1", ""),
        )

    def test_append_pending_rows_dedupes_by_five_part_key(self):
        """The same field from the same request/run is one pending proposal; a new run is new
        evidence and must be kept as its own row."""
        pending = []
        parent = {"version": "v1", "config_path": "v1.json", "callback_id": "cb",
                  "canonical_callback": "fixture_callback"}
        group = {"evidence": {"request_id": "req-1", "worker_run_id": "run-1"},
                 "parameters": [param("a"), "bad", param("a")]}
        append_pending_rows(pending, [group], parent)
        append_pending_rows(pending, [group], parent)
        self.assertEqual(len(pending), 1)
        row = pending[0]
        self.assertEqual(row["candidate_status"], "pending_runtime_proposal")
        self.assertEqual((row["request_id"], row["run_id"], row["callback_id"]), ("req-1", "run-1", "cb"))
        self.assertEqual(row["parent_version"], "v1")

        append_pending_rows(pending, [{**group, "evidence": {"request_id": "req-1", "run_id": "run-2"}}], parent)
        self.assertEqual([item["run_id"] for item in pending], ["run-1", "run-2"])

    def test_without_discarded_returns_none_when_nothing_to_discard(self):
        """No discard set means the caller must not rewrite the checkpoint."""
        pending = [param("a", request_id="r", run_id="w")]
        self.assertIsNone(without_discarded(pending, []))
        self.assertIsNone(without_discarded(pending, [{"evidence": {}, "parameters": ["bad"]}]))

    def test_without_discarded_keeps_non_mapping_items(self):
        """Only matching rows are removed; unknown entries are left for the caller as before."""
        pending = ["legacy", param("a", request_id="r", run_id="w"), param("a", request_id="r", run_id="other")]
        result = without_discarded(pending, [{"evidence": {"request_id": "r", "worker_run_id": "w"},
                                              "parameters": [param("a")]}])
        self.assertEqual(result, ["legacy", pending[2]])
        self.assertIsNot(result, pending)


class FreshRuntimeCandidatesTests(unittest.TestCase):
    def test_fresh_runtime_candidates_order_and_types(self):
        """Fresh candidates keep the pending_probes, new_parameters, observed_parameters order;
        malformed entries or fields are ignored instead of breaking reconciliation."""
        result = {
            "observed_parameters": [param("observed")],
            "new_parameters": [param("new"), "bad"],
            "pending_probes": [param("probe")],
        }
        self.assertEqual([item["name"] for item in fresh_runtime_candidates(result)], ["probe", "new", "observed"])
        self.assertEqual(fresh_runtime_candidates({"pending_probes": param("x"), "new_parameters": None}), [])


if __name__ == "__main__":
    unittest.main()
