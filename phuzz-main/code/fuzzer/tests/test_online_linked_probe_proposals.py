import unittest

from online_linked.coordination.probe_proposals import (
    add_accepted_records,
    drop_queue_row,
    group_accepted_records,
    probe_proposals,
    proposal_result,
)
from online_linked.coordination.request_matching import _parameter_key


def param(name, source="POST", location="form", fuzzable=True, **extra):
    return {"name": name, "source": source, "location": location, "fuzzable": fuzzable, **extra}


def evidence(request_id, run_id="run-1", params=None):
    return {"request_id": request_id, "run_id": run_id,
            "request": {"request_params": params if params is not None else {"q": "1"}}}


class AddAcceptedRecordsTests(unittest.TestCase):
    def test_same_field_in_another_method_is_a_separate_proof(self):
        """A proof in one HTTP method never covers the same field in another method, so the
        GET and POST reads are both kept; repeats and non-Mapping noise add nothing."""
        records, keys = [], set()
        get_a = param("a", request_method="GET")
        post_a = param("a", request_method="POST")
        add_accepted_records(records, keys, [get_a, post_a, "noise"], evidence("r1"), {"status": "x"})
        self.assertEqual(len(records), 2)
        add_accepted_records(records, keys, [dict(post_a)], evidence("r2"), {})
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0], {"parameter": get_a, "evidence": evidence("r1"), "result": {"status": "x"}})


class DropQueueRowTests(unittest.TestCase):
    def test_drop_queue_row_removes_only_the_exact_row(self):
        """The saved queue is the resume record: dropping a row that differs in parent,
        candidate or evidence would silently lose a probe after a restart."""
        candidate, ev = {"name": "a"}, evidence("r1")
        exact = {"parent_version": "v1", "candidate": candidate, "evidence": ev}
        other_parent = {"parent_version": "v2", "candidate": candidate, "evidence": ev}
        other_candidate = {"parent_version": "v1", "candidate": {"name": "b"}, "evidence": ev}
        other_evidence = {"parent_version": "v1", "candidate": candidate, "evidence": evidence("r2")}
        kept = drop_queue_row([exact, other_parent, other_candidate, other_evidence],
                              parent_version="v1", candidate=dict(candidate), evidence=dict(ev))
        self.assertEqual(kept, [other_parent, other_candidate, other_evidence])


class GroupAcceptedRecordsTests(unittest.TestCase):
    def test_records_sharing_evidence_form_one_group_with_last_result(self):
        """Fields read by the same request are one coherent proof; the group carries the
        latest probe result because it saw the most of that request."""
        ev = evidence("r1")
        records = [
            {"parameter": param("a"), "evidence": ev, "result": {"n": 1}},
            {"parameter": param("b"), "evidence": dict(ev), "result": {"n": 2}},
        ]
        groups = group_accepted_records(records)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0]["parameters"]), 2)
        self.assertEqual(groups[0]["result"], {"n": 2})


class ProbeProposalsTests(unittest.TestCase):
    def test_multiple_groups_try_combined_proposal_first(self):
        """Separate reads justify trying one combined request first; each field keeps its own
        evidence so admission can check every original pair."""
        ev_a, ev_b = evidence("r1"), evidence("r2")
        records = [
            {"parameter": param("b"), "evidence": ev_b, "result": {"n": 2}},
            {"parameter": param("a"), "evidence": ev_a, "result": {"n": 1}},
        ]
        groups = group_accepted_records(records)
        proposals = probe_proposals(groups, records)
        self.assertEqual(len(proposals), 3)
        self.assertIs(proposals[0]["combined"], True)
        self.assertEqual([p["name"] for p in proposals[0]["parameters"]], ["a", "b"])
        self.assertEqual(proposals[0]["parameter_evidence"],
                         {_parameter_key(param("a")): ev_a, _parameter_key(param("b")): ev_b})
        single = [records[0]]
        single_groups = group_accepted_records(single)
        self.assertEqual(probe_proposals(single_groups, single), single_groups)


class ProposalResultTests(unittest.TestCase):
    def test_coherent_only_group_does_not_inherit_parent_fields(self):
        """A coherent-only retry publishes just what this request proved, not the parent's set,
        and continues instead of reporting the probe's own missing reads."""
        a, x = param("a"), param("x")
        group = {"parameters": [a], "evidence": evidence("r1"), "result": {"status": "REPLAY_FAILED",
                                                                          "missing_parameters": [x]}}
        result = proposal_result(group, convergence={"_coherent_only": True}, existing=[x], deferred=[],
                                 evidence_origin="worker_poll", target_key="t")
        self.assertEqual(result["known_parameters"], [a])
        self.assertEqual(result["status"], "CONTINUE")
        self.assertEqual(result["missing_parameters"], [])

    def test_method_transition_keeps_report_and_observed_fuzzable_fields(self):
        """After a GET->POST transition the parent's fields belong to the old method, so the
        child takes the transition's identity and only the fuzzable fields it observed."""
        a, b = param("a"), param("b", fuzzable=False)
        report = {"from": "GET", "to": "POST"}
        group = {"parameters": [a], "evidence": evidence("r1"), "result": {
            "method_transition_report": report, "candidate_key": "k2", "observed_parameters": [a, b]}}
        result = proposal_result(group, convergence={}, existing=[param("old")], deferred=[],
                                 evidence_origin="worker_poll", target_key="t")
        self.assertEqual(result["candidate_key"], "k2")
        self.assertEqual(result["known_parameters"], [a])
        self.assertEqual(result["method_transition_report"], report)

    def test_proposal_result_drops_pending_probes_and_marks_group_dispatch(self):
        """The proposal is a finished decision: leftover probes must not be re-queued from it,
        deferred ones travel with it, and it falls back to the coordinator's target key."""
        deferred = [{"name": "later"}]
        group = {"parameters": [param("a")], "evidence": evidence("r1"),
                 "result": {"pending_probes": [{"name": "z"}]}}
        result = proposal_result(group, convergence={}, existing=[], deferred=deferred,
                                 evidence_origin="runtime_batch", target_key="target-1")
        self.assertNotIn("pending_probes", result)
        self.assertIs(result["_pending_group_dispatch"], True)
        self.assertIs(result["deferred_probes"], deferred)
        self.assertEqual(result["candidate_key"], "target-1")
        self.assertEqual(result["evidence_origin"], "runtime_batch")


if __name__ == "__main__":
    unittest.main()
