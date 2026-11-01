import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from fuzz_guidance.cmplog.hints import (
    apply_cmplog_hint,
    normalize_comparison_events,
)
from core.candidate import Candidate
from fuzzer import Fuzzer


def empty_guard(source="GET", path=None, operation="empty", attributed=True):
    return {
        "source": source, "path": path if path is not None else ["mode"],
        "operation": operation,
        "callback_context": {"attributed": attributed, "root_callback": "Demo::handle"},
    }


class EmptyGuardHintTests(unittest.TestCase):
    def test_empty_guard_changes_only_matching_fuzzable_parameter(self):
        fuzz = {"query_params": {"mode": "fuzz", "other": "keep"}}
        event = empty_guard()
        hints = normalize_comparison_events(
            {"request_id": "r-empty", "events": [event, event]}, fuzz,
        )
        self.assertEqual(len(hints), 1)
        self.assertEqual(hints[0]["opcode"], "EMPTY")
        self.assertEqual(hints[0]["reason"], "empty_guard")
        result = apply_cmplog_hint(fuzz, hints[0])
        self.assertEqual(result["fuzz_params"]["query_params"], {"mode": "", "other": "keep"})
        self.assertEqual(fuzz["query_params"]["mode"], "fuzz")
        self.assertIsNone(apply_cmplog_hint(result["fuzz_params"], hints[0]))

    def test_supports_post_and_nested_rest_transports(self):
        for source, path, parameter in [
            ("POST", ["mode"], "mode"),
            ("REST", ["POST", "filter", "mode"], "filter[mode]"),
        ]:
            with self.subTest(source=source):
                hints = normalize_comparison_events(
                    {"request_id": "r-empty", "events": [empty_guard(source, path)]},
                    {"body_params": {parameter: "fuzz"}},
                )
                self.assertEqual(len(hints), 1)
                self.assertEqual(hints[0]["placement"], "body_params")
                self.assertEqual(hints[0]["parameter"], parameter)
                self.assertEqual(hints[0]["candidate_value"], "")

    def test_empty_hint_precedes_comparison_hint_without_replacing_it(self):
        hints = normalize_comparison_events({
            "request_id": "r-empty", "events": [empty_guard()],
            "comparison_events": [{
                "opcode": "IS_EQUAL", "source": "GET", "path": ["mode"],
                "runtime_value": "fuzz", "comparison_value": "advanced",
            }],
        }, {"query_params": {"mode": "fuzz"}})
        self.assertEqual([hint["candidate_value"] for hint in hints], ["", "advanced"])

    def test_ignores_unattributed_unfuzzable_sensitive_and_already_empty_guards(self):
        for event, fuzz in [
            (empty_guard(attributed=False), {"query_params": {"mode": "fuzz"}}),
            (empty_guard(operation="read"), {"query_params": {"mode": "fuzz"}}),
            (empty_guard(), {"query_params": {}}),
            (empty_guard(), {"query_params": {"mode": ""}}),
            (empty_guard(path=["nonce"]), {"query_params": {"nonce": "fixed"}}),
            (empty_guard(source="REQUEST"), {"query_params": {"mode": "fuzz"}}),
            (empty_guard(), {"query_params": {"mode": ["unsupported"]}}),
            ({**empty_guard(), "callback_context": {}}, {"query_params": {"mode": "fuzz"}}),
            ({**empty_guard(), "callback_context": None}, {"query_params": {"mode": "fuzz"}}),
        ]:
            with self.subTest(event=event, fuzz=fuzz):
                self.assertEqual(normalize_comparison_events(
                    {"request_id": "r-empty", "events": [event]}, fuzz,
                ), [])

    def test_worker_ingests_guard_once_then_sends_empty_value(self):
        worker = object.__new__(Fuzzer)
        worker.cmplog_enabled = True
        worker.cmplog_hints = []
        worker.cmplog_seen_artifacts = set()
        worker._cmplog_hint_keys = set()
        worker.scoring_formula = SimpleNamespace(calculate_priority=lambda c: 1)
        worker.fuzzer_id = 1
        worker.config = {}
        parent = Candidate(http_target="http://web/", fuzz_params={"query_params": {"mode": "fuzz"}})
        artifact = {"request_id": parent.coverage_id, "events": [empty_guard()]}
        with patch("fuzzer.os.path.exists", return_value=True), patch(
            "fuzzer.fuzz_open", side_effect=lambda *args: io.StringIO(json.dumps(artifact)),
        ):
            worker._ingest_cmplog_hints(parent)
            worker._ingest_cmplog_hints(parent)
        self.assertEqual(len(worker.cmplog_hints), 1)
        child = worker.ff_mutate(parent)
        self.assertEqual(child.mutation_source, "cmplog")
        self.assertEqual(child.fuzz_params["query_params"]["mode"], "")
        self.assertIn("mode=", worker.prepare_request(child).url)

    def test_worker_rejects_guard_from_different_request(self):
        worker = object.__new__(Fuzzer)
        worker.cmplog_enabled = True
        worker.cmplog_hints = []
        worker.cmplog_seen_artifacts = set()
        worker._cmplog_hint_keys = set()
        parent = Candidate(fuzz_params={"query_params": {"mode": "fuzz"}})
        artifact = {"request_id": "another-request", "events": [empty_guard()]}
        with patch("fuzzer.os.path.exists", return_value=True), patch(
            "fuzzer.fuzz_open", side_effect=lambda *args: io.StringIO(json.dumps(artifact)),
        ):
            worker._ingest_cmplog_hints(parent)
        self.assertEqual(worker.cmplog_hints, [])

    def test_disabled_cmplog_does_not_read_empty_guards(self):
        worker = object.__new__(Fuzzer)
        worker.cmplog_enabled = False
        with patch("fuzzer.fuzz_open") as read_artifact:
            worker._ingest_cmplog_hints(Candidate())
        read_artifact.assert_not_called()


class IssetGuardHintTests(unittest.TestCase):
    def test_isset_removes_key_even_when_value_is_empty_and_deduplicates(self):
        for value in ("fuzz", ""):
            with self.subTest(value=value):
                fuzz = {"query_params": {"mode": value, "other": "keep"}}
                event = empty_guard(operation="isset")
                hints = normalize_comparison_events(
                    {"request_id": "r-isset", "events": [event, event]}, fuzz,
                )
                self.assertEqual(len(hints), 1)
                self.assertEqual(hints[0]["mutation"], "remove")
                result = apply_cmplog_hint(fuzz, hints[0])
                self.assertEqual(result["fuzz_params"]["query_params"], {"other": "keep"})
                self.assertIn("mode", fuzz["query_params"])
                self.assertIsNone(apply_cmplog_hint(result["fuzz_params"], hints[0]))

    def test_isset_preserves_fixed_sensitive_and_unattributed_fields(self):
        for event, fuzz in [
            (empty_guard(operation="isset"), {"query_params": {}}),
            (empty_guard(operation="isset", path=["nonce"]), {"query_params": {"nonce": "fixed"}}),
            (empty_guard(operation="isset", attributed=False), {"query_params": {"mode": "fuzz"}}),
        ]:
            with self.subTest(event=event):
                self.assertEqual(normalize_comparison_events(
                    {"request_id": "r-isset", "events": [event]}, fuzz,
                ), [])

    def test_removed_parameter_stays_absent_in_get_and_post_requests(self):
        for placement, source, method in [("query_params", "GET", "GET"), ("body_params", "POST", "POST")]:
            with self.subTest(method=method):
                worker = object.__new__(Fuzzer)
                worker.config = {}
                worker.scoring_formula = SimpleNamespace(calculate_priority=lambda c: 1)
                worker.fuzzer_id = 1
                target = "http://web/?mode=fuzz&keep=1" if method == "GET" else "http://web/"
                parent = Candidate(http_target=target, http_method=method,
                                   fuzz_params={placement: {"mode": "fuzz", "other": "keep"}},
                                   fixed_params={"query_params": {"action": "demo"}})
                worker.cmplog_hints = normalize_comparison_events(
                    {"request_id": parent.coverage_id, "events": [empty_guard(source, operation="isset")]},
                    parent.fuzz_params,
                )
                child = worker.ff_mutate(parent)
                request = worker.prepare_request(child)
                self.assertNotIn("mode=", request.url)
                self.assertNotIn("mode=", request.body or "")
                self.assertIn("action=demo", request.url)
                self.assertNotEqual(child.get_params_hash(), parent.get_params_hash())
                self.assertIn("mode", parent.fuzz_params[placement])

    def test_interesting_omission_can_be_queued_without_freezing_missing_value(self):
        worker = object.__new__(Fuzzer)
        worker.seen_mutations = set()
        worker.stop_on_vuln_count = 0
        worker.cmplog_enabled = False
        parent = Candidate(fuzz_params={"query_params": {"mode": "fuzz", "other": "keep"}})
        child = Candidate(parent=parent, fuzz_params={"query_params": {"other": "keep"}},
                          mutated_param_type="query_params", mutated_param_name="mode")
        class StopLoop(Exception):
            pass
        with patch.multiple(worker,
            generate_initial_candidates=Mock(return_value=iter([])),
            ff_sync_candidates=Mock(return_value=(0, 0, 0)),
            ff_choose_next=Mock(return_value=parent), calculate_energy=Mock(return_value=1),
            ff_mutate=Mock(return_value=child), ff_send_request=Mock(), ff_get_coverage=Mock(),
            calculate_score=Mock(), calculate_priority=Mock(),
            ff_has_exceptions=Mock(return_value=False), ff_has_vulns=Mock(return_value=False),
            ff_is_interesting=Mock(return_value=True),
        ), patch("fuzzer.os.path.exists", return_value=False), patch.object(
            Candidate, "write_sync_file", side_effect=StopLoop,
        ):
            with self.assertRaises(StopLoop):
                worker.fuzz_fast()
        self.assertIs(worker.ff_interesting_candidates[0], child)


class NullTypeCheckHintTests(unittest.TestCase):
    def artifact(self, source="REST_JSON", value="fuzz", target=None, path=None):
        return {"request_id": "r-null", "comparison_events": [{
            "callback": "Demo::handle", "opcode": "TYPE_CHECK", "source": source,
            "path": path or ["mode"], "runtime_value": value, "comparison_value": target,
        }]}

    def test_json_keeps_key_and_sends_typed_null_then_can_mutate_again(self):
        parent = Candidate(http_target="http://web/", http_method="POST",
                           fixed_params={"headers": {"Content-Type": "application/json"}},
                           fuzz_params={"body_params": {"mode": "fuzz", "other": "keep"}})
        worker = object.__new__(Fuzzer)
        worker.config = {}
        worker.scoring_formula = SimpleNamespace(calculate_priority=lambda c: 1)
        worker.fuzzer_id = 1
        worker.cmplog_hints = normalize_comparison_events(self.artifact(), parent.fuzz_params)
        self.assertEqual(len(worker.cmplog_hints), 1)
        self.assertIsNone(worker.cmplog_hints[0]["candidate_value"])
        self.assertNotEqual(worker.cmplog_hints[0].get("mutation"), "remove")
        child = worker.ff_mutate(parent)
        self.assertEqual(json.loads(worker.prepare_request(child).body), {"mode": None, "other": "keep"})
        self.assertEqual(parent.fuzz_params["body_params"]["mode"], "fuzz")
        with patch("fuzzer.random.choices", return_value=["body_params"]), patch(
            "fuzzer.random.choice", return_value="mode",
        ):
            next_child = worker.ff_mutate(child)
        self.assertEqual(next_child.fuzz_params["body_params"]["mode"], "")

    def test_query_and_form_null_checks_remove_key_instead_of_sending_string(self):
        for source, placement in [("GET", "query_params"), ("POST", "body_params"),
                                  ("REST_QUERY", "query_params"), ("REST_FORM", "body_params")]:
            with self.subTest(source=source):
                fuzz = {placement: {"mode": "fuzz", "other": "keep"}}
                hints = normalize_comparison_events(self.artifact(source), fuzz)
                self.assertEqual(len(hints), 1)
                self.assertEqual(hints[0]["mutation"], "remove")
                self.assertEqual(apply_cmplog_hint(fuzz, hints[0])["fuzz_params"][placement], {"other": "keep"})

    def test_null_is_distinct_from_literal_none_in_request_hash(self):
        null = Candidate(fuzz_params={"body_params": {"mode": None}})
        for value in ("None", 'None__null_fields:[["fuzz", "body_params", "mode"]]'):
            with self.subTest(value=value):
                text = Candidate(fuzz_params={"body_params": {"mode": value}})
                self.assertNotEqual(null.get_params_hash(), text.get_params_hash())

    def test_rejects_non_null_checks_fixed_sensitive_and_stale_values(self):
        cases = [self.artifact(target="null"), self.artifact(value="stale"),
                 self.artifact(path=["nonce"]), self.artifact(path=["fixed"]),
                 self.artifact(source="COOKIE")]
        missing_target = self.artifact()
        del missing_target["comparison_events"][0]["comparison_value"]
        cases.append(missing_target)
        for artifact in cases:
            with self.subTest(artifact=artifact):
                self.assertEqual(normalize_comparison_events(artifact, {
                    "body_params": {"mode": "fuzz", "nonce": "fuzz"},
                }), [])

    def test_typed_null_hint_is_not_applied_to_form_request(self):
        parent = Candidate(http_target="http://web/", http_method="POST",
                           fuzz_params={"body_params": {"mode": "fuzz"}})
        worker = object.__new__(Fuzzer)
        worker.config = {}
        worker.scoring_formula = SimpleNamespace(calculate_priority=lambda c: 1)
        worker.fuzzer_id = 1
        worker.cmplog_hints = normalize_comparison_events(self.artifact(), parent.fuzz_params)
        child = worker.ff_mutate(parent)
        self.assertIsNotNone(child.fuzz_params["body_params"]["mode"])
        self.assertEqual(child.mutation_source, "normal")


class CmpLogNormalizationTests(unittest.TestCase):
    def test_bool_not_falsey_targets_preserve_parameter_and_other_inputs(self):
        artifact = {"request_id": "r-bool", "comparison_events": [{
            "callback": "Demo::handle", "opcode": "BOOL_NOT", "source": "GET",
            "path": ["mode"], "runtime_value": "fuzz", "comparison_value": value,
        } for value in ("", "0")]}
        fuzz = {"query_params": {"mode": "fuzz", "other": "keep"}}
        hints = normalize_comparison_events(artifact, fuzz)
        self.assertEqual([hint["candidate_value"] for hint in hints], ["", "0"])
        for hint in hints:
            result = apply_cmplog_hint(fuzz, hint)
            self.assertEqual(result["fuzz_params"]["query_params"], {
                "mode": hint["candidate_value"], "other": "keep",
            })
        self.assertEqual(fuzz["query_params"]["mode"], "fuzz")

    def test_bool_not_does_not_mutate_fixed_sensitive_or_stale_parameters(self):
        for source, path, value in [
            ("GET", ["fixed"], "fuzz"), ("GET", ["nonce"], "fuzz"),
            ("GET", ["mode"], "stale"), ("NONE", [], "fuzz"),
        ]:
            with self.subTest(source=source, path=path):
                artifact = {"request_id": "r-bool", "comparison_events": [{
                    "opcode": "BOOL_NOT", "source": source, "path": path,
                    "runtime_value": value, "comparison_value": "",
                }]}
                self.assertEqual(normalize_comparison_events(artifact, {
                    "query_params": {"mode": "fuzz", "nonce": "fuzz"},
                }), [])

    def test_active_zend_extension_contract_mentions_comparison_artifacts(self) -> None:
        source = (
            FUZZER_DIR / "zend_discovery" / "extension" / "hookphuzz_opcode.c"
        ).read_text(encoding="utf-8")

        self.assertIn("comparison_events", source)
        self.assertIn("ZEND_IS_EQUAL", source)
        self.assertIn("ZEND_IS_NOT_EQUAL", source)
        self.assertIn("ZEND_IS_IDENTICAL", source)
        self.assertIn("ZEND_IS_NOT_IDENTICAL", source)
        self.assertIn("ZEND_SWITCH_STRING", source)

    def test_normalizes_rest_string_comparison_to_the_same_parameter(self) -> None:
        artifact = {
            "request_id": "request-1",
            "comparison_events": [
                {
                    "callback": "Demo::handle",
                    "opcode": "IS_IDENTICAL",
                    "source": "REST",
                    "path": ["GET", "mode"],
                    "runtime_value": "INVALID_VALUE",
                    "comparison_value": "special_operation",
                }
            ],
        }

        hints = normalize_comparison_events(
            artifact,
            {"query_params": {"mode": "INVALID_VALUE"}},
        )

        self.assertEqual(len(hints), 1)
        self.assertEqual(hints[0]["parameter"], "mode")
        self.assertEqual(hints[0]["placement"], "query_params")
        self.assertEqual(hints[0]["candidate_value"], "special_operation")
        self.assertEqual(hints[0]["request_id"], "request-1")
        self.assertEqual(hints[0]["callback"], "Demo::handle")

    def test_rejects_unlinked_and_constant_comparisons(self) -> None:
        artifact = {
            "request_id": "request-2",
            "comparison_events": [
                {
                    "callback": "Demo::handle",
                    "opcode": "IS_IDENTICAL",
                    "source": "NONE",
                    "path": [],
                    "runtime_value": "AAAA",
                    "comparison_value": "special_operation",
                }
            ],
        }

        self.assertEqual(
            normalize_comparison_events(
                artifact,
                {"query_params": {"mode": "AAAA"}},
            ),
            [],
        )

    def test_deduplicates_and_does_not_cross_parameters(self) -> None:
        event = {
            "callback": "Demo::handle",
            "opcode": "IS_EQUAL",
            "source": "REST",
            "path": ["POST", "mode"],
            "runtime_value": "INVALID_MODE",
            "comparison_value": "special_mode",
        }
        artifact = {
            "request_id": "request-3",
            "comparison_events": [event, dict(event), {
                "callback": "Demo::handle",
                "opcode": "IS_IDENTICAL",
                "source": "REST",
                "path": ["POST", "other"],
                "runtime_value": "INVALID_OTHER",
                "comparison_value": "special_other",
            }],
        }

        hints = normalize_comparison_events(
            artifact,
            {"body_params": {"mode": "INVALID_MODE", "other": "INVALID_OTHER"}},
        )

        self.assertEqual(
            {(item["parameter"], item["candidate_value"]) for item in hints},
            {("mode", "special_mode"), ("other", "special_other")},
        )

    def test_rejects_sensitive_parameter_and_non_scalar_target(self) -> None:
        artifact = {
            "request_id": "request-4",
            "comparison_events": [
                {
                    "callback": "Demo::auth",
                    "opcode": "IS_IDENTICAL",
                    "source": "POST",
                    "path": ["nonce"],
                    "runtime_value": "AAAA",
                    "comparison_value": "BBBB",
                },
                {
                    "callback": "Demo::handle",
                    "opcode": "IS_IDENTICAL",
                    "source": "POST",
                    "path": ["mode"],
                    "runtime_value": "AAAA",
                    "comparison_value": ["not", "scalar"],
                },
            ],
        }

        self.assertEqual(
            normalize_comparison_events(
                artifact,
                {"body_params": {"nonce": "AAAA", "mode": "AAAA"}},
            ),
            [],
        )


class CmpLogMutationTests(unittest.TestCase):
    def test_applies_normalized_hint_to_the_matching_parameter(self) -> None:
        hint = {
            "request_id": "request-1",
            "callback": "Demo::handle",
            "opcode": "IS_IDENTICAL",
            "source": "REST_QUERY",
            "path": ["mode"],
            "parameter": "mode",
            "placement": "query_params",
            "observed_value": "INVALID_VALUE",
            "candidate_value": "special_operation",
            "reason": "cmplog",
        }

        result = apply_cmplog_hint(
            {"query_params": {"mode": "INVALID_VALUE"}},
            hint,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["fuzz_params"]["query_params"]["mode"], "special_operation")
        self.assertEqual(result["mutated_param_type"], "query_params")
        self.assertEqual(result["mutated_param_name"], "mode")
        self.assertEqual(result["mutation_source"], "cmplog")

    def test_ff_mutate_consumes_normalized_hints_without_artifact_io(self) -> None:
        source = (FUZZER_DIR / "fuzzer.py").read_text(encoding="utf-8")
        mutate_body = source.split("    def ff_mutate(self, c):", 1)[1].split(
            "    def ff_send_request", 1
        )[0]

        self.assertIn("self.cmplog_hints", mutate_body)
        self.assertIn("apply_cmplog_hint", mutate_body)
        self.assertNotIn("opcode-events", mutate_body)
        self.assertNotIn("json.load", mutate_body)


if __name__ == "__main__":
    unittest.main()
