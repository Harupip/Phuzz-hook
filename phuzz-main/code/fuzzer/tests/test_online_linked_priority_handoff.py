from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

import core.candidate as candidate_module
import fuzzer as fuzzer_module
from core.candidate import Candidate
from core.scoring import DefaultScoringFormula, SCORING_MODE_PHUZZ
from fuzzer import Fuzzer
from hook_energy.seed_generation.online_common import config_hash
from core import online_handoff as handoff


def _candidate(value: str) -> Candidate:
    return Candidate(
        score=1, priority=1, http_target="http://web/wp-admin/admin-ajax.php", http_method="POST",
        fixed_params={"headers": {}, "cookies": {}, "query_params": {}, "body_params": {"action": "x"}},
        fuzz_params={"headers": {}, "cookies": {}, "query_params": {}, "body_params": {"other": value}},
        fuzz_weights={"headers": 1, "cookies": 1, "query_params": 1, "body_params": 1},
    )


class PauseProtocolWorkerTests(unittest.TestCase):
    def test_pause_keeps_round_progress_and_resumes_after_rejection(self) -> None:
        """A paused worker must not send, must report its real round progress,
        and must continue the same round after the coordinator rejects the child.

        Without this the coordinator either races two workers or `carryover`
        reads an invented attempts_used.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worker = object.__new__(Fuzzer)
            worker.stop_on_vuln_count = 0
            worker.seen_mutations = set()
            worker.scoring_formula = DefaultScoringFormula(mode=SCORING_MODE_PHUZZ)
            parent = _candidate("seed")
            sends: list[str] = []
            mutate_calls = 0
            observed: dict[str, object] = {}
            created: list[Candidate] = []

            def mutate(candidate, **kwargs):
                nonlocal mutate_calls
                mutate_calls += 1
                if mutate_calls == 10:
                    # The request arrives while attempt 10 is being generated; it names
                    # the sent request m5 whose trace opened the branch.
                    handoff.request_pause("key-1", "tok-1", "run-v0", request_id=created[4].coverage_id, root=root)
                # Attempt 4 repeats attempt 3: deduplicated but still a used attempt.
                created.append(_candidate("dup" if mutate_calls in {3, 4} else f"m{mutate_calls}"))
                return created[-1]

            def sleep(seconds):
                if "ack" not in observed:
                    observed["ack"] = handoff.read_ack("key-1", root=root)
                    observed["sends_at_ack"] = list(sends)
                    self.assertTrue(handoff.release("key-1", "tok-1", root=root))

            env = {"HOOKPHUZZ_HANDOFF_KEY": "key-1", "HOOKPHUZZ_LEGACY_RUN_ID": "run-v0", "FUZZER_CLEANUP": "0"}
            with patch.dict(os.environ, env), patch.object(handoff, "HANDOFF_ROOT", root), \
                    patch.object(handoff, "_sleep", sleep), \
                    patch.object(fuzzer_module, "phuzz_base_energy", Mock(return_value=12)), patch.multiple(
                        worker, create=True,
                        generate_initial_candidates=Mock(return_value=[]),
                        ff_sync_candidates=Mock(return_value=(0, 0, 0)),
                        ff_choose_next=Mock(side_effect=[parent, StopIteration]),
                        calculate_energy=Mock(return_value=20),
                        ff_mutate=Mock(side_effect=mutate),
                        ff_send_request=Mock(side_effect=lambda c: sends.append(c.fuzz_params["body_params"]["other"])),
                        _ingest_cmplog_hints=Mock(), ff_get_coverage=Mock(), calculate_score=Mock(),
                        calculate_priority=Mock(), ff_has_exceptions=Mock(return_value=False),
                        ff_has_vulns=Mock(return_value=False), ff_is_interesting=Mock(return_value=False),
                    ), patch.object(Candidate, "write_sync_file", Mock()), \
                    patch.object(Candidate, "get_sync_file", Mock(return_value=str(root / "missing.json"))):
                with self.assertRaises(StopIteration):
                    worker.fuzz_fast()

            ack = observed["ack"]
            self.assertEqual(
                (ack["token"], ack["worker_run_id"], ack["allocated_energy"], ack["attempts_used"]),
                ("tok-1", "run-v0", 20, 9),
            )
            self.assertEqual(ack["round_id"], 1)
            # m5 was scored by this worker: its original PHUZZ energy (12), not the round's 20, travels with the ACK.
            self.assertEqual((ack["request_id"], ack["seed_phuzz_energy"]), (created[4].coverage_id, 12))
            # The lookup cache keeps numbers only, never candidates with their responses.
            self.assertTrue(all(type(value) is int for value in worker._scored_energy.values()))
            # 9 attempts used, one deduplicated: 8 sends and nothing while paused.
            self.assertEqual(observed["sends_at_ack"], ["m1", "m2", "dup", "m5", "m6", "m7", "m8", "m9"])
            # Resume continues attempt 10 of the same round, not a fresh round.
            self.assertEqual(mutate_calls, 20)
            self.assertEqual(sends[8], "m10")
            self.assertEqual(len(sends), 19)
            self.assertIsNone(handoff.read_ack("key-1", root=root))

    def test_stale_or_foreign_pause_request_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handoff.request_pause("key-1", "tok-1", "other-run", root=root)
            gate = handoff.PauseGate("key-1", "run-v0", root=root)
            self.assertFalse(gate.wait_if_paused(round_id=1, allocated_energy=5, attempts_used=0))
            self.assertIsNone(handoff.read_ack("key-1", root=root))
            self.assertFalse(handoff.release("key-1", "wrong", root=root))
            self.assertTrue((root / "key-1" / "pause.json").is_file())

    def test_cli_round_trip_prints_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out: list[str] = []
            with patch("builtins.print", side_effect=lambda value: out.append(value)):
                self.assertEqual(handoff.main(["request", "key-1", "tok-1", "run-v0"], root=root), 0)
                handoff.write_ack("key-1", {"token": "tok-1", "worker_run_id": "run-v0",
                                            "round_id": 3, "allocated_energy": 7, "attempts_used": 2}, root=root)
                self.assertEqual(handoff.main(["ack", "key-1"], root=root), 0)
                self.assertEqual(handoff.main(["release", "key-1", "tok-1"], root=root), 0)
            self.assertEqual(json.loads(out[1])["attempts_used"], 2)
            self.assertEqual(json.loads(out[2]), {"released": True})


CHILD_CONFIG = {
    "target": "http://web/wp-admin/admin-ajax.php", "methods": ["POST"],
    "body_params": {"data": [
        {"name": "action", "value": "fixture"}, {"name": "option_id", "value": "fuzz"},
        {"name": "other", "value": "fuzz"}, {"name": "extra", "value": "fuzz"},
    ], "fixed": ["action"], "fuzz": ["option_id", "other", "extra"]},
}
REPLAY_CONFIG = {
    "target": "http://web/wp-admin/admin-ajax.php", "methods": ["POST"], "config_type": "replay_only",
    "body_params": {"data": [
        {"name": "action", "value": "fixture"}, {"name": "option_id", "value": "8uzz"},
        {"name": "other", "value": "replay-other"}, {"name": "extra", "value": False},
    ], "fixed": [], "fuzz": []},
}


def _worker(config: dict) -> Fuzzer:
    worker = object.__new__(Fuzzer)
    worker.fuzzer_id = "2"
    worker.config = json.loads(json.dumps(config))
    worker.path_hashes = set()
    worker.seen_mutations = set()
    worker.cmplog_hints = []
    worker.stop_on_vuln_count = 0
    worker.request_timeout = 5
    worker.http_methods = []
    for bucket in ("headers", "cookies", "query_params", "body_params"):
        setattr(worker, f"fixed_{bucket}", {})
        setattr(worker, f"fuzz_{bucket}", {})
        setattr(worker, f"weight_{bucket}", 0.25)
    worker.scoring_formula = DefaultScoringFormula(mode=SCORING_MODE_PHUZZ)
    worker.load_request_data()
    return worker


class PriorityRoundTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        replay = self.root / "configs" / "online-linked" / "fixture" / "v1-replay.json"
        replay.parent.mkdir(parents=True)
        replay.write_text(json.dumps(REPLAY_CONFIG), encoding="utf-8")

    def descriptor(self, **overrides) -> str:
        payload = {
            "replay_slug": "online-linked/fixture/v1-replay", "replay_hash": config_hash(REPLAY_CONFIG),
            "targets": [["body_params", "other"], ["body_params", "extra"]],
            "mode": "seed-plus-bonus", "allocated_energy": 20, "attempts_used": 9,
        }
        payload.update(overrides)
        return json.dumps(payload)

    def run_worker(self, descriptor: str, *, choices=None, seed_energy: int = 6, coverage: int | None = None,
                   expect=StopIteration, online_linked: bool = False):
        """Run fuzz_fast until the normal scheduler asks for its first candidate."""
        worker = _worker(CHILD_CONFIG)
        worker.output_dir = str(self.root / "worker-output")
        os.makedirs(worker.output_dir, exist_ok=True)
        sends: list[dict] = []
        mutations: list[tuple[str, str]] = []

        def mutate(candidate, target=None):
            mutations.append(target)
            fuzz = json.loads(json.dumps(candidate.fuzz_params))
            fuzz[target[0]][target[1]] = f"m{len(mutations)}"
            return Candidate(parent=candidate, http_target=candidate.http_target, http_method=candidate.http_method,
                             fixed_params=candidate.fixed_params, fuzz_params=fuzz,
                             fuzz_weights=candidate.fuzz_weights, mutated_param_type=target[0],
                             mutated_param_name=target[1])

        def send(candidate):
            sends.append({"method": candidate.http_method, **candidate.fixed_params["body_params"],
                          **candidate.fuzz_params["body_params"]})

        choice = Mock(side_effect=choices) if choices is not None else Mock(side_effect=lambda targets: targets[0])
        env = {"HOOKPHUZZ_PRIORITY_SEED": descriptor, "FUZZER_CLEANUP": "0"}
        if online_linked:
            env.update(HOOKPHUZZ_HANDOFF_KEY="key-1", HOOKPHUZZ_LEGACY_RUN_ID="run-v1")
        out = io.StringIO()
        with patch.dict(os.environ, env), patch.object(fuzzer_module, "PRIORITY_CONFIG_DIR", str(self.root / "configs")), \
                patch.object(fuzzer_module, "phuzz_base_energy", Mock(return_value=seed_energy)), \
                patch.object(handoff, "HANDOFF_ROOT", self.root / "handoff"), \
                patch.multiple(
                    worker, create=True,
                    ff_sync_candidates=Mock(return_value=(0, 0, 0)),
                    ff_choose_next=Mock(side_effect=StopIteration),
                    calculate_energy=Mock(side_effect=AssertionError("priority energy must not use the scoring mode")),
                    ff_mutate=Mock(side_effect=mutate), ff_send_request=Mock(side_effect=send),
                    _choose_priority_target=choice,
                    _ingest_cmplog_hints=Mock(), ff_get_coverage=Mock(return_value=coverage), calculate_score=Mock(),
                    calculate_priority=Mock(), ff_has_exceptions=Mock(return_value=False),
                    ff_has_vulns=Mock(return_value=False), ff_is_interesting=Mock(return_value=False),
                ), patch.object(Candidate, "write_sync_file", Mock()), \
                patch.object(Candidate, "get_sync_file", Mock(return_value=str(self.root / "missing.json"))), \
                redirect_stdout(out):
            with self.assertRaises(expect):
                worker.fuzz_fast()
        summary = [json.loads(line.split(" ", 1)[1]) for line in out.getvalue().splitlines()
                   if line.startswith("[priority] ")]
        return worker, sends, mutations, summary

    def test_priority_seed_runs_before_normal_seeds_and_shared_queue(self) -> None:
        other, extra = ("body_params", "other"), ("body_params", "extra")
        picks = [other, other, extra, other, extra, extra, other, extra]
        worker, sends, mutations, summary = self.run_worker(self.descriptor(), choices=picks)
        # The verified seed goes first, with its real values and types.
        self.assertEqual(sends[0], {"method": "POST", "action": "fixture", "option_id": "8uzz",
                                    "other": "replay-other", "extra": False})
        priority = sends[1:1 + len(picks)]
        self.assertEqual(mutations, picks)
        for send, target in zip(priority, picks):
            self.assertEqual(send["option_id"], "8uzz")
            unchanged = {"other": "replay-other", "extra": False}
            unchanged.pop(target[1])
            self.assertEqual({name: send[name] for name in unchanged}, unchanged)
        # Then the normal initial seed of the updated config, with its own selector values.
        self.assertEqual(sends[1 + len(picks):], [{"method": "POST", "action": "fixture", "option_id": "fuzz",
                                                   "other": "fuzz", "extra": "fuzz"}])
        self.assertEqual(summary[-1]["per_field"], {"body_params:other": 4, "body_params:extra": 4})
        self.assertEqual(summary[-1]["attempted"], 8)

    def test_priority_energy_modes_use_seed_or_ack_snapshot(self) -> None:
        energy = handoff.priority_energy
        self.assertEqual(energy("seed-plus-bonus", seed_energy=6, target_count=1, allocated_energy=20, attempts_used=7), 7)
        self.assertEqual(energy("seed-plus-bonus", seed_energy=6, target_count=2, allocated_energy=20, attempts_used=7), 8)
        self.assertEqual(energy("carryover", seed_energy=6, target_count=1, allocated_energy=20, attempts_used=7), 13)
        self.assertEqual(energy("carryover", seed_energy=6, target_count=1, allocated_energy=20, attempts_used=9), 11)
        self.assertEqual(energy("carryover", seed_energy=6, target_count=1, allocated_energy=20, attempts_used=20), 1)
        self.assertEqual(handoff.priority_energy_mode(None), "seed-plus-bonus")
        with self.assertRaises(ValueError):
            handoff.priority_energy_mode("bonus")
        # The worker grants exactly that many attempts in each mode.
        _, _, mutations, summary = self.run_worker(self.descriptor(targets=[["body_params", "other"]]))
        self.assertEqual((len(mutations), summary[-1]["seed_energy"], summary[-1]["bonus"]), (7, 6, 1))
        _, _, mutations, summary = self.run_worker(self.descriptor(mode="carryover"))
        self.assertEqual((len(mutations), summary[-1]["granted"]), (11, 11))
        # The verified request's own PHUZZ energy wins over re-scoring the rebuilt seed.
        _, _, mutations, summary = self.run_worker(
            self.descriptor(targets=[["body_params", "other"]], seed_phuzz_energy=31))
        self.assertEqual((len(mutations), summary[-1]["seed_energy"], summary[-1]["seed_energy_source"]),
                         (32, 31, "WORKER_SCORE"))
        # Missing seed coverage: PHUZZ base 1, reported, never the scheduler's energy.
        _, _, mutations, summary = self.run_worker(self.descriptor(), coverage=0)
        self.assertEqual((len(mutations), summary[-1]["seed_coverage"]), (3, "SEED_COVERAGE_UNAVAILABLE"))

    def test_priority_result_is_kept_per_worker_for_later_checks(self) -> None:
        # stdout dies with the container and the worker wipes its own fuzzer-N folder on start,
        # so each handoff's round is kept in one file named after the worker run, outside that folder.
        worker, _, mutations, summary = self.run_worker(self.descriptor(), online_linked=True)
        path = Path(worker.output_dir).parent / "priority" / "run-v1.json"
        saved = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(saved, {**summary[-1], "worker_run_id": "run-v1"})
        self.assertEqual((saved["status"], saved["granted"], saved["attempted"]), ("DONE", 8, len(mutations)))
        self.assertNotIn(Path(worker.output_dir), path.parents)
        # A rejected priority seed is kept too, so a check shows why no round ran.
        with patch.dict(os.environ, {"HOOKPHUZZ_LEGACY_RUN_ID": "run/cand 7-v2"}):
            self.run_worker(self.descriptor(replay_slug="../outside"), expect=SystemExit)
        rejected = json.loads((path.parent / "run-cand-7-v2.json").read_text(encoding="utf-8"))
        self.assertEqual(rejected["status"], "REJECTED")
        # The earlier worker's file is still there.
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["status"], "DONE")

    def test_energy_is_cached_only_for_requests_with_coverage(self) -> None:
        # A request without coverage has no measured PHUZZ energy: it must not seed a later handoff.
        worker, _, mutations, _ = self.run_worker(self.descriptor(), coverage=0, online_linked=True)
        self.assertTrue(mutations)
        self.assertEqual(dict(worker._scored_energy), {})
        worker, _, mutations, _ = self.run_worker(self.descriptor(), online_linked=True)
        # Priority seed + its mutations + the normal initial seed: every measured request.
        self.assertEqual(len(worker._scored_energy), 1 + len(mutations) + 1)

    def test_unusable_priority_seed_fails_worker_start(self) -> None:
        # A handoff promised the verified seed first: never fall back to the normal seeds.
        for name, descriptor in (("hash", self.descriptor(replay_hash="0" * 64)),
                                 ("target", self.descriptor(targets=[["body_params", "action"]])),
                                 ("slug", self.descriptor(replay_slug="../outside")),
                                 ("energy", self.descriptor(allocated_energy="nine"))):
            with self.subTest(case=name):
                _, sends, mutations, summary = self.run_worker(descriptor, expect=SystemExit)
                self.assertEqual((sends, mutations), ([], []))
                self.assertEqual(summary[-1]["status"], "REJECTED")

    def test_ff_mutate_target_changes_only_that_field_and_keeps_cmplog_hints(self) -> None:
        worker = _worker(CHILD_CONFIG)
        hint = {"opcode": "IS_EQUAL", "param_type": "body_params", "param_name": "option_id", "candidate_value": "x"}
        worker.cmplog_hints = [hint]
        seed = Candidate(http_target="http://web", http_method="POST",
                         fixed_params={"headers": {}, "cookies": {}, "query_params": {}, "body_params": {"action": "fixture"}},
                         fuzz_params={"headers": {}, "cookies": {}, "query_params": {},
                                      "body_params": {"option_id": "8uzz", "other": "abc", "extra": "def"}},
                         fuzz_weights={"headers": 0.25, "cookies": 0.25, "query_params": 0.25, "body_params": 0.25})
        for _ in range(20):
            child = worker.ff_mutate(seed, target=("body_params", "extra"))
            self.assertEqual((child.mutated_param_type, child.mutated_param_name), ("body_params", "extra"))
            self.assertEqual({k: v for k, v in child.fuzz_params["body_params"].items() if k != "extra"},
                             {"option_id": "8uzz", "other": "abc"})
        self.assertEqual(worker.cmplog_hints, [hint])
        self.assertIsNone(worker.ff_mutate(seed, target=("body_params", "action")))


class PhuzzEnergyTests(unittest.TestCase):
    def test_phuzz_base_energy_ignores_hook_mode_and_candidate_state(self) -> None:
        from core.scoring import PhuzzScoringFormula, phuzz_base_energy
        parent = Candidate(score=27, priority=27)
        parent.score, parent.number_of_new_paths = 27, 3
        child = Candidate(parent=parent)
        child.score, child.paths, child.new_paths = 20, ["a::::1"], set()
        child.final_energy = 99
        self.assertEqual(phuzz_base_energy(child, child.score), 3 + 7)
        self.assertEqual(child.final_energy, 99)  # pure: the scheduler's fields stay untouched
        self.assertEqual(phuzz_base_energy(child, child.score), PhuzzScoringFormula().calculate_energy(child))

    def test_plain_fuzzer_keeps_no_energy_cache(self) -> None:
        worker = _worker(CHILD_CONFIG)
        worker._scored_energy = {}
        worker._remember_scored(_candidate("x"), None, measured=True)
        self.assertEqual(worker._scored_energy, {})


class SyncNamespaceTests(unittest.TestCase):
    def test_candidates_of_another_config_are_not_synced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = Candidate(http_target="http://web", fuzz_params={"body_params": {"old": "x"}})
            with patch.object(candidate_module, "SYNC_ROOT", str(root)), patch.dict(os.environ, {"FUZZER_COMPRESS": "0"}):
                with patch.dict(os.environ, {"HOOKPHUZZ_SYNC_NAMESPACE": "cfg-old"}):
                    old.write_sync_file()
                with patch.dict(os.environ, {"HOOKPHUZZ_SYNC_NAMESPACE": "cfg-new"}):
                    self.assertEqual(Path(old.get_sync_file()).parent, root / "cfg-new")
                    self.assertFalse(Path(old.get_sync_file()).exists())
                    worker = object.__new__(Fuzzer)
                    worker.seen_mutations, worker.ff_candidates = set(), []
                    worker.ff_interesting_candidates, worker.ff_interesting_candidates_hashes = [], set()
                    self.assertEqual(worker.ff_sync_candidates(), (0, 0, 0))
                with patch.dict(os.environ, {"HOOKPHUZZ_SYNC_NAMESPACE": "../escape"}):
                    with self.assertRaises(ValueError):
                        old.get_sync_file()


if __name__ == "__main__":
    unittest.main()
