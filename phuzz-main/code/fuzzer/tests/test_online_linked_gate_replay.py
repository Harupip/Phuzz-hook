import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from filesystem_paths import filesystem_path
from online_linked.coordination.gate_replay import (
    gate_replay_name,
    gate_replay_row,
    guard_replay_summary,
    load_gate_evidence,
    unsent_guard_probes,
)


class GateReplayNameTests(unittest.TestCase):
    def test_gate_replay_name_v0_resume_and_reactivation(self):
        """The gate config name keeps a first v0 gate apart from resume/reactivation gates, so a
        reactivation never overwrites the proof config of an earlier activation."""
        self.assertEqual(
            gate_replay_name({"version": "v0"}, resume=False, resume_count=0), ("v0", False),
        )
        self.assertEqual(
            gate_replay_name(
                {"version": "v3", "readiness_history": [{}]}, resume=True, resume_count=2,
            ),
            ("resume-2-v3-activation-1", True),
        )
        self.assertEqual(
            gate_replay_name(
                {"version": "v1", "readiness_history": [{}, {}]}, resume=False, resume_count=0,
            ),
            ("resume-0-v1-activation-2", True),
        )


class GateReplayRowTests(unittest.TestCase):
    def test_gate_replay_row_keys_and_slug(self):
        """The row is written to JSON, so its key order is part of the artifact format; a config
        outside config_root must fail loudly instead of producing a misleading slug."""
        root = Path("cfg-root")
        version = {
            "hook_name": "h", "callback_id": "c", "resolved_method": "m", "entrypoint_type": "e",
            "seed_item": {"seed": {"seed_variant_id": 7}},
        }
        row = gate_replay_row(version, root / "sub" / "gate.json", config_root=root)
        self.assertEqual(list(row), [
            "config_slug", "hook_name", "callback_id", "resolved_method",
            "entrypoint_type", "seed_variant_id",
        ])
        self.assertEqual(row["config_slug"], "sub/gate")
        self.assertEqual(row["seed_variant_id"], "7")
        version["seed_item"] = {}
        self.assertEqual(
            gate_replay_row(version, root / "gate.json", config_root=root)["seed_variant_id"], "",
        )
        with self.assertRaises(ValueError):
            gate_replay_row(version, Path("elsewhere") / "gate.json", config_root=root)


class LoadGateEvidenceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.request_dir = base / "request"
        self.zend_dir = base / "zend"
        self.request_dir.mkdir()
        self.zend_dir.mkdir()
        self.version = {"version": "v0", "worker_run_id": "run-1"}

    def _write(self, directory, name, payload):
        filesystem_path(directory / name).write_text(json.dumps(payload), encoding="utf-8")

    def _write_pair(self, request_name="r1.json", zend_name="r1.json"):
        self._write(self.request_dir, request_name, {
            "request_id": "r1", "run_id": "run-1", "target_plugin": "plug",
        })
        self._write(self.zend_dir, zend_name, {"request_id": "r1", "run_id": "run-1"})

    def _load(self, row, convergence=None):
        return load_gate_evidence(
            self.version, row, self.request_dir, self.zend_dir, convergence or {},
            plugin_slug="plug",
        )

    def test_load_gate_evidence_rejects_unsafe_or_ambiguous_artifacts(self):
        """Gate evidence is the proof a callback ran, so a path escape, a missing or ambiguous
        Zend trace, or a request id the probe did not converge on must yield no evidence."""
        # The escaped target exists and is not JSON: reading it before rejecting the name raises.
        filesystem_path(self.request_dir.parent / "x.json").write_text("{not json", encoding="utf-8")
        self._write(self.zend_dir, "x.json", {"request_id": "x", "run_id": "run-1"})
        self.assertIsNone(self._load({"matched_artifact": "../x.json", "zend_artifact": "x.json"}))
        self.assertIsNone(self._load({"matched_artifact": "r1.json", "zend_artifact": "r1.json"}))

        self._write(self.request_dir, "r1.json", {
            "request_id": "r1", "run_id": "run-1", "target_plugin": "plug",
        })
        # Wrong zend stem and no same-stem file in the zend dir.
        self._write(self.zend_dir, "other.json", {"request_id": "r1", "run_id": "run-1"})
        self.assertIsNone(self._load({"matched_artifact": "r1.json", "zend_artifact": "bad.json"}))

        # Wrong zend stem but exactly one same-stem file: that file is used.
        self._write(self.zend_dir, "r1.json", {"request_id": "r1", "run_id": "run-1"})
        evidence = self._load({"matched_artifact": "r1.json", "zend_artifact": "bad.json"})
        self.assertEqual(evidence["zend_name"], "r1.json")

        # Convergence names a different request id.
        self.assertIsNone(self._load(
            {"matched_artifact": "r1.json", "zend_artifact": "r1.json"}, {"request_id": "r2"},
        ))

        valid = self._load({"matched_artifact": "r1.json", "zend_artifact": "r1.json"}, {"request_id": "r1"})
        self.assertEqual(valid["evidence_origin"], "v0_gate")

    def test_load_gate_evidence_rejects_two_same_stem_zend_files(self):
        """Two Zend traces for one request stem are ambiguous, so none may be guessed. glob() is
        mocked because on Windows trace.json and trace.JSON are the same file."""
        self._write(self.request_dir, "trace.json", {
            "request_id": "trace", "run_id": "run-1", "target_plugin": "plug",
        })
        self._write(self.zend_dir, "trace.json", {"request_id": "trace", "run_id": "run-1"})
        two = [self.zend_dir / "trace.json", self.zend_dir / "trace.JSON"]
        with patch.object(type(filesystem_path(self.zend_dir)), "glob", return_value=two):
            self.assertIsNone(
                self._load({"matched_artifact": "trace.json", "zend_artifact": "bad.json"}),
            )


class GuardReplaySummaryTests(unittest.TestCase):
    def test_guard_replay_summary_keys_and_slug(self):
        """The summary is handed to the converge function and persisted, so its key order is part
        of the artifact format; a replay config outside config_root must fail loudly (the caller
        turns that ValueError into a REJECTED event)."""
        root = Path("cfg-root")
        current = {
            "replay_config_path": str(root / "sub" / "guard.json"),
            "hook_name": "h", "callback_id": "c", "seed_variant_id": 5,
            "resolved_method": "POST",
        }
        summary = guard_replay_summary(
            current, {"request_name": "req.json"}, config_root=root, replay_run_id="run-1",
        )
        self.assertEqual(list(summary), ["legacy_run_id", "runs"])
        self.assertEqual(summary["legacy_run_id"], "run-1")
        run = summary["runs"][0]
        self.assertEqual(list(run), [
            "config_slug", "hook_name", "callback_id", "seed_variant_id", "callback_reached",
            "matched_artifact", "resolved_method", "process_status",
        ])
        self.assertEqual(run["config_slug"], "sub/guard")
        self.assertEqual(run["seed_variant_id"], "5")
        self.assertEqual(run["matched_artifact"], "req.json")
        self.assertEqual(run["process_status"], "replaying")
        self.assertIs(run["callback_reached"], True)
        current["replay_config_path"] = str(Path("elsewhere") / "guard.json")
        with self.assertRaises(ValueError):
            guard_replay_summary(
                current, {"request_name": "req.json"}, config_root=root, replay_run_id="run-1",
            )


class UnsentGuardProbesTests(unittest.TestCase):
    def test_unsent_guard_probes_only_matching_source_and_name(self):
        """Only probes for parameters the guard replay reported as unsent may be re-probed, matched
        by (SOURCE upper-cased, name); anything else would send probes the guard never needed."""
        pending = [
            {"source": "post", "name": "a", "value": 1},
            {"source": "GET", "name": "a"},
            "not-a-mapping",
            {"source": "POST", "name": "b"},
            {"source": "get", "name": "c"},
        ]
        result = {
            "observed_parameters": [
                {"source": "post", "name": "a", "candidate_reason": "unsent_guard"},
                {"source": "GET", "name": "c", "candidate_reason": "unsent_guard"},
                {"source": "POST", "name": "b", "candidate_reason": "other"},
                "junk",
            ],
            "pending_probes": pending,
        }
        probes = unsent_guard_probes(result)
        self.assertEqual(probes, [pending[0], pending[4]])
        self.assertIsNot(probes[0], pending[0])
        self.assertEqual(unsent_guard_probes({"observed_parameters": None, "pending_probes": pending}), [])
        self.assertEqual(unsent_guard_probes({}), [])


if __name__ == "__main__":
    unittest.main()
