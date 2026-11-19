"""Per-candidate tmpfs purge.

2026-11-18: the 1 GB shared tmpfs filled during cookie-notice runs because no
candidate's request/Zend artifacts were ever removed. Later candidates then lost
their v0 evidence. Finished candidates must free their artifacts, and only theirs.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from online_linked.coordination.campaign import build_argument_parser, run_online_linked
from online_linked.evidence import RUNTIME_PURGE_SCRIPT, purge_runtime_artifacts

PREFIX = "run-candidate-001-wp_ajax_x"


def _artifact(run_id, request_id, plugin="fixture", field="run_id"):
    return {"request_id": request_id, field: run_id, "target_plugin": plugin}


@unittest.skipUnless(shutil.which("php"), "requires PHP CLI")
class PurgeScriptTests(unittest.TestCase):
    def run_script(self, root, prefix=PREFIX, plugin="fixture"):
        result = subprocess.run(
            [shutil.which("php"), "-n", "-r", RUNTIME_PURGE_SCRIPT, "--", prefix, plugin,
             str(root / "requests"), str(root / "zend")],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_removes_only_this_candidates_request_and_zend_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requests").mkdir()
            (root / "zend").mkdir()
            requests = {
                "r1": _artifact(f"{PREFIX}-v0", "r1"),
                "r2": _artifact(f"{PREFIX}-v2-n3", "r2", field="legacy_run_id"),
                "r3": _artifact(PREFIX, "r3"),
                # Same index prefix without the "-" boundary belongs to another candidate.
                "keep_boundary": _artifact(f"{PREFIX}_other-v0", "keep_boundary"),
                "keep_next": _artifact("run-candidate-002-wp_ajax_y-v0", "keep_next"),
                "keep_plugin": _artifact(f"{PREFIX}-v0", "keep_plugin", plugin="other"),
                "keep_bootstrap": {"request_id": "keep_bootstrap", "run_id": "", "target_plugin": "fixture"},
            }
            for name, payload in requests.items():
                (root / "requests" / f"{name}.json").write_text(json.dumps(payload))
                (root / "zend" / f"{name}.json").write_text(json.dumps(payload))
            # Zend file whose request artifact was never written (e.g. tmpfs already full).
            (root / "zend" / "orphan.json").write_text(json.dumps(_artifact(f"{PREFIX}-v1", "orphan")))
            # A same-named Zend file owned by another run must survive: ownership is read
            # from each file's own metadata, never inferred from the request's name.
            (root / "requests" / "collide.json").write_text(json.dumps(_artifact(f"{PREFIX}-v0", "collide")))
            (root / "zend" / "collide.json").write_text(
                json.dumps(_artifact("run-candidate-002-wp_ajax_y-v0", "collide", plugin="other")))
            (root / "requests" / "r9.json.tmp.ab12").write_text("partial")
            (root / "requests" / "broken.json").write_text("{not json")

            stats = self.run_script(root)

            kept = {path.stem for path in (root / "requests").glob("*.json")}
            self.assertEqual(kept, {"keep_boundary", "keep_next", "keep_plugin", "keep_bootstrap", "broken"})
            kept_zend = {path.stem for path in (root / "zend").glob("*.json")}
            self.assertEqual(kept_zend, {"keep_boundary", "keep_next", "keep_plugin", "keep_bootstrap", "collide"})
            self.assertTrue((root / "requests" / "r9.json.tmp.ab12").exists(), "in-flight writes are not ours")
            self.assertEqual((stats["deleted_requests"], stats["deleted_zend"], stats["failed"]), (4, 4, 0))
            self.assertGreater(stats["freed_bytes"], 0)

    def test_empty_prefix_or_plugin_deletes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requests").mkdir()
            (root / "zend").mkdir()
            (root / "requests" / "r1.json").write_text(json.dumps(_artifact("", "r1")))
            for prefix, plugin in (("", "fixture"), (PREFIX, "")):
                with self.subTest(prefix=prefix, plugin=plugin):
                    self.assertEqual(self.run_script(root, prefix, plugin)["deleted_requests"], 0)
            self.assertTrue((root / "requests" / "r1.json").exists())


class PurgeTransportTests(unittest.TestCase):
    def test_runs_script_in_web_container_and_returns_stats(self):
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, json.dumps(
                {"deleted_requests": 2, "deleted_zend": 2, "failed": 0, "freed_bytes": 10}), "")

        stats = purge_runtime_artifacts(run_prefix=PREFIX, plugin_slug="fixture", timeout=30, run_command=run)
        command, kwargs = calls[0]
        self.assertEqual(command[:5], ["docker", "compose", "exec", "-T", "web"])
        self.assertEqual(command[-4:], [PREFIX, "fixture", "/shared-tmpfs/hook-coverage/requests",
                                        "/shared/opcode-events"])
        self.assertEqual(kwargs["timeout"], 30)
        self.assertEqual(stats["deleted_requests"], 2)

    def test_failures_raise_runtime_error(self):
        cases = (
            lambda command, **kwargs: subprocess.CompletedProcess(command, 1, "", "daemon busy"),
            lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "not json", ""),
            lambda command, **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired(command, 30)),
        )
        for run in cases:
            with self.subTest(run=run), self.assertRaises(RuntimeError):
                purge_runtime_artifacts(run_prefix=PREFIX, plugin_slug="fixture", timeout=30, run_command=run)
        with self.assertRaises(ValueError):
            purge_runtime_artifacts(run_prefix="", plugin_slug="fixture", timeout=30, run_command=cases[0])


class CampaignPurgeTests(unittest.TestCase):
    STATUSES = ("BOUNDED_ONLINE_COMPLETE", "NOT_VERIFIED", "VULN_FOUND", "PARTIAL")

    def run_batch(self, root, *, keep, purge, statuses=None, resume=False, item_count=None):
        statuses = self.STATUSES if statuses is None else statuses
        items = [{"hook_name": f"wp_ajax_fixture_{i}", "callback_id": f"cb-{i}", "seed": {"method": "GET"}}
                 for i in range(len(statuses) if item_count is None else item_count)]
        suggested = root / "suggested.json"
        suggested.write_text(json.dumps({"suggested_seeds": items}))
        registry = root / "registry.json"
        registry.write_text("{}")
        remaining = iter(statuses)

        class FakeCoordinator:
            def __init__(self, **kwargs):
                self.state_path = root / f"state-{kwargs['legacy_run_id']}.json"
                self.state = {"terminal_status": next(remaining), "terminal_reason": "X", "versions": [],
                              "candidate_queue": []}

            def run(self):
                return 0

        args = SimpleNamespace(
            suggested_seeds=str(suggested), bootstrap_config="", config_root=str(root / "configs"),
            output_root=str(root / "output"), plugin_slug="fixture", legacy_run_id="run", max_seconds=2,
            max_versions=2, max_candidates=8, campaign_seconds=60, callback_registry=str(registry),
            service="fixture", keep_runtime_artifacts=keep, resume=resume,
        )
        with patch("online_linked.coordination.campaign.OnlineLinkedCoordinator", FakeCoordinator), \
                patch("online_linked.coordination.campaign.purge_runtime_artifacts", purge), \
                patch("online_linked.coordination.campaign.export_online_linked_batch", return_value=0):
            run_online_linked(args)
        return json.loads((root / "output/online-linked/run/batch-state.json").read_text())

    def test_finished_candidates_free_their_artifacts_unless_partial_or_vulnerable(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = []

            def purge(**kwargs):
                calls.append(kwargs)
                return {"deleted_requests": 1, "deleted_zend": 1, "failed": 0, "freed_bytes": 5}

            state = self.run_batch(Path(tmp), keep=False, purge=purge)
            purged = [call["run_prefix"] for call in calls]
            by_status = {row["terminal_status"]: row for row in state["candidates"]}
            self.assertEqual(purged, [by_status["BOUNDED_ONLINE_COMPLETE"]["run_id"],
                                      by_status["NOT_VERIFIED"]["run_id"]])
            self.assertTrue(all(call["plugin_slug"] == "fixture" for call in calls))
            self.assertEqual(by_status["NOT_VERIFIED"]["runtime_artifact_purge"]["deleted_requests"], 1)
            # A finding stays reproducible and a PARTIAL candidate may still be resumed.
            self.assertNotIn("runtime_artifact_purge", by_status["VULN_FOUND"])
            self.assertNotIn("runtime_artifact_purge", by_status["PARTIAL"])

    def test_purge_failure_is_recorded_without_stopping_the_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            def purge(**kwargs):
                raise RuntimeError("RUNTIME_PURGE_FAILED: daemon busy")

            state = self.run_batch(Path(tmp), keep=False, purge=purge)
            self.assertEqual(len(state["candidates"]), len(self.STATUSES))
            first = state["candidates"][0]
            self.assertEqual(first["terminal_status"], "BOUNDED_ONLINE_COMPLETE")
            self.assertIn("daemon busy", first["runtime_artifact_purge"]["error"])

    def test_resume_retries_a_purge_interrupted_after_the_final_checkpoint(self):
        """The final checkpoint drops the candidate from the queue; a stop before the purge ends
        must not leave its artifacts in tmpfs for good."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def interrupted(**kwargs):
                raise KeyboardInterrupt

            with self.assertRaises(KeyboardInterrupt):
                self.run_batch(root, keep=False, purge=interrupted, statuses=("BOUNDED_ONLINE_COMPLETE",))
            saved = json.loads((root / "output/online-linked/run/batch-state.json").read_text())
            self.assertEqual(saved["candidates"][0]["runtime_artifact_purge"], {"status": "pending"})

            calls = []

            def purge(**kwargs):
                calls.append(kwargs)
                return {"deleted_requests": 3, "deleted_zend": 3, "failed": 0, "freed_bytes": 9}

            state = self.run_batch(root, keep=False, purge=purge, statuses=(), resume=True, item_count=1)
            self.assertEqual([call["run_prefix"] for call in calls], [saved["candidates"][0]["run_id"]])
            record = state["candidates"][0]["runtime_artifact_purge"]
            self.assertEqual((record["status"], record["deleted_requests"]), ("done", 3))

    def test_undeleted_files_keep_the_purge_retryable_on_resume(self):
        """A purge that left files behind is not done: --resume must try again."""
        for first in ({"deleted_requests": 2, "deleted_zend": 1, "failed": 1, "freed_bytes": 3},
                      RuntimeError("RUNTIME_PURGE_FAILED: daemon busy")):
            with self.subTest(first=first), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)

                def partial(**kwargs):
                    if isinstance(first, Exception):
                        raise first
                    return dict(first)

                saved = self.run_batch(root, keep=False, purge=partial, statuses=("NOT_VERIFIED",))
                self.assertEqual(saved["candidates"][0]["runtime_artifact_purge"]["status"], "failed")
                calls = []
                state = self.run_batch(root, keep=False, statuses=(), resume=True, item_count=1,
                                       purge=lambda **kwargs: calls.append(kwargs) or
                                       {"deleted_requests": 1, "deleted_zend": 0, "failed": 0, "freed_bytes": 1})
                self.assertEqual(len(calls), 1)
                self.assertEqual(state["candidates"][0]["runtime_artifact_purge"]["status"], "done")

    def test_keep_flag_disables_purge(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = []
            state = self.run_batch(Path(tmp), keep=True, purge=lambda **kwargs: calls.append(kwargs))
            self.assertEqual(calls, [])
            self.assertTrue(all("runtime_artifact_purge" not in row for row in state["candidates"]))

    def test_parser_purges_by_default(self):
        required = ['--suggested-seeds', 's', '--config-root', 'c', '--output-root', 'o',
                    '--plugin-slug', 'p', '--legacy-run-id', 'r', '--callback-registry', 'g']
        self.assertIs(build_argument_parser().parse_args(required).keep_runtime_artifacts, False)
        self.assertIs(build_argument_parser().parse_args(
            required + ['--keep-runtime-artifacts']).keep_runtime_artifacts, True)


if __name__ == "__main__":
    unittest.main()
