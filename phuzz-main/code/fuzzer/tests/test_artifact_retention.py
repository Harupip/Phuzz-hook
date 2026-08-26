from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from artifacts.retention.generated_runs import retain_artifacts
from hook_energy.seed_generation.generated_config_runner import load_generated_configs


class ArtifactRetentionTests(unittest.TestCase):
    def _make_tree(self, root: Path, run_name: str = "run-B") -> dict[str, Path]:
        seed_dir = root / "seed_generation"
        run_dir = seed_dir / "zend-bridge" / run_name
        zend_discovery_dir = root / "zend-discovery" / run_name
        final_dir = run_dir / "final"
        config_path = root / "configs" / "final-config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            json.dumps({"target": "http://web/", "methods": ["POST"], "body_params": {"fuzz": ["value"]}}),
            encoding="utf-8",
        )
        final_dir.mkdir(parents=True, exist_ok=True)
        (final_dir / "target-0" / "seeds.json").parent.mkdir(parents=True, exist_ok=True)
        (final_dir / "target-0" / "seeds.json").write_text('{"suggested_seeds": []}', encoding="utf-8")
        (run_dir / "zend_convergence_summary.json").write_text(
            json.dumps({"legacy_run_id": run_name, "status": "CONVERGED", "targets": []}), encoding="utf-8"
        )
        final_run_summary = run_dir / "final-generated_config_run_summary.json"
        final_run_summary.write_text(
            json.dumps(
                {
                    "legacy_run_id": run_name,
                    "counts": {"total": 1, "callback_reached": 1},
                    "runs": [{"config_path": str(config_path), "callback_reached": True}],
                }
            ),
            encoding="utf-8",
        )
        final_config_summary = seed_dir / "generated_config_summary.json"
        final_config_summary.write_text(
            json.dumps(
                {
                    "generated": [
                        {
                            "config_path": str(config_path),
                            "config_slug": "generated-hooks/final",
                            "hook_name": "hook-final",
                            "callback_id": "callback-final",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        (run_dir / "hookphuzz-callback-registry.json").write_text("registry", encoding="utf-8")
        (run_dir / "pass1-generated_config_summary.json").write_text("pass1", encoding="utf-8")
        (run_dir / "pass1-generated_config_run_summary.json").write_text("pass1-run", encoding="utf-8")
        (run_dir / "pass1-configs" / "one.json").parent.mkdir(parents=True, exist_ok=True)
        (run_dir / "pass1-configs" / "one.json").write_text("config", encoding="utf-8")
        (run_dir / "targets" / "t0" / "iterations" / "0" / "state.json").parent.mkdir(parents=True, exist_ok=True)
        (run_dir / "targets" / "t0" / "iterations" / "0" / "state.json").write_text("target", encoding="utf-8")
        (run_dir / "current" / "state.json").parent.mkdir(parents=True, exist_ok=True)
        (run_dir / "current" / "state.json").write_text("current", encoding="utf-8")
        (run_dir / "logs" / "pass1.json").parent.mkdir(parents=True, exist_ok=True)
        (run_dir / "logs" / "pass1.json").write_text("log", encoding="utf-8")
        (run_dir / "zend_convergence_targets.json").write_text("targets", encoding="utf-8")
        (run_dir / "final-generated_config_summary.json").write_text("old-final-summary", encoding="utf-8")
        (run_dir / "generated_param_summary.json").write_text("generated-params", encoding="utf-8")
        (run_dir / "validation_result.json").write_text("validation", encoding="utf-8")
        (seed_dir / "suggested_seeds.json").write_text('{"suggested_seeds": []}', encoding="utf-8")
        (seed_dir / "runtime_coverage_snapshot.json").write_text("coverage", encoding="utf-8")
        (seed_dir / "hook_gap_report.json").write_text("gap", encoding="utf-8")
        (seed_dir / "zend_merged_suggested_seeds.json").write_text('{"suggested_seeds": []}', encoding="utf-8")
        zend_discovery_dir.mkdir(parents=True, exist_ok=True)
        (zend_discovery_dir / "zend_enriched_seeds.json").write_text("enriched", encoding="utf-8")
        return {
            "seed_dir": seed_dir,
            "run_dir": run_dir,
            "final_dir": final_dir,
            "final_config_summary": final_config_summary,
            "final_run_summary": final_run_summary,
            "config_path": config_path,
            "merged_suggested_seeds": seed_dir / "zend_merged_suggested_seeds.json",
            "zend_discovery_dir": zend_discovery_dir,
        }

    def _retain(self, paths: dict[str, Path], status: str, keep_debug_artifacts: bool = False):
        return retain_artifacts(
            paths["run_dir"],
            terminal_status=status,
            seed_output_dir=paths["seed_dir"],
            merged_suggested_seeds=paths["merged_suggested_seeds"],
            final_config_summary=paths["final_config_summary"],
            final_run_summary=paths["final_run_summary"],
            zend_discovery_run_dir=paths["zend_discovery_dir"],
            keep_debug_artifacts=keep_debug_artifacts,
        )

    def test_successful_run_prunes_intermediates_and_keeps_final_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = self._make_tree(Path(tmp_dir))

            result = self._retain(paths, "PASS")

            self.assertGreater(result.pruned, 0)
            self.assertFalse((paths["run_dir"] / "hookphuzz-callback-registry.json").exists())
            self.assertFalse((paths["run_dir"] / "pass1-configs").exists())
            self.assertFalse((paths["run_dir"] / "targets").exists())
            self.assertFalse((paths["run_dir"] / "generated_param_summary.json").exists())
            self.assertFalse((paths["run_dir"] / "validation_result.json").exists())
            self.assertFalse(paths["zend_discovery_dir"].exists())
            self.assertTrue((paths["run_dir"] / "zend_convergence_summary.json").exists())
            self.assertTrue(paths["final_dir"].exists())
            self.assertTrue(paths["final_run_summary"].exists())
            self.assertTrue(paths["config_path"].exists())
            self.assertFalse((paths["seed_dir"] / "suggested_seeds.json").exists())
            self.assertTrue((paths["seed_dir"] / "hook_gap_report.json").exists())
            self.assertTrue((paths["seed_dir"] / "zend_merged_suggested_seeds.json").exists())

    def test_unmerged_suggested_seeds_are_retained(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = self._make_tree(Path(tmp_dir))
            (paths["seed_dir"] / "suggested_seeds.json").write_text(
                json.dumps({"suggested_seeds": [{"hook_name": "unmerged", "callback_id": "callback-unmerged"}]}),
                encoding="utf-8",
            )

            self._retain(paths, "PASS")

            self.assertTrue((paths["seed_dir"] / "suggested_seeds.json").exists())

    def test_failed_run_preserves_all_intermediates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = self._make_tree(Path(tmp_dir))

            result = self._retain(paths, "FAIL")

            self.assertEqual(result.pruned, 0)
            self.assertTrue((paths["run_dir"] / "hookphuzz-callback-registry.json").exists())
            self.assertTrue((paths["run_dir"] / "pass1-configs").exists())
            self.assertTrue((paths["run_dir"] / "targets").exists())
            self.assertTrue((paths["run_dir"] / "generated_param_summary.json").exists())
            self.assertTrue((paths["run_dir"] / "validation_result.json").exists())
            self.assertTrue((paths["seed_dir"] / "suggested_seeds.json").exists())
            self.assertTrue(paths["zend_discovery_dir"].exists())

    def test_expected_partial_auth_success_prunes_intermediates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = self._make_tree(Path(tmp_dir))

            result = self._retain(paths, "PASS_PARTIAL_AUTH_EXPECTED")

            self.assertGreater(result.pruned, 0)
            self.assertFalse((paths["run_dir"] / "targets").exists())
            self.assertTrue((paths["run_dir"] / "zend_convergence_summary.json").exists())
            self.assertFalse(paths["zend_discovery_dir"].exists())

    def test_keep_debug_artifacts_preserves_success_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = self._make_tree(Path(tmp_dir))

            result = self._retain(paths, "PASS", keep_debug_artifacts=True)

            self.assertEqual(result.pruned, 0)
            self.assertTrue((paths["run_dir"] / "hookphuzz-callback-registry.json").exists())
            self.assertTrue((paths["run_dir"] / "pass1-configs").exists())
            self.assertTrue((paths["run_dir"] / "targets").exists())
            self.assertTrue((paths["seed_dir"] / "suggested_seeds.json").exists())
            self.assertTrue(paths["zend_discovery_dir"].exists())

    def test_cleanup_isolated_to_current_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            paths_a = self._make_tree(root, "run-A")
            paths_b = self._make_tree(root, "run-B")
            before_a = {
                path.relative_to(paths_a["run_dir"]): path.read_bytes()
                for path in paths_a["run_dir"].rglob("*")
                if path.is_file()
            }
            before_zend_a = {
                path.relative_to(paths_a["zend_discovery_dir"]): path.read_bytes()
                for path in paths_a["zend_discovery_dir"].rglob("*")
                if path.is_file()
            }

            self._retain(paths_b, "PASS")

            after_a = {
                path.relative_to(paths_a["run_dir"]): path.read_bytes()
                for path in paths_a["run_dir"].rglob("*")
                if path.is_file()
            }
            self.assertEqual(before_a, after_a)
            self.assertTrue((paths_a["run_dir"] / "targets").exists())
            self.assertFalse((paths_b["run_dir"] / "targets").exists())
            after_zend_a = {
                path.relative_to(paths_a["zend_discovery_dir"]): path.read_bytes()
                for path in paths_a["zend_discovery_dir"].rglob("*")
                if path.is_file()
            }
            self.assertEqual(before_zend_a, after_zend_a)
            self.assertFalse(paths_b["zend_discovery_dir"].exists())

    def test_retained_final_artifacts_still_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = self._make_tree(Path(tmp_dir))

            self._retain(paths, "PASS")

            configs = load_generated_configs(paths["final_config_summary"])
            final_run = json.loads(paths["final_run_summary"].read_text(encoding="utf-8"))
            self.assertEqual(len(configs), 1)
            self.assertEqual(configs[0]["callback_id"], "callback-final")
            self.assertTrue(final_run["runs"][0]["callback_reached"])


if __name__ == "__main__":
    unittest.main()
