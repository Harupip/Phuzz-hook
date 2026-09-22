from __future__ import annotations

import copy
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from config_comparison.comparator import compare_configs
from config_comparison.models import DifferenceKind, Status
from config_comparison.policy import ComparisonPolicy


class ComparisonPromptTests(unittest.TestCase):
    def test_prompt_selects_current_run_and_writes_real_report(self):
        from config_comparison.online_linked import main

        with tempfile.TemporaryDirectory() as directory:
            paths = create_batch(Path(directory))
            batch_dir = paths["chosen"].parent.parent
            with patch("sys.stdin.isatty", return_value=True), patch(
                "builtins.input", side_effect=["y", "1", str(paths["reference"])]
            ):
                self.assertEqual(main(["--prompt-batch", str(batch_dir)]), 0)
            report = json.loads((batch_dir / "config-comparison.json").read_text())
            self.assertEqual(report["counts"]["MATCH"], 1)

    def test_prompt_skips_noninteractive_decline_and_empty_export(self):
        from config_comparison.online_linked import main

        with tempfile.TemporaryDirectory() as directory:
            paths = create_batch(Path(directory))
            batch_dir = paths["chosen"].parent.parent
            with patch("sys.stdin.isatty", return_value=False), patch("builtins.input") as ask:
                self.assertEqual(main(["--prompt-batch", str(batch_dir)]), 0)
                ask.assert_not_called()
            with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="") as ask:
                self.assertEqual(main(["--prompt-batch", str(batch_dir)]), 0)
                self.assertEqual(ask.call_count, 1)
            with patch("sys.stdin.isatty", return_value=True), patch("builtins.input") as ask:
                self.assertEqual(main(["--prompt-batch", str(Path(directory) / "empty")]), 0)
                ask.assert_not_called()
            self.assertFalse((batch_dir / "config-comparison.json").exists())

    def test_prompt_cancel_and_invalid_selection_do_not_write(self):
        from config_comparison.online_linked import main

        with tempfile.TemporaryDirectory() as directory:
            paths = create_batch(Path(directory))
            batch_dir = paths["chosen"].parent.parent
            for answers, expected in [(["y", "99"], 2), (["y", "oops"], 2), (["y", ""], 0), (["y", "1", ""], 0), ([EOFError()], 0)]:
                with self.subTest(answers=answers), patch("sys.stdin.isatty", return_value=True), patch("builtins.input", side_effect=answers):
                    self.assertEqual(main(["--prompt-batch", str(batch_dir)]), expected)
            self.assertFalse((batch_dir / "config-comparison.json").exists())


def comparison_config() -> dict:
    return {
        "target": "http://web/wp-admin/admin-ajax.php",
        "methods": ["POST"],
        "headers": {
            "data": [{"name": "Authorization", "value": "Bearer expected"}],
            "fixed": ["Authorization"],
            "fuzz": [],
        },
        "cookies": {
            "data": [{"name": "wordpress_test_cookie", "value": "expected-cookie"}],
            "fixed": ["wordpress_test_cookie"],
            "fuzz": [],
        },
        "body_params": {
            "data": [
                {"name": "action", "value": "demo"},
                {"name": "metadata", "value": "request-value"},
            ],
            "fixed": ["action", "metadata"],
            "fuzz": [],
        },
        "metadata": {"hook_name": "wp_ajax_demo", "custom": {"run": 7}},
    }


def write_json(path: Path, value: object, *, bom: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(value)
    path.write_text(("\ufeff" if bom else "") + text, encoding="utf-8")


def create_batch(root: Path) -> dict[str, Path]:
    batch_dir = root / "online-linked" / "run-1"
    final_dir = batch_dir / "final-configs"
    final_dir.mkdir(parents=True)
    chosen = final_dir / "chosen.json"
    other = final_dir / "other.json"
    reference = root / "experiment reference with spaces.json"
    state_path = batch_dir / "batch-state.json"
    report_path = batch_dir / "config-comparison.json"

    reference_config = comparison_config()
    chosen_config = copy.deepcopy(reference_config)
    chosen_config["metadata"]["hook_name"] = "selected-final"
    other_config = copy.deepcopy(reference_config)
    other_config["methods"] = ["GET"]
    write_json(chosen, chosen_config)
    write_json(other, other_config)
    write_json(reference, reference_config)
    write_json(
        state_path,
        {
            "mode": "online-linked-batch",
            "legacy_run_id": "run-1",
            "campaign_status": "complete",
            "discovery": {"callbacks": 4},
            "vulnerability": {"status": "NOT_PROVEN"},
        },
    )
    return {
        "batch_dir": batch_dir,
        "final_dir": final_dir,
        "chosen": chosen,
        "other": other,
        "reference": reference,
        "state": state_path,
        "report": report_path,
    }


def run_offline(final_path: Path, reference_path: Path) -> int:
    from config_comparison.online_linked import run_comparison

    return run_comparison(final_path, reference_path)


class OnlineLinkedConfigComparisonPolicyTests(unittest.TestCase):
    def test_final_comparison_ignores_metadata_but_keeps_request(self) -> None:
        from config_comparison.online_linked import COMPARISON_POLICY

        expected = {"target": "http://web/a", "methods": ["POST"]}
        actual = {**expected, "metadata": {"hook_name": "new", "custom": {"run": 7}}}
        before = copy.deepcopy(actual)

        self.assertEqual(compare_configs(expected, actual, COMPARISON_POLICY).status, Status.MATCH)
        self.assertEqual(actual, before)

        actual["methods"] = ["GET"]
        self.assertEqual(compare_configs(expected, actual, COMPARISON_POLICY).status, Status.MISMATCH)

    def test_final_comparison_ignores_all_metadata_variants(self) -> None:
        from config_comparison.online_linked import COMPARISON_POLICY

        expected = comparison_config()
        for actual_metadata in (
            {"hook_name": "changed", "unknown": {"nested": [1, 2, 3]}},
            None,
        ):
            actual = copy.deepcopy(expected)
            if actual_metadata is None:
                actual.pop("metadata")
            else:
                actual["metadata"] = actual_metadata
            expected_before = copy.deepcopy(expected)
            actual_before = copy.deepcopy(actual)

            with self.subTest(actual_metadata=actual_metadata):
                result = compare_configs(expected, actual, COMPARISON_POLICY)

                self.assertEqual(result.status, Status.MATCH)
                self.assertEqual(expected, expected_before)
                self.assertEqual(actual, actual_before)

    def test_final_comparison_keeps_request_differences_and_does_not_mutate_inputs(self) -> None:
        from config_comparison.online_linked import COMPARISON_POLICY

        mutations = {
            "body parameter named metadata": lambda config: config["body_params"]["data"][1].update(
                value="changed-request-value"
            ),
            "authorization header": lambda config: config["headers"]["data"][0].update(
                value="Bearer changed"
            ),
            "cookie": lambda config: config["cookies"]["data"][0].update(value="changed-cookie"),
            "fixed/fuzz selector": lambda config: (
                config["body_params"]["fixed"].remove("metadata"),
                config["body_params"]["fuzz"].append("metadata"),
            ),
        }

        for name, mutate in mutations.items():
            with self.subTest(name=name):
                expected = comparison_config()
                actual = copy.deepcopy(expected)
                expected_before = copy.deepcopy(expected)
                mutate(actual)
                actual_before = copy.deepcopy(actual)

                result = compare_configs(expected, actual, COMPARISON_POLICY)

                self.assertEqual(result.status, Status.MISMATCH)
                self.assertEqual(expected, expected_before)
                self.assertEqual(actual, actual_before)

    def test_existing_semantic_policy_still_checks_unknown_metadata(self) -> None:
        expected = comparison_config()
        actual = copy.deepcopy(expected)
        actual["metadata"]["hook_name"] = "changed-hook"

        result = compare_configs(expected, actual, ComparisonPolicy(mode="semantic"))

        self.assertEqual(result.status, Status.MISMATCH)
        self.assertTrue(any(d.path == "/metadata/hook_name" for d in result.differences))
        self.assertTrue(any(d.kind == DifferenceKind.VALUE_MISMATCH for d in result.differences))


class OnlineLinkedConfigComparisonFilesystemTests(unittest.TestCase):
    def test_selected_final_is_compared_and_only_summary_is_added(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = create_batch(Path(tmp_dir) / "run folder with spaces")
            state_before = json.loads(paths["state"].read_text(encoding="utf-8"))
            chosen_bytes = paths["chosen"].read_bytes()
            reference_bytes = paths["reference"].read_bytes()

            exit_code = run_offline(paths["chosen"], paths["reference"])

            self.assertEqual(exit_code, 0)
            report = json.loads(paths["report"].read_text(encoding="utf-8"))
            self.assertEqual(report["expected"], str(paths["reference"].resolve()))
            self.assertEqual(report["actual"], str(paths["chosen"].resolve()))
            self.assertEqual(report["results"][0]["status"], Status.MATCH.value)
            self.assertEqual(report["counts"][Status.MATCH.value], 1)
            self.assertEqual(report["policy"]["mode"], "semantic")
            self.assertIn("/metadata", report["policy"]["ignored_metadata_paths"])
            self.assertEqual(paths["chosen"].read_bytes(), chosen_bytes)
            self.assertEqual(paths["reference"].read_bytes(), reference_bytes)

            state_after = json.loads(paths["state"].read_text(encoding="utf-8"))
            self.assertEqual(
                {key: value for key, value in state_after.items() if key != "config_comparison"},
                state_before,
            )
            self.assertEqual(
                state_after["config_comparison"],
                {
                    "status": Status.MATCH.value,
                    "exit_code": 0,
                    "report_path": str(paths["report"].resolve()),
                    "expected": str(paths["reference"].resolve()),
                    "actual": str(paths["chosen"].resolve()),
                    "counts": report["counts"],
                },
            )

    def test_mismatch_variants_keep_comparator_differences(self) -> None:
        mutations = {
            "value": lambda config: config["body_params"]["data"][1].update(value="changed"),
            "method": lambda config: config.update(methods=["GET"]),
            "source": lambda config: (
                config["body_params"]["data"].pop(0),
                config["body_params"]["fixed"].remove("action"),
                config.update(
                    query_params={
                        "data": [{"name": "action", "value": "demo"}],
                        "fixed": ["action"],
                        "fuzz": [],
                    }
                ),
            ),
        }

        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp_dir:
                paths = create_batch(Path(tmp_dir))
                actual = json.loads(paths["chosen"].read_text(encoding="utf-8"))
                mutate(actual)
                write_json(paths["chosen"], actual)

                exit_code = run_offline(paths["chosen"], paths["reference"])

                self.assertEqual(exit_code, 1)
                report = json.loads(paths["report"].read_text(encoding="utf-8"))
                self.assertEqual(report["results"][0]["status"], Status.MISMATCH.value)
                self.assertTrue(report["results"][0]["differences"])
                self.assertEqual(report["counts"][Status.MISMATCH.value], 1)

    def test_invalid_config_is_reported_as_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = create_batch(Path(tmp_dir))
            write_json(paths["chosen"], {"metadata": {"only": "metadata"}})

            exit_code = run_offline(paths["chosen"], paths["reference"])

            self.assertEqual(exit_code, 2)
            report = json.loads(paths["report"].read_text(encoding="utf-8"))
            self.assertEqual(report["results"][0]["status"], Status.INVALID.value)
            self.assertTrue(report["results"][0]["errors"])
            self.assertEqual(report["counts"][Status.INVALID.value], 1)
            self.assertEqual(report["input_errors"], [])

    def test_input_errors_are_not_no_reference(self) -> None:
        cases = ("missing", "malformed", "duplicate", "reference-directory")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp_dir:
                paths = create_batch(Path(tmp_dir))
                if case == "missing":
                    final_path = paths["final_dir"] / "missing.json"
                else:
                    final_path = paths["chosen"]
                    if case == "malformed":
                        paths["reference"].write_text("{not-json", encoding="utf-8")
                    elif case == "duplicate":
                        paths["reference"].write_text(
                            '{"target":"http://web","target":"http://other","methods":["GET"]}',
                            encoding="utf-8",
                        )
                    else:
                        paths["reference"].unlink()
                        paths["reference"].mkdir()

                exit_code = run_offline(final_path, paths["reference"])

                self.assertEqual(exit_code, 2)
                report = json.loads(paths["report"].read_text(encoding="utf-8"))
                self.assertEqual(report["results"], [])
                self.assertTrue(report["input_errors"])
                self.assertEqual(report["counts"][Status.NO_REFERENCE.value], 0)

    def test_utf8_bom_is_loaded_as_a_valid_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = create_batch(Path(tmp_dir))
            reference = json.loads(paths["reference"].read_text(encoding="utf-8"))
            write_json(paths["reference"], reference, bom=True)

            self.assertEqual(run_offline(paths["chosen"], paths["reference"]), 0)

    def test_invalid_final_or_batch_does_not_write_existing_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            paths = create_batch(root)
            paths["report"].write_bytes(b"old report")

            cases = {
                "running": lambda: json.loads(paths["state"].read_text(encoding="utf-8")) | {"campaign_status": "running"},
                "wrong-id": lambda: json.loads(paths["state"].read_text(encoding="utf-8")) | {"legacy_run_id": "other-run"},
            }
            for name, state_value in cases.items():
                with self.subTest(case=name):
                    write_json(paths["state"], state_value())
                    state_before = paths["state"].read_bytes()
                    self.assertEqual(run_offline(paths["chosen"], paths["reference"]), 2)
                    self.assertEqual(paths["report"].read_bytes(), b"old report")
                    self.assertEqual(paths["state"].read_bytes(), state_before)

            missing_state = paths["state"]
            missing_state.unlink()
            self.assertEqual(run_offline(paths["chosen"], paths["reference"]), 2)
            self.assertEqual(paths["report"].read_bytes(), b"old report")

            outside = root / "outside.json"
            write_json(outside, comparison_config())
            write_json(paths["state"], {
                "mode": "online-linked-batch",
                "legacy_run_id": "run-1",
                "campaign_status": "complete",
            })
            self.assertEqual(run_offline(outside, paths["reference"]), 2)
            self.assertEqual(paths["report"].read_bytes(), b"old report")

    def test_final_symlink_outside_run_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = create_batch(Path(tmp_dir))
            external = Path(tmp_dir) / "outside-final.json"
            write_json(external, comparison_config())
            link = paths["final_dir"] / "outside-link.json"
            try:
                os.symlink(external, link)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink unavailable: {exc}")

            self.assertEqual(run_offline(link, paths["reference"]), 2)
            self.assertFalse(paths["report"].exists())

    def test_output_aliases_are_rejected_without_overwriting_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = create_batch(Path(tmp_dir))
            state_before = paths["state"].read_bytes()

            self.assertEqual(run_offline(paths["chosen"], paths["state"]), 2)
            self.assertEqual(paths["state"].read_bytes(), state_before)
            self.assertFalse(paths["report"].exists())

            write_json(paths["report"], comparison_config())
            report_before = paths["report"].read_bytes()
            self.assertEqual(run_offline(paths["chosen"], paths["report"]), 2)
            self.assertEqual(paths["report"].read_bytes(), report_before)
            self.assertEqual(paths["state"].read_bytes(), state_before)

    def test_writer_failure_before_replace_preserves_existing_report_and_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = create_batch(Path(tmp_dir))
            paths["report"].write_bytes(b"old report")
            state_before = paths["state"].read_bytes()

            with patch("config_comparison.online_linked.Path.replace", side_effect=OSError("replace blocked")):
                exit_code = run_offline(paths["chosen"], paths["reference"])

            self.assertEqual(exit_code, 2)
            self.assertEqual(paths["report"].read_bytes(), b"old report")
            self.assertEqual(paths["state"].read_bytes(), state_before)

    def test_state_update_failure_keeps_old_state_after_report_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = create_batch(Path(tmp_dir))
            state_before = paths["state"].read_bytes()
            from config_comparison import online_linked

            original_writer = online_linked._write_json_atomic

            def write_report_then_fail(path: Path, payload: dict) -> None:
                if path == paths["report"]:
                    original_writer(path, payload)
                    return
                raise OSError("state replace blocked")

            stderr = io.StringIO()
            with patch.object(online_linked, "_write_json_atomic", side_effect=write_report_then_fail), contextlib.redirect_stderr(stderr):
                exit_code = run_offline(paths["chosen"], paths["reference"])

            self.assertEqual(exit_code, 2)
            self.assertTrue(paths["report"].exists())
            self.assertEqual(paths["state"].read_bytes(), state_before)
            self.assertIn("report", stderr.getvalue().lower())
            self.assertIn("state", stderr.getvalue().lower())

    def test_rerun_replaces_comparison_for_user_selected_final_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = create_batch(Path(tmp_dir))
            state_before = json.loads(paths["state"].read_text(encoding="utf-8"))

            self.assertEqual(run_offline(paths["chosen"], paths["reference"]), 0)
            self.assertEqual(run_offline(paths["other"], paths["reference"]), 1)

            report = json.loads(paths["report"].read_text(encoding="utf-8"))
            state_after = json.loads(paths["state"].read_text(encoding="utf-8"))
            self.assertEqual(report["actual"], str(paths["other"].resolve()))
            self.assertEqual(report["results"][0]["status"], Status.MISMATCH.value)
            self.assertEqual(
                {key: value for key, value in state_after.items() if key != "config_comparison"},
                state_before,
            )
            self.assertEqual(state_after["config_comparison"]["exit_code"], 1)
            self.assertEqual(state_after["config_comparison"]["status"], Status.MISMATCH.value)

    def test_subprocess_smoke_uses_two_explicit_paths_and_required_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = create_batch(Path(tmp_dir) / "run folder with spaces")
            state_before = paths["state"].read_bytes()
            code_root = FUZZER_DIR.parent
            command = [
                sys.executable,
                "-m",
                "fuzzer.config_comparison.online_linked",
                "--compare-final-config",
                str(paths["chosen"]),
                "--compare-with",
                str(paths["reference"]),
            ]

            missing_flag = subprocess.run(
                command[:-2],
                cwd=code_root,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(missing_flag.returncode, 2)
            self.assertFalse(paths["report"].exists())
            self.assertEqual(paths["state"].read_bytes(), state_before)

            smoke = subprocess.run(
                command,
                cwd=code_root,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(smoke.returncode, 0, smoke.stderr)
            self.assertIn("Config comparison", smoke.stdout)
            self.assertTrue(paths["report"].exists())



if __name__ == "__main__":
    unittest.main()
