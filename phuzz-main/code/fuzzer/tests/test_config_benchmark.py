"""Benchmark harness tests.

The harness is the yardstick for every online-linked change: if it silently
skips runs, pairs hooks wrongly, or misses a drop versus the baseline, a
regression in config discovery looks like progress. Each test pins one of
those failure modes.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from config_comparison import benchmark  # noqa: E402


AJAX = "http://web/wp-admin/admin-ajax.php"


def ajax_config(action: str, body: list[dict], fixed: list[str], fuzz: list[str], *, header: bool = False) -> dict:
    config = {
        "target": AJAX,
        "methods": ["POST"],
        "query_params": {"weight": 1, "fixed": ["action"], "fuzz": [], "data": [{"name": "action", "value": action}]},
        "body_params": {"weight": 1, "fixed": fixed, "fuzz": fuzz, "data": body},
    }
    if header:
        config["headers"] = {
            "weight": 1,
            "fixed": ["Content\\-Type"],
            "fuzz": [],
            "data": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
        }
    return config


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def write_run(runs: Path, slug: str, stamp: str, status: str, exports: dict[str, dict], reasons: dict[str, str] | None = None) -> Path:
    run_dir = runs / f"{slug}-{stamp}"
    candidates = []
    batch_candidates = []
    for hook, config in exports.items():
        name = f"fuzzer-config.{hook}.json"
        write_json(run_dir / "final-configs" / name, config)
        candidates.append({
            "hook_name": hook,
            "selected_version": "v2",
            # Absolute path from another machine: the harness must fall back to final-configs/<name>.
            "exported_configs": [
                {"version": "v1", "config_path": f"C:/elsewhere/final-configs/{hook}.v1.json"},
                {"version": "v2", "config_path": f"C:/elsewhere/final-configs/{name}"},
            ],
        })
    for hook, reason in (reasons or {}).items():
        batch_candidates.append({"hook_name": hook, "terminal_status": "BOUNDED_ONLINE_COMPLETE", "terminal_reason": reason})
    write_json(run_dir / "final-config-summary.json", {"schema_version": 1, "candidates": candidates})
    write_json(run_dir / "batch-state.json", {
        "mode": "online-linked-batch",
        "plugin_slug": slug,
        "legacy_run_id": run_dir.name,
        "campaign_status": status,
        "candidates": batch_candidates,
    })
    return run_dir


def write_reference(refs: Path, dirname: str, endpoint: str, config: dict) -> None:
    write_json(refs / dirname / endpoint / f"fuzzer-config.{endpoint}.json", config)


class BenchmarkFixture(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.runs = root / "runs"
        self.refs = root / "refs"
        self.runs.mkdir()
        self.refs.mkdir()
        self.root = root

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def score(self) -> dict:
        return benchmark.build_report(self.runs, self.refs)


class PairingAndMetricsTests(BenchmarkFixture):
    def test_exact_config_scores_perfect_and_matches(self) -> None:
        ref = ajax_config("do-a", [{"name": "nonce", "value": "x"}], ["nonce"], ["id"])
        write_reference(self.refs, "1000-alpha.1.2.zip", "a", ref)
        actual = ajax_config("do-a", [{"name": "nonce", "value": "x"}], ["nonce"], ["id"])
        write_run(self.runs, "alpha", "20261101T000000Z", "complete", {"wp_ajax_do-a": actual})

        plugin = self.score()["plugins"]["alpha"]

        self.assertEqual(plugin["status"], "SCORED")
        self.assertEqual(plugin["metrics"]["hook_recall"], 1.0)
        self.assertEqual(plugin["metrics"]["param_recall"], 1.0)
        self.assertEqual(plugin["metrics"]["param_precision"], 1.0)
        self.assertEqual(plugin["metrics"]["classification_agreement"], 1.0)
        self.assertEqual(plugin["metrics"]["match_count"], 1)

    def test_missing_param_and_wrong_classification_lower_scores(self) -> None:
        # Reference: nonce fixed, other fuzz, option_id fuzz via selector only (no data entry).
        ref = ajax_config("do-b", [{"name": "nonce", "value": "fuzz"}, {"name": "other", "value": "fuzz"}], ["nonce"], ["option_id", "other"])
        write_reference(self.refs, "1000-beta.zip", "b", ref)
        # Actual: has nonce + option_id, misses other, puts option_id in fixed. Content-Type header is noise.
        actual = ajax_config(
            "do-b",
            [{"name": "nonce", "value": "probe"}, {"name": "option_id", "value": "fuzz"}],
            ["nonce", "option_id"],
            [],
            header=True,
        )
        write_run(self.runs, "beta", "20261101T000000Z", "complete", {"wp_ajax_do-b": actual})

        plugin = self.score()["plugins"]["beta"]
        pair = plugin["pairs"][0]

        # Reference params: action, nonce, other, option_id (selector literal counts). Actual hits 3 of 4.
        self.assertEqual(pair["missing_params"], ["body_params:other"])
        # option_id is in the reference fuzz selector, so it is not extra; the header is excluded as noise.
        self.assertEqual(pair["extra_params"], [])
        self.assertEqual(pair["ignored_params"], ["headers:Content-Type"])
        self.assertEqual(plugin["metrics"]["param_recall"], 0.75)
        self.assertEqual(plugin["metrics"]["param_precision"], 1.0)
        # Shared: action(fixed/fixed), nonce(fixed/fixed), option_id(fuzz/fixed) -> 2/3 agree.
        self.assertEqual(pair["classification_mismatches"], ["body_params:option_id"])
        self.assertAlmostEqual(plugin["metrics"]["classification_agreement"], 2 / 3)
        self.assertEqual(plugin["metrics"]["match_count"], 0)

    def test_request_metric_ignores_query_vs_body_transport(self) -> None:
        # Plugins reading $_REQUEST accept a param from GET or POST; the strict metric still
        # tells them apart (needed for query `action` fixed vs body `action` fuzz), the request metric does not.
        ref = {"target": AJAX, "methods": ["GET"], "query_params": {"weight": 1, "fixed": ["action"], "fuzz": ["url"], "data": [
            {"name": "action", "value": "r-a"}, {"name": "url", "value": "fuzz"}, {"name": "width", "value": "fuzz"}]}}
        actual = {"target": AJAX, "methods": ["POST"], "body_params": {"weight": 1, "fixed": ["action"], "fuzz": ["url"], "data": [
            {"name": "action", "value": "r-a"}, {"name": "url", "value": "fuzz"}]}}
        write_reference(self.refs, "1000-rho.zip", "a", ref)
        write_run(self.runs, "rho", "20261101T000000Z", "complete", {"wp_ajax_r-a": actual})

        metrics = self.score()["plugins"]["rho"]["metrics"]

        self.assertEqual(metrics["param_recall"], 0.0)
        self.assertEqual(metrics["request_param_recall"], 2 / 3)
        self.assertEqual(metrics["request_param_precision"], 1.0)

    def test_request_metric_counts_action_in_both_sections_once(self) -> None:
        both = ajax_config("s-a", [{"name": "action", "value": "fuzz"}, {"name": "id", "value": "x"}], [], ["action", "id"])
        write_reference(self.refs, "1000-sig.zip", "a", both)
        write_run(self.runs, "sig", "20261101T000000Z", "complete", {"wp_ajax_s-a": both})

        plugin = self.score()["plugins"]["sig"]

        self.assertEqual(plugin["counts"]["request_reference_params"], 2)  # action, id
        self.assertEqual(plugin["metrics"]["request_param_recall"], 1.0)

    def test_reference_hook_without_export_lowers_hook_recall(self) -> None:
        write_reference(self.refs, "1000-gamma.zip", "a", ajax_config("g-a", [], [], []))
        write_reference(self.refs, "1000-gamma.zip", "b", ajax_config("g-b", [], [], []))
        write_run(self.runs, "gamma", "20261101T000000Z", "complete", {
            "wp_ajax_g-a": ajax_config("g-a", [], [], []),
            "wp_ajax_g-extra": ajax_config("g-extra", [], [], []),
        })

        plugin = self.score()["plugins"]["gamma"]

        self.assertEqual(plugin["metrics"]["hook_recall"], 0.5)
        self.assertEqual(plugin["missing_hooks"], ["ajax:g-b"])
        self.assertEqual(plugin["unreferenced_exports"], ["wp_ajax_g-extra"])

    def test_auth_and_nopriv_exports_both_pair_with_one_reference(self) -> None:
        write_reference(self.refs, "1000-delta.zip", "a", ajax_config("d-a", [], [], []))
        write_run(self.runs, "delta", "20261101T000000Z", "complete", {
            "wp_ajax_d-a": ajax_config("d-a", [], [], []),
            "wp_ajax_nopriv_d-a": ajax_config("d-a", [], [], []),
        })

        plugin = self.score()["plugins"]["delta"]

        self.assertEqual(plugin["metrics"]["hook_recall"], 1.0)
        self.assertEqual(sorted(pair["hook"] for pair in plugin["pairs"]), ["wp_ajax_d-a", "wp_ajax_nopriv_d-a"])

    def test_auth_and_nopriv_references_pair_with_matching_export(self) -> None:
        # Experiment marks the unauthenticated variant only by the `nopriv_` filename prefix.
        write_json(self.refs / "1000-iota.zip" / "h" / "fuzzer-config.i-a.json",
                   ajax_config("i-a", [{"name": "auth_only", "value": "x"}], ["auth_only"], []))
        write_json(self.refs / "1000-iota.zip" / "h" / "fuzzer-config.nopriv_i-a.json", ajax_config("i-a", [], [], []))
        write_run(self.runs, "iota", "20261101T000000Z", "complete", {
            "wp_ajax_i-a": ajax_config("i-a", [{"name": "auth_only", "value": "x"}], ["auth_only"], []),
            "wp_ajax_nopriv_i-a": ajax_config("i-a", [], [], []),
        })

        plugin = self.score()["plugins"]["iota"]

        self.assertEqual(plugin["errors"], [])
        self.assertEqual(plugin["counts"]["reference_hooks"], 2)
        self.assertEqual(plugin["metrics"]["hook_recall"], 1.0)
        self.assertEqual(plugin["metrics"]["param_recall"], 1.0)
        self.assertEqual(plugin["metrics"]["param_precision"], 1.0)

    def test_action_in_query_and_body_uses_query_action(self) -> None:
        # Fuzzing POST `action` puts it in both sections; the query value names the hook.
        def both(action: str) -> dict:
            return ajax_config(action, [{"name": "action", "value": "fuzz"}], [], ["action"])
        write_reference(self.refs, "1000-kappa.zip", "a", both("k-a"))
        write_run(self.runs, "kappa", "20261101T000000Z", "complete", {"wp_ajax_k-a": both("k-a")})

        plugin = self.score()["plugins"]["kappa"]

        self.assertEqual(plugin["errors"], [])
        self.assertEqual(plugin["metrics"]["match_count"], 1)

    def test_unexported_candidate_is_missing_hook_not_error(self) -> None:
        write_reference(self.refs, "1000-lam.zip", "a", ajax_config("l-a", [], [], []))
        run_dir = write_run(self.runs, "lam", "20261101T000000Z", "complete", {})
        write_json(run_dir / "final-config-summary.json", {"schema_version": 1, "candidates": [
            {"hook_name": "wp_ajax_l-a", "selected_version": None, "exported_configs": []}]})

        plugin = self.score()["plugins"]["lam"]

        self.assertEqual(plugin["errors"], [])
        self.assertEqual(plugin["missing_hooks"], ["ajax:l-a"])
        self.assertEqual(plugin["counts"]["unexported_candidates"], 1)

    def test_older_summary_schema_uses_candidate_config_path(self) -> None:
        write_reference(self.refs, "1000-mu.zip", "a", ajax_config("m-a", [], [], []))
        run_dir = write_run(self.runs, "mu", "20261101T000000Z", "complete", {"wp_ajax_m-a": ajax_config("m-a", [], [], [])})
        write_json(run_dir / "final-config-summary.json", {"schema_version": 1, "candidates": [
            {"hook_name": "wp_ajax_m-a", "selected_version": "v3",
             "config_path": "C:\\elsewhere\\final-configs\\fuzzer-config.wp_ajax_m-a.json"}]})

        plugin = self.score()["plugins"]["mu"]

        self.assertEqual(plugin["errors"], [])
        self.assertEqual(plugin["metrics"]["hook_recall"], 1.0)

    def test_export_without_action_is_plugin_error_not_crash(self) -> None:
        write_reference(self.refs, "1000-eta.zip", "a", ajax_config("h-a", [], [], []))
        no_action = {"target": AJAX, "methods": ["POST"], "body_params": {"fixed": [], "fuzz": [], "data": []}}
        write_run(self.runs, "eta", "20261101T000000Z", "complete", {
            "wp_ajax_h-a": ajax_config("h-a", [], [], []),
            "wp_ajax_broken": no_action,
        })

        plugin = self.score()["plugins"]["eta"]

        self.assertEqual(plugin["metrics"]["hook_recall"], 1.0)
        self.assertEqual(len(plugin["errors"]), 1)
        self.assertIn("wp_ajax_broken", plugin["errors"][0])

    def test_terminal_reasons_are_counted(self) -> None:
        write_reference(self.refs, "1000-eps.zip", "a", ajax_config("e-a", [], [], []))
        write_run(self.runs, "eps", "20261101T000000Z", "complete", {"wp_ajax_e-a": ajax_config("e-a", [], [], [])},
                  reasons={"h1": "BUDGET_EXPIRED", "h2": "BUDGET_EXPIRED", "h3": "HARD_CANDIDATE_TIME_CAP"})

        report = self.score()

        self.assertEqual(report["plugins"]["eps"]["terminal_reasons"], {"BUDGET_EXPIRED": 2, "HARD_CANDIDATE_TIME_CAP": 1})
        self.assertEqual(report["aggregate"]["terminal_reasons"]["BUDGET_EXPIRED"], 2)


class RunSelectionTests(BenchmarkFixture):
    def test_uses_latest_completed_run_and_lists_newer_incomplete_as_skipped(self) -> None:
        write_reference(self.refs, "1000-alpha.zip", "a", ajax_config("do-a", [], [], []))
        write_run(self.runs, "alpha", "20261101T000000Z", "complete", {"wp_ajax_do-a": ajax_config("do-a", [], [], [])})
        newer = write_run(self.runs, "alpha", "20261102T000000Z", "PARTIAL", {})

        report = self.score()

        self.assertEqual(report["plugins"]["alpha"]["run"], "alpha-20261101T000000Z")
        self.assertIn({"run": newer.name, "reason": "campaign_status=PARTIAL"}, report["skipped_runs"])

    def test_plugin_without_completed_run_is_reported_not_dropped(self) -> None:
        write_reference(self.refs, "1000-alpha.zip", "a", ajax_config("do-a", [], [], []))
        write_run(self.runs, "alpha", "20261102T000000Z", "PARTIAL", {})

        self.assertEqual(self.score()["plugins"]["alpha"]["status"], "NO_COMPLETED_RUN")

    def test_plugin_without_reference_is_no_reference(self) -> None:
        write_run(self.runs, "zeta", "20261101T000000Z", "complete", {"wp_ajax_z": ajax_config("z", [], [], [])})

        plugin = self.score()["plugins"]["zeta"]

        self.assertEqual(plugin["status"], "NO_REFERENCE")
        self.assertNotIn("zeta", [p for p, v in self.score()["plugins"].items() if v["status"] == "SCORED"])

    def test_reference_dir_slug_parsing(self) -> None:
        self.assertEqual(benchmark.reference_slug("1000000-cookie-notice.2.4.8.zip"), "cookie-notice")
        self.assertEqual(benchmark.reference_slug("300000-cmb2.zip"), "cmb2")
        self.assertEqual(benchmark.reference_slug("1000000-wp-file-manager.zip"), "wp-file-manager")
        self.assertEqual(benchmark.reference_slug("400000-intuitive-custom-post-order.3.1.4.1.zip"), "intuitive-custom-post-order")


class BaselineAndCliTests(BenchmarkFixture):
    def _setup_beta(self, actual_body: list[dict]) -> None:
        ref = ajax_config("do-b", [{"name": "nonce", "value": "x"}, {"name": "other", "value": "x"}], ["nonce"], ["other"])
        write_reference(self.refs, "1000-beta.zip", "b", ref)
        write_run(self.runs, "beta", "20261101T000000Z", "complete",
                  {"wp_ajax_do-b": ajax_config("do-b", actual_body, ["nonce"], ["other"])})

    def test_metric_drop_versus_baseline_is_regression(self) -> None:
        self._setup_beta([{"name": "nonce", "value": "x"}, {"name": "other", "value": "x"}])
        baseline = self.score()
        self.runs = self.root / "runs2"
        self.runs.mkdir()
        write_run(self.runs, "beta", "20261102T000000Z", "complete",
                  {"wp_ajax_do-b": ajax_config("do-b", [{"name": "nonce", "value": "x"}], ["nonce"], [])})

        regressions = benchmark.diff_baseline(baseline, self.score())["regressions"]

        # Reference params action/nonce/other; the new run lost `other`.
        self.assertIn({"plugin": "beta", "metric": "param_recall", "baseline": 1.0, "current": 2 / 3}, regressions)

    def test_plugin_scored_in_baseline_but_not_now_is_regression(self) -> None:
        self._setup_beta([{"name": "nonce", "value": "x"}, {"name": "other", "value": "x"}])
        baseline = self.score()
        (self.root / "empty-runs").mkdir()
        current = benchmark.build_report(self.root / "empty-runs", self.refs)

        regressions = benchmark.diff_baseline(baseline, current)["regressions"]

        self.assertEqual(regressions[0]["plugin"], "beta")
        self.assertEqual(regressions[0]["metric"], "status")

    def test_cli_exit_codes(self) -> None:
        self._setup_beta([{"name": "nonce", "value": "x"}, {"name": "other", "value": "x"}])
        out = self.root / "report.json"
        args = ["--runs", str(self.runs), "--references", str(self.refs), "--output", str(out)]

        self.assertEqual(benchmark.main(args), 0)
        same_args = ["--runs", str(self.runs), "--references", str(self.refs), "--output", str(self.root / "r2.json")]
        self.assertEqual(benchmark.main(same_args + ["--baseline", str(out)]), 0)

        worse = json.loads(out.read_text(encoding="utf-8"))
        worse["plugins"]["beta"]["metrics"]["param_recall"] = 2.0  # pretend baseline was better
        better_baseline = self.root / "better.json"
        better_baseline.write_text(json.dumps(worse), encoding="utf-8")
        self.assertEqual(benchmark.main(same_args + ["--baseline", str(better_baseline)]), 1)

        self.assertEqual(benchmark.main(["--runs", str(self.root / "missing"), "--references", str(self.refs), "--output", str(out)]), 2)

    def test_output_must_not_overwrite_or_land_inside_inputs(self) -> None:
        """A report written over a reference config or into a run would destroy benchmark input."""
        self._setup_beta([{"name": "nonce", "value": "x"}])
        reference = next(self.refs.rglob("fuzzer-config*.json"))
        run_file = next(self.runs.rglob("final-config-summary.json"))
        for target in (reference, run_file, self.refs / "report.json", self.runs / "report.json"):
            with self.subTest(target=target.name):
                before = target.read_bytes() if target.exists() else None
                args = ["--runs", str(self.runs), "--references", str(self.refs), "--output", str(target)]
                self.assertEqual(benchmark.main(args), 2)
                self.assertEqual(target.read_bytes() if target.exists() else None, before)

    def test_missing_or_malformed_export_summary_is_not_scored(self) -> None:
        """No export summary means nothing was scored; it must not read as a perfect-looking SCORED run."""
        for name, content in (("missing", None), ("list", []), ("candidates-not-list", {"candidates": {}}),
                              ("candidate-not-object", {"candidates": ["x"]}),
                              ("exports-not-list", {"candidates": [{"hook_name": "wp_ajax_do-b",
                                                                    "selected_version": "v2",
                                                                    "exported_configs": "x"}]})):
            with self.subTest(name=name):
                self._setup_beta([{"name": "nonce", "value": "x"}])
                summary = next(self.runs.rglob("final-config-summary.json"))
                if content is None:
                    summary.unlink()
                else:
                    summary.write_text(json.dumps(content), encoding="utf-8")
                plugin = self.score()["plugins"]["beta"]
                if name == "exports-not-list":
                    # The summary is readable, but its only selected export is not: nothing was scored.
                    self.assertEqual(plugin["status"], "INVALID_EXPORTS")
                    self.assertTrue(any("exported_configs" in error for error in plugin["errors"]))
                else:
                    self.assertEqual(plugin["status"], "INVALID_EXPORT_SUMMARY")
                    self.assertTrue(plugin["errors"])
                # Callers must see a failure when bad input left nothing to score; the report is still written.
                out = self.root / f"{name}.json"
                self.assertEqual(benchmark.main(
                    ["--runs", str(self.runs), "--references", str(self.refs), "--output", str(out)]), 2)
                self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["plugins"]["beta"]["status"],
                                 plugin["status"])
                shutil.rmtree(self.runs)
                shutil.rmtree(self.refs)
                self.runs.mkdir()
                self.refs.mkdir()

    def test_malformed_export_record_is_a_plugin_error_not_a_crash(self) -> None:
        """One bad record must not lose the whole batch report."""
        good = {"hook_name": "wp_ajax_do-b", "selected_version": "v2",
                "exported_configs": [{"version": "v2", "config_path": "C:/x/final-configs/fuzzer-config.wp_ajax_do-b.json"}]}
        for name, bad in (
            ("missing-config-path", {"hook_name": "wp_ajax_x", "selected_version": "v2",
                                     "exported_configs": [{"version": "v2"}]}),
            ("numeric-config-path", {"hook_name": "wp_ajax_x", "selected_version": "v2",
                                     "exported_configs": [{"version": "v2", "config_path": 7}]}),
            ("missing-hook-name", {"selected_version": "v2", "exported_configs": [
                {"version": "v2", "config_path": "C:/x/final-configs/fuzzer-config.wp_ajax_do-b.json"}]}),
        ):
            with self.subTest(name=name):
                self._setup_beta([{"name": "nonce", "value": "x"}, {"name": "other", "value": "x"}])
                summary = next(self.runs.rglob("final-config-summary.json"))
                summary.write_text(json.dumps({"candidates": [bad, good]}), encoding="utf-8")
                plugin = self.score()["plugins"]["beta"]
                self.assertEqual(plugin["status"], "SCORED")
                self.assertEqual(plugin["metrics"]["hook_recall"], 1.0, "the valid record is still scored")
                self.assertEqual(len(plugin["errors"]), 1)
                shutil.rmtree(self.runs)
                shutil.rmtree(self.refs)
                self.runs.mkdir()
                self.refs.mkdir()

    def test_run_whose_every_selected_export_is_unreadable_fails(self) -> None:
        """0 pairs + 1 error must not pass as a SCORED run with exit 0."""
        self._setup_beta([{"name": "nonce", "value": "x"}])
        summary = next(self.runs.rglob("final-config-summary.json"))
        summary.write_text(json.dumps({"candidates": [
            {"hook_name": "wp_ajax_do-b", "selected_version": "v2", "exported_configs": [{"version": "v2"}]}]}),
            encoding="utf-8")
        plugin = self.score()["plugins"]["beta"]
        self.assertEqual(plugin["status"], "INVALID_EXPORTS")
        self.assertEqual(len(plugin["errors"]), 1)
        out = self.root / "report.json"
        self.assertEqual(benchmark.main(
            ["--runs", str(self.runs), "--references", str(self.refs), "--output", str(out)]), 2)
        self.assertTrue(out.exists(), "the report is still written for inspection")

    def test_valid_summary_without_selected_exports_is_scored_as_zero_coverage(self) -> None:
        """A campaign that exported nothing is a real (bad) result, not broken input."""
        self._setup_beta([{"name": "nonce", "value": "x"}])
        summary = next(self.runs.rglob("final-config-summary.json"))
        summary.write_text(json.dumps({"candidates": [
            {"hook_name": "wp_ajax_do-b", "selected_version": None}]}), encoding="utf-8")
        plugin = self.score()["plugins"]["beta"]
        self.assertEqual(plugin["status"], "SCORED")
        self.assertEqual(plugin["metrics"]["hook_recall"], 0.0)
        out = self.root / "report.json"
        self.assertEqual(benchmark.main(
            ["--runs", str(self.runs), "--references", str(self.refs), "--output", str(out)]), 0)

    def test_output_must_not_overwrite_baseline(self) -> None:
        self._setup_beta([{"name": "nonce", "value": "x"}])
        out = self.root / "report.json"
        args = ["--runs", str(self.runs), "--references", str(self.refs), "--output", str(out)]
        self.assertEqual(benchmark.main(args), 0)
        before = out.read_bytes()

        # Writing the report over its own baseline would silently destroy the baseline.
        self.assertEqual(benchmark.main(args + ["--baseline", str(out)]), 2)
        self.assertEqual(out.read_bytes(), before)
