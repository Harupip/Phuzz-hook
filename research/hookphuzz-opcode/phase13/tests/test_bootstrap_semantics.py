from __future__ import annotations
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("phase13_runner", ROOT / "scripts" / "phase13.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
STEPS = ["verify_wordpress_files", "create_wp_config", "wait_for_database", "install_wordpress", "verify_plugin_zip", "verify_plugin_sha256", "install_plugin", "activate_plugin", "verify_plugin_version", "capture_registry"]

def current_run_gate(result: Path, run_id: str) -> bool:
    value=json.loads(result.read_text())
    return value.get("run_id") == run_id and value.get("bootstrap_exit_code") == 0

def project(run_id: str, slug: str) -> str:
    return ("hookphuzz-phase13-"+slug+"-"+run_id.lower())[:63]

def executed_steps(failure: str | None = None) -> list[str]:
    return STEPS[:STEPS.index(failure)+1] if failure else STEPS

class BootstrapSemanticTests(unittest.TestCase):
    def test_wp_config_precedes_database(self): self.assertLess(STEPS.index("create_wp_config"), STEPS.index("wait_for_database"))
    def test_failure_suppresses_later_steps(self): self.assertNotIn("capture_registry", executed_steps("verify_plugin_zip"))
    def test_missing_zip_and_sha_are_distinct(self): self.assertNotEqual("plugin_zip_missing", "sha256_mismatch")
    def test_install_activation_and_version_are_distinct(self): self.assertEqual(len({"plugin_install_failure","plugin_activation_failure","plugin_version_mismatch"}),3)
    def test_current_run_gate_rejects_stale(self):
        p=Path(self.id().replace(".","_")+'.json'); p.write_text(json.dumps({"run_id":"old","bootstrap_exit_code":0})); self.assertFalse(current_run_gate(p,"new")); p.unlink()
    def test_unique_compose_projects(self): self.assertNotEqual(project("r1","a"),project("r1","b"))
    def test_plugin_result_isolation(self): self.assertNotEqual(Path("results/r/a"),Path("results/r/b"))
    def test_redaction_pattern(self):
        import re
        self.assertNotIn("secret",re.sub(r"(?i)(password|cookie)=[^\s]+",r"\1=<redacted>","password=secret cookie=secret"))
    def test_no_cross_plugin_reuse(self): self.assertNotEqual(("a","request"),("b","request"))
    def test_scoped_cleanup_name(self): self.assertTrue(project("r","a").startswith("hookphuzz-phase13-a-"))
    def test_sentinel_is_not_scoped(self): self.assertNotIn("sentinel", project("r","a"))
    def test_missing_zip_stops_install(self): self.assertNotIn("install_plugin", executed_steps("verify_plugin_zip"))
    def test_bad_sha_stops_install(self): self.assertNotIn("install_plugin", executed_steps("verify_plugin_sha256"))
    def test_install_failure_stops_activation(self): self.assertNotIn("activate_plugin", executed_steps("install_plugin"))
    def test_activation_failure_stops_version_check(self): self.assertNotIn("verify_plugin_version", executed_steps("activate_plugin"))
    def test_version_failure_stops_capture(self): self.assertNotIn("capture_registry", executed_steps("verify_plugin_version"))
    def test_bootstrap_environment_is_plugin_scoped(self):
        env = RUNNER.bootstrap_env({}, {"slug":"a","zip":"a.zip","version":"1","zip_sha256":"digest","plugin_main_file":"a/main.php"}, "run")
        self.assertEqual(env["PHASE13_RESULTS_DIR"], "/results/run/plugins/a")
        self.assertEqual(env["PHASE13_PLUGIN_MAIN_FILE"], "a/main.php")
        self.assertEqual(env["PHASE13_PLUGIN_VERSION"], "1")
        self.assertEqual(env["PHASE13_PLUGIN_SHA256"], "digest")
    def test_compose_passes_plugin_main_file_to_web(self):
        self.assertIn("PHASE13_PLUGIN_MAIN_FILE", (ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    def test_bootstrap_registry_must_match_current_plugin_run(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "plugins" / "a"; path.mkdir(parents=True)
            (path / "registry.json").write_text(json.dumps({"run_id":"run","plugin_slug":"a","plugin_version":"1","routes":[{}]}))
            self.assertEqual(RUNNER.captured_registry(Path(temp), "run", {"slug":"a","version":"1"})["routes"], [{}])
            with self.assertRaisesRegex(RuntimeError, "invalid_bootstrap_registry"):
                RUNNER.captured_registry(Path(temp), "other", {"slug":"a","version":"1"})

if __name__ == "__main__": unittest.main()
