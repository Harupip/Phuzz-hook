import json
from pathlib import Path
import unittest


CODE_DIR = Path(__file__).resolve().parents[1]
FIXTURE_DIR = CODE_DIR / "tests" / "fixtures" / "hookphuzz-online-discovery-fixture"
PLUGIN_SOURCE = FIXTURE_DIR / "hookphuzz-online-discovery-fixture.php"
BOOTSTRAP_CONFIG = (
    CODE_DIR / "configs" / "wordpress" / "hookphuzz-online-discovery-fixture.json"
)
CASE_CONFIG_DIR = CODE_DIR / "configs" / "wordpress" / "hookphuzz-online-discovery-fixture"


class OnlinePluginFixtureTests(unittest.TestCase):
    def test_fixture_exposes_rest_discovery_and_ajax_provenance(self) -> None:
        self.assertTrue(PLUGIN_SOURCE.is_file(), PLUGIN_SOURCE)
        source = PLUGIN_SOURCE.read_text(encoding="utf-8")

        for marker in (
            "WP_REST_Request",
            "get_param('search')",
            "get_param('new_param')",
            "register_rest_route('hookphuzz-online/v1', '/probe'",
            "wp_ajax_nopriv_hookphuzz_online_discovery",
            "$_GET['ajax_get']",
            "$_POST['ajax_post']",
            "$_REQUEST['ajax_request']",
            "$_COOKIE['ajax_cookie']",
        ):
            self.assertIn(marker, source)

    def test_fixture_covers_known_ajax_and_rest_request_cases(self) -> None:
        source = PLUGIN_SOURCE.read_text(encoding="utf-8")
        for marker in (
            "hookphuzz_online_discovery_url_probe",
            "$request->get_url_params()",
            "hookphuzz_online_discovery_get_probe",
            "$request->get_query_params()",
            "hookphuzz_online_discovery_form_probe",
            "$request->get_body_params()",
            "hookphuzz_online_discovery_json_probe",
            "$request->get_json_params()",
            "register_rest_route('hookphuzz-online/v1', '/cases/url/(?P<url_id>[a-z0-9-]+)'",
            "register_rest_route('hookphuzz-online/v1', '/cases/get'",
            "register_rest_route('hookphuzz-online/v1', '/cases/form'",
            "register_rest_route('hookphuzz-online/v1', '/cases/json'",
            "wp_ajax_nopriv_hookphuzz_online_discovery_secondary",
            "$_POST['ajax_secondary']",
        ):
            self.assertIn(marker, source)

        expected_configs = {
            "rest-url.json": ("GET", "/cases/url/seed-url", "rest_get"),
            "rest-get.json": ("GET", "/cases/get", "rest_get"),
            "rest-post.json": ("POST", "/cases/form", "rest_post"),
            "rest-json.json": ("POST", "/cases/json", "rest_json"),
            "ajax.json": ("POST", "/wp-admin/admin-ajax.php", "ajax_post"),
        }
        for name, (method, target_fragment, fuzz_name) in expected_configs.items():
            path = CASE_CONFIG_DIR / name
            self.assertTrue(path.is_file(), path)
            config = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn(target_fragment, config["target"])
            self.assertEqual(config["methods"], [method])
            sections = [config.get("query_params", {}), config.get("body_params", {})]
            self.assertTrue(any(fuzz_name in section.get("fuzz", []) for section in sections))

        json_config = json.loads((CASE_CONFIG_DIR / "rest-json.json").read_text(encoding="utf-8"))
        self.assertEqual(json_config["headers"]["data"], [{"name": "Content-Type", "value": "application/json"}])

    def test_bootstrap_keeps_new_parameter_out_of_v0_identity(self) -> None:
        self.assertTrue(BOOTSTRAP_CONFIG.is_file(), BOOTSTRAP_CONFIG)
        config = json.loads(BOOTSTRAP_CONFIG.read_text(encoding="utf-8"))
        self.assertEqual(config["methods"], ["GET"])
        self.assertIn("rest_route=/hookphuzz-online/v1/probe", config["target"])
        self.assertIn("new_param=seed", config["target"])
        self.assertEqual(config["query_params"]["fuzz"], ["^seed$"])
        self.assertEqual(
            [item["name"] for item in config["query_params"]["data"]],
            ["seed"],
        )


if __name__ == "__main__":
    unittest.main()
