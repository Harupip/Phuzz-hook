import json
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.importer import HookSeedImporter


def build_callback(
    callback_id: str,
    hook_name: str,
    *,
    auth_mode: str,
) -> dict:
    action_name = hook_name.removeprefix("wp_ajax_nopriv_").removeprefix("wp_ajax_")
    return {
        "callback_id": callback_id,
        "hook_name": hook_name,
        "callback_name": f"{hook_name}_handler",
        "status": "uncovered",
        "is_active": True,
        "direct_http_supported": True,
        "generation_status": "supported_http_seed",
        "seed_priority": "highest",
        "target_family": "wp_ajax" if auth_mode == "authenticated" else "wp_ajax_nopriv",
        "source_file": "/var/www/html/wp-content/plugins/shop-demo/shop-demo.php",
        "source_line": 200,
        "accepted_args": 1,
        "seed": {
            "method": "POST",
            "path": "/wp-admin/admin-ajax.php",
            "content_type": "application/x-www-form-urlencoded",
            "body": {"action": action_name},
            "auth_mode": auth_mode,
        },
    }


class HookSeedImporterReplayableTests(unittest.TestCase):
    def test_importer_splits_replayable_callbacks_by_auth_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            handoff_dir = root / "handoff"
            handoff_dir.mkdir()
            (handoff_dir / "hook_gap_report.json").write_text(
                json.dumps(
                    {
                        "summary": {"direct_http_seed_candidates": 2},
                        "callbacks": [
                            build_callback("cb-auth", "wp_ajax_shop_demo_refresh_panel", auth_mode="authenticated"),
                            build_callback(
                                "cb-public",
                                "wp_ajax_nopriv_shop_demo_public_ping",
                                auth_mode="unauth-capable",
                            ),
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (handoff_dir / "suggested_seeds.json").write_text(
                json.dumps({"suggested_seeds": []}),
                encoding="utf-8",
            )

            importer = HookSeedImporter(
                handoff_doc=handoff_dir / "SEED_HANDOFF_FOR_AGENTS.md",
                hook_gap_report=handoff_dir / "hook_gap_report.json",
                suggested_seeds=handoff_dir / "suggested_seeds.json",
            )
            result = importer.import_from_handoff()

            self.assertEqual(len(result.authenticated_queue), 1)
            self.assertEqual(len(result.unauthenticated_queue), 1)
            self.assertEqual(result.authenticated_queue[0].auth_mode, "authenticated")
            self.assertEqual(result.unauthenticated_queue[0].auth_mode, "unauth-capable")
            self.assertEqual(result.authenticated_queue[0].path, "/wp-admin/admin-ajax.php")
            self.assertEqual(result.unauthenticated_queue[0].body["action"], "shop_demo_public_ping")

    def test_importer_skips_non_replayable_callbacks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            handoff_dir = root / "handoff"
            handoff_dir.mkdir()
            skipped_callback = build_callback(
                "cb-inactive",
                "wp_ajax_shop_demo_refresh_panel",
                auth_mode="authenticated",
            )
            skipped_callback["status"] = "covered"
            skipped_callback["is_active"] = False
            (handoff_dir / "hook_gap_report.json").write_text(
                json.dumps({"summary": {"direct_http_seed_candidates": 1}, "callbacks": [skipped_callback]}),
                encoding="utf-8",
            )
            (handoff_dir / "suggested_seeds.json").write_text(
                json.dumps({"suggested_seeds": []}),
                encoding="utf-8",
            )

            importer = HookSeedImporter(
                handoff_doc=handoff_dir / "SEED_HANDOFF_FOR_AGENTS.md",
                hook_gap_report=handoff_dir / "hook_gap_report.json",
                suggested_seeds=handoff_dir / "suggested_seeds.json",
            )
            result = importer.import_from_handoff()

            self.assertEqual(result.authenticated_queue, [])
            self.assertEqual(result.unauthenticated_queue, [])

    def test_importer_rejects_unknown_auth_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            handoff_dir = root / "handoff"
            handoff_dir.mkdir()
            unknown_auth_callback = build_callback(
                "cb-weird-auth",
                "wp_ajax_shop_demo_refresh_panel",
                auth_mode="cookie-bound",
            )
            (handoff_dir / "hook_gap_report.json").write_text(
                json.dumps({"summary": {"direct_http_seed_candidates": 1}, "callbacks": [unknown_auth_callback]}),
                encoding="utf-8",
            )
            (handoff_dir / "suggested_seeds.json").write_text(
                json.dumps({"suggested_seeds": []}),
                encoding="utf-8",
            )

            importer = HookSeedImporter(
                handoff_doc=handoff_dir / "SEED_HANDOFF_FOR_AGENTS.md",
                hook_gap_report=handoff_dir / "hook_gap_report.json",
                suggested_seeds=handoff_dir / "suggested_seeds.json",
            )
            result = importer.import_from_handoff()

            self.assertEqual(result.authenticated_queue, [])
            self.assertEqual(result.unauthenticated_queue, [])

    def test_importer_rejects_malformed_seed_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            handoff_dir = root / "handoff"
            handoff_dir.mkdir()
            malformed_seed_callback = build_callback(
                "cb-bad-seed",
                "wp_ajax_nopriv_shop_demo_public_ping",
                auth_mode="unauth-capable",
            )
            malformed_seed_callback["seed"] = {
                "method": "POST",
                "path": "/wp-admin/admin-ajax.php",
                "content_type": "application/x-www-form-urlencoded",
                "body": ["not", "a", "mapping"],
                "auth_mode": "unauth-capable",
            }
            (handoff_dir / "hook_gap_report.json").write_text(
                json.dumps({"summary": {"direct_http_seed_candidates": 1}, "callbacks": [malformed_seed_callback]}),
                encoding="utf-8",
            )
            (handoff_dir / "suggested_seeds.json").write_text(
                json.dumps({"suggested_seeds": []}),
                encoding="utf-8",
            )

            importer = HookSeedImporter(
                handoff_doc=handoff_dir / "SEED_HANDOFF_FOR_AGENTS.md",
                hook_gap_report=handoff_dir / "hook_gap_report.json",
                suggested_seeds=handoff_dir / "suggested_seeds.json",
            )
            result = importer.import_from_handoff()

            self.assertEqual(result.authenticated_queue, [])
            self.assertEqual(result.unauthenticated_queue, [])

    def test_importer_preserves_optional_request_parts_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            handoff_dir = root / "handoff"
            handoff_dir.mkdir()
            callback = build_callback(
                "cb-rich-request",
                "wp_ajax_nopriv_shop_demo_public_ping",
                auth_mode="unauth-capable",
            )
            callback["seed"]["query_params"] = {"page": "1"}
            callback["seed"]["headers"] = {"X-Debug-Seed": "yes"}
            callback["seed"]["cookies"] = {"wordpress_test_cookie": "WP Cookie check"}
            (handoff_dir / "hook_gap_report.json").write_text(
                json.dumps({"summary": {"direct_http_seed_candidates": 1}, "callbacks": [callback]}),
                encoding="utf-8",
            )
            (handoff_dir / "suggested_seeds.json").write_text(
                json.dumps({"suggested_seeds": []}),
                encoding="utf-8",
            )

            importer = HookSeedImporter(
                handoff_doc=handoff_dir / "SEED_HANDOFF_FOR_AGENTS.md",
                hook_gap_report=handoff_dir / "hook_gap_report.json",
                suggested_seeds=handoff_dir / "suggested_seeds.json",
            )
            result = importer.import_from_handoff()

            self.assertEqual(result.unauthenticated_queue[0].query_params, {"page": "1"})
            self.assertEqual(result.unauthenticated_queue[0].headers, {"X-Debug-Seed": "yes"})
            self.assertEqual(
                result.unauthenticated_queue[0].cookies,
                {"wordpress_test_cookie": "WP Cookie check"},
            )


class HookSeedImporterBacklogTests(unittest.TestCase):
    def test_importer_preserves_metadata_and_backlogs_manual_callbacks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            handoff_dir = root / "handoff"
            handoff_dir.mkdir()
            replayable = build_callback(
                "cb-auth",
                "admin_post_shop_demo_export_orders",
                auth_mode="authenticated",
            )
            replayable["target_family"] = "admin_post"
            replayable["priority"] = 10

            manual_only = {
                "callback_id": "cb-manual",
                "hook_name": "template_redirect",
                "callback_name": "shop_render_test_ui",
                "status": "uncovered",
                "is_active": True,
                "direct_http_supported": False,
                "generation_status": "manual_analysis_required",
                "seed_priority": "low",
                "target_family": "internal_or_manual",
                "source_file": "/var/www/html/wp-content/plugins/shop-demo/shop-demo.php",
                "source_line": 321,
                "accepted_args": 1,
                "seed": None,
            }
            (handoff_dir / "hook_gap_report.json").write_text(
                json.dumps(
                    {
                        "summary": {"direct_http_seed_candidates": 1},
                        "callbacks": [replayable, manual_only],
                    }
                ),
                encoding="utf-8",
            )
            (handoff_dir / "suggested_seeds.json").write_text(
                json.dumps({"suggested_seeds": []}),
                encoding="utf-8",
            )

            importer = HookSeedImporter(
                handoff_doc=handoff_dir / "SEED_HANDOFF_FOR_AGENTS.md",
                hook_gap_report=handoff_dir / "hook_gap_report.json",
                suggested_seeds=handoff_dir / "suggested_seeds.json",
            )
            result = importer.import_from_handoff()

            self.assertEqual(result.authenticated_queue[0].metadata["source_file"], replayable["source_file"])
            self.assertEqual(result.authenticated_queue[0].metadata["source_line"], 200)
            self.assertEqual(result.authenticated_queue[0].metadata["priority"], 10)
            self.assertEqual(result.authenticated_queue[0].metadata["accepted_args"], 1)
            self.assertEqual(result.authenticated_queue[0].metadata["target_family"], "admin_post")
            self.assertEqual(len(result.manual_analysis_queue), 1)
            self.assertEqual(result.manual_analysis_queue[0]["callback_id"], "cb-manual")
            self.assertEqual(result.manual_analysis_queue[0]["hook_name"], "template_redirect")
            self.assertNotIn("request_id", result.manual_analysis_queue[0])


class HookSeedImporterStaleArtifactTests(unittest.TestCase):
    def test_importer_warns_when_source_code_has_seed_hooks_but_report_has_zero_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            handoff_dir = root / "handoff"
            handoff_dir.mkdir()
            source_dir = root / "source"
            source_dir.mkdir()
            (handoff_dir / "hook_gap_report.json").write_text(
                json.dumps({"summary": {"direct_http_seed_candidates": 0}, "callbacks": []}),
                encoding="utf-8",
            )
            (handoff_dir / "suggested_seeds.json").write_text(
                json.dumps({"suggested_seeds": []}),
                encoding="utf-8",
            )
            (source_dir / "pipeline.py").write_text(
                "wp_ajax_* -> POST /wp-admin/admin-ajax.php\n"
                "admin_post_* -> POST /wp-admin/admin-post.php\n",
                encoding="utf-8",
            )
            (source_dir / "shop-demo.php").write_text(
                "add_action('wp_ajax_shop_demo_refresh_panel', 'shop_seed_ajax_refresh_panel');\n"
                "add_action('admin_post_shop_demo_export_orders', 'shop_seed_admin_post_export_orders');\n",
                encoding="utf-8",
            )

            importer = HookSeedImporter(
                handoff_doc=handoff_dir / "SEED_HANDOFF_FOR_AGENTS.md",
                hook_gap_report=handoff_dir / "hook_gap_report.json",
                suggested_seeds=handoff_dir / "suggested_seeds.json",
                source_pipeline=source_dir / "pipeline.py",
                source_plugin=source_dir / "shop-demo.php",
            )
            result = importer.import_from_handoff()

            self.assertEqual(result.authenticated_queue, [])
            self.assertEqual(result.unauthenticated_queue, [])


class HookSeedImporterOutputTests(unittest.TestCase):
    def test_importer_writes_expected_output_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            handoff_dir = root / "handoff"
            handoff_dir.mkdir()
            output_dir = root / "seed-output"
            (handoff_dir / "hook_gap_report.json").write_text(
                json.dumps(
                    {
                        "summary": {"direct_http_seed_candidates": 1},
                        "callbacks": [
                            build_callback(
                                "cb-public",
                                "wp_ajax_nopriv_shop_demo_public_ping",
                                auth_mode="unauth-capable",
                            )
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (handoff_dir / "suggested_seeds.json").write_text(
                json.dumps({"suggested_seeds": []}),
                encoding="utf-8",
            )

            importer = HookSeedImporter(
                handoff_doc=handoff_dir / "SEED_HANDOFF_FOR_AGENTS.md",
                hook_gap_report=handoff_dir / "hook_gap_report.json",
                suggested_seeds=handoff_dir / "suggested_seeds.json",
            )
            result = importer.write_artifacts(output_dir)

            self.assertTrue((output_dir / "imported_unauth_seeds.json").exists())
            self.assertTrue((output_dir / "imported_auth_seeds.json").exists())
            self.assertTrue((output_dir / "manual_analysis_queue.json").exists())
            self.assertTrue((output_dir / "import_summary.json").exists())

            unauth_payload = json.loads((output_dir / "imported_unauth_seeds.json").read_text(encoding="utf-8"))
            summary_payload = json.loads((output_dir / "import_summary.json").read_text(encoding="utf-8"))

            self.assertEqual(result.authenticated_queue, [])
            self.assertEqual(len(result.unauthenticated_queue), 1)
            self.assertEqual(unauth_payload[0]["path"], "/wp-admin/admin-ajax.php")
            self.assertEqual(summary_payload["authenticated_count"], 0)
            self.assertEqual(summary_payload["unauthenticated_count"], 1)
            self.assertEqual(summary_payload["manual_analysis_count"], 0)

    def test_importer_fails_when_primary_hook_gap_report_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            handoff_dir = root / "handoff"
            handoff_dir.mkdir()
            importer = HookSeedImporter(
                handoff_doc=handoff_dir / "SEED_HANDOFF_FOR_AGENTS.md",
                hook_gap_report=handoff_dir / "missing-hook-gap-report.json",
                suggested_seeds=handoff_dir / "suggested_seeds.json",
            )

            with self.assertRaises(FileNotFoundError):
                importer.import_from_handoff()


if __name__ == "__main__":
    unittest.main()
