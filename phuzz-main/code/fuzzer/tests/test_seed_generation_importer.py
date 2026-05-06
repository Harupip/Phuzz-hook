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


if __name__ == "__main__":
    unittest.main()
