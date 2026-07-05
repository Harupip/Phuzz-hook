from __future__ import annotations

import sys
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.entrypoints import direct_http_details, rest_http_template


class EntrypointRuleTests(unittest.TestCase):
    def test_longer_public_ajax_prefix_wins_before_authenticated_ajax_prefix(self) -> None:
        details = direct_http_details("wp_ajax_nopriv_demo_lookup")

        self.assertIsNotNone(details)
        self.assertEqual(details["entry_type"], "ajax_unauthenticated")
        self.assertFalse(details["auth_required"])
        self.assertEqual(details["http_template"]["body_params"], {"action": "demo_lookup"})

    def test_heartbeat_uses_exact_admin_ajax_action(self) -> None:
        details = direct_http_details("heartbeat_received")

        self.assertIsNotNone(details)
        self.assertEqual(details["entry_type"], "heartbeat_authenticated")
        self.assertEqual(details["http_template"]["path"], "/wp-admin/admin-ajax.php")
        self.assertEqual(details["http_template"]["body_params"], {"action": "heartbeat"})

    def test_admin_post_nopriv_maps_to_admin_post_with_fixed_action(self) -> None:
        details = direct_http_details('admin_post_nopriv_export_orders')

        self.assertIsNotNone(details)
        self.assertEqual(details['entry_type'], 'admin_post_unauthenticated')
        self.assertFalse(details['auth_required'])
        self.assertEqual(details['http_template']['method'], 'POST')
        self.assertEqual(details['http_template']['path'], '/wp-admin/admin-post.php')
        self.assertEqual(details['http_template']['body_params'], {'action': 'export_orders'})

    def test_login_form_maps_to_login_with_fixed_query_action(self) -> None:
        details = direct_http_details('login_form_resetpass')

        self.assertIsNotNone(details)
        self.assertEqual(details['entry_type'], 'login_form')
        self.assertFalse(details['auth_required'])
        self.assertEqual(details['http_template']['method'], 'POST')
        self.assertEqual(details['http_template']['path'], '/wp-login.php')
        self.assertEqual(details['http_template']['query_params'], {'action': 'resetpass'})

    def test_heartbeat_nopriv_marks_unauthenticated_auth_mode(self) -> None:
        details = direct_http_details('heartbeat_nopriv_received')

        self.assertIsNotNone(details)
        self.assertEqual(details['entry_type'], 'heartbeat_unauthenticated')
        self.assertFalse(details['auth_required'])
        self.assertEqual(details['http_template']['path'], '/wp-admin/admin-ajax.php')
        self.assertEqual(details['http_template']['body_params'], {'action': 'heartbeat'})

    def test_rest_template_uses_wp_json_path_without_action(self) -> None:
        template = rest_http_template(
            {
                "entrypoint_type": "rest_route",
                "namespace": "demo/v1",
                "route": "/items",
                "methods": ["GET", "POST"],
            }
        )

        self.assertEqual(template["method"], "GET")
        self.assertEqual(template["path"], "/wp-json/demo/v1/items")
        self.assertEqual(template["query_params"], {})
        self.assertEqual(template["body_params"], {})


if __name__ == "__main__":
    unittest.main()
