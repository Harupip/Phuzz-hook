import os
import json
import importlib
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


class RequestAuthContextTests(unittest.TestCase):
    def test_php_override_selects_guest_without_admin_identity(self):
        php = shutil.which('php')
        self.assertIsNotNone(php, 'PHP CLI required for override test')
        path = Path(__file__).resolve().parents[2] / 'web/applications/wordpress/_overrides/99-wordpress.php'
        source = path.read_text(encoding='utf-8').split("if ( getenv( 'HOOKPHUZZ_STRICT_NONCE_PROOF' ) === '1' )", 1)[0]
        stub = '''
function get_current_screen() {}
class WP_User { public $ID; function __construct($id) { $this->ID = $id; } }
function get_user_by($field, $id) { return new WP_User($id); }
function uopz_set_return($name, $value, $execute = false) {
    $GLOBALS['returns'][$name] = $name === 'wp_get_current_user' ? $value()->ID : $value;
}
$GLOBALS['__uopz_request'] = [];
'''
        for context, user_id, logged_in in [('guest', 0, False), ('authenticated', 1, True)]:
            code = '<?php\n' + stub + "$_SERVER['HTTP_X_HOOKPHUZZ_AUTH_CONTEXT'] = " + json.dumps(context) + ';\n'
            code += source.removeprefix('<?php') + "\necho json_encode([$GLOBALS['returns'], $GLOBALS['__uopz_request']]);"
            result = subprocess.run([php], input=code, text=True, capture_output=True, timeout=10, check=True)
            returns, artifact = json.loads(result.stdout)
            self.assertEqual(returns['get_current_user_id'], user_id)
            self.assertEqual(returns['wp_get_current_user'], user_id)
            self.assertEqual(returns['is_user_logged_in'], logged_in)
            self.assertEqual(returns['current_user_can'], logged_in)
            self.assertEqual(artifact['auth_context'], context)
            if context == 'guest':
                self.assertNotIn('get_user_meta', returns)

    def test_guest_header_cannot_be_mutated_and_auth_cookies_are_removed(self):
        module_root = Path(__file__).resolve().parents[1]
        if str(module_root) not in sys.path:
            sys.path.insert(0, str(module_root))
        fuzzer_module = importlib.import_module('fuzzer.fuzzer')
        sender = object.__new__(fuzzer_module.Fuzzer)
        sender.config = {'metadata': {'hook_name': 'wp_ajax_nopriv_demo'}}
        empty = {'query_params': {}, 'body_params': {}, 'cookies': {}, 'headers': {}}
        candidate = SimpleNamespace(http_target='http://web/wp-admin/admin-ajax.php', http_method='POST',
            coverage_id='test', fixed_params=empty, fuzz_params={**empty,
                'headers': {'x-hookphuzz-auth-context': 'authenticated', 'Cookie': 'wordpress_logged_in_x=secret'},
                'cookies': {'wordpress_logged_in_x': 'secret', 'wordpress_x': 'secret', 'preference': 'ok'}})
        req = sender.prepare_request(candidate)
        self.assertEqual(req.headers['X-HookPhuzz-Auth-Context'], 'guest')
        self.assertNotIn('secret', req.headers.get('Cookie', ''))
        sender.config = {'metadata': {'hook_name': 'wp_ajax_demo'}}
        self.assertEqual(sender.prepare_request(candidate).headers['X-HookPhuzz-Auth-Context'], 'authenticated')


if __name__ == '__main__':
    unittest.main()
