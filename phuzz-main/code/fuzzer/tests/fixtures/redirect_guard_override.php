<?php
// Run with real uopz and no auto_prepend_file; keep WordPress out of this unit check.
function get_current_screen() {}
class WP_User { public $ID; function __construct($id) { $this->ID = $id; } }
function get_user_by($field, $id) { return new WP_User($id); }
function get_user_meta($user_id, $key = '', $single = false) { return null; }
function current_user_can(...$args) { return false; }
function wp_verify_nonce($nonce, $action) { return false; }
function check_ajax_referer(...$args) { return false; }
function check_admin_referer(...$args) { return false; }
function wp_redirect($location, $status = 302) {
    header('Location: ' . $location, true, $status);
    return true;
}
function __uopz_current_parent_callback_metadata() { return $GLOBALS['callback_metadata']; }
$GLOBALS['callback_metadata'] = ['callback_id' => 'fixture'];
$GLOBALS['__uopz_request'] = [];
$_SERVER['HTTP_X_HOOKPHUZZ_AUTH_CONTEXT'] = $argv[2];
require $argv[1];
$expected = $argv[2] === 'authenticated';
$strict = getenv('HOOKPHUZZ_STRICT_NONCE_PROOF') === '1';
$expectedNonce = $strict ? false : 1;
if (current_user_can('manage_options') !== $expected || wp_verify_nonce('probe', 'action') !== $expectedNonce
    || check_ajax_referer('action') !== $expectedNonce || check_admin_referer('action') !== $expectedNonce) {
    throw new Exception('override behavior changed');
}
$location = '/destination?credential=fixture-secret';
if (wp_redirect($location, 303) !== true) {
    throw new Exception('redirect behavior changed');
}
header('Location: /direct-header', true, 302);
$GLOBALS['callback_metadata'] = null;
current_user_can('manage_options');
wp_redirect('/unattributed');
$expectedEvents = [[
    'kind' => 'guard', 'function' => 'current_user_can', 'mode' => 'override', 'passed' => $expected,
    'callback_id' => 'fixture',
]];
if (!$strict) {
    foreach (['wp_verify_nonce', 'check_ajax_referer', 'check_admin_referer'] as $function) {
        $expectedEvents[] = [
            'kind' => 'guard', 'function' => $function, 'mode' => 'override', 'passed' => true,
            'callback_id' => 'fixture',
        ];
    }
}
$expectedEvents[] = [
    'kind' => 'redirect', 'function' => 'wp_redirect', 'mode' => 'observed', 'status' => 303,
    'location_sha256' => hash('sha256', $location), 'callback_id' => 'fixture',
];
if (($GLOBALS['__uopz_request']['guard_redirect_events'] ?? []) !== $expectedEvents) {
    throw new Exception('missing or unexpected guard and redirect evidence');
}
echo "guard override check passed: " . $argv[2] . "\n";
