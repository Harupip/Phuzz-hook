<?php
/**
 * Plugin Name: HookPhuzz REST Probe Only Fixture
 * Description: Minimal REST get_param fixture for live Zend convergence proof.
 * Version: 1.0.0
 */

function hookphuzz_rest_probe_only_fixture(WP_REST_Request $request)
{
    $value = $request->get_param('search');

    return rest_ensure_response([
        'hookphuzz_rest_probe_only_fixture' => true,
        'value' => $value,
    ]);
}

add_action('rest_api_init', static function (): void {
    register_rest_route('hookphuzz/v1', '/probe', [
        'methods' => 'GET',
        'callback' => 'hookphuzz_rest_probe_only_fixture',
        'permission_callback' => '__return_true',
    ]);
});
