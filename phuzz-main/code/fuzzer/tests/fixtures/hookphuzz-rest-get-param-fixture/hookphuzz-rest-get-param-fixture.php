<?php
/**
 * Plugin Name: HookPhuzz REST Get Param Fixture
 * Description: Minimal REST runtime get_param discovery fixture.
 * Version: 1.0.0
 */

function hookphuzz_rest_get_param_fixture(WP_REST_Request $request)
{
    $search = $request->get_param('search');

    return rest_ensure_response([
        'hookphuzz_rest_get_param_fixture' => true,
        'search_seen' => $search !== null,
    ]);
}

add_action('rest_api_init', static function (): void {
    register_rest_route('hookphuzz-rest-get-param/v1', '/search', [
        'methods' => 'GET',
        'callback' => 'hookphuzz_rest_get_param_fixture',
        'permission_callback' => '__return_true',
    ]);
});
