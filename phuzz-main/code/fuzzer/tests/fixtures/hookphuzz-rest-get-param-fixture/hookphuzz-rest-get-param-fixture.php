<?php
/**
 * Plugin Name: HookPhuzz REST Get Param Fixture
 * Description: Minimal REST runtime get_param discovery fixture.
 * Version: 1.0.0
 */

class Foo
{
    public $params = [
        'GET' => [
            'search' => 'hello',
        ],
    ];
}

function hookphuzz_rest_get_param_fixture(WP_REST_Request $request)
{
    $value = $request->get_param('search');
    $foo = new Foo();
    $foo_value = $foo->params['GET']['search'];
    $array = ['GET' => ['search' => 'hello']];
    $array_value = $array['GET']['search'];

    return rest_ensure_response([
        'hookphuzz_rest_get_param_fixture' => true,
        'value' => $value,
        'controls_seen' => $foo_value === 'hello' && $array_value === 'hello',
    ]);
}

add_action('rest_api_init', static function (): void {
    register_rest_route('hookphuzz/v1', '/probe', [
        'methods' => 'GET',
        'callback' => 'hookphuzz_rest_get_param_fixture',
        'permission_callback' => '__return_true',
    ]);
});
