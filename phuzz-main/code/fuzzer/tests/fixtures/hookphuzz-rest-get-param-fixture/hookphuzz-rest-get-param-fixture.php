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
            'filters' => [
                'name' => 'alice',
            ],
        ],
    ];
}

function normal_array()
{
    return [
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
    $normal_value = normal_array()['GET']['search'];

    return rest_ensure_response([
        'hookphuzz_rest_get_param_fixture' => true,
        'value' => $value,
        'controls_seen' => $foo_value === 'hello' && $array_value === 'hello' && $normal_value === 'hello',
    ]);
}

function hookphuzz_rest_query_params_fixture(WP_REST_Request $request)
{
    $value = $request->get_query_params()['search'];

    return rest_ensure_response([
        'hookphuzz_rest_query_params_fixture' => true,
        'value' => $value,
    ]);
}

function hookphuzz_rest_nested_get_param_fixture(WP_REST_Request $request)
{
    $value = $request->get_param('filters')['name'];

    return rest_ensure_response([
        'hookphuzz_rest_nested_get_param_fixture' => true,
        'value' => $value,
    ]);
}

add_action('rest_api_init', static function (): void {
    register_rest_route('hookphuzz/v1', '/probe', [
        'methods' => 'GET',
        'callback' => 'hookphuzz_rest_get_param_fixture',
        'permission_callback' => '__return_true',
    ]);
    register_rest_route('hookphuzz/v1', '/query-params', [
        'methods' => 'GET',
        'callback' => 'hookphuzz_rest_query_params_fixture',
        'permission_callback' => '__return_true',
    ]);
    register_rest_route('hookphuzz/v1', '/nested-param', [
        'methods' => 'GET',
        'callback' => 'hookphuzz_rest_nested_get_param_fixture',
        'permission_callback' => '__return_true',
    ]);
});
