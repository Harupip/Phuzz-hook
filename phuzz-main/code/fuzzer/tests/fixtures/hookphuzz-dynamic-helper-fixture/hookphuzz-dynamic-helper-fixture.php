<?php
/**
 * Plugin Name: HookPhuzz Dynamic Helper Fixture
 * Description: Deterministic helper-reader fixture for HookPhuzz tests.
 * Version: 1.0.0
 */

class HookPhuzzFixtureRequest
{
    public static function post($key)
    {
        return $_POST[$key] ?? null;
    }

    public static function get($key)
    {
        return $_GET[$key] ?? null;
    }

    public static function request($key)
    {
        return $_REQUEST[$key] ?? null;
    }
}

function hookphuzz_fixture_post_callback(): void
{
    $value = HookPhuzzFixtureRequest::post('fixture_post_value');
    wp_send_json_success(['hookphuzz_fixture_marker' => 'post', 'value_seen' => $value !== null]);
}

function hookphuzz_fixture_get_callback(): void
{
    $value = HookPhuzzFixtureRequest::get('fixture_get_value');
    wp_send_json_success(['hookphuzz_fixture_marker' => 'get', 'value_seen' => $value !== null]);
}

function hookphuzz_fixture_save_callback(): void
{
    $value = HookPhuzzFixtureRequest::request('fixture_request_value');
    wp_send_json_success(['hookphuzz_fixture_marker' => 'request', 'value_seen' => $value !== null]);
}

add_action('wp_ajax_hookphuzz_fixture_post', 'hookphuzz_fixture_post_callback');
add_action('wp_ajax_hookphuzz_fixture_get', 'hookphuzz_fixture_get_callback');
add_action('admin_post_hookphuzz_fixture_save', 'hookphuzz_fixture_save_callback');
