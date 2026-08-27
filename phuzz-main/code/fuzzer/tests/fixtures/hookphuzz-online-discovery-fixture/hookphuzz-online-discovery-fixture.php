<?php
/**
 * Plugin Name: HookPhuzz Online Discovery Fixture
 * Description: Minimal local REST and AJAX fixture for bounded online discovery.
 * Version: 1.0.0
 */

function hookphuzz_online_discovery_probe(WP_REST_Request $request)
{
    $search = $request->get_param('search');
    $new_param = $request->get_param('new_param');

    return rest_ensure_response([
        'fixture' => 'hookphuzz-online-discovery-fixture',
        'search' => (string) $search,
        'new_param' => (string) $new_param,
        'new_param_seen' => $new_param !== null && $new_param !== '',
    ]);
}

function hookphuzz_online_discovery_url_probe(WP_REST_Request $request)
{
    $url_params = $request->get_url_params();

    return rest_ensure_response([
        'case' => 'rest_url',
        'url_id' => (string) ($url_params['url_id'] ?? ''),
    ]);
}

function hookphuzz_online_discovery_get_probe(WP_REST_Request $request)
{
    $query_params = $request->get_query_params();

    return rest_ensure_response([
        'case' => 'rest_get',
        'rest_get' => (string) ($query_params['rest_get'] ?? ''),
    ]);
}

function hookphuzz_online_discovery_form_probe(WP_REST_Request $request)
{
    $body_params = $request->get_body_params();

    return rest_ensure_response([
        'case' => 'rest_post',
        'rest_post' => (string) ($body_params['rest_post'] ?? ''),
    ]);
}

function hookphuzz_online_discovery_json_probe(WP_REST_Request $request)
{
    $json_params = $request->get_json_params();

    return rest_ensure_response([
        'case' => 'rest_json',
        'rest_json' => (string) ($json_params['rest_json'] ?? ''),
    ]);
}

function hookphuzz_online_discovery_ajax(): void
{
    $values = [
        'get' => isset($_GET['ajax_get']) ? sanitize_text_field(wp_unslash($_GET['ajax_get'])) : '',
        'post' => isset($_POST['ajax_post']) ? sanitize_text_field(wp_unslash($_POST['ajax_post'])) : '',
        'request' => isset($_REQUEST['ajax_request']) ? sanitize_text_field(wp_unslash($_REQUEST['ajax_request'])) : '',
        'cookie' => isset($_COOKIE['ajax_cookie']) ? sanitize_text_field(wp_unslash($_COOKIE['ajax_cookie'])) : '',
    ];

    wp_send_json_success($values);
}

function hookphuzz_online_discovery_secondary_ajax(): void
{
    $secondary = isset($_POST['ajax_secondary'])
        ? sanitize_text_field(wp_unslash($_POST['ajax_secondary']))
        : '';

    wp_send_json_success([
        'case' => 'ajax_secondary',
        'ajax_secondary' => $secondary,
    ]);
}

add_action('rest_api_init', static function (): void {
    register_rest_route('hookphuzz-online/v1', '/probe', [
        'methods' => 'GET',
        'callback' => 'hookphuzz_online_discovery_probe',
        'permission_callback' => '__return_true',
    ]);
    register_rest_route('hookphuzz-online/v1', '/cases/url/(?P<url_id>[a-z0-9-]+)', [
        'methods' => 'GET',
        'callback' => 'hookphuzz_online_discovery_url_probe',
        'permission_callback' => '__return_true',
    ]);
    register_rest_route('hookphuzz-online/v1', '/cases/get', [
        'methods' => 'GET',
        'callback' => 'hookphuzz_online_discovery_get_probe',
        'permission_callback' => '__return_true',
    ]);
    register_rest_route('hookphuzz-online/v1', '/cases/form', [
        'methods' => 'POST',
        'callback' => 'hookphuzz_online_discovery_form_probe',
        'permission_callback' => '__return_true',
    ]);
    register_rest_route('hookphuzz-online/v1', '/cases/json', [
        'methods' => 'POST',
        'callback' => 'hookphuzz_online_discovery_json_probe',
        'permission_callback' => '__return_true',
    ]);
});

add_action('wp_ajax_nopriv_hookphuzz_online_discovery', 'hookphuzz_online_discovery_ajax');
add_action('wp_ajax_hookphuzz_online_discovery', 'hookphuzz_online_discovery_ajax');
add_action('wp_ajax_nopriv_hookphuzz_online_discovery_secondary', 'hookphuzz_online_discovery_secondary_ajax');
add_action('wp_ajax_hookphuzz_online_discovery_secondary', 'hookphuzz_online_discovery_secondary_ajax');
