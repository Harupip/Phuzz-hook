<?php

function fixture_get_only() {
    return $_GET['id'] ?? null;
}

function fixture_post_only() {
    return $_POST['id'] ?? null;
}

function fixture_request_only() {
    return $_REQUEST['id'] ?? null;
}

function fixture_get_and_post() {
    return [$_GET['a'] ?? null, $_POST['b'] ?? null];
}

function fixture_cookie_only() {
    return $_COOKIE['session'] ?? null;
}

function fixture_rest() {
    return null;
}

add_action('wp_ajax_fixture_get', 'fixture_get_only');
add_action('wp_ajax_nopriv_fixture_post', 'fixture_post_only');
add_action('admin_post_fixture_request', 'fixture_request_only');
add_action('admin_post_nopriv_fixture_mixed', 'fixture_get_and_post');
add_action('wp_ajax_fixture_cookie', 'fixture_cookie_only');

register_rest_route('fixture/v1', '/get', ['methods' => 'GET', 'callback' => 'fixture_rest']);
register_rest_route('fixture/v1', '/post', ['methods' => 'POST', 'callback' => 'fixture_rest']);
register_rest_route('fixture/v1', '/put', ['methods' => 'PUT', 'callback' => 'fixture_rest']);
register_rest_route('fixture/v1', '/patch', ['methods' => 'PATCH', 'callback' => 'fixture_rest']);
register_rest_route('fixture/v1', '/delete', ['methods' => 'DELETE', 'callback' => 'fixture_rest']);
register_rest_route('fixture/v1', '/options', ['methods' => 'OPTIONS', 'callback' => 'fixture_rest']);
register_rest_route('fixture/v1', '/multi', ['methods' => 'GET,POST', 'callback' => 'fixture_rest']);
