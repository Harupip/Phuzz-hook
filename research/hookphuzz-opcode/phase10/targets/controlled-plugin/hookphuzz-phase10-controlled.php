<?php
/**
 * Plugin Name: HookPhuzz Phase 10 Controlled
 * Version: 1.0.0
 */

function hookphuzz_phase10_helper_read(string $key): string {
    return isset($_POST[$key]) ? (string) $_POST[$key] : '';
}

function hookphuzz_phase10_controlled(): void {
    $runtime_key = isset($_POST['runtime_selector']) ? (string) $_POST['runtime_selector'] : 'runtime_value';
    $markers = [
        'get' => $_GET['direct_get'] ?? '',
        'post' => $_POST['direct_post'] ?? '',
        'cookie' => $_COOKIE['direct_cookie'] ?? '',
        'request' => $_REQUEST['request_value'] ?? '',
        'nested' => $_POST['profile']['email'] ?? '',
        'runtime' => $_POST[$runtime_key] ?? '',
        'helper' => hookphuzz_phase10_helper_read('helper_value'),
        'duplicate_direct' => $_POST['duplicate_value'] ?? '',
        'duplicate_helper' => hookphuzz_phase10_helper_read('duplicate_value'),
    ];
    wp_send_json_success(['phase10_markers' => $markers]);
}
add_action('wp_ajax_nopriv_hookphuzz_phase10_controlled', 'hookphuzz_phase10_controlled');
add_action('wp_ajax_hookphuzz_phase10_controlled', 'hookphuzz_phase10_controlled');
