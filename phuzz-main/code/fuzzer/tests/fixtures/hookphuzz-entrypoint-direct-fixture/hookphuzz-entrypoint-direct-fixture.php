<?php
/**
 * Plugin Name: HookPhuzz Entrypoint Direct Fixture
 * Description: Direct GET/POST entrypoint fixture for HookPhuzz generated pipeline tests.
 * Version: 1.0.0
 */

function hookphuzz_entrypoint_direct_ajax(): void
{
    $value = $_POST['direct_post_value'] ?? null;
    wp_send_json_success(['hookphuzz_entrypoint_marker' => 'ajax', 'value_seen' => $value !== null]);
}

function hookphuzz_entrypoint_direct_admin_post(): void
{
    $value = $_GET['direct_get_value'] ?? null;
    wp_send_json_success(['hookphuzz_entrypoint_marker' => 'admin_post', 'value_seen' => $value !== null]);
}

add_action('wp_ajax_hookphuzz_entrypoint_direct_ajax', 'hookphuzz_entrypoint_direct_ajax');
add_action('admin_post_hookphuzz_entrypoint_direct_admin', 'hookphuzz_entrypoint_direct_admin_post');
