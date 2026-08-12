<?php
/**
 * Plugin Name: HookPhuzz Entrypoint Direct Fixture
 * Description: Stage 1 direct GET/POST Zend discovery fixture.
 * Version: 1.0.0
 */

function hookphuzz_stage1_direct_ajax(): void
{
    $x = $_GET['x'] ?? null;
    $y = $_POST['y'] ?? null;
    wp_send_json_success(['hookphuzz_stage1_marker' => 'ajax', 'x_seen' => $x !== null, 'y_seen' => $y !== null]);
}

add_action('wp_ajax_hookphuzz_stage1_direct', 'hookphuzz_stage1_direct_ajax');
