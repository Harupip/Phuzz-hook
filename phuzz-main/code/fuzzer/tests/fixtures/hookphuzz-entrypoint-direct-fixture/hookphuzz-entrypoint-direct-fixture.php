<?php
/**
 * Plugin Name: HookPhuzz Entrypoint Direct Fixture
 * Description: Direct POST Zend convergence fixture.
 * Version: 1.0.0
 */

function hookphuzz_stage1_direct_ajax(): void
{
    $name = $_POST['name'];

    if ($name) {
        $age = $_POST['age'];
        wp_send_json_success([
            'hookphuzz_stage1_marker' => 'ajax',
            'branch' => 'name',
            'age_seen' => $age !== '',
        ]);
    }

    wp_send_json_success([
        'hookphuzz_stage1_marker' => 'ajax',
        'branch' => 'bootstrap',
    ]);
}

add_action('wp_ajax_hookphuzz_stage1_direct', 'hookphuzz_stage1_direct_ajax');
