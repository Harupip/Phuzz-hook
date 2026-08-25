<?php
/**
 * Plugin Name: HookPhuzz Admin Post Fixture
 * Description: Runtime-only authenticated admin-post fixture.
 * Version: 1.0.0
 */

function hookphuzz_admin_post_test(): void
{
    $probe = $_POST["probe"];
    echo $probe === 'fixture_value' ? 'hookphuzz_admin_post_fixture_ok' : 'hookphuzz_admin_post_fixture_bad';
    exit;
}

add_action('admin_post_hookphuzz_admin_post_test', 'hookphuzz_admin_post_test');
