<?php
/**
 * Plugin Name: HookPhuzz Phase 6 Fixture
 * Version: 1.0.0
 */

declare(strict_types=1);

function hookphuzz_phase6_probe(): void
{
    $literalGet = $_GET['literal_get'];
    $literalPost = $_POST['literal_post'];
    $runtimeKey = $_POST['runtime_selector'] ?? 'runtime_default';
    $runtimeValue = $_POST[$runtimeKey];
    $profileEmail = $_REQUEST['profile']['email'];
    $fixtureCookie = $_COOKIE['fixture_cookie'];
    $issetKey = isset($_GET['isset_key']);
    $emptyKey = empty($_POST['empty_key']);
    $optionalKey = $_REQUEST['optional_key'] ?? null;

    wp_send_json_success([
        'literal_get' => $literalGet,
        'literal_post' => $literalPost,
        'runtime_key' => $runtimeKey,
        'runtime_value' => $runtimeValue,
        'profile_email' => $profileEmail,
        'fixture_cookie' => $fixtureCookie,
        'isset_key' => $issetKey,
        'empty_key' => $emptyKey,
        'optional_key' => $optionalKey,
    ]);
}

add_action('wp_ajax_nopriv_hookphuzz_phase6_probe', 'hookphuzz_phase6_probe');
