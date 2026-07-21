<?php
/**
 * Plugin Name: HookPhuzz Phase 7 Fixture
 * Version: 1.0.0
 */

declare(strict_types=1);

$phase7BootstrapNoise = $_GET['phase7_bootstrap_noise'] ?? null;

function hookphuzz_phase7_helper_level_2(): string
{
    return $_POST['helper_level_2']['value'];
}

function hookphuzz_phase7_helper_level_1(): array
{
    $helperLevel1 = $_REQUEST['helper_level_1'];
    return [$helperLevel1, hookphuzz_phase7_helper_level_2()];
}

function hookphuzz_phase7_cap_reads(): void
{
    for ($index = 0; $index < 8192; $index++) {
        $_POST['cap_value'];
    }
}

function hookphuzz_phase7_probe(): void
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
    $directCallback = $_POST['direct_callback'];
    $mode = $_POST['phase7_mode'] ?? 'normal';
    if ($mode === 'cap') {
        hookphuzz_phase7_cap_reads();
        wp_send_json_success(['mode' => 'cap']);
    }
    if ($mode === 'early') {
        $earlyMarker = $_POST['early_marker'];
        wp_send_json_success(['mode' => 'early', 'early_marker' => $earlyMarker]);
    }
    try {
        [$helperLevel1, $helperLevel2] = hookphuzz_phase7_helper_level_1();
        if ($mode === 'throw') throw new RuntimeException($_POST['throw_marker']);
    } catch (RuntimeException $error) {
        $afterCatch = $_POST['after_catch'];
        wp_send_json_success(['mode' => 'throw', 'after_catch' => $afterCatch]);
    }
    wp_send_json_success([
        'mode' => 'normal', 'literal_get' => $literalGet, 'literal_post' => $literalPost,
        'runtime_key' => $runtimeKey, 'runtime_value' => $runtimeValue,
        'profile_email' => $profileEmail, 'fixture_cookie' => $fixtureCookie,
        'isset_key' => $issetKey, 'empty_key' => $emptyKey, 'optional_key' => $optionalKey,
        'direct_callback' => $directCallback, 'helper_level_1' => $helperLevel1,
        'helper_level_2' => $helperLevel2,
    ]);
}

final class HookPhuzz_Phase7_Handler
{
    public static function probe(): void
    {
        $methodDirect = $_POST['method_direct'];
        wp_send_json_success(['mode' => 'method', 'method_direct' => $methodDirect]);
    }
}

add_action('wp_ajax_nopriv_hookphuzz_phase7_probe', 'hookphuzz_phase7_probe');
add_action('wp_ajax_nopriv_hookphuzz_phase7_method_probe', [HookPhuzz_Phase7_Handler::class, 'probe']);
