<?php
/**
 * Plugin Name: HookPhuzz Phase 8 Fixture
 * Version: 1.0.0
 */
declare(strict_types=1);

$phase8BootstrapNoise = $_GET['phase8_bootstrap_noise'] ?? null;

function hookphuzz_phase8_helper_level_2(): string { return $_POST['helper_level_2']['value']; }
function hookphuzz_phase8_helper_level_1(): array { return [$_REQUEST['helper_level_1'], hookphuzz_phase8_helper_level_2()]; }
function hookphuzz_phase8_cap_reads(): void { for ($i = 0; $i < 8192; $i++) $_POST['cap_value']; }

function hookphuzz_phase8_function_probe(): void
{
    $literalGet = $_GET['literal_get'];
    $literalPost = $_POST['literal_post'];
    $runtimeKey = $_POST['runtime_selector'] ?? 'runtime_default';
    $runtimeValue = $_POST[$runtimeKey];
    $profileEmail = $_REQUEST['profile']['email'];
    $fixtureCookie = $_COOKIE['fixture_cookie'];
    $issetKey = isset($_GET['isset_key']);
    $emptyKey = empty($_POST['empty_key']);
    $optionalKey = $_POST['optional_key'] ?? null;
    $directCallback = $_POST['direct_callback'];
    $mode = $_POST['phase8_mode'] ?? 'normal';
    if ($mode === 'cap') { hookphuzz_phase8_cap_reads(); wp_send_json_success(['mode' => 'cap']); }
    if ($mode === 'early') { wp_send_json_success(['mode' => 'early', 'early_marker' => $_POST['early_marker']]); }
    try {
        [$helperLevel1, $helperLevel2] = hookphuzz_phase8_helper_level_1();
        if ($mode === 'throw') throw new RuntimeException($_POST['throw_marker']);
    } catch (RuntimeException $error) {
        wp_send_json_success(['mode' => 'throw', 'after_catch' => $_POST['after_catch']]);
    }
    wp_send_json_success(compact('literalGet', 'literalPost', 'runtimeKey', 'runtimeValue', 'profileEmail', 'fixtureCookie', 'issetKey', 'emptyKey', 'optionalKey', 'directCallback', 'helperLevel1', 'helperLevel2'));
}

final class HookPhuzz_Phase8_Handler { public function probe(): void { wp_send_json_success(['method_direct' => $_POST['method_direct']]); } }
final class HookPhuzz_Phase8_Handler_A { public function probe(): void { wp_send_json_success(['class_a' => $_POST['class_a']]); } }
final class HookPhuzz_Phase8_Handler_B { public function probe(): void { wp_send_json_success(['class_b' => $_POST['class_b']]); } }
function hookphuzz_phase8_unselected(): void { wp_send_json_success(['unselected' => $_POST['unselected']]); }
function hookphuzz_phase8_filter_only($value) { return $value; }

add_action('wp_ajax_nopriv_hookphuzz_phase8_function', 'hookphuzz_phase8_function_probe');
add_filter('hookphuzz_phase8_filter_probe', 'hookphuzz_phase8_filter_only', 10, 1);
add_action('wp_ajax_nopriv_hookphuzz_phase8_method', [new HookPhuzz_Phase8_Handler(), 'probe']);
add_action('wp_ajax_nopriv_hookphuzz_phase8_class_a', [new HookPhuzz_Phase8_Handler_A(), 'probe']);
add_action('wp_ajax_nopriv_hookphuzz_phase8_class_b', [new HookPhuzz_Phase8_Handler_B(), 'probe']);
add_action('wp_ajax_nopriv_hookphuzz_phase8_unselected', 'hookphuzz_phase8_unselected');
add_action('hookphuzz_phase8_closure', static function (): void {});
