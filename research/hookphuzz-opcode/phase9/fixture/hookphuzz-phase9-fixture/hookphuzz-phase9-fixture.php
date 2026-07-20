<?php
/** Plugin Name: HookPhuzz Phase 9 Fixture
 * Version: 1.0.0
 */
declare(strict_types=1);

$phase9BootstrapNoise = $_GET['phase9_bootstrap_noise'] ?? null;

function hookphuzz_phase9_helper_2(): ?string { return $_POST['helper_level_2']['value'] ?? null; }
function hookphuzz_phase9_helper_1(): array { return [$_REQUEST['helper_level_1'] ?? null, hookphuzz_phase9_helper_2()]; }
function hookphuzz_phase9_function_probe(): void {
    $literalGet = $_GET['literal_get'] ?? null;
    $literalPost = $_POST['literal_post'] ?? null;
    $sharedGet = $_GET['shared_name'] ?? null;
    $sharedPost = $_POST['shared_name'] ?? null;
    $runtimeKey = $_POST['runtime_selector'] ?? 'runtime_default';
    $runtimeValue = $_POST['runtime_key'] ?? $_POST[$runtimeKey] ?? null;
    $profileEmail = $_REQUEST['profile']['email'] ?? null;
    $fixtureCookie = $_COOKIE['fixture_cookie'] ?? null;
    $issetKey = isset($_GET['isset_key']);
    $emptyKey = empty($_POST['empty_key']);
    $optionalKey = $_POST['optional_key'] ?? null;
    [$helper1, $helper2] = hookphuzz_phase9_helper_1();
    $phase9Markers = [
        'GET:literal_get'=>hookphuzz_phase9_marker($literalGet), 'POST:literal_post'=>hookphuzz_phase9_marker($literalPost),
        'GET:shared_name'=>hookphuzz_phase9_marker($sharedGet), 'POST:shared_name'=>hookphuzz_phase9_marker($sharedPost),
        'POST:runtime_selector'=>hookphuzz_phase9_marker($_POST['runtime_selector'] ?? null), 'POST:runtime_key'=>hookphuzz_phase9_marker($_POST['runtime_key'] ?? null),
        'REQUEST:profile[email]'=>hookphuzz_phase9_marker($profileEmail), 'COOKIE:fixture_cookie'=>hookphuzz_phase9_marker($fixtureCookie),
        'GET:isset_key'=>hookphuzz_phase9_marker($_GET['isset_key'] ?? null), 'POST:empty_key'=>hookphuzz_phase9_marker($_POST['empty_key'] ?? null),
        'POST:optional_key'=>hookphuzz_phase9_marker($optionalKey), 'REQUEST:helper_level_1'=>hookphuzz_phase9_marker($helper1),
        'POST:helper_level_2[value]'=>hookphuzz_phase9_marker($helper2),
    ];
    wp_send_json_success(compact('literalGet','literalPost','sharedGet','sharedPost','runtimeKey','runtimeValue','profileEmail','fixtureCookie','issetKey','emptyKey','optionalKey','helper1','helper2','phase9Markers'));
}
final class HookPhuzz_Phase9_Handler { public function probe(): void { $v=$_POST['method_direct'] ?? null; wp_send_json_success(['method_direct'=>$v,'phase9Markers'=>['POST:method_direct'=>hookphuzz_phase9_marker($v)]]); } }
final class HookPhuzz_Phase9_Handler_A { public function probe(): void { $v=$_POST['class_a'] ?? null; wp_send_json_success(['class_a'=>$v,'phase9Markers'=>['POST:class_a'=>hookphuzz_phase9_marker($v)]]); } }
final class HookPhuzz_Phase9_Handler_B { public function probe(): void { $v=$_POST['class_b'] ?? null; wp_send_json_success(['class_b'=>$v,'phase9Markers'=>['POST:class_b'=>hookphuzz_phase9_marker($v)]]); } }
function hookphuzz_phase9_authenticated(): void { $v=$_POST['auth_value'] ?? null; wp_send_json_success(['authenticated'=>is_user_logged_in(),'auth_value'=>$v,'phase9Markers'=>['POST:auth_value'=>hookphuzz_phase9_marker($v)]]); }
function hookphuzz_phase9_internal_hook(): void { $_POST['internal_only']; }
function hookphuzz_phase9_marker(mixed $value): ?string { return is_string($value) && str_starts_with($value, 'PHASE9_') ? $value : null; }
function hookphuzz_phase9_source_reply(string $source, mixed $value): void { wp_send_json_success(['callback'=>'hookphuzz_phase9_'.$source.'_probe','runtime_source'=>strtoupper($source),'path'=>['phase9_key'],'marker_observed'=>hookphuzz_phase9_marker($value)]); }
function hookphuzz_phase9_get_probe(): void { hookphuzz_phase9_source_reply('get', $_GET['phase9_key'] ?? null); }
function hookphuzz_phase9_post_probe(): void { hookphuzz_phase9_source_reply('post', $_POST['phase9_key'] ?? null); }
function hookphuzz_phase9_cookie_probe(): void { hookphuzz_phase9_source_reply('cookie', $_COOKIE['phase9_key'] ?? null); }
function hookphuzz_phase9_request_probe(): void { hookphuzz_phase9_source_reply('request', $_REQUEST['phase9_key'] ?? null); }
function hookphuzz_phase9_duplicate_helper(): mixed { return $_POST['duplicate_key'] ?? null; }
function hookphuzz_phase9_duplicate_probe(): void { $first=$_POST['duplicate_key'] ?? null; $second=hookphuzz_phase9_duplicate_helper(); $third=$_POST['duplicate_key'] ?? null; wp_send_json_success(['phase9Markers'=>['POST:duplicate_key'=>hookphuzz_phase9_marker($first),'POST:duplicate_key:helper'=>hookphuzz_phase9_marker($second),'POST:duplicate_key:again'=>hookphuzz_phase9_marker($third)]]); }

add_action('wp_ajax_nopriv_hookphuzz_phase9_function', 'hookphuzz_phase9_function_probe');
add_action('wp_ajax_nopriv_hookphuzz_phase9_method', [new HookPhuzz_Phase9_Handler(), 'probe']);
add_action('wp_ajax_nopriv_hookphuzz_phase9_class_a', [new HookPhuzz_Phase9_Handler_A(), 'probe']);
add_action('wp_ajax_nopriv_hookphuzz_phase9_class_b', [new HookPhuzz_Phase9_Handler_B(), 'probe']);
add_action('wp_ajax_hookphuzz_phase9_authenticated', 'hookphuzz_phase9_authenticated');
add_action('hookphuzz_phase9_internal_hook', 'hookphuzz_phase9_internal_hook');
add_action('wp_ajax_nopriv_hookphuzz_phase9_get_probe', 'hookphuzz_phase9_get_probe');
add_action('wp_ajax_nopriv_hookphuzz_phase9_post_probe', 'hookphuzz_phase9_post_probe');
add_action('wp_ajax_nopriv_hookphuzz_phase9_cookie_probe', 'hookphuzz_phase9_cookie_probe');
add_action('wp_ajax_nopriv_hookphuzz_phase9_request_probe', 'hookphuzz_phase9_request_probe');
add_action('wp_ajax_nopriv_hookphuzz_phase9_duplicate_probe', 'hookphuzz_phase9_duplicate_probe');
