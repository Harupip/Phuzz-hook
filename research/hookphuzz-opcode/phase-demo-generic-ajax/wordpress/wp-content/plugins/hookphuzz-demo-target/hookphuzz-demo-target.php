<?php
/**
 * Plugin Name: HookPhuzz Generic AJAX Demo Target
 * Version: 1.0.0
 */

add_action(
    'wp_ajax_nopriv_hookphuzz_demo',
    'hookphuzz_demo_callback'
);

function hookphuzz_demo_callback(): void
{
    if ($_GET['test']) {
        $value = $_GET['mo'];
    }

    echo json_encode(['value' => $value ?? null]);

    wp_die();
}

add_action('wp_ajax_nopriv_hookphuzz_demo_nested', 'hookphuzz_demo_nested_callback');
function hookphuzz_demo_nested_callback(): void
{
    if (!empty($_GET['outer'])) {
        if (!empty($_POST['middle'])) {
            $value = $_POST['deep'] ?? null;
        } else {
            $value = $_GET['fallback'] ?? null;
        }
    }

    echo json_encode(['value' => $value ?? null]);
    wp_die();
}

add_action('wp_ajax_save_profile', 'hookphuzz_save_profile');
function hookphuzz_save_profile(): void
{
    echo $_POST['name'] ?? '';
    wp_die();
}

/*
 * Ví dụ khác: chỉ bật MỘT block thay cho hook/callback mặc định ở trên.
 * Nếu bật nhiều hook cùng lúc, đặt HOOKPHUZZ_DEMO_HOOK=<ten-hook> khi chạy.
 *
 * 1. Hàm thường, AJAX đã đăng nhập:
 *

 *
 * 2. Static method, AJAX không đăng nhập:
 *
 * final class HookPhuzz_Static_Demo
 * {
 *     public static function save(): void
 *     {
 *         echo $_GET['page'] ?? '';
 *         wp_die();
 *     }
 * }
 * add_action('wp_ajax_nopriv_save_static', [HookPhuzz_Static_Demo::class, 'save']);
 *
 * 3. Object method, AJAX không đăng nhập:
 *
 * final class HookPhuzz_Object_Demo
 * {
 *     public function save(): void
 *     {
 *         echo $_COOKIE['token'] ?? '';
 *         wp_die();
 *     }
 * }
 * $hookphuzz_demo_handler = new HookPhuzz_Object_Demo();
 * add_action('wp_ajax_nopriv_save_object', [$hookphuzz_demo_handler, 'save']);
 */
