<?php
/**
 * Plugin Name: Fuzzer UOPZ Bootstrap
 * Description: Retries UOPZ hook installation after WordPress has loaded its hook API.
 * Author: Fuzz_WP
 * Version: 1.0.0
 */

$instrumentationFile = '/var/www/fuzzer/hook_coverage/instrumentation/uopz_hook_runtime.php';
if (file_exists($instrumentationFile)) {
    require_once $instrumentationFile;
}

if (function_exists('add_action')) {
    add_action('muplugins_loaded', function () {
        if (function_exists('__uopz_install_wp_hooks')) {
            __uopz_install_wp_hooks();
        }
    }, -99999);

    add_action('plugins_loaded', function () {
        if (function_exists('__uopz_install_wp_hooks')) {
            __uopz_install_wp_hooks();
        }
    }, -99999);
}
