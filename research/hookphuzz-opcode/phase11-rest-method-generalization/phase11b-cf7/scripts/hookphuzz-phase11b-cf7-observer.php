<?php
/** Plugin Name: HookPhuzz Phase 11B CF7 Observer */
declare(strict_types=1);

const HP11B_ROUTE = '/contact-form-7/v1/contact-forms';
const HP11B_CALLBACK = 'WPCF7_REST_Controller::get_contact_forms';
const HP11B_HOOK_CALLBACK = 'WPCF7_REST_Controller->get_contact_forms';

$hp11b_id = static function (): string {
    $id = $_SERVER['HTTP_X_HOOKPHUZZ_REQUEST_ID'] ?? '';
    return is_string($id) && preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/', $id) ? $id : '';
};
$hp11b_doc = [
    'schema_version' => 1,
    'plugin' => 'contact-form-7',
    'plugin_version' => defined('WPCF7_VERSION') ? WPCF7_VERSION : null,
    'route' => HP11B_ROUTE,
    'callback' => HP11B_CALLBACK,
    'permission_callback_passed' => false,
    'callback_reached' => false,
    'parameter_observed' => false,
];
$hp11b_write = static function () use (&$hp11b_doc, $hp11b_id): void {
    $id = $hp11b_id();
    if ($id === '') {
        return;
    }
    $hp11b_doc['plugin_version'] = defined('WPCF7_VERSION') ? WPCF7_VERSION : null;
    $hp11b_doc['hookphuzz_instrumentation_loaded'] = function_exists('__uopz_install_wp_hooks');
    $hp11b_doc['hookphuzz_registered_callback_count'] = count($GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'] ?? []);
    $hp11b_doc['hookphuzz_install_failures'] = $GLOBALS['__uopz_hook_failures'] ?? [];
    $hp11b_doc['hookphuzz_cf7_route_candidates'] = array_values(array_filter($GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'] ?? [], static function ($entry): bool {
        return is_array($entry) && ($entry['entrypoint_type'] ?? '') === 'rest_route' && ($entry['namespace'] ?? '') === 'contact-form-7/v1';
    }));
    foreach (($GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'] ?? []) as $callback_id => $entry) {
        if (!is_array($entry) || ($entry['entrypoint_type'] ?? '') !== 'rest_route') {
            continue;
        }
        if (($entry['namespace'] ?? '') === 'contact-form-7/v1' && ($entry['route'] ?? '') === HP11B_ROUTE && ($entry['callback_repr'] ?? '') === HP11B_HOOK_CALLBACK) {
            $hp11b_doc['hookphuzz_route_capture'] = [
                'callback_id' => $callback_id,
                'namespace' => $entry['namespace'],
                'route_pattern' => $entry['route'],
                'declared_methods' => $entry['methods'] ?? [],
                'callback' => $entry['callback_repr'],
                'permission_callback' => $entry['permission_callback'] ?? null,
                'rest_argument_schema_version' => $entry['rest_argument_schema_version'] ?? null,
                'endpoint_definition_index' => $entry['endpoint_definition_index'] ?? null,
                'route_common_argument_definitions' => $entry['route_common_argument_definitions'] ?? [],
                'argument_definitions' => $entry['argument_definitions'] ?? [],
                'source_file' => $entry['source_file'] ?? null,
                'source_line' => $entry['source_line'] ?? null,
            ];
            break;
        }
    }
    $hp11b_doc['request_id'] = $id;
    $hp11b_doc['http_method'] = $_SERVER['REQUEST_METHOD'] ?? '';
    $hp11b_doc['timestamp'] = gmdate('c');
    $dir = '/results/callbacks';
    if (!is_dir($dir)) {
        mkdir($dir, 0700, true);
    }
    $json = json_encode($hp11b_doc, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    $tmp = tempnam($dir, '.tmp-');
    if ($tmp !== false && $json !== false && file_put_contents($tmp, $json, LOCK_EX) !== false) {
        rename($tmp, "$dir/$id.json");
    } elseif ($tmp !== false) {
        @unlink($tmp);
    }
};
add_action('rest_api_init', static function (): void {
    if (function_exists('__uopz_install_wp_hooks')) {
        __uopz_install_wp_hooks();
    }
}, 1);
add_action('rest_api_init', static function () use (&$hp11b_doc, $hp11b_id): void {
    if (!function_exists('uopz_set_hook') || !class_exists('WPCF7_REST_Controller')) {
        return;
    }
    uopz_set_hook('WPCF7_REST_Controller', 'get_contact_forms', static function () use (&$hp11b_doc, $hp11b_id): void {
        if ($hp11b_id() === '') {
            return;
        }
        $hp11b_doc['permission_callback_passed'] = true;
        $hp11b_doc['callback_reached'] = true;
    });
    uopz_set_hook('WP_REST_Request', 'get_param', static function ($key) use (&$hp11b_doc, $hp11b_id): void {
        if ($hp11b_id() === '' || $key !== 'search') {
            return;
        }
        foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 12) as $frame) {
            if (($frame['class'] ?? '') === 'WPCF7_REST_Controller' && ($frame['function'] ?? '') === 'get_contact_forms') {
                $value = $_GET['search'] ?? null;
                $hp11b_doc['parameter_name'] = 'search';
                $hp11b_doc['parameter_value'] = is_scalar($value) ? (string) $value : null;
                $hp11b_doc['parameter_observed'] = is_scalar($value);
                return;
            }
        }
    });
}, PHP_INT_MAX);
register_shutdown_function($hp11b_write);
