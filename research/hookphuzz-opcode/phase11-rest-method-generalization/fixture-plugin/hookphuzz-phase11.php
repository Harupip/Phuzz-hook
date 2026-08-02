<?php
/**
 * Plugin Name: HookPhuzz Phase 11 REST Fixture
 * Version: 1.0.0
 */
declare(strict_types=1);

const HP11_NAMESPACE = 'hookphuzz/v1';
const HP11_RESULTS = '/results';

function hp11_request_id(): string {
    $id = (string) ($_SERVER['HTTP_X_HOOKPHUZZ_REQUEST_ID'] ?? '');
    return preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/', $id) ? $id : '';
}
function hp11_write(string $directory, string $id, array $payload): void {
    if ($id === '') return;
    $dir = HP11_RESULTS . '/' . $directory;
    if (!is_dir($dir)) mkdir($dir, 0700, true);
    $tmp = tempnam($dir, '.tmp-');
    if ($tmp === false) return;
    $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json !== false && file_put_contents($tmp, $json, LOCK_EX) !== false) rename($tmp, "$dir/$id.json"); else @unlink($tmp);
}
function hp11_callback(string $callback, WP_REST_Request $request): WP_REST_Response {
    $id = hp11_request_id();
    $payload = [
        'phase' => 11, 'callback' => $callback, 'callback_reached' => true,
        'request_method' => $request->get_method(), 'request_id' => $id,
        'id' => (string) $request->get_param('id'), 'name' => (string) $request->get_param('name'),
        'marker' => (string) $request->get_param('marker'), 'timestamp' => gmdate('c'),
    ];
    hp11_write('callbacks', $id, $payload);
    return new WP_REST_Response($payload, 200);
}
function hookphuzz_phase11_get_item(WP_REST_Request $request): WP_REST_Response { return hp11_callback(__FUNCTION__, $request); }
function hookphuzz_phase11_update_item(WP_REST_Request $request): WP_REST_Response { return hp11_callback(__FUNCTION__, $request); }
function hookphuzz_phase11_delete_item(WP_REST_Request $request): WP_REST_Response { return hp11_callback(__FUNCTION__, $request); }
function hookphuzz_phase11_create_item(WP_REST_Request $request): WP_REST_Response { return hp11_callback(__FUNCTION__, $request); }

function hp11_methods($value): array {
    $out = [];
    $add = static function ($item) use (&$add, &$out): void {
        if (is_array($item)) { foreach ($item as $value) $add($value); return; }
        foreach (explode(',', str_replace('|', ',', (string) $item)) as $part) {
            $method = strtoupper(trim($part));
            if ($method !== '' && !in_array($method, $out, true)) $out[] = $method;
        }
    };
    $add($value); return $out;
}
function hp11_callback_name($callback): string {
    if (is_string($callback)) return $callback;
    if (is_array($callback) && isset($callback[1])) return (is_object($callback[0]) ? get_class($callback[0]) : (string) $callback[0]) . '::' . $callback[1];
    return 'unsupported';
}
function hp11_capture_registration($namespace, $route, $args): void {
    if (trim((string) $namespace, '/') !== HP11_NAMESPACE) return;
    $id = hp11_request_id(); if ($id === '') return;
    $entries = isset($args['callback']) ? [$args] : (is_array($args) ? $args : []);
    $routes = [];
    foreach ($entries as $entry) {
        if (!is_array($entry) || !isset($entry['callback'])) continue;
        $routes[] = ['namespace' => HP11_NAMESPACE, 'route_pattern' => '/' . trim((string) $route, '/'),
            'callback' => hp11_callback_name($entry['callback']), 'route_declared_methods' => hp11_methods($entry['methods'] ?? null)];
    }
    $constants = [];
    foreach (['READABLE', 'CREATABLE', 'EDITABLE', 'DELETABLE', 'ALLMETHODS'] as $name) {
        $value = constant('WP_REST_Server::' . $name);
        $constants[$name] = ['runtime_value' => $value, 'normalized_methods' => hp11_methods($value)];
    }
    $existing = HP11_RESULTS . '/registrations/' . $id . '.json';
    $prior = is_file($existing) ? json_decode((string) file_get_contents($existing), true) : [];
    $priorRoutes = is_array($prior) && isset($prior['routes']) && is_array($prior['routes']) ? $prior['routes'] : [];
    hp11_write('registrations', $id, ['phase' => 11, 'register_rest_route_hook_seen' => true, 'request_id' => $id,
        'wordpress_version' => get_bloginfo('version'), 'routes' => array_merge($priorRoutes, $routes), 'constants' => $constants]);
}
if (function_exists('uopz_set_hook')) {
    uopz_set_hook('register_rest_route', static function ($namespace, $route, $args): void {
        hp11_capture_registration($namespace, $route, $args);
    });
}

add_action('rest_api_init', static function (): void {
    register_rest_route(HP11_NAMESPACE, '/items/(?P<id>\\d+)', [
        ['methods' => 'GET', 'callback' => 'hookphuzz_phase11_get_item', 'permission_callback' => '__return_true'],
        ['methods' => ['PUT', 'PATCH'], 'callback' => 'hookphuzz_phase11_update_item', 'permission_callback' => '__return_true'],
        ['methods' => 'DELETE', 'callback' => 'hookphuzz_phase11_delete_item', 'permission_callback' => '__return_true'],
    ]);
    register_rest_route(HP11_NAMESPACE, '/items', ['methods' => 'POST', 'callback' => 'hookphuzz_phase11_create_item', 'permission_callback' => '__return_true']);
});
