<?php
/** Plugin Name: HookPhuzz Phase 13 REST observer */
declare(strict_types=1);

$hp13_id = static function (): string { $id = $_SERVER['HTTP_X_HOOKPHUZZ_REQUEST_ID'] ?? ''; return is_string($id) && preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/', $id) ? $id : ''; };
$hp13_callable = static function ($callback): string {
    if (is_string($callback)) return $callback;
    if (is_array($callback) && count($callback) === 2) return (is_object($callback[0]) ? get_class($callback[0]) : (string) $callback[0]) . '::' . (string) $callback[1];
    if ($callback instanceof Closure) return 'Closure';
    if (is_object($callback) && method_exists($callback, '__invoke')) return get_class($callback) . '::__invoke';
    return 'unresolved';
};
$hp13_write = static function () use ($hp13_id): void {
    $id = $hp13_id(); if ($id === '') return;
    $coverage = $GLOBALS['__uopz_request']['hook_coverage'] ?? [];
    $value = ['schema_version'=>1, 'request_id'=>$id, 'method'=>($_SERVER['REQUEST_METHOD'] ?? ''), 'registered_callbacks'=>$coverage['registered_callbacks'] ?? [], 'executed_callbacks'=>$coverage['executed_callbacks'] ?? [], 'parameters'=>$GLOBALS['hp13_runtime_parameters'] ?? [], 'rest_dispatch'=>$GLOBALS['hp13_rest_dispatch'] ?? [], 'route_callback_invocations'=>$GLOBALS['hp13_route_callback_invocations'] ?? [], 'permission_callback_invocations'=>$GLOBALS['hp13_permission_callback_invocations'] ?? []];
    $dir=(string)getenv('PHASE13_RESULTS_DIR') . '/runtime'; if (!is_dir($dir)) mkdir($dir,0700,true);
    $tmp=tempnam($dir,'.tmp-'); $json=json_encode($value,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);
    if ($tmp !== false && $json !== false && file_put_contents($tmp,$json,LOCK_EX)!==false) rename($tmp,"$dir/$id.json");
};
add_action('rest_api_init', static function (): void { if (function_exists('__uopz_install_wp_hooks')) __uopz_install_wp_hooks(); }, 1);
add_action('rest_api_init', static function () use ($hp13_id, $hp13_callable): void {
    if (!function_exists('uopz_set_hook')) return;
    uopz_set_hook('WP_REST_Request', 'get_param', static function ($name) use ($hp13_id): void { if ($hp13_id() !== '') $GLOBALS['hp13_runtime_parameters'][] = ['name'=>(string)$name,'source'=>'WP_REST_Request::get_param']; });
    foreach (rest_get_server()->get_routes() as $route => $handlers) foreach ($handlers as $handler) foreach (['callback'=>'route_callback_invocations','permission_callback'=>'permission_callback_invocations'] as $field => $bucket) {
        if (!isset($handler[$field]) || !is_callable($handler[$field])) continue;
        $callback = $handler[$field]; $identity = $hp13_callable($callback);
        $hook = static function () use ($hp13_id, $bucket, $route, $identity): void { if ($hp13_id() !== '') $GLOBALS['hp13_' . $bucket][] = ['route'=>$route,'callable'=>$identity]; };
        try {
            if (is_string($callback) && function_exists($callback)) uopz_set_hook($callback, $hook);
            elseif (is_array($callback) && count($callback) === 2) uopz_set_hook(is_object($callback[0]) ? get_class($callback[0]) : $callback[0], $callback[1], $hook);
        } catch (Throwable $ignored) { }
    }
}, PHP_INT_MAX);
add_filter('rest_request_before_callbacks', static function ($response, $handler, $request) use ($hp13_id, $hp13_callable) { if ($hp13_id() !== '') $GLOBALS['hp13_rest_dispatch'][] = ['route'=>$request->get_route(), 'callback'=>$hp13_callable($handler['callback'] ?? null), 'permission_callback'=>$hp13_callable($handler['permission_callback'] ?? null), 'stage'=>'before_callbacks']; return $response; }, 10, 3);
add_filter('rest_request_after_callbacks', static function ($response, $handler, $request) use ($hp13_id, $hp13_callable) { if ($hp13_id() !== '') $GLOBALS['hp13_rest_dispatch'][] = ['route'=>$request->get_route(), 'callback'=>$hp13_callable($handler['callback'] ?? null), 'permission_callback'=>$hp13_callable($handler['permission_callback'] ?? null), 'stage'=>'after_callbacks']; return $response; }, PHP_INT_MAX, 3);
add_filter('rest_post_dispatch', static function ($response, $server, $request) use ($hp13_id) { if ($hp13_id() !== '') $GLOBALS['hp13_rest_dispatch'][] = ['route'=>$request->get_route(), 'stage'=>'post_dispatch', 'response_status'=>$response instanceof WP_REST_Response ? $response->get_status() : null]; return $response; }, PHP_INT_MAX, 3);
register_shutdown_function($hp13_write);
