<?php
/** Plugin Name: HookPhuzz Generic AJAX Demo Discovery */
declare(strict_types=1);

if (!function_exists('uopz_set_hook')) {
    error_log('hookphuzz_demo_discovery: uopz unavailable');
    return;
}

$root = rtrim((string)getenv('HOOKPHUZZ_DEMO_DISCOVERY_ROOT'), '/') . '/';
$rows = [];
$diagnostics = [];
$inScope = static function () use ($root): bool {
    foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 8) as $frame) {
        if ($root !== '' && isset($frame['file']) && str_starts_with($frame['file'], $root)) return true;
    }
    return false;
};
$record = static function ($hook, $callback, $priority = 10, $acceptedArgs = 1) use (&$rows, &$diagnostics, $inScope): void {
    if (!$inScope() || !is_string($hook) || !is_int($priority) || !is_int($acceptedArgs)) return;
    $type = 'unsupported';
    $canonical = null;
    if (is_string($callback) && $callback !== '') {
        $type = 'function';
        $canonical = $callback;
    } elseif (is_array($callback) && count($callback) === 2 && is_string($callback[1]) && $callback[1] !== '') {
        if (is_string($callback[0])) {
            $type = 'static_method';
            $canonical = $callback[0] . '::' . $callback[1];
        } elseif (is_object($callback[0])) {
            $type = 'object_method';
            $canonical = $callback[0]::class . '::' . $callback[1];
        }
    } elseif ($callback instanceof Closure) {
        $diagnostics[] = ['hook' => $hook, 'callback_type' => 'closure', 'reason' => 'unstable_identity'];
        return;
    }
    if ($canonical === null) {
        $diagnostics[] = ['hook' => $hook, 'callback_type' => $type, 'reason' => 'unsupported_callback'];
        return;
    }
    $row = [
        'hook' => $hook,
        'callback' => $canonical,
        'canonical_callback' => $canonical,
        'callback_type' => $type,
        'priority' => $priority,
        'accepted_args' => $acceptedArgs,
        'plugin' => 'hookphuzz-demo-target',
    ];
    $rows[$hook . "\0" . strtolower($canonical) . "\0" . $priority . "\0" . $acceptedArgs] = $row;
};

if (!uopz_set_hook('add_action', $record)) error_log('hookphuzz_demo_discovery: add_action hook failed');

register_shutdown_function(static function () use (&$rows, &$diagnostics): void {
    $path = '/shared/hook-registration.json';
    $registrations = array_values($rows);
    usort($registrations, static fn(array $a, array $b): int => [$a['hook'], $a['canonical_callback'], $a['priority']] <=> [$b['hook'], $b['canonical_callback'], $b['priority']]);
    $json = json_encode(['schema_version' => 1, 'generated_by' => 'hookphuzz_demo_runtime_discovery', 'registrations' => $registrations, 'diagnostics' => $diagnostics], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    $tmp = is_string($json) ? tempnam(dirname($path), '.hookphuzz-demo-registry-') : false;
    if ($tmp === false) return;
    if (file_put_contents($tmp, $json, LOCK_EX) === false || !chmod($tmp, 0644) || !rename($tmp, $path)) {
        @unlink($tmp);
        error_log('hookphuzz_demo_discovery: registry write failed');
    }
});

