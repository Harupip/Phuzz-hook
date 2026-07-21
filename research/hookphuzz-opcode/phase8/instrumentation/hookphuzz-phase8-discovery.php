<?php
/**
 * Plugin Name: HookPhuzz Phase 8 Discovery
 * Description: Runtime-only callback registry writer for the Phase 8 fixture.
 */
declare(strict_types=1);

if (!function_exists('uopz_set_hook')) {
    error_log('hookphuzz_phase8_discovery: uopz is unavailable');
    return;
}

$hookphuzzPhase8Root = (string) getenv('HOOKPHUZZ_PHASE8_DISCOVERY_ROOT');
$hookphuzzPhase8Registry = [];
$hookphuzzPhase8Diagnostics = [];

$hookphuzzPhase8InScope = static function () use ($hookphuzzPhase8Root): bool {
    if ($hookphuzzPhase8Root === '') return false;
    foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 8) as $frame) {
        if (isset($frame['file']) && str_starts_with($frame['file'], $hookphuzzPhase8Root)) return true;
    }
    return false;
};

$hookphuzzPhase8Record = static function ($hookName, $callback, $priority = 10, $acceptedArgs = 1) use (&$hookphuzzPhase8Registry, &$hookphuzzPhase8Diagnostics, $hookphuzzPhase8InScope): void {
    if (!$hookphuzzPhase8InScope() || !is_string($hookName) || !is_int($priority) || !is_int($acceptedArgs)) return;
    $type = 'unsupported';
    $canonical = null;
    $display = null;
    if (is_string($callback) && $callback !== '') {
        $type = 'function'; $canonical = $callback; $display = $callback;
    } elseif (is_array($callback) && count($callback) === 2 && is_string($callback[1]) && $callback[1] !== '') {
        if (is_string($callback[0]) && $callback[0] !== '') {
            $type = 'static_method'; $canonical = $callback[0] . '::' . $callback[1]; $display = $canonical;
        } elseif (is_object($callback[0])) {
            $type = 'object_method'; $canonical = $callback[0]::class . '::' . $callback[1]; $display = $canonical;
        }
    } elseif ($callback instanceof Closure) {
        $hookphuzzPhase8Diagnostics[] = ['hook_name' => $hookName, 'callback_type' => 'closure', 'reason' => 'unstable_identity'];
        return;
    }
    if ($canonical === null) {
        $hookphuzzPhase8Diagnostics[] = ['hook_name' => $hookName, 'callback_type' => $type, 'reason' => 'unsupported_callback'];
        return;
    }
    $entry = ['hook_name' => $hookName, 'callback' => $display, 'canonical_callback' => $canonical,
        'callback_type' => $type, 'priority' => $priority, 'accepted_args' => $acceptedArgs];
    $hookphuzzPhase8Registry[strtolower($canonical)] = $entry;
};

foreach (['add_action', 'add_filter'] as $hookphuzzPhase8Function) {
    if (!uopz_set_hook($hookphuzzPhase8Function, $hookphuzzPhase8Record)) {
        error_log('hookphuzz_phase8_discovery: failed to hook ' . $hookphuzzPhase8Function);
    }
}

register_shutdown_function(static function () use (&$hookphuzzPhase8Registry, &$hookphuzzPhase8Diagnostics): void {
    $path = '/shared/phase8-callback-registry.json';
    $json = json_encode(['schema_version' => 1, 'generated_by' => 'hookphuzz_phase8_uopz_discovery',
        'registrations' => array_values($hookphuzzPhase8Registry), 'diagnostics' => $hookphuzzPhase8Diagnostics], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (!is_string($json) || ($temp = tempnam(dirname($path), '.phase8-registry-')) === false) return;
    $stream = fopen($temp, 'wb');
    if ($stream === false || fwrite($stream, $json) !== strlen($json) || !fflush($stream)
        || (function_exists('fsync') && !fsync($stream)) || !fclose($stream) || !rename($temp, $path)) {
        if (is_resource($stream)) fclose($stream);
        @unlink($temp);
        error_log('hookphuzz_phase8_discovery: registry write failed');
    }
});
