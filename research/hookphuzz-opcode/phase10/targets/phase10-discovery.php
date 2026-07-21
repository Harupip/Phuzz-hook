<?php
/* Phase 10 callback registry: target-plugin registrations only. */
$phase10_rows = [];
$phase10_roots = [
    '/wp-content/plugins/hookphuzz-phase10-controlled/',
    '/wp-content/plugins/crm-perks-forms/',
    '/wp-content/plugins/contact-form-7/',
];
$phase10_in_scope = static function () use ($phase10_roots): bool {
    foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS) as $frame) {
        $file = $frame['file'] ?? '';
        foreach ($phase10_roots as $root) if (strpos($file, $root) !== false) return true;
    }
    return false;
};
$phase10_record = static function ($hook, $callback, $priority = 10, $accepted = 1) use (&$phase10_rows, $phase10_in_scope): void {
    if (!$phase10_in_scope() || !is_string($hook)) return;
    if (is_string($callback)) { $canonical = $callback; $type = 'function'; }
    elseif (is_array($callback) && count($callback) === 2 && is_string($callback[1])) {
        $canonical = is_object($callback[0]) ? $callback[0]::class . '::' . $callback[1] : (is_string($callback[0]) ? $callback[0] . '::' . $callback[1] : null);
        $type = is_object($callback[0] ?? null) ? 'object_method' : 'static_method';
    } else return;
    if (!$canonical) return;
    $phase10_rows[$hook . "\0" . $canonical . "\0" . $priority] = ['hook_name' => $hook, 'callback' => $canonical, 'canonical_callback' => $canonical, 'callback_type' => $type, 'priority' => (int) $priority, 'accepted_args' => (int) $accepted];
};
if (extension_loaded('uopz')) {
    uopz_set_hook('add_action', static function ($hook, $callback, $priority = 10, $accepted = 1) use ($phase10_record): void { $phase10_record($hook, $callback, $priority, $accepted); });
    uopz_set_hook('add_filter', static function ($hook, $callback, $priority = 10, $accepted = 1) use ($phase10_record): void { $phase10_record($hook, $callback, $priority, $accepted); });
}
register_shutdown_function(static function () use (&$phase10_rows): void {
    $path = '/results/phase10-callback-registry.json';
    $payload = json_encode(['schema_version' => 1, 'generated_by' => 'hookphuzz_phase10_uopz_discovery', 'registrations' => array_values($phase10_rows)], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($payload === false) return;
    $temp = tempnam(dirname($path), '.phase10-registry-');
    if ($temp && file_put_contents($temp, $payload, LOCK_EX) !== false) rename($temp, $path);
});
