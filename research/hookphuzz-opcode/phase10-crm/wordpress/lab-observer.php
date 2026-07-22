<?php
/** Plugin Name: HookPhuzz Phase 10 CRM Lab Observer */
declare(strict_types=1);
/* Lab-only UOPZ observer. It records no values, cookies, nonces, or pointers. */
$phase10_root = '/var/www/html/wp-content/plugins/crm-perks-forms/';
$phase10_rows = [];
$phase10_id = static fn(): string => isset($_SERVER['HTTP_X_FUZZER_COVID']) && preg_match('/^[A-Za-z0-9_.-]{1,128}$/', $_SERVER['HTTP_X_FUZZER_COVID']) ? $_SERVER['HTTP_X_FUZZER_COVID'] : '';
$phase10_write = static function (string $name, array $row) use ($phase10_id): void {
    $id = $phase10_id(); if ($id === '') return; $dir = '/results/runtime'; if (!is_dir($dir)) mkdir($dir, 0700, true);
    $path = "$dir/$id.$name.json"; $tmp = tempnam($dir, '.tmp-'); if ($tmp === false) return;
    $json = json_encode($row, JSON_UNESCAPED_SLASHES); if ($json !== false && file_put_contents($tmp, $json, LOCK_EX) !== false) rename($tmp, $path); else @unlink($tmp);
};
if (function_exists('uopz_set_hook')) {
    $in_scope = static function () use ($phase10_root): bool { foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 8) as $f) if (isset($f['file']) && str_starts_with($f['file'], $phase10_root)) return true; return false; };
    uopz_set_hook('add_action', static function ($hook, $callback, $priority = 10, $accepted = 1) use (&$phase10_rows, $in_scope): void {
        if (!$in_scope() || !is_string($hook)) return; $canonical = null; $type = 'unsupported';
        if (is_string($callback)) { $canonical = $callback; $type = 'function'; }
        elseif (is_array($callback) && count($callback) === 2 && is_string($callback[1])) { $canonical = is_object($callback[0]) ? $callback[0]::class . '::' . $callback[1] : (is_string($callback[0]) ? $callback[0] . '::' . $callback[1] : null); $type = is_object($callback[0] ?? null) ? 'object_method' : 'static_method'; }
        if ($canonical !== null) $phase10_rows[$hook . "\0" . $canonical] = ['hook_name'=>$hook, 'callback'=>$canonical, 'canonical_callback'=>$canonical, 'callback_type'=>$type, 'priority'=>(int)$priority, 'accepted_args'=>(int)$accepted];
    });
}
register_shutdown_function(static function () use (&$phase10_rows): void {
    $doc = ['schema_version'=>1, 'generated_by'=>'phase10_crm_uopz_registration', 'registrations'=>array_values($phase10_rows)];
    $tmp = tempnam('/results', '.registry-'); $json = json_encode($doc, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES); if ($tmp && $json !== false && file_put_contents($tmp, $json, LOCK_EX) !== false) rename($tmp, '/results/runtime-hook-registration.json'); elseif ($tmp) @unlink($tmp);
});
add_action('plugins_loaded', static function () use ($phase10_write): void {
    if (!function_exists('uopz_set_hook') || !class_exists('cfx_form') || !class_exists('cfx_form_admin_pages')) return;
    uopz_set_hook('cfx_form', 'post', static function ($key, $arr = '') use ($phase10_write): void { if ($key === 'cfx_settings') $phase10_write('helper', ['request_id'=>$_SERVER['HTTP_X_FUZZER_COVID'] ?? '', 'evidence_type'=>'helper_runtime', 'source'=>'REQUEST', 'path'=>['cfx_settings'], 'helper'=>'cfx_form::post', 'callback'=>'cfx_form_admin_pages::save_api_settings']); });
    uopz_set_hook('cfx_form_admin_pages', 'save_api_settings', static function () use ($phase10_write): void { $marker = $_POST['cfx_settings']['alert_emails'] ?? null; $phase10_write('callback', ['request_id'=>$_SERVER['HTTP_X_FUZZER_COVID'] ?? '', 'callback'=>'cfx_form_admin_pages::save_api_settings', 'callback_reached'=>true, 'marker_observed'=>is_string($marker) && str_starts_with($marker, 'PHASE10_CRM_')]); });
}, 999);
