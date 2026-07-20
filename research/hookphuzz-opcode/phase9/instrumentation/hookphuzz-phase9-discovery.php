<?php
/** Plugin Name: HookPhuzz Phase 9 Discovery */
declare(strict_types=1);
if (!function_exists('uopz_set_hook')) { error_log('hookphuzz_phase9_discovery: uopz unavailable'); return; }
$root = (string)getenv('HOOKPHUZZ_PHASE9_DISCOVERY_ROOT'); $rows = []; $diagnostics = [];
$inScope = static function () use ($root): bool { foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 8) as $f) if ($root !== '' && isset($f['file']) && str_starts_with($f['file'], $root)) return true; return false; };
$record = static function ($hook, $callback, $priority = 10, $accepted = 1) use (&$rows, &$diagnostics, $inScope): void {
    if (!$inScope() || !is_string($hook) || !is_int($priority) || !is_int($accepted)) return;
    $type = 'unsupported'; $canonical = null;
    if (is_string($callback) && $callback !== '') { $type='function'; $canonical=$callback; }
    elseif (is_array($callback) && count($callback) === 2 && is_string($callback[1]) && $callback[1] !== '') { if (is_string($callback[0])) { $type='static_method'; $canonical=$callback[0].'::'.$callback[1]; } elseif (is_object($callback[0])) { $type='object_method'; $canonical=$callback[0]::class.'::'.$callback[1]; } }
    elseif ($callback instanceof Closure) { $diagnostics[]=['hook_name'=>$hook,'callback_type'=>'closure','reason'=>'unstable_identity']; return; }
    if ($canonical === null) { $diagnostics[]=['hook_name'=>$hook,'callback_type'=>$type,'reason'=>'unsupported_callback']; return; }
    $row=['hook_name'=>$hook,'callback'=>$canonical,'canonical_callback'=>$canonical,'callback_type'=>$type,'priority'=>$priority,'accepted_args'=>$accepted];
    $rows[$hook."\0".strtolower($canonical)."\0".$priority."\0".$accepted]=$row;
};
foreach (['add_action','add_filter'] as $fn) if (!uopz_set_hook($fn, $record)) error_log('hookphuzz_phase9_discovery: hook failed');
register_shutdown_function(static function () use (&$rows, &$diagnostics): void {
    $path='/shared/phase9-callback-registry.json'; $registrations=array_values($rows); usort($registrations, static fn($a,$b) => [$a['hook_name'],$a['canonical_callback'],$a['priority'],$a['accepted_args']] <=> [$b['hook_name'],$b['canonical_callback'],$b['priority'],$b['accepted_args']]);
    $json=json_encode(['schema_version'=>1,'generated_by'=>'hookphuzz_phase9_uopz_discovery','registrations'=>$registrations,'diagnostics'=>$diagnostics], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);
    $tmp=is_string($json) ? tempnam(dirname($path), '.phase9-registry-') : false; if ($tmp===false) return;
    if (file_put_contents($tmp,$json,LOCK_EX)===false || !rename($tmp,$path)) { @unlink($tmp); error_log('hookphuzz_phase9_discovery: registry write failed'); }
});
