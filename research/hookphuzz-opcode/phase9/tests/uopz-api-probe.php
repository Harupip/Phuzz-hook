<?php
declare(strict_types=1);
$seen = [];
function hookphuzz_phase9_probe_action(string $name, $callback, int $priority = 10, int $acceptedArgs = 1): void {}
function hookphuzz_phase9_probe_filter(string $name, $callback, int $priority = 10, int $acceptedArgs = 1): void {}
foreach (['hookphuzz_phase9_probe_action', 'hookphuzz_phase9_probe_filter'] as $name) {
    if (!uopz_set_hook($name, static function (...$args) use (&$seen, $name): void { $seen[$name] = count($args); })) throw new RuntimeException("hook failed: $name");
}
hookphuzz_phase9_probe_action('a', 'b');
hookphuzz_phase9_probe_filter('c', 'd');
if (($seen['hookphuzz_phase9_probe_action'] ?? 0) < 2 || ($seen['hookphuzz_phase9_probe_filter'] ?? 0) < 2) throw new RuntimeException('hook arguments missing');
echo json_encode(['status' => 'PASS', 'uopz_version' => phpversion('uopz'), 'hook_arguments_seen' => $seen], JSON_PRETTY_PRINT), "\n";
