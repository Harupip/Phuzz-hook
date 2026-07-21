<?php
declare(strict_types=1);
function fail(string $message): never { fwrite(STDERR, "$message\n"); exit(1); }
function json_file(string $path): array { try { $v = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR); } catch (Throwable $e) { fail('invalid json: ' . $e->getMessage()); } return $v; }
function artifact(string $path): array {
    $a = json_file($path);
    if (($a['schema_version'] ?? null) !== 3 || !is_array($a['events'] ?? null) || ($a['event_count'] ?? -1) !== count($a['events']) || !is_array($a['target_loading'] ?? null)) fail('invalid artifact');
    foreach ($a['events'] as $e) if (!is_array($e['callback_context'] ?? null)) fail('missing callback context');
    return $a;
}
function report(array $v): void { echo json_encode(['status' => 'PASS'] + $v, JSON_PRETTY_PRINT), "\n"; }
function root_events(array $a, string $root): array { return array_values(array_filter($a['events'], static fn($e) => ($e['callback_context']['root_callback'] ?? null) === $root)); }
function require_event(array $events, string $source, array $path, int $depth): void { foreach ($events as $e) if (($e['source'] ?? null) === $source && ($e['path'] ?? null) === $path && ($e['callback_context']['depth'] ?? null) === $depth) return; fail("missing $source " . json_encode($path) . " depth $depth"); }
$mode = $argv[1] ?? '';
if ($mode === 'discovery') {
    $d = json_file($argv[2]); if (($d['schema_version'] ?? null) !== 1 || !is_array($d['registrations'] ?? null)) fail('bad registry');
    $names = array_column($d['registrations'], 'canonical_callback');
    foreach (['hookphuzz_phase8_function_probe', 'HookPhuzz_Phase8_Handler::probe', 'HookPhuzz_Phase8_Handler_A::probe', 'HookPhuzz_Phase8_Handler_B::probe'] as $name) if (!in_array($name, $names, true)) fail("missing $name");
    if (!array_filter($d['diagnostics'] ?? [], static fn($x) => ($x['callback_type'] ?? null) === 'closure')) fail('closure diagnostic missing');
    if (preg_match('/cookie-|literal-post|runtime-value|object_id|0x[0-9a-f]+/i', json_encode($d))) fail('registry leaks data');
    report(['registrations' => count($names)]);
}
if ($mode === 'root') {
    $a = artifact($argv[2]); $root = $argv[3]; $events = root_events($a, $root); if (!$events) fail("missing root $root");
    if (count(array_filter($a['callback_summaries'], static fn($s) => ($s['callback'] ?? null) === $root)) !== 1) fail('summary mismatch');
    report(['request_id' => $a['request_id'], 'root' => $root, 'event_count' => count($events)]);
}
if ($mode === 'function') {
    $a = artifact($argv[2]); $events = root_events($a, 'hookphuzz_phase8_function_probe');
    foreach ([['GET',['literal_get'],0],['POST',['literal_post'],0],['REQUEST',['profile','email'],0],['COOKIE',['fixture_cookie'],0],['REQUEST',['helper_level_1'],1],['POST',['helper_level_2','value'],2]] as [$s,$p,$d]) require_event($events,$s,$p,$d);
    report(['request_id'=>$a['request_id'],'event_count'=>count($events)]);
}
if ($mode === 'target') {
    $a=artifact($argv[2]); $t=$a['target_loading']; foreach (array_slice($argv,3) as $pair) { [$k,$v]=explode('=',$pair,2); if ((string)($t[$k] ?? '') !== $v) fail("target $k"); } report($t);
}
if ($mode === 'none') { $a=artifact($argv[2]); if ($a['callback_summaries'] !== []) fail('unexpected summaries'); report(['request_id'=>$a['request_id']]); }
if ($mode === 'cap') { $a=artifact($argv[2]); if (($a['event_count'] ?? 0) !== 4096 || ($a['dropped_event_count'] ?? 0) < 1) fail('cap failed'); report(['event_count'=>4096,'dropped_event_count'=>$a['dropped_event_count']]); }
if ($mode === 'noise') { $a=artifact($argv[2]); if (!array_filter($a['events'], static fn($e) => ($e['callback_context']['attributed'] ?? true) === false)) fail('missing bootstrap noise'); report(['request_id'=>$a['request_id']]); }
if ($mode === 'cleanup') { $a=artifact($argv[2]); $events=root_events($a,'hookphuzz_phase8_function_probe'); require_event($events,'POST',['after_catch'],0); report(['request_id'=>$a['request_id']]); }
