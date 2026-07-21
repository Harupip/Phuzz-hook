<?php
declare(strict_types=1);

function fail(string $message): never { fwrite(STDERR, "$message\n"); exit(1); }
function document(string $path): array {
    try { $value = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR); }
    catch (Throwable $error) { fail("malformed JSON: {$error->getMessage()}"); }
    foreach (['schema_version', 'request_id', 'event_count', 'dropped_event_count', 'events', 'callback_summaries'] as $field) {
        if (!array_key_exists($field, $value)) fail("missing $field");
    }
    if ($value['schema_version'] !== 2 || $value['event_count'] !== count($value['events'])) fail('invalid artifact metadata');
    foreach ($value['events'] as $event) {
        $context = $event['callback_context'] ?? null;
        if (!is_array($context) || !array_key_exists('attributed', $context)) fail('missing callback context');
        if ($context['attributed']) {
            if (!is_string($context['root_callback'] ?? null) || !is_string($context['current_function'] ?? null)
                || !is_int($context['depth'] ?? null) || $context['depth'] < 0) fail('invalid attributed context');
        } elseif (!array_key_exists('root_callback', $context) || !array_key_exists('depth', $context)
            || $context['root_callback'] !== null || $context['depth'] !== null) fail('invalid un-attributed context');
    }
    return $value;
}
function events(array $artifact, string $root = null): array {
    return array_values(array_filter($artifact['events'], static function (array $event) use ($root): bool {
        return $root === null || (($event['callback_context']['root_callback'] ?? null) === $root);
    }));
}
function has(array $events, string $source, array $path, string $operation, string $current, int $depth): bool {
    foreach ($events as $event) {
        $context = $event['callback_context'];
        if (($event['source'] ?? null) === $source && ($event['path'] ?? null) === $path
            && ($event['operation'] ?? null) === $operation && ($context['current_function'] ?? null) === $current
            && ($context['depth'] ?? null) === $depth) return true;
    }
    return false;
}
function report(array $value): never { echo json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"; exit(0); }

$mode = $argv[1] ?? '';
if ($mode === 'function') {
    $artifact = document($argv[2] ?? ''); $runtimeKey = $argv[3] ?? '';
    $root = 'hookphuzz_phase7_probe'; $items = events($artifact, $root);
    $expected = [
        ['GET', ['literal_get'], 'read'], ['POST', ['literal_post'], 'read'], ['POST', ['runtime_selector'], 'silent_read'],
        ['POST', [$runtimeKey], 'read'], ['REQUEST', ['profile'], 'read'], ['REQUEST', ['profile', 'email'], 'read'],
        ['COOKIE', ['fixture_cookie'], 'read'], ['GET', ['isset_key'], 'isset'], ['POST', ['empty_key'], 'empty'],
        ['REQUEST', ['optional_key'], 'silent_read'], ['POST', ['direct_callback'], 'read'],
    ];
    foreach ($expected as [$source, $path, $operation]) {
        if (!has($items, $source, $path, $operation, $root, 0)) fail("missing direct root event: $source " . json_encode($path));
    }
    if (!has($items, 'REQUEST', ['helper_level_1'], 'read', 'hookphuzz_phase7_helper_level_1', 1)) fail('missing helper level 1');
    if (!has($items, 'POST', ['helper_level_2', 'value'], 'read', 'hookphuzz_phase7_helper_level_2', 2)) fail('missing helper level 2');
    $summary = array_values(array_filter($artifact['callback_summaries'], static fn(array $v): bool => ($v['callback'] ?? null) === $root));
    if (count($summary) !== 1 || $summary[0]['event_count'] !== count($items)) fail('function summary mismatch');
    report(['status' => 'PASS', 'request_id' => $artifact['request_id'], 'root' => $root, 'event_count' => count($items)]);
}
if ($mode === 'method') {
    $artifact = document($argv[2] ?? ''); $root = 'HookPhuzz_Phase7_Handler::probe'; $items = events($artifact, $root);
    if (!has($items, 'POST', ['method_direct'], 'read', $root, 0)) fail('missing method callback event');
    foreach ($artifact['events'] as $event) if (($event['callback_context']['root_callback'] ?? null) === 'hookphuzz_phase7_probe') fail('function root contaminated method request');
    report(['status' => 'PASS', 'request_id' => $artifact['request_id'], 'root' => $root, 'event_count' => count($items)]);
}
if ($mode === 'none') {
    $artifact = document($argv[2] ?? '');
    foreach ($artifact['events'] as $event) if (($event['callback_context']['attributed'] ?? false) === true) fail('unexpected attributed event');
    if ($artifact['callback_summaries'] !== []) fail('unexpected callback summary');
    report(['status' => 'PASS', 'request_id' => $artifact['request_id'], 'unattributed_events' => $artifact['event_count']]);
}
if ($mode === 'noise') {
    $artifact = document($argv[2] ?? ''); $noise = 0;
    foreach ($artifact['events'] as $event) if (($event['callback_context']['attributed'] ?? true) === false) $noise++;
    if ($noise === 0) fail('missing raw bootstrap noise');
    report(['status' => 'PASS', 'request_id' => $artifact['request_id'], 'unattributed_events' => $noise]);
}
if ($mode === 'valid') {
    $artifact = document($argv[2] ?? '');
    report(['status' => 'PASS', 'request_id' => $artifact['request_id'], 'event_count' => $artifact['event_count']]);
}
if ($mode === 'cleanup') {
    $artifact = document($argv[2] ?? ''); $root = 'hookphuzz_phase7_probe'; $items = events($artifact, $root);
    if (!has($items, 'POST', ['after_catch'], 'read', $root, 0)) fail('post-catch context was not restored');
    report(['status' => 'PASS', 'request_id' => $artifact['request_id'], 'post_catch_depth' => 0]);
}
if ($mode === 'cap') {
    $artifact = document($argv[2] ?? ''); $accepted = 0;
    foreach ($artifact['events'] as $event) if (($event['source'] ?? null) === 'POST' && ($event['path'] ?? null) === ['cap_value']) $accepted++;
    if ($artifact['event_count'] !== 4096 || $artifact['dropped_event_count'] !== 8192 - $accepted) fail('event cap counter mismatch');
    report(['status' => 'PASS', 'request_id' => $artifact['request_id'], 'event_count' => 4096, 'dropped_event_count' => $artifact['dropped_event_count'], 'accepted_cap_reads' => $accepted]);
}
if ($mode === 'response') {
    $body = json_decode((string) file_get_contents($argv[2] ?? ''), true);
    if (!is_array($body) || ($body['success'] ?? null) !== true) fail('invalid JSON response');
    report(['status' => 'PASS']);
}
fail('usage: assert.php function|method|none|noise|valid|cleanup|cap|response ...');
