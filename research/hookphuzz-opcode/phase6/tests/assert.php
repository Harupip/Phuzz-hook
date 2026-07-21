<?php
declare(strict_types=1);

function fail(string $message): never {
    fwrite(STDERR, $message . "\n");
    exit(1);
}

function document(string $path): array {
    try {
        $value = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
    } catch (Throwable $error) {
        fail("malformed JSON: {$error->getMessage()}");
    }
    if (!is_array($value)) fail('artifact is not an object');
    foreach (['schema_version', 'request_id', 'pid', 'method', 'uri', 'event_count', 'dropped_event_count', 'events'] as $field) {
        if (!array_key_exists($field, $value)) fail("missing top-level field: $field");
    }
    if ($value['schema_version'] !== 1 || !is_int($value['pid']) || $value['pid'] < 1) fail('invalid artifact metadata');
    if (!is_array($value['events']) || $value['event_count'] !== count($value['events'])) fail('event_count mismatch');
    if (!is_string($value['uri']) || !str_starts_with($value['uri'], '/')) fail('invalid URI');
    if (str_contains($value['uri'], '?')) {
        foreach (preg_split('/[&;]/', explode('?', $value['uri'], 2)[1]) as $part) {
            if ($part !== '' && !str_ends_with($part, '=<redacted>')) fail('URI value was not redacted');
        }
    }
    return $value;
}

function fixtureEvents(array $artifact): array {
    return array_values(array_filter($artifact['events'], static fn ($event): bool =>
        is_array($event)
        && ($event['function'] ?? null) === 'hookphuzz_phase6_probe'
        && is_string($event['file'] ?? null)
        && str_ends_with($event['file'], '/hookphuzz-phase6-fixture.php')));
}

function eventExists(array $events, string $source, array $path, string $operation): bool {
    foreach ($events as $event) {
        if (($event['source'] ?? null) === $source && ($event['path'] ?? null) === $path && ($event['operation'] ?? null) === $operation) return true;
    }
    return false;
}

$mode = $argv[1] ?? '';
if ($mode === 'fixture') {
    [$script, $mode, $path, $id, $runtimeKey] = $argv + [null, null, null, null, null];
    $artifact = document((string) $path);
    if ($artifact['request_id'] !== $id || $artifact['method'] !== 'POST') fail('request metadata mismatch');
    $events = fixtureEvents($artifact);
    $expected = [
        ['GET', ['literal_get'], 'read'],
        ['POST', ['literal_post'], 'read'],
        ['POST', ['runtime_selector'], 'silent_read'],
        ['POST', [$runtimeKey], 'read'],
        ['REQUEST', ['profile'], 'read'],
        ['REQUEST', ['profile', 'email'], 'read'],
        ['COOKIE', ['fixture_cookie'], 'read'],
        ['GET', ['isset_key'], 'isset'],
        ['POST', ['empty_key'], 'empty'],
        ['REQUEST', ['optional_key'], 'silent_read'],
    ];
    foreach ($expected as [$source, $eventPath, $operation]) {
        if (!eventExists($events, $source, $eventPath, $operation)) fail("missing fixture event: $source " . json_encode($eventPath) . " $operation");
    }
    exit(0);
}

if ($mode === 'no-fixture') {
    $artifact = document((string) ($argv[2] ?? ''));
    if (fixtureEvents($artifact) !== []) fail('fixture event found in non-fixture request');
    exit(0);
}

if ($mode === 'response') {
    [$script, $mode, $path, $tag, $runtimeKey] = $argv + [null, null, null, null, null];
    try {
        $body = json_decode((string) file_get_contents((string) $path), true, 64, JSON_THROW_ON_ERROR);
    } catch (Throwable $error) {
        fail("malformed response JSON: {$error->getMessage()}");
    }
    $expected = [
        'literal_get' => "literal-get-$tag",
        'literal_post' => "literal-post-$tag",
        'runtime_key' => $runtimeKey,
        'runtime_value' => "runtime-value-$tag",
        'profile_email' => "profile-email-$tag",
        'fixture_cookie' => "cookie-$tag",
        'isset_key' => true,
        'empty_key' => false,
        'optional_key' => "optional-$tag",
    ];
    if (($body['success'] ?? null) !== true || ($body['data'] ?? null) !== $expected) fail('fixture response mismatch');
    exit(0);
}

if ($mode === 'noise') {
    [$script, $mode, $path, $cap, $jsonPath, $markdownPath] = $argv + [null, null, null, null, null, null];
    $artifact = document((string) $path);
    $fixtureIndexes = [];
    $counts = ['GET' => 0, 'POST' => 0, 'REQUEST' => 0, 'COOKIE' => 0];
    foreach ($artifact['events'] as $index => $event) {
        $source = $event['source'] ?? '';
        if (array_key_exists($source, $counts)) $counts[$source]++;
        if (in_array($event, fixtureEvents(['events' => [$event]]), true)) $fixtureIndexes[] = $index;
    }
    if ($fixtureIndexes === []) fail('no fixture events available for noise analysis');
    $firstFixtureIndex = $fixtureIndexes[0];
    $report = [
        'request_id' => $artifact['request_id'],
        'total_events' => $artifact['event_count'],
        'events_before_first_fixture_event' => $firstFixtureIndex,
        'event_count_by_source' => $counts,
        'configured_event_cap' => (int) $cap,
        'dropped_event_count' => $artifact['dropped_event_count'],
        'cap_reached' => $artifact['event_count'] >= (int) $cap || $artifact['dropped_event_count'] > 0,
        'fixture_event_indexes' => $fixtureIndexes,
        'fixture_event_count' => count($fixtureIndexes),
        'analysis_scope' => 'Event order and fixture file/function identity only; this is not callback-context attribution.',
    ];
    file_put_contents((string) $jsonPath, json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    file_put_contents((string) $markdownPath, "# WordPress noise analysis\n\n"
        . "- Total events: {$report['total_events']}\n"
        . "- Events before first fixture event: {$report['events_before_first_fixture_event']}\n"
        . "- GET/POST/REQUEST/COOKIE: {$counts['GET']}/{$counts['POST']}/{$counts['REQUEST']}/{$counts['COOKIE']}\n"
        . "- Configured cap: {$report['configured_event_cap']}\n"
        . "- Dropped events: {$report['dropped_event_count']}\n"
        . "- Cap reached: " . ($report['cap_reached'] ? 'yes' : 'no') . "\n"
        . "- Fixture events: {$report['fixture_event_count']}\n\n"
        . "This separates events by fixture file/function and event order; it does not attribute parameters to callback context.\n");
    if ($report['cap_reached']) fail('event cap reached');
    exit(0);
}

fail('usage: assert.php fixture|no-fixture|response|noise ...');
