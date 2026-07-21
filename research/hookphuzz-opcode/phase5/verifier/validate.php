<?php
declare(strict_types=1);

if ($argc !== 6) {
    fwrite(STDERR, "usage: validate.php ARTIFACT REQUEST_ID METHOD EXPECTED_EVENTS_JSON EXPECTED_DROPPED\n");
    exit(2);
}

[$script, $artifactPath, $requestId, $method, $expectedJson, $expectedDropped] = $argv;

try {
    $artifact = json_decode((string) file_get_contents($artifactPath), true, 512, JSON_THROW_ON_ERROR);
    $expected = json_decode($expectedJson, true, 32, JSON_THROW_ON_ERROR);
} catch (Throwable $error) {
    fwrite(STDERR, "malformed JSON: {$error->getMessage()}\n");
    exit(1);
}

$fail = static function (string $message): never {
    fwrite(STDERR, $message . "\n");
    exit(1);
};

$requiredTop = ['schema_version', 'request_id', 'pid', 'method', 'uri', 'event_count', 'dropped_event_count', 'events'];
foreach ($requiredTop as $field) {
    if (!array_key_exists($field, $artifact)) $fail("missing top-level field: $field");
}
if ($artifact['schema_version'] !== 1) $fail('schema_version mismatch');
if ($artifact['request_id'] !== $requestId) $fail('request_id mismatch');
if ($artifact['method'] !== $method) $fail('method mismatch');
if (!is_int($artifact['pid']) || $artifact['pid'] < 1) $fail('invalid pid');
if (!is_string($artifact['uri']) || !str_starts_with($artifact['uri'], '/')) $fail('invalid uri');
if (str_contains($artifact['uri'], '?')) {
    $query = explode('?', $artifact['uri'], 2)[1];
    foreach (preg_split('/[&;]/', $query) as $part) {
        if ($part !== '' && !str_ends_with($part, '=<redacted>')) $fail('URI query value was not redacted');
    }
}
if (!is_array($artifact['events']) || $artifact['event_count'] !== count($artifact['events'])) $fail('event_count mismatch');
if ($artifact['dropped_event_count'] !== (int) $expectedDropped) $fail('dropped_event_count mismatch');
if (count($artifact['events']) !== count($expected)) $fail('unexpected event count');

foreach ($artifact['events'] as $index => $event) {
    $want = $expected[$index];
    foreach (['source', 'path', 'operation', 'file', 'line', 'function', 'class'] as $field) {
        if (!array_key_exists($field, $event)) $fail("event $index missing $field");
    }
    if ($event['source'] !== $want[0]) $fail("event $index source mismatch");
    if ($event['path'] !== $want[1]) $fail("event $index path mismatch");
    if ($event['operation'] !== $want[2]) $fail("event $index operation mismatch");
    if (!is_string($event['file']) || !str_ends_with($event['file'], '.php')) $fail("event $index invalid file");
    if (!is_int($event['line']) || $event['line'] < 1) $fail("event $index invalid line");
    if ($event['function'] !== $want[3]) $fail("event $index function mismatch");
    if ($event['class'] !== null) $fail("event $index unexpected class");
    foreach ($event['path'] as $key) {
        if (!is_string($key) && !is_int($key)) $fail("event $index path contains non-scalar key");
    }
}
