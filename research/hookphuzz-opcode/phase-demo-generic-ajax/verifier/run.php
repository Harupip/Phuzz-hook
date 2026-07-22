<?php
declare(strict_types=1);

require __DIR__ . '/recursive-discovery.php';

$workspace = '/workspace';
$results = $workspace . '/results';
$shared = '/shared';
$runId = (string)(getenv('HOOKPHUZZ_DEMO_RUN_ID') ?: '');
$requestedHook = (string)(getenv('HOOKPHUZZ_DEMO_HOOK') ?: '');
$targetFile = 'wordpress/wp-content/plugins/hookphuzz-demo-target/hookphuzz-demo-target.php';
$workspaceName = 'research/hookphuzz-opcode/phase-demo-generic-ajax';
$selfCheck = ($argv[1] ?? '') === '--self-check';
if ($runId === '' && !$selfCheck) {
    fwrite(STDERR, "missing HOOKPHUZZ_DEMO_RUN_ID\n");
    exit(2);
}
@mkdir($results, 0777, true);

function writeJson(string $path, array $value): void {
    $tmp = $path . '.tmp.' . getmypid();
    $json = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    if (file_put_contents($tmp, $json . "\n", LOCK_EX) === false || !rename($tmp, $path)) {
        @unlink($tmp);
        throw new RuntimeException("cannot write $path");
    }
}

function writeText(string $path, string $value): void {
    if (file_put_contents($path, $value) === false) throw new RuntimeException("cannot write $path");
}

function keepUserArtifacts(): void {
    global $results;
    $keep = ['phuzz-config.json', 'recursive-discovery.json', 'executed-replay-configs.json', 'config-flow.md', 'run.stdout.log'];
    foreach (glob($results . '/*') ?: [] as $path) {
        if (is_file($path) && !in_array(basename($path), $keep, true)) @unlink($path);
    }
}

function stage(int $number, string $message): void {
    printf('[%d/7] %s%s', $number, $message, PHP_EOL);
}

function fail(string $reason, array $extra = []): never {
    global $results, $runId, $workspaceName, $targetFile;
    try {
        writeText($results . '/config-flow.md', "# HookPhuzz config flow\n\nStatus: **FAIL** (`$reason`)\n\nRun: `$runId`\n\nDetails: `" . json_encode($extra) . "`\n");
        keepUserArtifacts();
    } catch (Throwable) {
    }
    printf("PHASE_DEMO_GENERIC_AJAX_FAIL\nREASON=%s\n", $reason);
    exit(1);
    throw new RuntimeException($reason);
}

function readJson(string $path, string $reason): array {
    if (!is_file($path)) fail($reason, ['path' => $path]);
    try {
        $value = json_decode((string)file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        fail($reason, ['path' => $path]);
    }
    if (!is_array($value)) fail($reason, ['path' => $path]);
    return $value;
}

function waitForFile(string $path, int $attempts = 200): bool {
    for ($i = 0; $i < $attempts; $i++) {
        if (is_file($path)) return true;
        usleep(100000);
    }
    return false;
}

function entrypoint(string $hook): ?array {
    if (str_starts_with($hook, 'wp_ajax_nopriv_')) {
        return ['entrypoint_type' => 'wp_ajax_nopriv', 'action' => substr($hook, strlen('wp_ajax_nopriv_')), 'requires_auth' => false];
    }
    if (str_starts_with($hook, 'wp_ajax_')) {
        return ['entrypoint_type' => 'wp_ajax', 'action' => substr($hook, strlen('wp_ajax_')), 'requires_auth' => true];
    }
    return null;
}

function selectedTarget(array $registry, string $requestedHook): array {
    $registrations = $registry['registrations'] ?? null;
    if (!is_array($registrations)) fail('NO_AJAX_HOOK_FOUND', ['diagnostic' => 'malformed_registry']);
    $valid = [];
    foreach ($registrations as $row) {
        if (!is_array($row) || !is_string($row['hook'] ?? null) || !is_string($row['canonical_callback'] ?? null)) continue;
        $row['entrypoint'] = entrypoint($row['hook']);
        $valid[] = $row;
    }
    if ($requestedHook !== '') {
        $valid = array_values(array_filter($valid, static fn(array $row): bool => $row['hook'] === $requestedHook));
        if ($valid === []) fail('NO_AJAX_HOOK_FOUND', ['requested_hook' => $requestedHook]);
        if ($valid[0]['entrypoint'] === null) fail('UNSUPPORTED_ENTRYPOINT', ['hook' => $requestedHook]);
    } else {
        $valid = array_values(array_filter($valid, static fn(array $row): bool => $row['entrypoint'] !== null));
        if ($valid === []) {
            if (($registrations ?? []) !== []) fail('UNSUPPORTED_ENTRYPOINT', ['hooks' => array_values(array_filter(array_column($registrations, 'hook'), 'is_string'))]);
            fail('NO_AJAX_HOOK_FOUND');
        }
    }
    $unique = [];
    foreach ($valid as $row) $unique[$row['hook'] . "\0" . strtolower($row['canonical_callback'])] = $row;
    $unique = array_values($unique);
    if (count($unique) !== 1) {
        fail('AMBIGUOUS_TARGET', ['candidates' => array_map(static fn(array $row): array => ['hook' => $row['hook'], 'callback' => $row['canonical_callback']], $unique)]);
    }
    $selected = $unique[0];
    return [
        'hook' => $selected['hook'],
        'entrypoint_type' => $selected['entrypoint']['entrypoint_type'],
        'action' => $selected['entrypoint']['action'],
        'callback' => $selected['canonical_callback'],
        'callback_type' => $selected['callback_type'] ?? 'unknown',
        'priority' => $selected['priority'] ?? 10,
        'accepted_args' => $selected['accepted_args'] ?? 1,
        'plugin' => $selected['plugin'] ?? 'hookphuzz-demo-target',
        'requires_auth' => $selected['entrypoint']['requires_auth'],
    ];
}

function curlRequest(string $id, array $target, array $query = [], array $body = [], array $cookies = [], ?string $cookieJar = null): array {
    global $runId;
    $responseFile = tempnam(sys_get_temp_dir(), 'hookphuzz-demo-response-');
    if ($responseFile === false) fail('CALLBACK_NOT_REACHED', ['diagnostic' => 'temporary_response_create_failed']);
    $url = 'http://wordpress/wp-admin/admin-ajax.php';
    if ($query !== []) $url .= '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    $cmd = ['curl', '-sS', '--max-time', '20', '-o', $responseFile, '-w', '%{http_code}', '-X', 'POST', '-H', 'X-Fuzzer-Covid: ' . $id, '-H', 'X-Phase9-Run-ID: ' . $runId];
    if ($cookieJar !== null) $cmd[] = '-b';
    if ($cookieJar !== null) $cmd[] = $cookieJar;
    foreach ($cookies as $name => $value) {
        $cmd[] = '-b';
        $cmd[] = $name . '=' . $value;
    }
    $body = ['action' => $target['action']] + $body;
    foreach ($body as $name => $value) {
        $cmd[] = '--data-urlencode';
        $cmd[] = $name . '=' . $value;
    }
    $cmd[] = $url;
    $rawStatus = (string)shell_exec(implode(' ', array_map('escapeshellarg', $cmd)) . ' ; printf "\n__HOOKPHUZZ_CURL_EXIT=%s" "$?"');
    preg_match('/\n__HOOKPHUZZ_CURL_EXIT=(\d+)$/', $rawStatus, $match);
    $curlExit = isset($match[1]) ? (int)$match[1] : 1;
    $status = (int)trim(preg_replace('/\n__HOOKPHUZZ_CURL_EXIT=\d+$/', '', $rawStatus));
    $response = (string)file_get_contents($responseFile);
    @unlink($responseFile);
    $artifactPath = '/shared/opcode-events/' . $id . '.json';
    $found = waitForFile($artifactPath);
    return ['http_status' => $status, 'response' => $response, 'artifact_found' => $found, 'artifact_path' => $artifactPath, 'timeout' => $curlExit === 28];
}

function callbackEvents(array $artifact, string $callback): array {
    $out = [];
    foreach (($artifact['events'] ?? []) as $event) {
        if (!is_array($event) || ($event['callback_context']['root_callback'] ?? null) !== $callback) continue;
        $operation = $event['operation'] ?? 'read';
        if ($operation === 'null_coalesce') $operation = 'coalesce';
        $out[] = [
            'root_callback' => $callback,
            'function' => $event['callback_context']['current_function'] ?? $callback,
            'depth' => $event['callback_context']['depth'] ?? 0,
            'source' => $event['source'] ?? null,
            'path' => $event['path'] ?? [],
            'operation' => $operation,
        ];
    }
    return $out;
}

function effectiveSource(string $source): ?string {
    return match ($source) {
        'GET' => 'query',
        'POST' => 'body',
        'COOKIE' => 'cookies',
        'REQUEST' => 'body',
        default => null,
    };
}

function pathName(array $path): string {
    $name = '';
    foreach ($path as $index => $part) $name .= $index === 0 ? (string)$part : '[' . $part . ']';
    return $name;
}

function replayConfig(array $target, array $input): array {
    return [
        'method' => 'POST',
        'query' => $input['query'],
        'body' => ['action' => $target['action']] + $input['body'],
        'cookies' => $input['cookies'],
    ];
}

function parameterLabels(array $parameters): array {
    return array_map(static fn(array $parameter): string => $parameter['source'] . '.' . $parameter['name'], $parameters);
}

function discoveredParameters(array $events): array {
    $grouped = [];
    foreach ($events as $event) {
        if (!in_array($event['source'], ['GET', 'POST', 'REQUEST', 'COOKIE'], true) || !is_array($event['path']) || $event['path'] === []) continue;
        $effective = effectiveSource($event['source']);
        if ($effective === null) continue;
        $key = $event['source'] . "\0" . json_encode($event['path']);
        if (!isset($grouped[$key])) {
            $grouped[$key] = ['source' => $event['source'], 'effective_source' => $effective, 'path' => $event['path'], 'name' => pathName($event['path']), 'operations' => [], 'observed_count' => 0];
        }
        $grouped[$key]['operations'][$event['operation']] = true;
        $grouped[$key]['observed_count']++;
    }
    $parameters = array_values($grouped);
    foreach ($parameters as &$parameter) {
        $parameter['operations'] = array_keys($parameter['operations']);
        sort($parameter['operations']);
    }
    unset($parameter);
    $parameters = array_values(array_filter($parameters, static function (array $candidate) use ($parameters): bool {
        foreach ($parameters as $other) {
            if ($other === $candidate || $other['source'] !== $candidate['source'] || count($other['path']) <= count($candidate['path'])) continue;
            if (array_slice($other['path'], 0, count($candidate['path'])) === $candidate['path']) return false;
        }
        return true;
    }));
    usort($parameters, static fn(array $a, array $b): int => [$a['source'], $a['name']] <=> [$b['source'], $b['name']]);
    return $parameters;
}

function matchesParameter(array $events, array $parameter): bool {
    foreach ($events as $event) {
        if ($event['source'] === $parameter['source'] && $event['path'] === $parameter['path']) return true;
    }
    return false;
}

function containsMarker(string $response, string $marker): bool {
    return str_contains($response, $marker);
}

function login(): ?string {
    $jar = tempnam(sys_get_temp_dir(), 'hookphuzz-demo-auth-');
    if ($jar === false) return null;
    $cmd = ['curl', '-sS', '--max-time', '20', '-c', $jar, '-d', 'log=hookphuzzdemo', '-d', 'pwd=hookphuzzdemo', '-d', 'wp-submit=Log+In', '-d', 'redirect_to=/wp-admin/', 'http://wordpress/wp-login.php'];
    shell_exec(implode(' ', array_map('escapeshellarg', $cmd)));
    $contents = (string)file_get_contents($jar);
    if (!str_contains($contents, 'wordpress_logged_in_')) {
        @unlink($jar);
        return null;
    }
    return $jar;
}

if ($selfCheck) {
    $nopriv = entrypoint('wp_ajax_nopriv_save_profile');
    $auth = entrypoint('wp_ajax_update_settings');
    $selected = selectedTarget(['registrations' => [[
        'hook' => 'wp_ajax_nopriv_save_profile',
        'callback' => 'Demo_Handler::handle',
        'canonical_callback' => 'Demo_Handler::handle',
        'callback_type' => 'object_method',
        'priority' => 10,
        'accepted_args' => 1,
        'plugin' => 'hookphuzz-demo-target',
    ]]], '');
    $nested = discoveredParameters([
        ['source' => 'REQUEST', 'path' => ['profile'], 'operation' => 'silent_read'],
        ['source' => 'REQUEST', 'path' => ['profile', 'name'], 'operation' => 'coalesce'],
    ]);
    $traceConfig = replayConfig(['action' => 'save_profile'], ['query' => ['test' => '1', 'mo' => '1'], 'body' => [], 'cookies' => []]);
    if (($nopriv['action'] ?? null) !== 'save_profile' || ($nopriv['requires_auth'] ?? true) || ($auth['action'] ?? null) !== 'update_settings' || !($auth['requires_auth'] ?? false) || ($selected['callback'] ?? null) !== 'Demo_Handler::handle' || ($selected['action'] ?? null) !== 'save_profile' || pathName(['profile', 'name']) !== 'profile[name]' || count($nested) !== 1 || $nested[0]['name'] !== 'profile[name]' || $traceConfig['query'] !== ['test' => '1', 'mo' => '1'] || $traceConfig['body'] !== ['action' => 'save_profile']) {
        fwrite(STDERR, "self-check failed\n");
        exit(1);
    }
    echo "self-check passed\n";
    return;
}

if (trim((string)@file_get_contents($shared . '/extension-loaded.txt')) !== 'loaded') fail('EXTENSION_NOT_LOADED');
if (trim((string)@file_get_contents($shared . '/plugin-active.txt')) !== 'active') fail('PLUGIN_NOT_ACTIVE');
stage(2, 'Plugin active');

shell_exec("curl -fsS --max-time 20 http://wordpress/wp-login.php >/dev/null");
if (!waitForFile($shared . '/hook-registration.json')) fail('NO_AJAX_HOOK_FOUND', ['diagnostic' => 'registry_missing']);
$registry = readJson($shared . '/hook-registration.json', 'NO_AJAX_HOOK_FOUND');
$target = selectedTarget($registry, $requestedHook);
stage(3, 'AJAX hook discovered');

$jar = null;
if ($target['requires_auth']) {
    $jar = login();
    if ($jar === null) fail('AUTH_BLOCKED');
}

$discoveryId = $runId . '-discovery';
$executedConfigs = [];
$discovery = curlRequest($discoveryId, $target, [], [], [], $jar);
if ($discovery['timeout']) {
    writeJson($results . '/recursive-discovery.json', ['status' => 'FAIL', 'discovery_depth' => 0, 'replay_count' => 1, 'gate_params' => (object)[], 'discovered_params' => [], 'fuzz_params' => [], 'stop_reason' => 'timeout']);
    fail('TIMEOUT');
}
if (!$discovery['artifact_found']) {
    writeJson($results . '/recursive-discovery.json', ['status' => 'FAIL', 'discovery_depth' => 0, 'replay_count' => 1, 'gate_params' => (object)[], 'discovered_params' => [], 'fuzz_params' => [], 'stop_reason' => 'callback_not_reached']);
    fail('CALLBACK_NOT_REACHED', ['diagnostic' => 'discovery_artifact_missing']);
}
$discoveryArtifact = readJson($discovery['artifact_path'], 'CALLBACK_NOT_REACHED');
$events = callbackEvents($discoveryArtifact, $target['callback']);
if ($events === []) {
    writeJson($results . '/recursive-discovery.json', ['status' => 'FAIL', 'discovery_depth' => 0, 'replay_count' => 1, 'gate_params' => (object)[], 'discovered_params' => [], 'fuzz_params' => [], 'stop_reason' => 'callback_not_reached']);
    fail('CALLBACK_NOT_REACHED', ['http_status' => $discovery['http_status']]);
}
stage(4, 'Callback reached');

$parameters = discoveredParameters($events);
$executedConfigs[] = [
    'sequence' => 1,
    'request_id' => $discoveryId,
    'candidate' => null,
    'request_config' => replayConfig($target, ['query' => [], 'body' => [], 'cookies' => []]),
    'callback_reached' => true,
    'observed_params' => parameterLabels($parameters),
];
$recursiveReplay = 0;
$discoveryReport = recursiveRuntimeDiscovery($parameters, static function (array $input, array $candidate) use (&$recursiveReplay, &$executedConfigs, $runId, $target, $jar): array {
    $id = $runId . '-recursive-' . $recursiveReplay++;
    $request = curlRequest($id, $target, $input['query'], $input['body'], $input['cookies'], $jar);
    $trace = ['sequence' => count($executedConfigs) + 1, 'request_id' => $id, 'candidate' => $candidate['source'] . '.' . $candidate['name'], 'request_config' => replayConfig($target, $input), 'callback_reached' => false, 'observed_params' => []];
    if ($request['timeout']) {
        $trace['timeout'] = true;
        $executedConfigs[] = $trace;
        return ['callback_reached' => false, 'timeout' => true];
    }
    if (!$request['artifact_found']) {
        $executedConfigs[] = $trace;
        return ['callback_reached' => false];
    }
    try {
        $artifact = json_decode((string)file_get_contents($request['artifact_path']), true, 512, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        $executedConfigs[] = $trace;
        return ['callback_reached' => false];
    }
    $events = callbackEvents(is_array($artifact) ? $artifact : [], $target['callback']);
    $parameters = discoveredParameters($events);
    $trace['callback_reached'] = $events !== [];
    $trace['observed_params'] = parameterLabels($parameters);
    $executedConfigs[] = $trace;
    return ['callback_reached' => $events !== [], 'parameters' => $parameters];
});
writeJson($results . '/recursive-discovery.json', $discoveryReport);
writeJson($results . '/executed-replay-configs.json', ['status' => $discoveryReport['status'], 'stop_reason' => $discoveryReport['stop_reason'], 'configs' => $executedConfigs]);
if ($discoveryReport['status'] !== 'PASS') fail(strtoupper($discoveryReport['stop_reason']));
$parameters = $discoveryReport['discovered_params'];
stage(5, 'Recursive parameter discovery PASS');

$sections = ['body_params' => ['data' => [['name' => 'action', 'value' => $target['action']]], 'fixed' => ['action'], 'fuzz' => [], 'weight' => 1]];
foreach ($parameters as $parameter) {
    $section = match ($parameter['effective_source']) {
        'body' => 'body_params',
        'query' => 'query_params',
        'cookies' => 'cookies',
    };
    if (!isset($sections[$section])) $sections[$section] = ['data' => [], 'fixed' => [], 'fuzz' => [], 'weight' => 1];
    if (is_array($discoveryReport['gate_params']) && isset($discoveryReport['gate_params'][$parameter['name']])) {
        $sections[$section]['data'][] = ['name' => $parameter['name'], 'value' => '1'];
        $sections[$section]['fixed'][] = $parameter['name'];
    } else {
        $sections[$section]['data'][] = ['name' => $parameter['name'], 'value' => 'fuzz'];
        $sections[$section]['fuzz'][] = $parameter['name'];
    }
}
$phuzzConfig = [
    'target' => 'http://web/wp-admin/admin-ajax.php',
    'methods' => ['POST'],
    'print_timestamps' => true,
    'entrypoint_type' => $target['requires_auth'] ? 'ajax_authenticated' : 'ajax_unauthenticated',
] + $sections + [
    'config_type' => (count($sections['body_params']['fuzz']) + count($sections['query_params']['fuzz'] ?? [])) > 0 ? 'fuzzing_ready' : 'replay_only',
    'metadata' => [
        'entrypoint_type' => $target['requires_auth'] ? 'ajax_authenticated' : 'ajax_unauthenticated',
        'hook_name' => $target['hook'],
        'callback_repr' => $target['callback'],
        'auth_mode' => $target['requires_auth'] ? 'authenticated' : 'unauth-capable',
        'generated_reason' => 'runtime_opcode_replay_passed',
        'fuzzing_ready' => (count($sections['body_params']['fuzz']) + count($sections['query_params']['fuzz'] ?? [])) > 0,
        'setup_required' => false,
        'manual_analysis' => false,
    ],
];
try {
    writeJson($results . '/phuzz-config.json', $phuzzConfig);
} catch (Throwable) {
    fail('CONFIG_GENERATION_FAIL');
}
$flow = ['# HookPhuzz config flow', '', 'Status: **PASS**', '', '1. Plugin registers `' . $target['hook'] . '` at runtime.', '2. Runner resolves fixed `action=' . $target['action'] . '` and calls the callback.', '3. Zend opcode events discover parameter paths from one ungated replay.', '4. Each candidate is replayed with fixed value `1`, up to depth 3 and 10 replays.', '5. [executed-replay-configs.json](executed-replay-configs.json) records every config actually sent, in order.', '6. Candidates that reveal deeper paths become fixed gates; the remaining paths are fuzz parameters.', '7. Only now is [phuzz-config.json](phuzz-config.json) exported for PHUZZ.', '', '## Fuzz parameters'];
foreach ($parameters as $parameter) {
    if (is_array($discoveryReport['gate_params']) && isset($discoveryReport['gate_params'][$parameter['name']])) continue;
    $flow[] = '- `' . $parameter['source'] . '.' . $parameter['name'] . '` -> `' . $parameter['effective_source'] . '`';
}
$flow[] = '';
$flow[] = 'Run `./run.sh` again after editing the target plugin; the loop starts fresh and replaces this config only after validation passes.';
writeText($results . '/config-flow.md', implode("\n", $flow) . "\n");
keepUserArtifacts();
if ($jar !== null) @unlink($jar);
printf("PHASE_DEMO_GENERIC_AJAX_PASS\n");
