<?php
declare(strict_types=1);

require __DIR__ . '/../verifier/recursive-discovery.php';

function parameter(string $source, string|array $name): array {
    $path = is_array($name) ? $name : [$name];
    $display = array_shift($path);
    foreach ($path as $part) $display .= '[' . $part . ']';
    return ['source' => $source, 'effective_source' => match ($source) {'GET' => 'query', 'POST', 'REQUEST' => 'body', 'COOKIE' => 'cookies'}, 'path' => is_array($name) ? $name : [$name], 'name' => $display, 'operations' => ['read'], 'observed_count' => 1];
}

function check(bool $condition, string $name): void {
    if (!$condition) throw new RuntimeException("failed: $name");
    echo "PASS $name\n";
}

$getGate = recursiveRuntimeDiscovery([parameter('GET', 'test')], static function (array $input): array {
    return ['callback_reached' => true, 'parameters' => ($input['query']['test'] ?? null) === '1' ? [parameter('GET', 'mo')] : []];
});
check($getGate['status'] === 'PASS' && $getGate['gate_params'] === ['test' => '1'] && in_array('mo', $getGate['fuzz_params'], true) && $getGate['discovery_depth'] === 2 && $getGate['stop_reason'] === 'no_new_params', 'GET gate reveals GET parameter');

$postGate = recursiveRuntimeDiscovery([parameter('POST', 'outer')], static function (array $input): array {
    return ['callback_reached' => true, 'parameters' => ($input['body']['outer'] ?? null) === '1' ? [parameter('POST', ['profile', 'inner'])] : []];
});
check($postGate['gate_params'] === ['outer' => '1'] && in_array('profile[inner]', $postGate['fuzz_params'], true), 'POST gate reveals nested POST parameter');

$nested = recursiveRuntimeDiscovery([parameter('GET', 'outer')], static function (array $input): array {
    if (($input['query']['outer'] ?? null) !== '1') return ['callback_reached' => true, 'parameters' => []];
    if (($input['body']['middle'] ?? null) === '1') return ['callback_reached' => true, 'parameters' => [parameter('POST', 'middle'), parameter('COOKIE', 'deep')]];
    return ['callback_reached' => true, 'parameters' => [parameter('GET', 'fallback'), parameter('POST', 'middle')]];
});
check($nested['gate_params'] === ['middle' => '1', 'outer' => '1'] && $nested['fuzz_params'] === ['deep', 'fallback'] && $nested['discovery_depth'] === 3 && $nested['stop_reason'] === 'no_new_params', 'nested if else reaches depth three');

$noNew = recursiveRuntimeDiscovery([parameter('GET', 'plain')], static fn(array $input): array => ['callback_reached' => true, 'parameters' => []]);
check($noNew['replay_count'] === 2 && $noNew['stop_reason'] === 'no_new_params', 'no new parameter stops after one extra replay');

$depth = recursiveRuntimeDiscovery([parameter('GET', 'one')], static function (array $input, array $candidate): array {
    return ['callback_reached' => true, 'parameters' => [parameter('GET', 'next_' . $candidate['name'])]];
});
check($depth['discovery_depth'] === 3 && $depth['stop_reason'] === 'max_depth', 'maximum depth is respected');

$callbackFailure = recursiveRuntimeDiscovery([parameter('GET', 'test')], static fn(array $input): array => ['callback_reached' => false]);
check($callbackFailure['status'] === 'FAIL' && $callbackFailure['stop_reason'] === 'callback_not_reached', 'callback not reached fails safely');
