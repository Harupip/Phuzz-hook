<?php
declare(strict_types=1);

const HOOKPHUZZ_PHASE_A_MAX_DEPTH = 3;
const HOOKPHUZZ_PHASE_A_MAX_REPLAYS = 10;

function phaseAKey(array $parameter): string {
    return ($parameter['source'] ?? '') . "\0" . json_encode($parameter['path'] ?? []);
}

function phaseARoutingParameter(array $parameter): bool {
    return in_array(($parameter['path'][0] ?? null), ['action', 'rest_route'], true);
}

function phaseAInput(array $gates, array $candidate): array {
    $input = ['query' => [], 'body' => [], 'cookies' => []];
    foreach (array_merge($gates, [$candidate]) as $parameter) {
        $bucket = $parameter['effective_source'] ?? null;
        if (isset($input[$bucket])) $input[$bucket][$parameter['name']] = '1';
    }
    return $input;
}

function phaseAReport(array $all, array $gates, int $depth, int $replays, string $status, string $reason): array {
    $parameters = array_values($all);
    usort($parameters, static fn(array $a, array $b): int => [$a['source'], $a['name']] <=> [$b['source'], $b['name']]);
    $gateParams = [];
    foreach ($gates as $parameter) $gateParams[$parameter['name']] = '1';
    ksort($gateParams);
    $gateKeys = array_fill_keys(array_keys($gates), true);
    return [
        'status' => $status,
        'discovery_depth' => $depth,
        'replay_count' => $replays,
        'gate_params' => $gateParams === [] ? (object)[] : $gateParams,
        'discovered_params' => $parameters,
        'fuzz_params' => array_values(array_map(
            static fn(array $parameter): string => $parameter['name'],
            array_filter($parameters, static fn(array $parameter): bool => !isset($gateKeys[phaseAKey($parameter)]))
        )),
        'stop_reason' => $reason,
    ];
}

/**
 * @param callable(array, array, int): array{callback_reached:bool,timeout?:bool,parameters?:array} $replay
 */
function recursiveRuntimeDiscovery(array $initial, callable $replay, int $maxDepth = HOOKPHUZZ_PHASE_A_MAX_DEPTH, int $maxReplays = HOOKPHUZZ_PHASE_A_MAX_REPLAYS): array {
    $all = [];
    $pending = [];
    foreach ($initial as $parameter) {
        if (!is_array($parameter) || phaseARoutingParameter($parameter)) continue;
        $key = phaseAKey($parameter);
        $all[$key] = $parameter;
        $pending[] = ['parameter' => $parameter, 'depth' => 1];
    }
    $gates = [];
    $depth = $pending === [] ? 0 : 1;
    $replays = 1; // The caller has already performed the ungated replay.

    while ($pending !== []) {
        if ($replays >= $maxReplays) return phaseAReport($all, $gates, $depth, $replays, 'PASS', 'max_replays');
        $next = array_shift($pending);
        $parameter = $next['parameter'];
        $candidateDepth = $next['depth'];
        $result = $replay(phaseAInput($gates, $parameter), $parameter, $candidateDepth);
        $replays++;
        if (($result['timeout'] ?? false) === true) return phaseAReport($all, $gates, $depth, $replays, 'FAIL', 'timeout');
        if (($result['callback_reached'] ?? false) !== true) return phaseAReport($all, $gates, $depth, $replays, 'FAIL', 'callback_not_reached');

        $new = [];
        foreach (($result['parameters'] ?? []) as $observed) {
            if (!is_array($observed) || phaseARoutingParameter($observed)) continue;
            $key = phaseAKey($observed);
            if (!isset($all[$key])) $new[$key] = $observed;
        }
        if ($new === []) continue;

        $gates[phaseAKey($parameter)] = $parameter;
        if ($candidateDepth >= $maxDepth) return phaseAReport($all, $gates, $depth, $replays, 'PASS', 'max_depth');
        foreach ($new as $key => $observed) {
            $all[$key] = $observed;
            $pending[] = ['parameter' => $observed, 'depth' => $candidateDepth + 1];
        }
        $depth = max($depth, $candidateDepth + 1);
    }
    return phaseAReport($all, $gates, $depth, $replays, 'PASS', 'no_new_params');
}
