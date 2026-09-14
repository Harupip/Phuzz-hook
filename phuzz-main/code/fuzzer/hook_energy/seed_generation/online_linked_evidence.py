from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Mapping
from typing import Any


class RuntimeBatchTimeout(RuntimeError):
    """The bounded transport did not complete before its timeout."""


RUNTIME_BATCH_SCRIPT = r'''
$runId = (string) ($argv[1] ?? '');
$pluginSlug = (string) ($argv[2] ?? '');
$startedAt = microtime(true);
$stats = [
    'file_count' => 0,
    'run_plugin_matches' => 0,
    'paired_count' => 0,
    'missing_zend' => 0,
    'invalid_payloads' => 0,
    'temp_files' => 0,
    'last_reason' => '',
];
$pairs = [];
$requestDir = '/shared-tmpfs/hook-coverage/requests';
$zendDir = '/shared/opcode-events';

$validRequestId = static function ($value): bool {
    $value = (string) $value;
    return $value !== ''
        && $value !== '.'
        && $value !== '..'
        && preg_match('/\\A[A-Za-z0-9_.-]+\\z/D', $value) === 1
        && strpos($value, '.tmp') === false;
};
$firstNonEmpty = static function ($payload, array $fields): string {
    foreach ($fields as $field) {
        if (isset($payload->{$field}) && (string) $payload->{$field} !== '') {
            return (string) $payload->{$field};
        }
    }
    return '';
};
$invalid = static function (array &$stats, string $reason): void {
    $stats['invalid_payloads']++;
    $stats['last_reason'] = $reason;
};

$files = glob($requestDir . '/*') ?: [];
foreach ($files as $requestPath) {
    if (!is_file($requestPath)) {
        continue;
    }
    $stats['file_count']++;
    $requestName = basename($requestPath);
    if (preg_match('/\\.json\\.tmp(?:\\.|$)/', $requestName) === 1) {
        $stats['temp_files']++;
        continue;
    }
    if (substr($requestName, -5) !== '.json') {
        continue;
    }
    $requestId = substr($requestName, 0, -5);
    if (!$validRequestId($requestId)) {
        $invalid($stats, 'INVALID_REQUEST_FILENAME');
        continue;
    }
    $rawRequest = @file_get_contents($requestPath);
    if ($rawRequest === false) {
        $invalid($stats, 'REQUEST_READ_FAILED');
        continue;
    }
    try {
        $request = json_decode($rawRequest, false, 512, JSON_THROW_ON_ERROR);
    } catch (Throwable $error) {
        $invalid($stats, 'REQUEST_JSON_INVALID');
        continue;
    }
    if (!($request instanceof stdClass)) {
        $invalid($stats, 'REQUEST_JSON_NOT_OBJECT');
        continue;
    }
    if ((string) ($request->request_id ?? '') !== $requestId) {
        $invalid($stats, 'REQUEST_ID_MISMATCH');
        continue;
    }
    if ($firstNonEmpty($request, ['legacy_run_id', 'run_id']) !== $runId) {
        continue;
    }
    if ((string) ($request->target_plugin ?? '') !== $pluginSlug) {
        continue;
    }
    $stats['run_plugin_matches']++;
    $zendName = $requestId . '.json';
    if (!$validRequestId($requestId)) {
        $invalid($stats, 'INVALID_ZEND_FILENAME');
        continue;
    }
    $zendPath = $zendDir . '/' . $zendName;
    if (!is_file($zendPath)) {
        $stats['missing_zend']++;
        $stats['last_reason'] = 'MISSING_ZEND';
        continue;
    }
    $rawZend = @file_get_contents($zendPath);
    if ($rawZend === false) {
        $invalid($stats, 'ZEND_READ_FAILED');
        continue;
    }
    try {
        $zend = json_decode($rawZend, false, 512, JSON_THROW_ON_ERROR);
    } catch (Throwable $error) {
        $invalid($stats, 'ZEND_JSON_INVALID');
        continue;
    }
    if (!($zend instanceof stdClass)) {
        $invalid($stats, 'ZEND_JSON_NOT_OBJECT');
        continue;
    }
    if ((string) ($zend->request_id ?? '') !== $requestId) {
        $invalid($stats, 'ZEND_REQUEST_ID_MISMATCH');
        continue;
    }
    if ($firstNonEmpty($zend, ['run_id', 'legacy_run_id']) !== $runId) {
        $invalid($stats, 'ZEND_RUN_ID_MISMATCH');
        continue;
    }
    $pairs[] = [
        'request_name' => $requestName,
        'request_json' => $rawRequest,
        'zend_name' => $zendName,
        'zend_json' => $rawZend,
    ];
}
$stats['paired_count'] = count($pairs);
$stats['duration_ms'] = round((microtime(true) - $startedAt) * 1000, 2);
echo json_encode(
    ['pairs' => $pairs, 'stats' => $stats],
    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION
);
'''


def read_runtime_batch(
    *,
    run_id: str,
    plugin_slug: str,
    timeout: float,
    run_command: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Read one run/plugin-filtered request/Zend batch inside the web container."""
    if timeout <= 0:
        raise RuntimeError("RUNTIME_BATCH_BUDGET_EXPIRED")
    command = [
        "docker", "compose", "exec", "-T", "web", "php",
        "-d", "display_errors=0", "-d", "log_errors=1", "-r",
        RUNTIME_BATCH_SCRIPT, "--", str(run_id), str(plugin_slug),
    ]
    try:
        result = run_command(
            command,
            timeout=float(timeout),
            check=False,
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeBatchTimeout("RUNTIME_BATCH_TIMEOUT") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"RUNTIME_BATCH_FAILED: {exc}") from exc
    if int(getattr(result, "returncode", 1)) != 0:
        detail = str(getattr(result, "stderr", "") or "").strip()
        raise RuntimeError(f"RUNTIME_BATCH_FAILED: {detail or 'docker command failed'}")
    try:
        envelope = json.loads(getattr(result, "stdout", "") or "")
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("RUNTIME_BATCH_INVALID_OUTPUT") from exc
    if not isinstance(envelope, Mapping) or not isinstance(envelope.get("pairs"), list):
        raise RuntimeError("RUNTIME_BATCH_INVALID_OUTPUT")
    for pair in envelope["pairs"]:
        if not isinstance(pair, Mapping):
            raise RuntimeError("RUNTIME_BATCH_INVALID_OUTPUT")
        if not all(isinstance(pair.get(field), str) and pair[field] for field in (
            "request_name", "zend_name",
        )):
            raise RuntimeError("RUNTIME_BATCH_INVALID_OUTPUT")
        try:
            # Decode original bytes on the host: PHP numbers can lose precision.
            pair["request"] = json.loads(pair.pop("request_json"))
            pair["zend"] = json.loads(pair.pop("zend_json"))
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("RUNTIME_BATCH_INVALID_OUTPUT") from exc
        if not isinstance(pair.get("request"), Mapping) or not isinstance(pair.get("zend"), Mapping):
            raise RuntimeError("RUNTIME_BATCH_INVALID_OUTPUT")
    stats = envelope.get("stats")
    if stats is not None and not isinstance(stats, Mapping):
        raise RuntimeError("RUNTIME_BATCH_INVALID_OUTPUT")
    return dict(envelope)
