<?php
/** Source-proven runtime parameter discovery. */

function hookphuzz_runtime_param_reader_registry(): array
{
    $path = (string) getenv('HOOKPHUZZ_HELPER_READER_REGISTRY');
    if ($path === '' || !is_file($path)) {
        return [];
    }
    $payload = json_decode((string) @file_get_contents($path), true);
    $readers = is_array($payload) && is_array($payload['readers'] ?? null) ? $payload['readers'] : [];
    $result = [];
    foreach ($readers as $reader) {
        if (!is_array($reader)
            || ($reader['schema_version'] ?? '') !== 'hookphuzz-helper-reader-v1'
            || ($reader['symbol_type'] ?? '') !== 'static_method'
            || !is_string($reader['declaring_class'] ?? null)
            || !is_string($reader['method_name'] ?? null)
            || !is_int($reader['formal_key_argument_index'] ?? null)
            || !in_array($reader['http_source'] ?? null, ['GET', 'POST', 'REQUEST', 'COOKIE'], true)
            || ($reader['reader_kind'] ?? '') !== 'custom_helper'
            || ($reader['confidence'] ?? '') !== 'high'
            || ($reader['analysis_mode'] ?? '') !== 'source-assisted') {
            continue;
        }
        $result[] = [
            'class' => $reader['declaring_class'],
            'method' => $reader['method_name'],
            'reader_type' => $reader['reader_kind'],
            'parameter_argument_index' => $reader['formal_key_argument_index'],
            'formal_parameter' => $reader['formal_key_argument_name'] ?? '',
            'http_source' => $reader['http_source'],
            'confidence' => $reader['confidence'],
        ];
    }
    return $result;
}

function hookphuzz_runtime_param_collector_init(): bool
{
    $mode = (string) getenv('HOOKPHUZZ_PARAM_DISCOVERY_MODE');
    $enabled = $mode === 'dynamic-helper' || $mode === 'hybrid';
    $GLOBALS['__hookphuzz_runtime_param'] = [
        'enabled' => $enabled,
        'requested_mode' => $enabled ? $mode : 'static',
        'discoveries' => [],
        'seen' => [],
        'reader_hooks' => [],
        'install_attempts' => 0,
        'discarded' => 0,
        'recording' => false,
    ];
    return $enabled;
}

function hookphuzz_runtime_param_enabled(): bool
{
    return !empty($GLOBALS['__hookphuzz_runtime_param']['enabled']);
}

function hookphuzz_runtime_param_path(string $name): array
{
    if (strpos($name, '[') === false) {
        return [$name];
    }
    preg_match_all('/([^\[\]]+)/', $name, $parts);
    return $parts[1] ?? [$name];
}

function hookphuzz_runtime_param_valid_name($value): bool
{
    return is_string($value)
        && $value !== ''
        && strlen($value) <= 256
        && preg_match('/^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_.-]+\])*$/', $value) === 1;
}

function hookphuzz_runtime_param_reader_location(array $reader): array
{
    try {
        $reflection = new ReflectionMethod($reader['class'], $reader['method']);
        return [$reflection->getFileName() ?: null, $reflection->getStartLine() ?: null];
    } catch (Throwable $e) {
        return [null, null];
    }
}

function hookphuzz_runtime_param_record(array $reader, array $args, ?array $activeCallback): void
{
    $state =& $GLOBALS['__hookphuzz_runtime_param'];
    if (empty($state['enabled']) || !empty($state['recording'])) {
        return;
    }

    $state['recording'] = true;
    try {
        $index = (int) $reader['parameter_argument_index'];
        $name = $args[$index] ?? null;
        if ($activeCallback === null || empty($activeCallback['callback_id']) || !hookphuzz_runtime_param_valid_name($name)) {
            $state['discarded']++;
            return;
        }

        $readerFunction = $reader['class'] . '::' . $reader['method'];
        $key = implode('|', [$activeCallback['callback_id'], $readerFunction, $reader['http_source'], $name]);
        if (isset($state['seen'][$key])) {
            return;
        }
        $state['seen'][$key] = true;
        [$readerFile, $readerLine] = hookphuzz_runtime_param_reader_location($reader);
        $hookName = (string) ($activeCallback['hook_name'] ?? '');
        $entrypointType = strpos($hookName, 'wp_ajax') === 0 ? 'wp_ajax' : null;
        $state['discoveries'][] = [
            'schema_version' => 'hookphuzz-runtime-param-v1',
            'entrypoint_type' => $entrypointType,
            'entrypoint_name' => $hookName !== '' ? $hookName : null,
            'callback_id' => $activeCallback['callback_id'],
            'callback_repr' => $activeCallback['callback_repr'] ?? null,
            'parameter_name' => $name,
            'parameter_path' => hookphuzz_runtime_param_path($name),
            'http_source' => $reader['http_source'],
            'observed_value' => null,
            'value_state' => 'not_collected',
            'reader_type' => $reader['reader_type'],
            'reader_function' => $readerFunction,
            'reader_file' => $readerFile,
            'reader_line' => $readerLine,
            'call_chain' => [$activeCallback['callback_repr'] ?? null, $readerFunction],
            'confidence' => $reader['confidence'],
            'discovery_mode' => $state['requested_mode'],
        ];
    } catch (Throwable $e) {
        $state['discarded']++;
    } finally {
        $state['recording'] = false;
    }
}

function hookphuzz_runtime_param_install_readers(callable $activeCallbackProvider): void
{
    $state =& $GLOBALS['__hookphuzz_runtime_param'];
    if (empty($state['enabled']) || !extension_loaded('uopz') || $state['install_attempts'] >= 3) {
        return;
    }
    $state['install_attempts']++;
    foreach (hookphuzz_runtime_param_reader_registry() as $reader) {
        $symbol = $reader['class'] . '::' . $reader['method'];
        if (($state['reader_hooks'][$symbol]['status'] ?? '') === 'installed') {
            $state['reader_hooks'][$symbol]['status'] = 'already_installed';
            continue;
        }
        if (!class_exists($reader['class'], false) || !method_exists($reader['class'], $reader['method'])) {
            $state['reader_hooks'][$symbol] = ['status' => 'not_defined'];
            continue;
        }
        try {
            $ok = @uopz_set_hook($reader['class'], $reader['method'], static function (...$args) use ($reader, $activeCallbackProvider): void {
                hookphuzz_runtime_param_record($reader, $args, $activeCallbackProvider());
            });
            $state['reader_hooks'][$symbol] = ['status' => $ok ? 'installed' : 'failed'];
        } catch (Throwable $e) {
            $state['reader_hooks'][$symbol] = ['status' => 'failed'];
        }
    }
}

function hookphuzz_runtime_param_get_discoveries(): array
{
    return $GLOBALS['__hookphuzz_runtime_param']['discoveries'] ?? [];
}

function hookphuzz_runtime_param_get_debug_metadata(): array
{
    $state = $GLOBALS['__hookphuzz_runtime_param'] ?? [];
    return [
        'requested_mode' => $state['requested_mode'] ?? 'static',
        'reader_hooks' => $state['reader_hooks'] ?? [],
        'install_attempts' => $state['install_attempts'] ?? 0,
        'discarded' => $state['discarded'] ?? 0,
    ];
}
