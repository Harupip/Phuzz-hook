<?php
/** Source-proven runtime parameter discovery. */

const HOOKPHUZZ_HELPER_READER_SCHEMA = 'hookphuzz-helper-reader-v2';
const HOOKPHUZZ_HELPER_REGISTRY_SCHEMA = 'hookphuzz-helper-reader-registry-v2';
const HOOKPHUZZ_READER_SOURCES = ['GET', 'POST', 'REQUEST', 'COOKIE', 'FILTER_INPUT_GET', 'FILTER_INPUT_POST', 'REST_GET_PARAM'];

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
        'registry_rejections' => [],
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

function hookphuzz_runtime_param_reader_registry(): array
{
    $path = (string) getenv('HOOKPHUZZ_HELPER_READER_REGISTRY');
    if ($path === '' || !is_file($path)) {
        return [];
    }
    $payload = json_decode((string) file_get_contents($path), true);
    $state =& $GLOBALS['__hookphuzz_runtime_param'];
    if (!is_array($payload) || ($payload['schema_version'] ?? '') !== HOOKPHUZZ_HELPER_REGISTRY_SCHEMA || !is_array($payload['readers'] ?? null)) {
        $state['registry_rejections'][] = ['symbol' => null, 'reason' => 'unsupported_registry_schema'];
        return [];
    }
    $result = [];
    foreach ($payload['readers'] as $reader) {
        [$ok, $reason] = hookphuzz_runtime_param_validate_reader_row($reader);
        if (!$ok) {
            $state['registry_rejections'][] = ['symbol' => is_array($reader) ? ($reader['symbol'] ?? null) : null, 'reason' => $reason];
            continue;
        }
        $result[] = hookphuzz_runtime_param_normalize_reader($reader);
    }
    return $result;
}

function hookphuzz_runtime_param_validate_reader_row($reader): array
{
    if (!is_array($reader)) {
        return [false, 'malformed_registry_entry'];
    }
    foreach (['schema_version', 'symbol', 'symbol_type', 'formal_key_argument_index', 'formal_key_argument_name', 'http_source', 'definition_file', 'definition_start_line', 'definition_end_line', 'evidence', 'confidence', 'analysis_mode'] as $field) {
        if (!array_key_exists($field, $reader)) {
            return [false, 'missing_required_field:' . $field];
        }
    }
    if ($reader['schema_version'] !== HOOKPHUZZ_HELPER_READER_SCHEMA) {
        return [false, 'unsupported_schema_version'];
    }
    if (!in_array($reader['symbol_type'], ['function', 'static_method', 'instance_method'], true)) {
        return [false, 'unsupported_symbol_type'];
    }
    if (!is_int($reader['formal_key_argument_index']) || $reader['formal_key_argument_index'] < 0 || !is_string($reader['formal_key_argument_name']) || $reader['formal_key_argument_name'] === '') {
        return [false, 'invalid_key_argument_mapping'];
    }
    if (!in_array($reader['http_source'], HOOKPHUZZ_READER_SOURCES, true)) {
        return [false, 'unsupported_source'];
    }
    if ($reader['confidence'] !== 'high') {
        return [false, 'low_confidence'];
    }
    if ($reader['analysis_mode'] !== 'source-assisted') {
        return [false, 'unsupported_analysis_mode'];
    }
    if (!is_array($reader['evidence']) || !is_int($reader['evidence']['source_line'] ?? null) || !is_string($reader['evidence']['source_expression'] ?? null)) {
        return [false, 'missing_evidence'];
    }
    if ($reader['evidence']['source_line'] < $reader['definition_start_line'] || $reader['evidence']['source_line'] > $reader['definition_end_line']) {
        return [false, 'evidence_line_outside_function_body'];
    }
    if ($reader['symbol_type'] !== 'function' && (!is_string($reader['declaring_class'] ?? null) || !is_string($reader['method_name'] ?? null))) {
        return [false, 'missing_method_symbol_fields'];
    }
    return [true, null];
}

function hookphuzz_runtime_param_normalize_reader(array $reader): array
{
    return [
        'symbol' => $reader['symbol'],
        'symbol_type' => $reader['symbol_type'],
        'class' => $reader['declaring_class'] ?? null,
        'method' => $reader['method_name'] ?? null,
        'function' => $reader['symbol_type'] === 'function' ? $reader['symbol'] : null,
        'reader_type' => $reader['reader_kind'] ?? 'custom_helper',
        'parameter_argument_index' => $reader['formal_key_argument_index'],
        'formal_parameter' => $reader['formal_key_argument_name'],
        'http_source' => $reader['http_source'],
        'confidence' => $reader['confidence'],
        'definition_file' => $reader['definition_file'],
        'definition_start_line' => $reader['definition_start_line'],
        'definition_end_line' => $reader['definition_end_line'],
        'evidence' => $reader['evidence'],
    ];
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
    return is_string($value) && $value !== '' && strlen($value) <= 256 && preg_match('/^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_.-]+\])*$/', $value) === 1;
}

function hookphuzz_runtime_param_reader_location(array $reader): array
{
    try {
        $reflection = hookphuzz_runtime_param_reflection($reader);
        return [$reflection->getFileName() ?: null, $reflection->getStartLine() ?: null];
    } catch (Throwable $e) {
        return [null, null];
    }
}

function hookphuzz_runtime_param_reflection(array $reader): ReflectionFunctionAbstract
{
    if ($reader['symbol_type'] === 'function') {
        return new ReflectionFunction((string) $reader['function']);
    }
    return new ReflectionMethod((string) $reader['class'], (string) $reader['method']);
}

function hookphuzz_runtime_param_runtime_symbol_valid(array $reader): array
{
    try {
        if ($reader['symbol_type'] === 'function') {
            if (!function_exists((string) $reader['function'])) {
                return [false, 'runtime_symbol_not_defined'];
            }
        } elseif (!class_exists((string) $reader['class'], false) || !method_exists((string) $reader['class'], (string) $reader['method'])) {
            return [false, 'runtime_symbol_not_defined'];
        }
        $reflection = hookphuzz_runtime_param_reflection($reader);
        $params = $reflection->getParameters();
        $index = (int) $reader['parameter_argument_index'];
        if (!isset($params[$index]) || $params[$index]->getName() !== $reader['formal_parameter']) {
            return [false, 'runtime_signature_mismatch'];
        }
        $registered = str_replace('\\', '/', (string) $reader['definition_file']);
        $actual = str_replace('\\', '/', (string) $reflection->getFileName());
        if ($registered !== '' && $actual !== '' && substr($actual, -strlen(basename($registered))) !== basename($registered)) {
            return [false, 'runtime_source_file_mismatch'];
        }
        return [true, null];
    } catch (Throwable $e) {
        return [false, 'runtime_symbol_validation_failed'];
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
        $readerFunction = $reader['symbol'];
        $key = implode('|', [$activeCallback['callback_id'], $readerFunction, $reader['http_source'], $name]);
        if (isset($state['seen'][$key])) {
            $state['discoveries'][$state['seen'][$key]]['observation_count']++;
            return;
        }
        $state['seen'][$key] = count($state['discoveries']);
        [$readerFile, $readerLine] = hookphuzz_runtime_param_reader_location($reader);
        $hookName = (string) ($activeCallback['hook_name'] ?? '');
        $entrypointType = strpos($hookName, 'wp_ajax') === 0 ? 'wp_ajax' : null;
        $state['discoveries'][] = [
            'schema_version' => 'hookphuzz-runtime-param-v1',
            'entrypoint_type' => $entrypointType,
            'entrypoint_name' => $hookName !== '' ? $hookName : null,
            'callback_id' => $activeCallback['callback_id'],
            'callback_repr' => $activeCallback['callback_repr'] ?? null,
            'callback_source' => $activeCallback['source_file'] ?? null,
            'parameter_name' => $name,
            'parameter_path' => hookphuzz_runtime_param_path($name),
            'http_source' => $reader['http_source'],
            'observed_value' => null,
            'value_state' => 'not_collected',
            'reader_type' => $reader['reader_type'],
            'reader_function' => $readerFunction,
            'reader_file' => $readerFile,
            'reader_line' => $readerLine,
            'plugin_source' => $readerFile,
            'source_expression' => $reader['evidence']['source_expression'] ?? null,
            'evidence_line' => $reader['evidence']['source_line'] ?? null,
            'observation_count' => 1,
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
        $symbol = $reader['symbol'];
        if (($state['reader_hooks'][$symbol]['status'] ?? '') === 'installed') {
            $state['reader_hooks'][$symbol] = ['status' => 'already_installed'];
            continue;
        }
        [$valid, $reason] = hookphuzz_runtime_param_runtime_symbol_valid($reader);
        if (!$valid) {
            $state['reader_hooks'][$symbol] = ['status' => 'rejected', 'reason' => $reason];
            continue;
        }
        try {
            $hook = static function (...$args) use ($reader, $activeCallbackProvider): void {
                hookphuzz_runtime_param_record($reader, $args, $activeCallbackProvider());
            };
            if ($reader['symbol_type'] === 'function') {
                $ok = uopz_set_hook((string) $reader['function'], $hook);
            } else {
                $ok = uopz_set_hook((string) $reader['class'], (string) $reader['method'], $hook);
            }
            $state['reader_hooks'][$symbol] = ['status' => $ok ? 'installed' : 'failed', 'reason' => $ok ? null : 'uopz_set_hook_failed'];
        } catch (Throwable $e) {
            $state['reader_hooks'][$symbol] = ['status' => 'failed', 'reason' => 'uopz_set_hook_exception'];
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
        'registry_rejections' => $state['registry_rejections'] ?? [],
        'install_attempts' => $state['install_attempts'] ?? 0,
        'discarded' => $state['discarded'] ?? 0,
    ];
}

