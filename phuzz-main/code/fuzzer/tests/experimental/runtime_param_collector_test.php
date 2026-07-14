<?php
declare(strict_types=1);

function helper_phase4_post($key) { return $_POST[$key] ?? null; }
class HelperPhase4Get { public function get($name) { return $_GET[$name] ?? null; } }

putenv('HOOKPHUZZ_PARAM_DISCOVERY_MODE=dynamic-helper');
$registryPath = tempnam(sys_get_temp_dir(), 'hookphuzz-reader-');
$registry = [
    'schema_version' => 'hookphuzz-helper-reader-registry-v2',
    'readers' => [[
        'schema_version' => 'hookphuzz-helper-reader-v2',
        'symbol' => 'helper_phase4_post',
        'symbol_type' => 'function',
        'formal_key_argument_index' => 0,
        'formal_key_argument_name' => 'key',
        'http_source' => 'POST',
        'reader_kind' => 'custom_helper',
        'definition_file' => __FILE__,
        'definition_start_line' => 4,
        'definition_end_line' => 4,
        'source_expression' => '$_POST[$key]',
        'evidence' => ['source_expression' => '$_POST[$key]', 'source_line' => 4, 'return_relation' => 'returns_value_read_from_http_source'],
        'confidence' => 'high',
        'analysis_mode' => 'source-assisted',
    ], [
        'schema_version' => 'hookphuzz-helper-reader-v2',
        'symbol' => 'HelperPhase4Get::get',
        'symbol_type' => 'instance_method',
        'declaring_class' => 'HelperPhase4Get',
        'method_name' => 'get',
        'formal_key_argument_index' => 0,
        'formal_key_argument_name' => 'name',
        'http_source' => 'GET',
        'reader_kind' => 'custom_helper',
        'definition_file' => __FILE__,
        'definition_start_line' => 5,
        'definition_end_line' => 5,
        'source_expression' => '$_GET[$name]',
        'evidence' => ['source_expression' => '$_GET[$name]', 'source_line' => 5, 'return_relation' => 'returns_value_read_from_http_source'],
        'confidence' => 'high',
        'analysis_mode' => 'source-assisted',
    ], [
        'schema_version' => 'hookphuzz-helper-reader-v2',
        'symbol' => 'bad_low',
        'symbol_type' => 'function',
        'formal_key_argument_index' => 0,
        'formal_key_argument_name' => 'key',
        'http_source' => 'POST',
        'definition_file' => __FILE__,
        'definition_start_line' => 1,
        'definition_end_line' => 1,
        'evidence' => ['source_expression' => '$_POST[$key]', 'source_line' => 1],
        'confidence' => 'low',
        'analysis_mode' => 'source-assisted',
    ]],
];
file_put_contents($registryPath, json_encode($registry));
putenv('HOOKPHUZZ_HELPER_READER_REGISTRY=' . $registryPath);
register_shutdown_function(static function () use ($registryPath): void { @unlink($registryPath); });
require_once __DIR__ . '/../../../web/instrumentation/hook_coverage/runtime_param_collector.php';

$check = static function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};
$callback = ['callback_id' => 'callback-1', 'callback_repr' => 'phase4_handler', 'hook_name' => 'wp_ajax_phase4'];

hookphuzz_runtime_param_collector_init();
$readers = hookphuzz_runtime_param_reader_registry();
$check(count($readers) === 2, 'valid registry entries accepted and low confidence rejected');
$debug = hookphuzz_runtime_param_get_debug_metadata();
$check(($debug['registry_rejections'][0]['reason'] ?? '') === 'low_confidence', 'rejection reason recorded');

hookphuzz_runtime_param_record($readers[0], ['runtime_only_field'], $callback);
hookphuzz_runtime_param_record($readers[0], ['runtime_only_field'], $callback);
hookphuzz_runtime_param_record($readers[1], ['lookup'], $callback);
hookphuzz_runtime_param_record($readers[0], ['bad space'], $callback);
$discoveries = hookphuzz_runtime_param_get_discoveries();
$check(count($discoveries) === 2, 'distinct reader/source observations retained');
$check($discoveries[0]['parameter_name'] === 'runtime_only_field', 'POST runtime-only key observed');
$check($discoveries[0]['http_source'] === 'POST', 'POST source preserved');
$check($discoveries[0]['reader_function'] === 'helper_phase4_post', 'function reader symbol preserved');
$check($discoveries[0]['observation_count'] === 2, 'duplicate observations coalesce');
$check($discoveries[1]['http_source'] === 'GET', 'GET source preserved');

putenv('HOOKPHUZZ_PARAM_DISCOVERY_MODE=static');
hookphuzz_runtime_param_collector_init();
hookphuzz_runtime_param_record($readers[0], ['runtime_only_field'], $callback);
$check(hookphuzz_runtime_param_get_discoveries() === [], 'static mode must not collect');

echo "runtime_param_collector_test: OK\n";


