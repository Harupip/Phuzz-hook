<?php
declare(strict_types=1);

putenv('HOOKPHUZZ_PARAM_DISCOVERY_MODE=dynamic-helper');
$registryPath = tempnam(sys_get_temp_dir(), 'hookphuzz-reader-');
file_put_contents($registryPath, json_encode(['readers' => [[
    'schema_version' => 'hookphuzz-helper-reader-v1',
    'symbol_type' => 'static_method',
    'declaring_class' => 'cfx_form',
    'method_name' => 'post',
    'formal_key_argument_index' => 0,
    'formal_key_argument_name' => 'key',
    'http_source' => 'REQUEST',
    'reader_kind' => 'custom_helper',
    'confidence' => 'high',
    'analysis_mode' => 'source-assisted',
]]]));
putenv('HOOKPHUZZ_HELPER_READER_REGISTRY=' . $registryPath);
register_shutdown_function(static function () use ($registryPath): void { @unlink($registryPath); });
require_once __DIR__ . '/../../../web/instrumentation/hook_coverage/runtime_param_collector.php';

$callback = [
    'callback_id' => 'callback-1',
    'callback_repr' => 'cfx_admin::save_api_settings',
    'hook_name' => 'wp_ajax_vx_form_save_api_settings',
];
$reader = hookphuzz_runtime_param_reader_registry()[0];
$check = static function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};

hookphuzz_runtime_param_collector_init();
hookphuzz_runtime_param_record($reader, ['cfx_settings'], $callback);
hookphuzz_runtime_param_record($reader, ['cfx_settings'], $callback);
hookphuzz_runtime_param_record($reader, ['vx_nonce'], $callback);
hookphuzz_runtime_param_record($reader, ['outside'], null);
foreach ([null, '', [], new stdClass()] as $invalid) {
    hookphuzz_runtime_param_record($reader, [$invalid], $callback);
}
$discoveries = hookphuzz_runtime_param_get_discoveries();
$check(count($discoveries) === 2, 'trusted reads must deduplicate and exclude invalid/untrusted inputs');
$check($discoveries[0]['parameter_name'] === 'cfx_settings', 'expected cfx_settings');
$check($discoveries[0]['http_source'] === 'REQUEST', 'expected REQUEST source');
$check($discoveries[0]['callback_repr'] === 'cfx_admin::save_api_settings', 'expected active callback');
$check($discoveries[0]['observed_value'] === null && $discoveries[0]['value_state'] === 'not_collected', 'values must not be stored');
$check($discoveries[1]['parameter_name'] === 'vx_nonce', 'different parameter must remain distinct');

putenv('HOOKPHUZZ_PARAM_DISCOVERY_MODE=static');
hookphuzz_runtime_param_collector_init();
hookphuzz_runtime_param_record($reader, ['cfx_settings'], $callback);
$check(hookphuzz_runtime_param_get_discoveries() === [], 'static mode must not collect');

echo "runtime_param_collector_test: OK\n";
