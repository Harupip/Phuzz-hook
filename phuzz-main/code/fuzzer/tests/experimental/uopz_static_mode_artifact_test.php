<?php
declare(strict_types=1);

putenv('HOOKPHUZZ_PARAM_DISCOVERY_MODE=static');
require_once __DIR__ . '/../../../web/instrumentation/hook_coverage/uopz_hook_wp.php';

$artifact = __uopz_build_request_export();
if (function_exists('hookphuzz_runtime_param_collector_init') || array_key_exists('runtime_param_discoveries', $artifact)) {
    throw new RuntimeException('static mode loaded runtime parameter discovery');
}

echo "uopz_static_mode_artifact_test: OK\n";
