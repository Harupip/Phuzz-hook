<?php
/**
 * Load the optional UOPZ hook coverage runtime next to the existing line coverage bootstrap.
 */

if (getenv('FUZZER_ENABLE_UOPZ') !== '1') {
    return;
}

if (!extension_loaded('uopz')) {
    return;
}

if (!getenv('FUZZER_HOOK_OUTPUT_DIR')) {
    putenv('FUZZER_HOOK_OUTPUT_DIR=/shared-tmpfs/hook-coverage');
}

if (!getenv('TARGET_APP_PATH')) {
    $targetPlugin = getenv('WP_TARGET_PLUGIN');
    if ($targetPlugin) {
        putenv("TARGET_APP_PATH=/var/www/html/wp-content/plugins/{$targetPlugin}/");
    }
}

$runtimeEntry = __DIR__ . '/../instrumentation/uopz_hook_runtime.php';
if (file_exists($runtimeEntry)) {
    require_once $runtimeEntry;
}

$muPluginSource = __DIR__ . '/uopz_mu_plugin.php';
$muPluginDir = '/var/www/html/wp-content/mu-plugins';
$muPluginTarget = $muPluginDir . '/fuzzer-uopz-bootstrap.php';

if (file_exists($muPluginSource)) {
    if (!is_dir($muPluginDir)) {
        @mkdir($muPluginDir, 0777, true);
    }

    $shouldSync = !file_exists($muPluginTarget)
        || @md5_file($muPluginSource) !== @md5_file($muPluginTarget);

    if ($shouldSync) {
        @copy($muPluginSource, $muPluginTarget);
    }
}
