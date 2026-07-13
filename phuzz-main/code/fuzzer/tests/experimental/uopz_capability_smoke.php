<?php
declare(strict_types=1);

namespace SmokeNs {
    function namespaced(string $value): string { return "ns:$value"; }
}

namespace {
    function register_activation_hook(...$args): void {}
    function register_deactivation_hook(...$args): void {}
    function add_action(...$args): void {}
    function plugin_dir_path(string $path): string { return dirname($path) . '/'; }
    function plugin_dir_url(string $path): string { return 'http://example.test/'; }
    function sanitize_text_field($value) { return $value; }
    function wp_unslash($value) { return $value; }

    function smoke_function(string $value): string { return "fn:$value"; }
    function smoke_duplicate(): string { return 'duplicate'; }
    function some_service(string $value): string { return $value; }
    function get_option(string $value): string { return $value; }

    class SmokeParent { public function inherited(string $value): string { return "parent:$value"; } }
    class SmokeChild extends SmokeParent {}
    class SmokeMethods {
        public function instance(string $value): string { return "instance:$value"; }
        public static function statik(string $value): string { return "static:$value"; }
        protected function protectedValue(string $value): string { return "protected:$value"; }
        private function privateValue(string $value): string { return "private:$value"; }
        public function callProtected(string $value): string { return $this->protectedValue($value); }
        public function callPrivate(string $value): string { return $this->privateValue($value); }
    }

    $results = [
        'php_version' => PHP_VERSION,
        'uopz_loaded' => extension_loaded('uopz'),
        'tests' => [],
    ];
    $seen = [];
    $hook = static function (string $id) use (&$seen): Closure {
        return static function (...$args) use (&$seen, $id): void {
            $seen[$id] = [
                'args' => $args,
                'backtrace_has_hook' => count(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS)) > 0,
            ];
        };
    };
    $check = static function (string $name, bool $passed, array $extra = []) use (&$results): void {
        $results['tests'][$name] = array_merge(['passed' => $passed], $extra);
    };

    $check('namespaced_function_install', uopz_set_hook('SmokeNs\\namespaced', $hook('namespaced')) === true);
    $check('namespaced_function', \SmokeNs\namespaced('one') === 'ns:one' && ($seen['namespaced']['args'] ?? []) === ['one']);

    $object = new SmokeMethods();
    $check('instance_method_install', uopz_set_hook(SmokeMethods::class, 'instance', $hook('instance')) === true);
    $check('instance_method', $object->instance('two') === 'instance:two' && ($seen['instance']['args'] ?? []) === ['two']);
    $check('static_method_install', uopz_set_hook(SmokeMethods::class, 'statik', $hook('static')) === true);
    $check('static_method', SmokeMethods::statik('three') === 'static:three' && ($seen['static']['args'] ?? []) === ['three']);
    $check('inherited_method_install', uopz_set_hook(SmokeParent::class, 'inherited', $hook('inherited')) === true);
    $check('inherited_method', (new SmokeChild())->inherited('four') === 'parent:four' && ($seen['inherited']['args'] ?? []) === ['four']);
    $check('protected_method_install', uopz_set_hook(SmokeMethods::class, 'protectedValue', $hook('protected')) === true);
    $check('protected_method', $object->callProtected('five') === 'protected:five' && ($seen['protected']['args'] ?? []) === ['five']);
    $check('private_method_install', uopz_set_hook(SmokeMethods::class, 'privateValue', $hook('private')) === true);
    $check('private_method', $object->callPrivate('six') === 'private:six' && ($seen['private']['args'] ?? []) === ['six']);

    $check('function_after_definition_install', uopz_set_hook('smoke_function', $hook('after_definition')) === true);
    $check('function_after_definition', smoke_function('seven') === 'fn:seven' && ($seen['after_definition']['args'] ?? []) === ['seven']);

    $initialInventoryHasLate = function_exists('smoke_late');
    eval('function smoke_late(string $value): string { return "late:" . $value; }');
    $check('late_symbol_initial_inventory', $initialInventoryHasLate === false);
    $check('late_symbol_hook_after_definition', uopz_set_hook('smoke_late', $hook('late')) === true);
    $check('late_symbol', smoke_late('eight') === 'late:eight' && ($seen['late']['args'] ?? []) === ['eight']);

    $duplicate = 0;
    $firstInstall = uopz_set_hook('smoke_duplicate', static function () use (&$duplicate): void { $duplicate += 1; });
    $secondInstall = uopz_set_hook('smoke_duplicate', static function () use (&$duplicate): void { $duplicate += 10; });
    $duplicateReturn = smoke_duplicate();
    $check('duplicate_install', $firstInstall === true && $secondInstall === true, ['effect_count' => $duplicate]);
    $check('duplicate_install_behavior', $duplicateReturn === 'duplicate' && $duplicate === 10, ['effect_count' => $duplicate]);

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
    $collectorPath = getenv('HOOKPHUZZ_RUNTIME_PARAM_COLLECTOR')
        ?: __DIR__ . '/../../../web/instrumentation/hook_coverage/runtime_param_collector.php';
    if (!file_exists($collectorPath) && file_exists('/var/www/fuzzer/hook_coverage/runtime_param_collector.php')) {
        $collectorPath = '/var/www/fuzzer/hook_coverage/runtime_param_collector.php';
    }
    require_once $collectorPath;
    hookphuzz_runtime_param_collector_init();
    $activeCallback = [
        'callback_id' => 'cfx-save-api-settings',
        'callback_repr' => 'cfx_admin::save_api_settings',
        'hook_name' => 'wp_ajax_vx_form_save_api_settings',
    ];
    hookphuzz_runtime_param_install_readers(static function () use (&$activeCallback): ?array { return $activeCallback; });
    $check('missing_late_reader', (hookphuzz_runtime_param_get_debug_metadata()['reader_hooks']['cfx_form::post']['status'] ?? null) === 'not_defined');

    require_once '/var/www/html/wp-content/plugins/crm-perks-forms/crm-perks-forms.php';
    $_REQUEST['cfx_settings'] = 'settings-value';
    hookphuzz_runtime_param_install_readers(static function () use (&$activeCallback): ?array { return $activeCallback; });
    hookphuzz_runtime_param_install_readers(static function () use (&$activeCallback): ?array { return $activeCallback; });
    $cfxReturn = cfx_form::post('cfx_settings');
    cfx_form::post('cfx_settings');
    cfx_form::post('vx_nonce');
    some_service('mode');
    get_option('mode');
    $discoveries = hookphuzz_runtime_param_get_discoveries();
    $debug = hookphuzz_runtime_param_get_debug_metadata();
    $check('cfx_form_post_runtime_discovery_and_return', $cfxReturn === 'settings-value' && count($discoveries) === 2 && ($discoveries[0]['parameter_name'] ?? null) === 'cfx_settings' && array_key_exists('observed_value', $discoveries[0]) && $discoveries[0]['observed_value'] === null, ['return' => $cfxReturn, 'discoveries' => $discoveries]);
    $check('runtime_reader_duplicate_hook_protection', ($debug['reader_hooks']['cfx_form::post']['status'] ?? null) === 'already_installed', ['reader_hooks' => $debug['reader_hooks']]);
    $activeCallback = null;
    cfx_form::post('outside');
    $check('runtime_reader_excludes_untrusted_calls', count(hookphuzz_runtime_param_get_discoveries()) === 2);

    $check('debug_backtrace_inside_hook', !empty($seen['namespaced']['backtrace_has_hook']));
    $results['passed'] = !in_array(false, array_column($results['tests'], 'passed'), true);
    echo json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    exit($results['passed'] ? 0 : 1);
}
