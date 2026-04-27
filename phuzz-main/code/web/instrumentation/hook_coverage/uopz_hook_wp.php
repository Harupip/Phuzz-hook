<?php
/**
 * UOPZ Hook Instrumentation for WordPress Fuzzing - Refactor v2
 *
 * Mục tiêu:
 * - Theo dõi callback-level registration
 * - Theo dõi hook fired
 * - Theo dõi callback-level dispatch (best effort qua WP_Hook)
 * - Export per-request + aggregate coverage
 *
 * Gợi ý triển khai:
 * - Có thể include file này từ MU plugin sớm
 * - Hoặc auto_prepend_file + gọi lại __uopz_install_wp_hooks() khi WP đã load xong plugin.php
 */

// ============================================================================
// GLOBAL STATE
// ============================================================================

// Mốc thời gian bắt đầu request để tính tổng thời gian xử lý ở cuối request.
$GLOBALS['__uopz_start_time'] = microtime(true);
// Cờ chặn việc cài hook lặp lại nhiều lần trong cùng một request.
$GLOBALS['__uopz_hooks_installed'] = false;
$GLOBALS['__uopz_hook_failures'] = [];
$GLOBALS['__uopz_runtime_hook_contexts'] = [];
$GLOBALS['__uopz_callback_origin_cache'] = [];

// Tạo request_id thân thiện: <Giờ-Phút-Giây>_<Method>_<Path>_<Random>
$__uopz_method = $_SERVER['REQUEST_METHOD'] ?? 'CLI';
$__uopz_uri = $_SERVER['REQUEST_URI'] ?? '';
$__uopz_path = parse_url($__uopz_uri, PHP_URL_PATH) ?: '';
$__uopz_slug = trim(str_replace(['/', '.', '?', '&', '='], '_', $__uopz_path), '_') ?: 'index';
$__uopz_slug = substr($__uopz_slug, 0, 30);

// Energy calculation da chuyen sang Python (fuzzing/energy.py).
// PHP chi can ghi raw hook_coverage vao per-request JSON.
// Python fuzzer se doc file do roi tinh energy in-memory.

// Đây là payload chính sẽ được ghi ra JSON khi request kết thúc.
$GLOBALS['__uopz_request'] = [
    'schema_version' => 'uopz-request-v3',
    'request_id' => date('His') . "_{$__uopz_method}_{$__uopz_slug}_" . bin2hex(random_bytes(2)),
    'timestamp' => date('Y-m-d H:i:s'),
    'http_method' => $__uopz_method,
    'http_target' => $__uopz_uri,
    'endpoint' => __uopz_detect_endpoint(),
    'input_signature' => __uopz_build_input_signature(),
    'request_params' => [
        'query_params' => $_GET ?? [],
        'body_params' => $_POST ?? [],
        'headers' => function_exists('getallheaders') ? getallheaders() : [],
        'cookies' => isset($_COOKIE) ? array_keys($_COOKIE) : [],
    ],
    'errors' => [],
    'response' => [
        'status_code' => 200,
        'time_ms' => 0,
    ],
    // Energy da chuyen sang Python. Khong tinh trong PHP nua.
    'hook_coverage' => [
        'registered_callbacks' => [],   // callback_id => data
        'executed_callbacks' => [],     // callback_id => data
        'blindspot_callbacks' => [],    // callback_id => data
    ],
    'debug' => [
        'target_app_path' => null,
        'install_failures' => [],
    ],
    'executed_callback_ids' => [],
    'new_callback_ids' => [],
    'rare_callback_ids' => [],
    'frequent_callback_ids' => [],
    'blindspot_callback_ids' => [],
    'new_hook_names' => [],
    'coverage_delta' => 0,
    'score' => 1,
];

// ============================================================================
// CONFIG
// ============================================================================

function __get_fuzzer_target(): string
{
    // TARGET_APP_PATH dùng để lọc frame nào thực sự thuộc plugin/app mục tiêu.
    $target = getenv('TARGET_APP_PATH');
    if (!$target) {
        $target = '/wp-content/plugins/';
    }
    $target = str_replace('\\', '/', $target);
    $GLOBALS['__uopz_request']['debug']['target_app_path'] = $target;
    return $target;
}

//export
function __uopz_base_dir(): string
{
    $baseDir = getenv('FUZZER_HOOK_OUTPUT_DIR');
    if (!$baseDir) {
        $baseDir = '/shared-tmpfs/hook-coverage';
    }
    return rtrim(str_replace('\\', '/', $baseDir), '/');
}

function __uopz_requests_dir(): string
{
    return __uopz_base_dir() . '/requests';
}
// lọc static (chưa biết hiệu quả thế nào)
function __uopz_should_persist_request(): bool
{
    $method = strtoupper((string) ($GLOBALS['__uopz_request']['http_method'] ?? 'CLI'));
    $target = (string) ($GLOBALS['__uopz_request']['http_target'] ?? '');
    $path = parse_url($target, PHP_URL_PATH) ?: '';
    $path = strtolower(rtrim($path, '/'));

    if ($method === 'CLI') {
        return false;
    }

    if ($path === '') {
        return true;
    }

    if ($path === '/favicon.ico') {
        return false;
    }

    if (strpos($path, '/.well-known/') === 0) {
        return false;
    }

    // Skip static/assets requests because they add little value for hook coverage.
    if (preg_match('/\.(css|js|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|eot|otf|mp4|webm|mp3|wav|pdf|txt|xml)$/', $path)) {
        return false;
    }

    return true;
}

// ============================================================================
// LOW-LEVEL HELPERS
// ============================================================================

set_error_handler(function ($errno, $errstr, $errfile, $errline) {
    $GLOBALS['__uopz_request']['errors'][] = [
        'errno' => $errno,
        'errstr' => $errstr,
        'errfile' => $errfile,
        'errline' => $errline,
    ];

    return false;
});

function __uopz_limit_backtrace(int $limit = 12): array
{
    // Giới hạn backtrace để giảm overhead vì helper này bị gọi rất thường xuyên.
    return debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, $limit);
}

function __uopz_path_matches_target(?string $file): bool //check xem file có thuộc target app không
{
    if (!$file) {
        return false;
    }

    $target = __get_fuzzer_target();
    $normalized = str_replace('\\', '/', $file);

    return strpos($normalized, $target) !== false;
}

function __is_target_app_code(): bool  //check xem có phải code của app cần fuzz không
{
    // Chỉ cần có một frame match target app là xem như hành động này đến từ app cần fuzz.
    foreach (__uopz_limit_backtrace(10) as $frame) {
        if (isset($frame['file']) && __uopz_path_matches_target($frame['file'])) {
            return true;
        }
    }
    return false;
}

function __get_caller_info(): string
{
    // Lấy file:line gần nhất thuộc target app để log gọn và dễ đọc.
    foreach (__uopz_limit_backtrace(12) as $frame) {
        if (isset($frame['file']) && __uopz_path_matches_target($frame['file'])) {
            return basename($frame['file']) . ':' . ($frame['line'] ?? '?');
        }
    }

    return 'framework-core';
}

function __uopz_safe_json($data): string
{
    return json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}

function __uopz_now_iso8601(): string
{
    return gmdate('c');
}

function __uopz_normalize_signature_value($value)
{
    if (!is_array($value)) {
        return $value;
    }

    if (array_keys($value) !== range(0, count($value) - 1)) {
        ksort($value);
    }

    foreach ($value as $key => $item) {
        $value[$key] = __uopz_normalize_signature_value($item);
    }

    return $value;
}

function __uopz_detect_endpoint(): string
{
    $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'CLI'));
    $uri = (string) ($_SERVER['REQUEST_URI'] ?? '');
    $path = (string) (parse_url($uri, PHP_URL_PATH) ?: '');

    if ($method === 'CLI') {
        return 'CLI';
    }

    if (isset($_GET['rest_route'])) {
        return 'REST:' . (string) $_GET['rest_route'];
    }

    if (strpos($path, '/wp-json/') === 0) {
        return 'REST:' . substr($path, strlen('/wp-json/'));
    }

    if ($path === '/wp-admin/admin-ajax.php') {
        return 'ADMIN_AJAX:' . (string) ($_REQUEST['action'] ?? 'unknown');
    }

    if ($path === '/wp-admin/admin-post.php') {
        return 'ADMIN_POST:' . (string) ($_REQUEST['action'] ?? 'unknown');
    }

    return $method . ':' . ($path ?: '/');
}

function __uopz_build_input_signature(): string
{
    $payload = [
        'method' => strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'CLI')),
        'endpoint' => __uopz_detect_endpoint(),
        'query' => __uopz_normalize_signature_value($_GET ?? []),
        'body' => __uopz_normalize_signature_value($_POST ?? []),
    ];

    return sha1(json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
}

function __uopz_callback_repr($callback): string
{
    // Chuẩn hóa callback của WordPress thành chuỗi ổn định để log và tạo ID.
    if (is_string($callback)) {
        return $callback;
    }

    if ($callback instanceof Closure) {
        try {
            $reflection = new ReflectionFunction($callback);
            $file = $reflection->getFileName() ?: 'closure';
            return 'Closure@' . basename($file) . ':' . $reflection->getStartLine();
        } catch (Throwable $e) {
            return 'Closure';
        }
    }

    if (is_array($callback) && count($callback) === 2) {
        [$target, $method] = $callback;

        if (is_object($target)) {
            return get_class($target) . '->' . $method;
        }

        if (is_string($target)) {
            return $target . '::' . $method;
        }
    }

    if (is_object($callback) && method_exists($callback, '__invoke')) {
        return get_class($callback) . '::__invoke';
    }

    return 'unknown_callback';
}

// callback_id la khoa de gom du lieu coverage o muc callback.
function __uopz_callback_id($callback, $hookName = '', $priority = null): string
{
    $repr = __uopz_callback_repr($callback);

    // callback-level identity, gắn thêm hook + priority để phân biệt cùng callback đăng ký ở nhiều nơi
    return sha1($hookName . '|' . (string) $priority . '|' . $repr);
}

function __uopz_callback_stable_id($callback): string
{
    $origin = __uopz_describe_callback_origin($callback);
    $file = (string) ($origin['file'] ?? '');
    $line = (string) ($origin['line'] ?? '');
    $repr = __uopz_callback_repr($callback);

    if (is_string($callback)) {
        return sha1('function|' . $callback);
    }

    if ($callback instanceof Closure) {
        return sha1('closure|' . $file . '|' . $line . '|' . $repr);
    }

    if (is_array($callback) && count($callback) === 2) {
        [$target, $method] = $callback;

        if (is_object($target)) {
            return sha1('object-method|' . get_class($target) . '|' . $method . '|' . $file . '|' . $line);
        }

        if (is_string($target)) {
            return sha1('static-method|' . $target . '::' . $method);
        }
    }

    if (is_object($callback) && method_exists($callback, '__invoke')) {
        return sha1('invokable|' . get_class($callback) . '::__invoke|' . $file . '|' . $line);
    }

    return sha1('repr|' . $repr);
}

function __uopz_callback_runtime_id($callback): string
{
    $stableId = __uopz_callback_stable_id($callback);

    if ($callback instanceof Closure) {
        return sha1('closure-runtime|' . $stableId . '|' . spl_object_id($callback));
    }

    if (is_array($callback) && count($callback) === 2) {
        [$target, $method] = $callback;

        if (is_object($target)) {
            return sha1('object-method-runtime|' . $stableId . '|' . get_class($target) . '|' . $method . '|' . spl_object_id($target));
        }
    }

    if (is_object($callback) && method_exists($callback, '__invoke')) {
        return sha1('invokable-runtime|' . $stableId . '|' . spl_object_id($callback));
    }

    return $stableId;
}

function __uopz_callback_identity($callback, $hookName = '', $priority = null): array
{
    $origin = __uopz_describe_callback_origin($callback);
    $repr = __uopz_callback_repr($callback);
    $stableId = __uopz_callback_stable_id($callback);
    $runtimeId = __uopz_callback_runtime_id($callback);

    return [
        'callback_id' => sha1($hookName . '|' . (string) $priority . '|' . $stableId),
        'callback_runtime_id' => sha1($hookName . '|' . (string) $priority . '|' . $runtimeId),
        'stable_id' => $stableId,
        'runtime_id' => $runtimeId,
        'callback_repr' => $repr,
        'source_file' => $origin['file'] ?? null,
        'source_line' => $origin['line'] ?? null,
        'origin_label' => $origin['caller_info'] ?? 'framework-core',
    ];
}

function __uopz_get_hook_depth(): int
{
    if (!isset($GLOBALS['wp_current_filter']) || !is_array($GLOBALS['wp_current_filter'])) {
        return 0;
    }

    return count($GLOBALS['wp_current_filter']);
}

function __uopz_set_runtime_hook_context(string $hookName, string $type, ?string $firedHook = null): void
{
    $depth = __uopz_get_hook_depth();
    if ($depth <= 0) {
        return;
    }

    $existing = $GLOBALS['__uopz_runtime_hook_contexts'][$depth] ?? null;
    if (
        is_array($existing)
        && ($existing['hook_name'] ?? '') === $hookName
        && ($existing['type'] ?? '') === 'action'
        && $type === 'filter'
    ) {
        return;
    }

    $GLOBALS['__uopz_runtime_hook_contexts'][$depth] = [
        'hook_name' => $hookName,
        'type' => $type,
        'fired_hook' => $firedHook ?: $hookName,
    ];
}

function __uopz_get_runtime_hook_context(): ?array
{
    $depth = __uopz_get_hook_depth();
    if ($depth <= 0) {
        return null;
    }

    if (!isset($GLOBALS['__uopz_runtime_hook_contexts'][$depth])) {
        return null;
    }

    return $GLOBALS['__uopz_runtime_hook_contexts'][$depth];
}

function __uopz_merge_registration_semantics(?array $existing, string $type, string $source): array
{
    if (!is_array($existing)) {
        return [$type, $source];
    }

    $existingType = (string) ($existing['type'] ?? '');
    $existingSource = (string) ($existing['source'] ?? '');

    // WordPress implements add_action() as an alias of add_filter().
    // Preserve action semantics when the alias path triggers both hooks.
    if ($existingType === 'action' || $existingSource === 'add_action') {
        return ['action', 'add_action'];
    }

    if ($type === 'action' || $source === 'add_action') {
        return ['action', 'add_action'];
    }

    return [$type, $source];
}

// Ghi nhan callback duoc add_action/add_filter dang ky vao request hien tai.
function __uopz_register_callback(
    string $type,
    string $hookName,
    $callback,
    int $priority = 10,
    int $acceptedArgs = 1,
    string $source = 'register'
): void {
    $identity = __uopz_callback_identity($callback, $hookName, $priority);
    $callbackId = $identity['callback_id'];
    $repr = $identity['callback_repr'];
    $timestamp = __uopz_now_iso8601();
    $existing = $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId] ?? null;
    [$type, $source] = __uopz_merge_registration_semantics(is_array($existing) ? $existing : null, $type, $source);

    if (!isset($GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId])) {
        $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId] = [
            'callback_id' => $callbackId,
            'request_id' => $GLOBALS['__uopz_request']['request_id'],
            'endpoint' => $GLOBALS['__uopz_request']['endpoint'],
            'input_signature' => $GLOBALS['__uopz_request']['input_signature'],
            'type' => $type,
            'hook_name' => $hookName,
            'callback_repr' => $repr,
            'callback_runtime_id' => $identity['callback_runtime_id'],
            'stable_id' => $identity['stable_id'],
            'runtime_id' => $identity['runtime_id'],
            'priority' => $priority,
            'accepted_args' => $acceptedArgs,
            'source_file' => $identity['source_file'],
            'source_line' => $identity['source_line'],
            'registered_from' => $identity['origin_label'],
            'registered_at' => $timestamp,
            'removed_at' => null,
            'removed_from' => null,
            'is_active' => true,
            'status' => 'registered_only',
            'source' => $source,
        ];
        return;
    }

    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['type'] = $type;
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['hook_name'] = $hookName;
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['callback_repr'] = $repr;
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['callback_runtime_id'] = $identity['callback_runtime_id'];
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['stable_id'] = $identity['stable_id'];
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['runtime_id'] = $identity['runtime_id'];
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['priority'] = $priority;
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['accepted_args'] = $acceptedArgs;
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['source_file'] = $identity['source_file'];
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['source_line'] = $identity['source_line'];
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['registered_from'] = $identity['origin_label'];
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['request_id'] = $GLOBALS['__uopz_request']['request_id'];
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['endpoint'] = $GLOBALS['__uopz_request']['endpoint'];
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['input_signature'] = $GLOBALS['__uopz_request']['input_signature'];
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['removed_at'] = null;
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['removed_from'] = null;
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['is_active'] = true;
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['source'] = $source;
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['status'] =
        isset($GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'][$callbackId]) ? 'covered' : 'registered_only';
}

function __uopz_unregister_callback(string $hookName, $callback, int $priority = 10, string $source = 'remove_filter'): void
{
    $callbackId = __uopz_callback_identity($callback, $hookName, $priority)['callback_id'];
    if (!isset($GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId])) {
        return;
    }

    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['is_active'] = false;
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['removed_at'] = __uopz_now_iso8601();
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['removed_from'] = $source;
    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['status'] = 'removed';
}

function __uopz_unregister_all_callbacks(string $hookName, $priority = false, string $source = 'remove_all_filters'): void
{
    foreach ($GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'] as $callbackId => $entry) {
        if (($entry['hook_name'] ?? '') !== $hookName) {
            continue;
        }

        if ($priority !== false && (int) ($entry['priority'] ?? 10) !== (int) $priority) {
            continue;
        }

        $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['is_active'] = false;
        $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['removed_at'] = __uopz_now_iso8601();
        $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['removed_from'] = $source;
        $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['status'] = 'removed';
    }
}

function __uopz_has_registered_callbacks(): bool
{
    return !empty($GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks']);
}

// Ghi nhan callback nam trong danh sach ma WP_Hook se dispatch cho hook hien tai.
function __uopz_mark_callback_executed(
    string $type,
    string $hookName,
    $callback,
    int $priority = 10,
    int $acceptedArgs = 1,
    string $source = 'dispatch',
    ?string $firedHook = null
): void {
    $identity = __uopz_callback_identity($callback, $hookName, $priority);
    $callbackId = $identity['callback_id'];
    $repr = $identity['callback_repr'];
    $timestamp = __uopz_now_iso8601();

    if (!isset($GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'][$callbackId])) {
        $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'][$callbackId] = [
            'callback_id' => $callbackId,
            'request_id' => $GLOBALS['__uopz_request']['request_id'],
            'endpoint' => $GLOBALS['__uopz_request']['endpoint'],
            'input_signature' => $GLOBALS['__uopz_request']['input_signature'],
            'type' => $type,
            'hook_name' => $hookName,
            'fired_hook' => $firedHook ?: $hookName,
            'callback_repr' => $repr,
            'callback_runtime_id' => $identity['callback_runtime_id'],
            'stable_id' => $identity['stable_id'],
            'runtime_id' => $identity['runtime_id'],
            'priority' => $priority,
            'accepted_args' => $acceptedArgs,
            'source_file' => $identity['source_file'],
            'source_line' => $identity['source_line'],
            'executed_from' => $identity['origin_label'],
            'source' => $source,
            'executed_count' => 0,
            'first_seen' => $timestamp,
            'last_seen' => $timestamp,
        ];
    }

    $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'][$callbackId]['executed_count']++;
    $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'][$callbackId]['last_seen'] = $timestamp;
    $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'][$callbackId]['fired_hook'] = $firedHook ?: $hookName;
    $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'][$callbackId]['callback_runtime_id'] = $identity['callback_runtime_id'];
    $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'][$callbackId]['stable_id'] = $identity['stable_id'];
    $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'][$callbackId]['runtime_id'] = $identity['runtime_id'];
    $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'][$callbackId]['source_file'] = $identity['source_file'];
    $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'][$callbackId]['source_line'] = $identity['source_line'];
    $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'][$callbackId]['request_id'] = $GLOBALS['__uopz_request']['request_id'];
    $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'][$callbackId]['endpoint'] = $GLOBALS['__uopz_request']['endpoint'];
    $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'][$callbackId]['input_signature'] = $GLOBALS['__uopz_request']['input_signature'];
    $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'][$callbackId]['source'] = $source;
}

function __uopz_get_current_priority_for_hook(string $hookName): int
{
    if (!isset($GLOBALS['wp_filter'][$hookName]) || !is_object($GLOBALS['wp_filter'][$hookName])) {
        return 10;
    }

    $wpHookObject = $GLOBALS['wp_filter'][$hookName];
    if (!method_exists($wpHookObject, 'current_priority')) {
        return 10;
    }

    $priority = $wpHookObject->current_priority();
    if ($priority === false || $priority === null) {
        return 10;
    }

    return (int) $priority;
}

function __uopz_record_actual_callback_invocation($callback, int $actualArgCount, string $source): void
{
    $context = __uopz_get_runtime_hook_context();
    if ($context === null) {
        return;
    }

    $hookName = (string) ($context['hook_name'] ?? '');
    if ($hookName === '') {
        return;
    }

    $priority = __uopz_get_current_priority_for_hook($hookName);
    $callbackId = __uopz_callback_identity($callback, $hookName, $priority)['callback_id'];
    $registered = $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId] ?? null;

    // Chỉ tính execution coverage cho callback mục tiêu đã có trong registry.
    if ($registered === null) {
        return;
    }

    __uopz_mark_callback_executed(
        (string) ($registered['type'] ?? ($context['type'] ?? 'unknown')),
        $hookName,
        $callback,
        $priority,
        (int) ($registered['accepted_args'] ?? $actualArgCount),
        ($registered['type'] ?? '') === 'action' ? 'do_action' : 'apply_filters',
        (string) ($context['fired_hook'] ?? $hookName)
    );

    $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'][$callbackId]['status'] = 'covered';
}

// Duyet cau truc noi bo cua WP_Hook de lay snapshot callbacks theo priority.
function __uopz_dispatch_callbacks_from_wp_hook($wpHookObject, string $hookName, string $type): void
{
    if (!is_object($wpHookObject)) {
        return;
    }

    __uopz_set_runtime_hook_context($hookName, $type, $hookName);
}

// Luu ly do cai hook that bai de debug luc auto_prepend chay qua som.
function __uopz_record_install_failure(string $name): void
{
    $GLOBALS['__uopz_hook_failures'][] = $name;
    $GLOBALS['__uopz_request']['debug']['install_failures'][] = $name;
}

// ============================================================================
// UOPZ INSTALLERS
// ============================================================================

// Thu gan hook vao ham global cua WP; neu ham chua ton tai thi chi log failure, khong fail cung.
function __uopz_try_hook_function(string $functionName, Closure $closure): bool
{
    if (!function_exists($functionName)) {
        __uopz_record_install_failure("function_missing:$functionName");
        return false;
    }

    $ok = @uopz_set_hook($functionName, $closure);
    if (!$ok) {
        __uopz_record_install_failure("hook_failed:$functionName");
    }

    return (bool) $ok;
}

// Thu gan hook vao method nhu WP_Hook::apply_filters / WP_Hook::do_action.
function __uopz_try_hook_method(string $className, string $methodName, Closure $closure): bool
{
    if (!class_exists($className, false) || !method_exists($className, $methodName)) {
        __uopz_record_install_failure("method_missing:$className::$methodName");
        return false;
    }

    $ok = @uopz_set_hook($className, $methodName, $closure);
    if (!$ok) {
        __uopz_record_install_failure("hook_failed:$className::$methodName");
    }

    return (bool) $ok;
}

// Day la diem cai dat chinh. Co the goi lai an toan sau khi WP load xong.
function __uopz_install_wp_hooks(): void
{
    if ($GLOBALS['__uopz_hooks_installed'] === true) {
        return;
    }

    if (!extension_loaded('uopz')) {
        __uopz_record_install_failure('extension_missing:uopz');
        return;
    }

    // ------------------------------------------------------------------------
    // Registration monitoring
    // ------------------------------------------------------------------------

    $installResults = [];

    $installResults[] = __uopz_try_hook_function('add_filter', function (...$args) {
        // Signature cua WP: add_filter($hook, $callback, $priority = 10, $accepted_args = 1)
        $hookName = (string) ($args[0] ?? 'unknown');
        $callback = $args[1] ?? null;
        $priority = (int) ($args[2] ?? 10);
        $acceptedArgs = (int) ($args[3] ?? 1);

        if ($callback === null) {
            return;
        }

        if (__uopz_is_target_callback($callback)) {
            __uopz_register_callback(
                'filter',
                $hookName,
                $callback,
                $priority,
                $acceptedArgs,
                'add_filter'
            );
        }
    });

    $installResults[] = __uopz_try_hook_function('add_action', function (...$args) {
        // add_action co shape du lieu giong add_filter, khac nhau o y nghia event.
        $hookName = (string) ($args[0] ?? 'unknown');
        $callback = $args[1] ?? null;
        $priority = (int) ($args[2] ?? 10);
        $acceptedArgs = (int) ($args[3] ?? 1);

        if ($callback === null) {
            return;
        }

        if (__uopz_is_target_callback($callback)) {
            __uopz_register_callback(
                'action',
                $hookName,
                $callback,
                $priority,
                $acceptedArgs,
                'add_action'
            );
        }
    });

    $installResults[] = __uopz_try_hook_function('remove_filter', function (...$args) {
        $hookName = (string) ($args[0] ?? 'unknown');
        $callback = $args[1] ?? null;
        $priority = (int) ($args[2] ?? 10);

        if ($callback === null) {
            return;
        }

        __uopz_unregister_callback($hookName, $callback, $priority, 'remove_filter');
    });

    $installResults[] = __uopz_try_hook_function('remove_action', function (...$args) {
        $hookName = (string) ($args[0] ?? 'unknown');
        $callback = $args[1] ?? null;
        $priority = (int) ($args[2] ?? 10);

        if ($callback === null) {
            return;
        }

        __uopz_unregister_callback($hookName, $callback, $priority, 'remove_action');
    });

    $installResults[] = __uopz_try_hook_function('remove_all_filters', function (...$args) {
        $hookName = (string) ($args[0] ?? 'unknown');
        $priority = $args[1] ?? false;

        __uopz_unregister_all_callbacks($hookName, $priority, 'remove_all_filters');
    });

    $installResults[] = __uopz_try_hook_function('remove_all_actions', function (...$args) {
        $hookName = (string) ($args[0] ?? 'unknown');
        $priority = $args[1] ?? false;

        __uopz_unregister_all_callbacks($hookName, $priority, 'remove_all_actions');
    });

    // ------------------------------------------------------------------------
    // Callback dispatch monitoring (best effort qua WP_Hook)
    // ------------------------------------------------------------------------
    // Lưu ý:
    // - uopz_set_hook trên method chạy ở đầu method
    // - ta snapshot danh sách callbacks mà WP_Hook sẽ iterate
    // - điều này gần callback-level execution hơn rất nhiều so với chỉ log do_action/apply_filters

    // Hook vao WP_Hook::apply_filters de nhin thay danh sach callback o muc thap hon ten hook.
    $installResults[] = __uopz_try_hook_method('WP_Hook', 'apply_filters', function (...$args) {
        // Method signature thực tế của WP_Hook::apply_filters khác nhau theo version,
        // nên ta không phụ thuộc chặt vào arg positions.
        // Hook name thường lấy được từ current_filter().
        $hookName = function_exists('current_filter') ? (string) current_filter() : 'unknown_filter';

        if (!isset($GLOBALS['wp_filter'][$hookName]) || !is_object($GLOBALS['wp_filter'][$hookName])) {
            return;
        }

        __uopz_dispatch_callbacks_from_wp_hook($GLOBALS['wp_filter'][$hookName], $hookName, 'filter');
    });

    // Hook vao WP_Hook::do_action voi muc dich tuong tu cho action hooks.
    $installResults[] = __uopz_try_hook_method('WP_Hook', 'do_action', function (...$args) {
        $hookName = function_exists('current_filter') ? (string) current_filter() : 'unknown_action';

        if (!isset($GLOBALS['wp_filter'][$hookName]) || !is_object($GLOBALS['wp_filter'][$hookName])) {
            return;
        }

        __uopz_dispatch_callbacks_from_wp_hook($GLOBALS['wp_filter'][$hookName], $hookName, 'action');
    });

    $installResults[] = __uopz_try_hook_method('WP_Hook', 'do_all_hook', function (...$args) {
        $firedHook = function_exists('current_filter') ? (string) current_filter() : 'unknown_hook';

        if (!isset($GLOBALS['wp_filter']['all']) || !is_object($GLOBALS['wp_filter']['all'])) {
            return;
        }

        __uopz_set_runtime_hook_context('all', 'all', $firedHook);
    });

    $installResults[] = __uopz_try_hook_function('call_user_func', function (...$args) {
        $callback = $args[0] ?? null;
        if ($callback === null) {
            return;
        }

        $actualArgCount = count($args) > 1 ? count($args) - 1 : 0;
        __uopz_record_actual_callback_invocation($callback, $actualArgCount, 'call_user_func');
    });

    $installResults[] = __uopz_try_hook_function('call_user_func_array', function (...$args) {
        $callback = $args[0] ?? null;
        if ($callback === null) {
            return;
        }

        $actualArgCount = isset($args[1]) && is_array($args[1]) ? count($args[1]) : 0;
        __uopz_record_actual_callback_invocation($callback, $actualArgCount, 'call_user_func_array');
    });

    // auto_prepend co the chay truoc khi WordPress load xong plugin API.
    // Neu danh dau "installed" qua som thi MU plugin se khong retry duoc nua.
    $GLOBALS['__uopz_hooks_installed'] = !in_array(false, $installResults, true);
}

// ============================================================================
// AGGREGATION
// ============================================================================

// Blindspot cua v2 = callback da register nhung chua xuat hien trong executed_callbacks.
function __uopz_compute_blindspots(): void
{
    $registered = $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'];
    $executed = $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'];

    $blindspots = [];

    foreach ($registered as $callbackId => &$data) {
        if (!($data['is_active'] ?? true)) {
            $data['status'] = 'removed';
            continue;
        }

        if (!isset($executed[$callbackId])) {
            $data['status'] = 'registered_only';
            $blindspots[$callbackId] = $data;
            continue;
        }

        $data['status'] = 'covered';
    }
    unset($data);

    $GLOBALS['__uopz_request']['hook_coverage']['blindspot_callbacks'] = $blindspots;
}

// Ghi file qua temp + rename de tranh JSON dang do khi request bi ngat giua chung.
function __uopz_write_json_atomic(string $path, array $data): void
{
    $tmp = $path . '.tmp.' . bin2hex(random_bytes(4));
    file_put_contents($tmp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    rename($tmp, $path);
}

function __uopz_build_request_export(): array
{
    $requestExport = $GLOBALS['__uopz_request'];
    if (isset($requestExport['debug']) && is_array($requestExport['debug'])) {
        unset($requestExport['debug']['install_failures']);
    }
    $requestExport['hook_coverage_summary'] = [
        'registered_callbacks' => count($GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'] ?? []),
        'executed_callbacks' => count($GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'] ?? []),
        'blindspot_callbacks' => count($GLOBALS['__uopz_request']['hook_coverage']['blindspot_callbacks'] ?? []),
    ];

    $executedHookNames = [];
    foreach (($GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'] ?? []) as $entry) {
        $hookName = (string) ($entry['hook_name'] ?? '');
        if ($hookName !== '' && !in_array($hookName, $executedHookNames, true)) {
            $executedHookNames[] = $hookName;
        }
    }

    $requestExport['hook_coverage'] = [
        'registered_callbacks' => $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'] ?? [],
        'executed_callbacks' => $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'] ?? [],
        'blindspot_callbacks' => $GLOBALS['__uopz_request']['hook_coverage']['blindspot_callbacks'] ?? [],
    ];
    $requestExport['executed_callback_ids'] = array_values(array_keys($GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'] ?? []));
    $requestExport['blindspot_callback_ids'] = array_values(array_keys($GLOBALS['__uopz_request']['hook_coverage']['blindspot_callbacks'] ?? []));
    $requestExport['new_callback_ids'] = [];
    $requestExport['rare_callback_ids'] = [];
    $requestExport['frequent_callback_ids'] = [];
    $requestExport['new_hook_names'] = $executedHookNames;
    $requestExport['coverage_delta'] = 0;
    $requestExport['score'] = 1;
    return $requestExport;
}

// ===========================================================================
// AGGREGATION
// ===========================================================================
// Merge du lieu request hien tai vao file tong hop dung chung cho nhieu request fuzz.
// Energy calculation da chuyen sang Python (fuzzing/energy.py), khong tinh o day nua.
function __uopz_update_total_coverage(): void
{
    $baseDir = __uopz_base_dir();
    $requestsDir = __uopz_requests_dir();
    $coverageFile = $baseDir . '/total_coverage.json';
    $lockFile = $baseDir . '/total_coverage.lock';

    if (!is_dir($requestsDir)) {
        @mkdir($requestsDir, 0777, true);
    }

    // Lock file de tranh hai request ghi total_coverage.json cung luc.
    $lockFp = fopen($lockFile, 'c+');
    if (!$lockFp) {
        return;
    }

    if (!flock($lockFp, LOCK_EX)) {
        fclose($lockFp);
        return;
    }

    try {
        $existing = [];
        if (file_exists($coverageFile)) {
            $existing = json_decode(file_get_contents($coverageFile), true) ?? [];
        }

        $existingRegistered = $existing['data']['registered_callbacks'] ?? [];
        $existingExecuted = $existing['data']['executed_callbacks'] ?? [];

        $currentRegistered = $GLOBALS['__uopz_request']['hook_coverage']['registered_callbacks'];
        $currentExecuted = $GLOBALS['__uopz_request']['hook_coverage']['executed_callbacks'];

        // Merge theo callback_id de du lieu aggregate khong bi duplicate.
        $allRegistered = $existingRegistered;
        foreach ($currentRegistered as $id => $item) {
            $allRegistered[$id] = $item;
        }

        $allExecuted = $existingExecuted;
        foreach ($currentExecuted as $id => $item) {
            if (!isset($allExecuted[$id])) {
                $allExecuted[$id] = $item;
                continue;
            }

            $allExecuted[$id]['executed_count'] =
                (int) ($allExecuted[$id]['executed_count'] ?? 0) + (int) ($item['executed_count'] ?? 0);

            if (!isset($allExecuted[$id]['first_seen']) && isset($item['first_seen'])) {
                $allExecuted[$id]['first_seen'] = $item['first_seen'];
            }

            if (isset($item['last_seen'])) {
                $allExecuted[$id]['last_seen'] = $item['last_seen'];
            }

            if (isset($item['fired_hook'])) {
                $allExecuted[$id]['fired_hook'] = $item['fired_hook'];
            }

            if (isset($item['source'])) {
                $allExecuted[$id]['source'] = $item['source'];
            }

            if (isset($item['request_id'])) {
                $allExecuted[$id]['request_id'] = $item['request_id'];
            }

            if (isset($item['endpoint'])) {
                $allExecuted[$id]['endpoint'] = $item['endpoint'];
            }

            if (isset($item['input_signature'])) {
                $allExecuted[$id]['input_signature'] = $item['input_signature'];
            }
        }

        // executed_callbacks o muc aggregate chi nen tinh tren callback cua target app
        // da tung register, neu khong tu so se bi doi len boi callback core WordPress.
        $coveredExecuted = [];
        $blindspots = [];
        foreach ($allRegistered as $id => $item) {
            if (isset($allExecuted[$id])) {
                $coveredExecuted[$id] = $allExecuted[$id];
                continue;
            }

            $blindspots[$id] = $item;
        }

        $coveredCount = count($allRegistered) > 0
            ? round((count($coveredExecuted) / count($allRegistered)) * 100, 2)
            : 0.0;

        $total = [
            'schema_version' => 'uopz-total-coverage-v3',
            'metadata' => [
                'total_registered_callbacks' => count($allRegistered),
                'total_executed_callbacks' => count($coveredExecuted),
                'coverage_percent' => $coveredCount . '%',
                'last_request_time' => date('Y-m-d H:i:s'),
                'last_request_id' => $GLOBALS['__uopz_request']['request_id'],
            ],
            'data' => [
                'registered_callbacks' => $allRegistered,
                'executed_callbacks' => $coveredExecuted,
                'blindspot_callbacks' => $blindspots,
            ],
        ];

        __uopz_write_json_atomic($coverageFile, $total);
    } finally {
        flock($lockFp, LOCK_UN);
        fclose($lockFp);
    }
}

// ============================================================================
// SHUTDOWN EXPORT
// ============================================================================

register_shutdown_function(function () {
    // Flush o shutdown de thu du errors va status code cuoi cung cua request.
    $GLOBALS['__uopz_request']['response']['status_code'] =
        function_exists('http_response_code') ? http_response_code() : 200;

    $GLOBALS['__uopz_request']['response']['time_ms'] =
        round((microtime(true) - $GLOBALS['__uopz_start_time']) * 1000, 2);

    __uopz_compute_blindspots();

    $requestsDir = __uopz_requests_dir();
    if (!is_dir($requestsDir)) {
        @mkdir($requestsDir, 0777, true);
    }

    if (!__uopz_should_persist_request()) {
        return;
    }

    // ĐÔNG LẠNH: Vô hiệu hóa việc PHP tự tính Total Coverage! 
    // Python (energy.py) bây giờ mới là người giữ state in-memory và tự merge 
    // để nhổ tận gốc cái nút thắt file I/O & JSON decode khổng lồ này.
    __uopz_update_total_coverage();

    // Cho phép tắt log request bằng biến môi trường để tránh nghẽn I/O (mặc định vẫn bật để xem)
    $enableRequestLog = getenv('FUZZER_ENABLE_REQUEST_LOG') !== '0' && getenv('FUZZER_ENABLE_REQUEST_LOG') !== 'false';
    if ($enableRequestLog) {
        $requestFile = $requestsDir . '/' . $GLOBALS['__uopz_request']['request_id'] . '.json';
        __uopz_write_json_atomic($requestFile, __uopz_build_request_export());
    }
});

// ============================================================================
// BOOTSTRAP
// ============================================================================

// Thử install ngay.
// Nếu lúc này WordPress core chưa load add_action/do_action/WP_Hook,
// bạn có thể gọi lại __uopz_install_wp_hooks() sau khi plugin.php đã được load.
// Co the goi lai ham nay sau khi WordPress load xong neu auto_prepend chay qua som.
__uopz_install_wp_hooks();

// ============================================================================
// CALLBACK OWNERSHIP HELPERS
// ============================================================================

function __uopz_callback_origin_cache_key($callback): string
{
    if (is_string($callback)) {
        return 'function:' . $callback;
    }

    if ($callback instanceof Closure) {
        return 'closure:' . spl_object_id($callback);
    }

    if (is_array($callback) && count($callback) === 2) {
        [$target, $method] = $callback;

        if (is_object($target)) {
            return 'object-method:' . spl_object_id($target) . '->' . $method;
        }

        if (is_string($target)) {
            return 'static-method:' . $target . '::' . $method;
        }
    }

    if (is_object($callback) && method_exists($callback, '__invoke')) {
        return 'invokable:' . get_class($callback) . '#' . spl_object_id($callback);
    }

    return 'repr:' . __uopz_callback_repr($callback);
}

function __uopz_reflect_callback($callback): ?ReflectionFunctionAbstract
{
    if (is_string($callback)) {
        if (strpos($callback, '::') !== false) {
            return new ReflectionMethod($callback);
        }

        return new ReflectionFunction($callback);
    }

    if ($callback instanceof Closure) {
        return new ReflectionFunction($callback);
    }

    if (is_array($callback) && count($callback) === 2) {
        [$target, $method] = $callback;
        return new ReflectionMethod($target, $method);
    }

    if (is_object($callback) && method_exists($callback, '__invoke')) {
        return new ReflectionMethod($callback, '__invoke');
    }

    return null;
}

function __uopz_describe_callback_origin($callback): array
{
    $cacheKey = __uopz_callback_origin_cache_key($callback);
    if (isset($GLOBALS['__uopz_callback_origin_cache'][$cacheKey])) {
        return $GLOBALS['__uopz_callback_origin_cache'][$cacheKey];
    }

    $origin = [
        'file' => null,
        'line' => null,
        'caller_info' => 'framework-core',
        'is_target' => false,
        'resolved_by' => 'none',
    ];

    try {
        $reflection = __uopz_reflect_callback($callback);
        if ($reflection instanceof ReflectionFunctionAbstract) {
            $file = $reflection->getFileName() ?: null;
            $line = $reflection->getStartLine() ?: null;

            if ($file !== null) {
                $origin['file'] = $file;
                $origin['line'] = $line;
                $origin['caller_info'] = basename($file) . ':' . ($line ?? '?');
                $origin['is_target'] = __uopz_path_matches_target($file);
                $origin['resolved_by'] = 'reflection';
            }
        }
    } catch (Throwable $e) {
        // Internal callbacks and some dynamic callbacks cannot be resolved to a file.
    }

    $GLOBALS['__uopz_callback_origin_cache'][$cacheKey] = $origin;
    return $origin;
}

function __uopz_is_target_callback($callback): bool
{
    return (bool) (__uopz_describe_callback_origin($callback)['is_target'] ?? false);
}

function __uopz_get_callback_origin_label($callback): string
{
    return (string) (__uopz_describe_callback_origin($callback)['caller_info'] ?? 'framework-core');
}
