<?php
/** Plugin Name: HookPhuzz Phase 12 Fixture */
declare(strict_types=1);

const HP12_DIR = '/results/fixture-callbacks';
function hp12_id(): string { $id = $_SERVER['HTTP_X_HOOKPHUZZ_REQUEST_ID'] ?? ''; return is_string($id) && preg_match('/^[A-Za-z0-9_.-]{1,128}$/', $id) ? $id : ''; }
function hp12_write(array $row): void { $id = hp12_id(); if ($id === '') return; if (!is_dir(HP12_DIR)) mkdir(HP12_DIR, 0700, true); $row['request_id'] = $id; $row['timestamp'] = gmdate('c'); $tmp = tempnam(HP12_DIR, '.tmp-'); if ($tmp && file_put_contents($tmp, json_encode($row, JSON_PRETTY_PRINT), LOCK_EX) !== false) rename($tmp, HP12_DIR . "/$id.json"); }
function hp12_validate($value): bool { $GLOBALS['hp12_validation'][] = ['value' => $value, 'accepted' => $value !== 'reject']; return $value !== 'reject'; }
function hp12_sanitize($value) { $out = is_string($value) ? strtoupper($value) : $value; $GLOBALS['hp12_sanitization'][] = ['raw' => $value, 'value' => $out]; return $out; }
function hp12_conflict_sanitize($value) { return 7; }
function hp12_callback(WP_REST_Request $request): WP_REST_Response {
    $read = $request->get_route() === '/hookphuzz-phase12/v1/runtime' ? ['undocumented'] : ($request->get_route() === '/hookphuzz-phase12/v1/conflict' ? ['conflicted'] : ['id','required','optional','defaulted','choice','integer','number','enabled','tags','profile','query','json','form','sanitized']);
    $values = []; foreach ($read as $name) $values[$name] = $request->get_param($name);
    hp12_write(['callback' => __FUNCTION__, 'method' => $request->get_method(), 'route' => $request->get_route(), 'values' => $values, 'url' => $request->get_url_params(), 'query' => $request->get_query_params(), 'body' => $request->get_body_params(), 'json' => $request->get_json_params(), 'files' => $request->get_file_params(), 'validation' => $GLOBALS['hp12_validation'] ?? [], 'sanitization' => $GLOBALS['hp12_sanitization'] ?? []]);
    return new WP_REST_Response(['ok' => true, 'request_id' => hp12_id()], 200);
}
function hp12_args(): array { return [
    'required' => ['type'=>'string','required'=>true], 'optional' => ['type'=>'string'], 'defaulted' => ['type'=>'string','default'=>'baseline'],
    'choice' => ['type'=>'string','enum'=>['red','blue']], 'integer' => ['type'=>'integer','minimum'=>2], 'number' => ['type'=>'number'], 'enabled' => ['type'=>'boolean'],
    'tags' => ['type'=>'array','items'=>['type'=>'integer']], 'profile' => ['type'=>'object','properties'=>['name'=>['type'=>'string']]],
    'query' => ['type'=>'string'], 'json' => ['type'=>'boolean'], 'form' => ['type'=>'string'],
    'sanitized' => ['type'=>'string','sanitize_callback'=>'hp12_sanitize'], 'validated' => ['type'=>'string','validate_callback'=>'hp12_validate'],
    'unsupported_pattern' => ['type'=>'string','pattern'=>'.*'], 'unsupported_object' => ['type'=>'object'],
    'unsupported_nested' => ['type'=>'object','properties'=>['nested'=>['type'=>'object']]], 'declared_unread' => ['type'=>'string'],
]; }
add_action('rest_api_init', static function (): void {
    $args = hp12_args();
    register_rest_route('hookphuzz-phase12/v1', '/items/(?P<id>\\d+)', ['methods'=>'GET','callback'=>'hp12_callback','permission_callback'=>'__return_true','args'=>$args]);
    register_rest_route('hookphuzz-phase12/v1', '/json', ['methods'=>'POST','callback'=>'hp12_callback','permission_callback'=>'__return_true','args'=>$args]);
    register_rest_route('hookphuzz-phase12/v1', '/form', ['methods'=>'POST','callback'=>'hp12_callback','permission_callback'=>'__return_true','args'=>$args]);
    register_rest_route('hookphuzz-phase12/v1', '/runtime', ['methods'=>'GET','callback'=>'hp12_callback','permission_callback'=>'__return_true']);
    register_rest_route('hookphuzz-phase12/v1', '/no-args', ['methods'=>'GET','callback'=>'hp12_callback','permission_callback'=>'__return_true']);
    register_rest_route('hookphuzz-phase12/v1', '/conflict', ['methods'=>'POST','callback'=>'hp12_callback','permission_callback'=>'__return_true','args'=>['conflicted'=>['type'=>'string','sanitize_callback'=>'hp12_conflict_sanitize']]]);
    register_rest_route('hookphuzz-phase12/v1', '/methods', ['args'=>['common'=>['type'=>'string']], ['methods'=>'PUT','callback'=>'hp12_callback','permission_callback'=>'__return_true','args'=>['name'=>['type'=>'string','required'=>true]]], ['methods'=>'PATCH','callback'=>'hp12_callback','permission_callback'=>'__return_true','args'=>['name'=>['type'=>'string','required'=>false]]]]);
});
