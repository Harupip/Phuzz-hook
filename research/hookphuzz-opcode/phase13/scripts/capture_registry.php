<?php
/** Write a complete, scalar-only REST registry directly to PHASE13_REGISTRY_TMP. */
function hp13_diag(string $stage, array $extra = []): void {
    $row = array_merge(['stage'=>$stage,'memory'=>memory_get_usage(true),'peak_memory'=>memory_get_peak_usage(true)], $extra);
    fwrite(STDERR, json_encode($row, JSON_UNESCAPED_SLASHES) . "\n");
}
function hp13_callback($value): array {
    $repr='unresolved'; $file=null; $line=0; $type='unresolved';
    try {
        if (is_string($value)) { $repr=$value; $type='function'; $r=new ReflectionFunction($value); }
        elseif (is_array($value) && count($value)===2) { $repr=(is_object($value[0])?get_class($value[0]):(string)$value[0]).'::'.(string)$value[1]; $type=is_object($value[0])?'object_method':'static_method'; $r=new ReflectionMethod($value[0],$value[1]); }
        elseif ($value instanceof Closure) { $repr='closure'; $type='closure'; $r=new ReflectionFunction($value); }
        elseif (is_object($value) && method_exists($value,'__invoke')) { $repr=get_class($value).'::__invoke'; $type='invokable'; $r=new ReflectionMethod($value,'__invoke'); }
        else return ['callback_repr'=>$repr,'callback_type'=>$type,'source_file'=>$file,'source_line'=>$line,'limitation'=>'unresolved_callback'];
        $file=$r->getFileName() ?: null; $line=$r->getStartLine();
    } catch (Throwable $e) { return ['callback_repr'=>$repr,'callback_type'=>$type,'source_file'=>null,'source_line'=>0,'limitation'=>'reflection_failure']; }
    return ['callback_repr'=>$repr,'callback_type'=>$type,'source_file'=>$file,'source_line'=>$line,'limitation'=>null];
}
function hp13_value($value, int $depth = 0) {
    if ($depth > 12) return ['unsupported'=>'depth_limit'];
    if (is_null($value) || is_bool($value) || is_int($value) || is_float($value) || is_string($value)) return $value;
    if (is_array($value)) { $out=[]; foreach ($value as $key=>$item) $out[(string)$key]=hp13_value($item,$depth+1); ksort($out,SORT_STRING); return $out; }
    return ['unsupported'=>is_object($value)?'object':gettype($value)];
}
register_shutdown_function(static function (): void { $last=error_get_last(); if ($last) hp13_diag('shutdown_error',['error_type'=>$last['type'],'error_file'=>basename((string)$last['file']),'error_line'=>$last['line']]); });
try {
    hp13_diag('script_started');
    if (!defined('ABSPATH')) throw new RuntimeException('registry_wordpress_not_loaded');
    hp13_diag('wordpress_loaded');
    $slug=(string)getenv('PHASE13_PLUGIN_SLUG'); $version=(string)getenv('PHASE13_PLUGIN_VERSION');
    if ($slug==='' || !is_plugin_active($slug.'/'.$slug.'.php') && $slug!=='contact-form-7') throw new RuntimeException('registry_plugin_not_active');
    hp13_diag('target_plugin_verified',['plugin'=>$slug]); hp13_diag('before_rest_server_init'); $server=rest_get_server(); hp13_diag('after_rest_server_init');
    $routes=$server->get_routes(); if (!is_array($routes)) throw new RuntimeException('registry_route_enumeration_failure'); hp13_diag('routes_received',['route_count'=>count($routes)]);
    $rows=[]; $index=0; hp13_diag('before_endpoint_normalization');
    foreach ($routes as $route=>$definitions) foreach ($definitions as $definition) {
        if (!is_array($definition) || !array_key_exists('callback',$definition)) continue;
        $callback=hp13_callback($definition['callback']); $permission=hp13_callback($definition['permission_callback'] ?? null);
        $rows[]=['route'=>(string)$route,'methods'=>hp13_value($definition['methods'] ?? []),'callback_repr'=>$callback['callback_repr'],'callback_type'=>$callback['callback_type'],'source_file'=>$callback['source_file'],'source_line'=>$callback['source_line'],'callback_limitation'=>$callback['limitation'],'permission_callback'=>$permission['callback_repr'],'permission_callback_type'=>$permission['callback_type'],'permission_source_file'=>$permission['source_file'],'permission_source_line'=>$permission['source_line'],'permission_limitation'=>$permission['limitation'],'argument_definitions'=>hp13_value($definition['args'] ?? [])];
        hp13_diag('endpoint_normalized',['route_index'=>$index++,'callback_type'=>$callback['callback_type']]);
    }
    usort($rows, static fn($a,$b)=>strcmp(json_encode($a),json_encode($b))); hp13_diag('after_endpoint_normalization',['endpoint_count'=>count($rows)]); hp13_diag('before_json_encode');
    $json=json_encode(['schema_version'=>1,'run_id'=>getenv('PHASE13_RUN_ID'),'plugin_slug'=>$slug,'plugin_version'=>$version,'captured_at'=>gmdate('c'),'routes'=>$rows], JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR); hp13_diag('after_json_encode',['bytes'=>strlen($json)]);
    $tmp=(string)getenv('PHASE13_REGISTRY_TMP'); if ($tmp==='') throw new RuntimeException('registry_artifact_write_failure'); hp13_diag('before_artifact_write');
    if (file_put_contents($tmp,$json,LOCK_EX)===false || filesize($tmp)===0) throw new RuntimeException('registry_artifact_empty'); hp13_diag('artifact_write_complete',['bytes'=>filesize($tmp)]); hp13_diag('script_complete');
} catch (Throwable $e) { hp13_diag('capture_failure',['failure_class'=>$e->getMessage() ?: 'registry_unknown_failure']); fwrite(STDERR,"registry_failure=".($e->getMessage() ?: 'registry_unknown_failure')."\n"); exit(1); }
