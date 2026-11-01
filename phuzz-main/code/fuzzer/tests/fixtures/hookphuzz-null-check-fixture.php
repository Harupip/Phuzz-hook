<?php

// Minimal REST request shape used by the Zend provenance tracker.
class WP_REST_Request {
    public $params;
    public function __construct($body) { $this->params = ['JSON' => $body]; }
    public function get_json_params() { return $this->params['JSON']; }
}

function hookphuzz_null_check_fixture(WP_REST_Request $request): array {
    $json = $request->get_json_params();
    $value = $json['mode'];
    $copy = $value;
    $query = $_GET['mode'] ?? null;
    $nonce = $json['nonce'];
    $out = [];
    if ($copy === null) {
        $out['json_null'] = $json['after_json_null'] ?? 'new-json-path';
    }
    if (is_null($copy)) {
        $out['is_null'] = true;
    }
    if ($query === null) {
        $out['query_null'] = $_GET['after_query_null'] ?? 'new-query-path';
    }
    if ($nonce === null) {
        $out['nonce'] = 'sensitive';
    }
    if (is_string($copy)) {
        $out['string'] = true;
    }
    return $out;
}

$input = $_GET;
$_GET = $input['query'];
echo json_encode(hookphuzz_null_check_fixture(new WP_REST_Request($input['body'])));
