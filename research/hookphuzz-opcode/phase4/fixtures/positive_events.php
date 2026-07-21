<?php

$_GET = ['a' => 'get-a', 'filters' => ['tag' => 'wordpress']];
$_POST = ['runtime_post' => 'post-runtime', 'settings' => ['email' => 'ops@example.test']];
$_REQUEST = ['token' => 'request-token'];
$_COOKIE = ['runtime_cookie' => ''];
$postKey = 'runtime_post';
$cookieKey = 'runtime_cookie';
$filterKey = 'tag';

$result = [
    $_GET['a'] ?? null,
    $_POST[$postKey] ?? null,
    isset($_REQUEST['token']),
    empty($_COOKIE[$cookieKey]),
    isset($_POST['settings']['email']),
    empty($_GET['filters'][$filterKey]),
    $_POST['settings']['email'] ?? null,
];
echo json_encode($result, JSON_UNESCAPED_SLASHES), PHP_EOL;
echo json_encode(hookphuzz_opcode_get_superglobal_dim_read_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
