<?php

$_GET = ['id' => 'get-id'];
$_POST = ['username' => 'alice', 'user' => ['name' => 'nested-name'], 10 => 'ten'];
$_REQUEST = ['email' => 'alice@example.test'];
$_COOKIE = ['session' => 'cookie-session'];
$runtimeKey = 'email';

$result = [
    $_GET['id'],
    $_POST['username'],
    $_REQUEST[$runtimeKey],
    $_COOKIE['session'],
    $_POST[10],
    $_POST['user']['name'],
];
echo json_encode($result, JSON_UNESCAPED_SLASHES), PHP_EOL;
echo json_encode(hookphuzz_opcode_get_superglobal_dim_read_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
