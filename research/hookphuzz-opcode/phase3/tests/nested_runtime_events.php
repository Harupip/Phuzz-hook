<?php

$_POST = ['user' => ['email' => 'alice@example.test']];
$root = 'user';
$leaf = 'email';
echo $_POST[$root][$leaf], PHP_EOL;
echo json_encode(hookphuzz_opcode_get_superglobal_dim_read_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
