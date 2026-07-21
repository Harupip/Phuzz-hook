<?php

$_REQUEST = ['email' => 'alice@example.test'];
$key = 'email';
echo $_REQUEST[$key], PHP_EOL;
echo json_encode(hookphuzz_opcode_get_superglobal_dim_read_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
