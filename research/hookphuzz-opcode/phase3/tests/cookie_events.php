<?php

$_COOKIE = ['session_id' => 'cookie-session'];
echo $_COOKIE['session_id'], PHP_EOL;
echo json_encode(hookphuzz_opcode_get_superglobal_dim_read_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
