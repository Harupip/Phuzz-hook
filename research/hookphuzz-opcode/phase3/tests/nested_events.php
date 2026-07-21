<?php

$_POST = ['user' => ['name' => 'alice']];
echo $_POST['user']['name'], PHP_EOL;
echo json_encode(hookphuzz_opcode_get_superglobal_dim_read_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
