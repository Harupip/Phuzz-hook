<?php

$_POST = ['username' => 'alice'];
echo $_POST['username'], PHP_EOL;
echo json_encode(hookphuzz_opcode_get_superglobal_dim_read_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
