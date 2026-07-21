<?php

$_GET = ['id' => 'get-id'];
echo $_GET['id'], PHP_EOL;
echo json_encode(hookphuzz_opcode_get_superglobal_dim_read_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
