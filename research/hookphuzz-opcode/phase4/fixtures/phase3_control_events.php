<?php

$data = ['id' => 1];
$_POST_FAKE = ['id' => 2];
$_post = ['id' => 3];
echo $data['id'], '|', $_POST_FAKE['id'], '|', $_post['id'], PHP_EOL;
echo json_encode(hookphuzz_opcode_get_superglobal_dim_read_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
