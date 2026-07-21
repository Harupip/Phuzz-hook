<?php

$data = [
    'user' => [
        'name' => 'alice',
    ],
];

echo $data['user']['name'], PHP_EOL;
echo json_encode(hookphuzz_opcode_get_fetch_dim_r_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
