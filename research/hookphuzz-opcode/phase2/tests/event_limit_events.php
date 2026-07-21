<?php

$data = ['x' => 'value'];

for ($index = 0; $index < 4097; $index++) {
    $data['x'];
}

echo hookphuzz_opcode_get_fetch_dim_r_count(), PHP_EOL;
echo hookphuzz_opcode_get_dropped_event_count(), PHP_EOL;
echo json_encode(hookphuzz_opcode_get_fetch_dim_r_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
