<?php

$_POST = ['x' => 'value'];
for ($index = 0; $index < 4097; $index++) {
    $_POST['x'];
}
echo count(hookphuzz_opcode_get_superglobal_dim_read_events()), PHP_EOL;
echo hookphuzz_opcode_get_dropped_event_count(), PHP_EOL;
echo json_encode(hookphuzz_opcode_get_superglobal_dim_read_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
