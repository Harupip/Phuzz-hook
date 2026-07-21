<?php

$_POST = ['name' => 'alice'];

$value = $_POST['name'];

echo $value, PHP_EOL;
echo hookphuzz_opcode_get_fetch_dim_r_count(), PHP_EOL;
