<?php

$_POST = ['literal' => 'literal-value', 'runtime' => 'runtime-value', 'present' => 'yes', 'empty' => '', 10 => 'integer-value'];
$runtimeKey = 'runtime';
$issetKey = 'present';
$emptyKey = 'empty';
$integerKey = 10;
$result = [
    $_POST['literal'] ?? null,
    $_POST[$runtimeKey] ?? null,
    isset($_POST['present']),
    isset($_POST[$issetKey]),
    empty($_POST['empty']),
    empty($_POST[$emptyKey]),
    $_POST[$integerKey] ?? null,
];
echo json_encode($result, JSON_UNESCAPED_SLASHES), PHP_EOL;
echo json_encode(hookphuzz_opcode_get_superglobal_dim_read_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
