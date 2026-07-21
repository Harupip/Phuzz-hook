<?php

$_POST = ['outer' => 'outer', 'inner' => 'inner', 'recur' => 'recur'];

function phase4_inner(): bool
{
    return isset($_POST['inner']);
}

function phase4_outer(): array
{
    return [isset($_POST['outer']), phase4_inner()];
}

function phase4_recur(int $remaining): bool
{
    $current = isset($_POST['recur']);
    return $remaining === 1 ? $current : ($current && phase4_recur($remaining - 1));
}

$result = [phase4_outer(), phase4_outer(), phase4_recur(3)];
echo json_encode($result, JSON_UNESCAPED_SLASHES), PHP_EOL;
echo json_encode(hookphuzz_opcode_get_superglobal_dim_read_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
