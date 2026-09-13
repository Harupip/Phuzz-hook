<?php

function hookphuzz_direct_argument_helper(): mixed
{
    return hookphuzz_runtime_sink($_POST['helper']);
}

function hookphuzz_direct_argument_fixture(): void
{
    $data = isset($_POST['data']) ? hookphuzz_runtime_sink($_POST['data']) : null;
    $helper = hookphuzz_direct_argument_helper();
    $direct = $_POST['direct'];
    $nested = $_POST['nested']['leaf'];
    $local = $_POST['local'];
    $copied = $local;
    $guard = isset($_POST['guard']);
    $empty = empty($_POST['empty_guard']);

    if ($data === 'data' && $helper === 'helper' && $direct === 'direct'
        && $nested === 'nested' && $copied === 'local') {
        echo $guard && !$empty ? 'direct-read' : 'guard-read';
    }
}

eval('function hookphuzz_runtime_sink($value) { return $value; }');

$_POST = [
    'data' => 'data',
    'helper' => 'helper',
    'direct' => 'direct',
    'nested' => ['leaf' => 'nested'],
    'local' => 'local',
    'guard' => 'present',
    'empty_guard' => '',
];

hookphuzz_direct_argument_fixture();
