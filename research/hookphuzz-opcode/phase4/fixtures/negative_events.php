<?php

final class Phase4Properties
{
    public array $_POST = ['name' => 'property'];
    public static array $_GET = ['name' => 'static'];
}

final class Phase4ArrayAccess implements ArrayAccess
{
    public function offsetExists(mixed $offset): bool { return true; }
    public function offsetGet(mixed $offset): mixed { return 'array-access'; }
    public function offsetSet(mixed $offset, mixed $value): void {}
    public function offsetUnset(mixed $offset): void {}
}

function phase4_parameter_control(array $_POSTLike): array
{
    return [isset($_POSTLike['name']), empty($_POSTLike['name'])];
}

$local = ['name' => 'local'];
$_FAKE = ['name' => 'fake'];
$_post = ['name' => 'lowercase'];
$property = new Phase4Properties();
$arrayAccess = new Phase4ArrayAccess();
$variableName = 'local';
$result = [
    $local['name'] ?? null,
    isset($local['name']),
    empty($local['name']),
    $GLOBALS['_FAKE']['name'] ?? null,
    $GLOBALS['_post']['name'] ?? null,
    isset($property->_POST['name']),
    empty($property->_POST['name']),
    isset(Phase4Properties::$_GET['name']),
    empty(Phase4Properties::$_GET['name']),
    isset($arrayAccess['name']),
    empty($arrayAccess['name']),
    phase4_parameter_control($local),
    $$variableName['name'] ?? null,
];
echo json_encode($result, JSON_UNESCAPED_SLASHES), PHP_EOL;
echo json_encode(hookphuzz_opcode_get_superglobal_dim_read_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
