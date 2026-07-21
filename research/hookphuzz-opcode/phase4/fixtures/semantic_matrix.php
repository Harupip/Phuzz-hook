<?php

final class Phase4StringCounter
{
    public static int $calls = 0;

    public function __toString(): string
    {
        self::$calls++;
        return 'converted';
    }
}

$_POST = [
    'null' => null,
    'false' => false,
    'zero' => 0,
    'string_zero' => '0',
    'empty_string' => '',
    'nested' => [],
    10 => 'integer-key',
];
$integerKey = 10;
$objectKey = new Phase4StringCounter();
$objectOutcome = null;
try {
    $objectOutcome = $_POST[$objectKey] ?? null;
} catch (Throwable $error) {
    $objectOutcome = [$error::class, $error->getMessage()];
}

$result = [
    'coalesce_missing' => $_POST['missing'] ?? null,
    'isset_missing' => isset($_POST['missing']),
    'empty_missing' => empty($_POST['missing']),
    'isset_null' => isset($_POST['null']),
    'empty_null' => empty($_POST['null']),
    'isset_false' => isset($_POST['false']),
    'empty_false' => empty($_POST['false']),
    'empty_zero' => empty($_POST['zero']),
    'empty_string_zero' => empty($_POST['string_zero']),
    'empty_string' => empty($_POST['empty_string']),
    'integer_key' => $_POST[$integerKey] ?? null,
    'object_key' => $objectOutcome,
    'to_string_calls' => Phase4StringCounter::$calls,
    'nested_missing' => $_POST['nested']['missing'] ?? null,
];
echo json_encode($result, JSON_UNESCAPED_SLASHES), PHP_EOL;
