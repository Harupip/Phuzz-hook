<?php

final class NoStringKey
{
    public function __toString(): string
    {
        echo 'TOSTRING_CALLED', PHP_EOL;
        return 'x';
    }
}

$data = ['x' => 'value'];
$key = new NoStringKey();

try {
    echo $data[$key], PHP_EOL;
} catch (TypeError $error) {
    echo 'caught:', $error::class, PHP_EOL;
}

echo json_encode(hookphuzz_opcode_get_fetch_dim_r_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
