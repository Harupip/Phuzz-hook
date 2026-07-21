<?php

final class NoStringKey
{
    public function __toString(): string
    {
        echo "TOSTRING_CALLED\n";
        return 'x';
    }
}

$_POST = ['x' => 'value'];
$key = new NoStringKey();
try {
    echo $_POST[$key], PHP_EOL;
} catch (TypeError $error) {
    echo 'caught:', $error::class, PHP_EOL;
}
echo json_encode(hookphuzz_opcode_get_superglobal_dim_read_events(), JSON_UNESCAPED_SLASHES), PHP_EOL;
