<?php

final class Phase3NoStringKey
{
    public function __toString(): string
    {
        echo "TOSTRING_CALLED\n";
        return 'x';
    }
}

$_POST = ['x' => 'value'];
$key = new Phase3NoStringKey();
try {
    echo $_POST[$key], PHP_EOL;
} catch (TypeError $error) {
    echo 'caught:', $error::class, PHP_EOL;
}
