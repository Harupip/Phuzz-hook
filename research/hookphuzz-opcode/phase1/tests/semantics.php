<?php

function display_name(string $name): string
{
    return strtoupper($name);
}

$payload = [
    'name' => 'alice',
    'profile' => ['role' => 'admin'],
];

echo display_name($payload['name']), '|', $payload['profile']['role'], PHP_EOL;
exit(0);
