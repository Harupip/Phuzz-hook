<?php

$data = [
    'username' => 'alice',
    10 => 'ten',
    'user' => ['name' => 'alice'],
];
$stringKey = 'username';
$integerKey = 10;
$root = 'user';
$leaf = 'name';

echo $data['username'], '|', $data[$stringKey], '|', $data[10], '|', $data[$integerKey], '|', $data['user']['name'], '|', $data[$root][$leaf], PHP_EOL;
