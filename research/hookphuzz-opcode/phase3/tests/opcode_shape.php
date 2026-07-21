<?php

function phase3_get(): mixed
{
    return $_GET['id'];
}

function phase3_post(): mixed
{
    return $_POST['username'];
}

function phase3_request(string $runtimeKey): mixed
{
    return $_REQUEST[$runtimeKey];
}

function phase3_cookie(): mixed
{
    return $_COOKIE['session'];
}

function phase3_nested_post(): mixed
{
    return $_POST['user']['name'];
}
