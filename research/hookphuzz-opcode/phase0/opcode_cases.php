<?php

function case_direct_post(): mixed
{
    return $_POST['name'];
}

function case_dynamic_post(string $key): mixed
{
    return $_POST[$key];
}

function case_null_coalesce(): mixed
{
    return $_POST['name'] ?? null;
}

function case_isset(): bool
{
    return isset($_POST['name']);
}

function case_empty(): bool
{
    return empty($_POST['name']);
}

function case_increment(): void
{
    $_POST['count']++;
}

function consume(mixed $value): mixed
{
    return $value;
}

function case_function_argument(): mixed
{
    return consume($_POST['name']);
}

function case_unset(): void
{
    unset($_POST['name']);
}

function case_nested(): mixed
{
    return $_POST['settings']['email'];
}

function case_nested_dynamic(string $index): mixed
{
    return $_POST['users'][$index]['email'];
}

function case_copy(): mixed
{
    $copy = $_POST;
    return $copy['name'];
}

function case_reference(): mixed
{
    $ref =& $_POST;
    return $ref['name'];
}
