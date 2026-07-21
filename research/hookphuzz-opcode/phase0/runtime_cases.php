<?php

error_reporting(E_ALL);
$_POST = [];

function capture_runtime_case(string $name, Closure $expression): void
{
    $warnings = [];
    set_error_handler(static function (int $severity, string $message) use (&$warnings): bool {
        $warnings[] = $message;
        return true;
    });

    try {
        $result = $expression();
        printf("%s | warnings=%s | return=%s\n", $name, json_encode($warnings), var_export($result, true));
    } finally {
        restore_error_handler();
    }
}

capture_runtime_case('direct_missing', static fn (): mixed => $_POST['missing']);
capture_runtime_case('null_coalesce_missing', static fn (): mixed => $_POST['missing'] ?? null);
capture_runtime_case('isset_missing', static fn (): bool => isset($_POST['missing']));
capture_runtime_case('empty_missing', static fn (): bool => empty($_POST['missing']));
