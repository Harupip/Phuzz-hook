<?php

function phase4_coalesce_literal(): mixed { return $_POST['name'] ?? null; }
function phase4_coalesce_runtime(string $runtimeKey): mixed { return $_POST[$runtimeKey] ?? null; }
function phase4_isset_literal(): bool { return isset($_POST['name']); }
function phase4_isset_runtime(string $runtimeKey): bool { return isset($_POST[$runtimeKey]); }
function phase4_empty_literal(): bool { return empty($_POST['name']); }
function phase4_empty_runtime(string $runtimeKey): bool { return empty($_POST[$runtimeKey]); }
function phase4_nested_coalesce(): mixed { return $_POST['settings']['email'] ?? null; }
function phase4_nested_isset(): bool { return isset($_POST['settings']['email']); }
function phase4_nested_empty(): bool { return empty($_POST['settings']['email']); }
function phase4_get_variant(): mixed { return $_GET['a'] ?? null; }
function phase4_request_variant(): bool { return isset($_REQUEST['token']); }
function phase4_cookie_variant(string $runtimeKey): bool { return empty($_COOKIE[$runtimeKey]); }
function phase4_local_control(array $local): mixed { return $local['name'] ?? null; }
function phase4_fake_control(): mixed { return $GLOBALS['_FAKE']['name'] ?? null; }
function phase4_lowercase_control(): mixed { return $GLOBALS['_post']['name'] ?? null; }
