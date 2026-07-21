<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
function phase5_parallel(): void {
    $key = ltrim((string) ($_SERVER['PATH_INFO'] ?? ''), '/');
    $_GET[$key];
}
phase5_parallel();
phase5_response('parallel');
