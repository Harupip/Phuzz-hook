<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
function phase5_get_runtime(): void { $key = 'get_runtime'; $_GET[$key]; }
phase5_get_runtime();
phase5_response('get-runtime');
