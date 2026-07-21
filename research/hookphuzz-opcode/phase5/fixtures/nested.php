<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
function phase5_nested(): void { $_POST['user']['email']; }
phase5_nested();
phase5_response('nested');
