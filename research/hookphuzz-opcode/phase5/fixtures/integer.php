<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
function phase5_integer(): void { $_GET[7]; }
phase5_integer();
phase5_response('integer');
