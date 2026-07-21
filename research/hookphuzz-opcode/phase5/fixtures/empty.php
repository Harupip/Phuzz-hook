<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
function phase5_empty(): void { empty($_POST['empty_key']); }
phase5_empty();
phase5_response('empty');
