<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
function phase5_isset(): void { isset($_GET['isset_key']); }
phase5_isset();
phase5_response('isset');
