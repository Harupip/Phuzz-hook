<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
function phase5_coalesce(): void { $_REQUEST['coalesce_key'] ?? 'default'; }
phase5_coalesce();
phase5_response('coalesce');
