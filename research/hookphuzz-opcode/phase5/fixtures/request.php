<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
function phase5_request(): void { $_REQUEST['request_key']; }
phase5_request();
phase5_response('request');
