<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
function phase5_cookie(): void { $_COOKIE['cookie_key']; }
phase5_cookie();
phase5_response('cookie');
