<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
function phase5_get_literal(): void { $_GET['get_literal']; }
phase5_get_literal();
phase5_response('get-literal');
