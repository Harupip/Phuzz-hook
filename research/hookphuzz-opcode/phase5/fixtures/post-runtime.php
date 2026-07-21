<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
function phase5_post_runtime(): void { $key = 'post_runtime'; $_POST[$key]; }
phase5_post_runtime();
phase5_response('post-runtime');
