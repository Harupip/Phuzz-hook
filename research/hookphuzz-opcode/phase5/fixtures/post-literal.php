<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
function phase5_post_literal(): void { $_POST['post_literal']; }
phase5_post_literal();
phase5_response('post-literal');
