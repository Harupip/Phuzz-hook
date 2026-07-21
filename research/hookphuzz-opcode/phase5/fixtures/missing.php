<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
function phase5_missing(): void { $_GET['missing_get']; $_POST['missing_post']; }
phase5_headers('missing');
phase5_missing();
echo json_encode(['fixture' => 'missing'], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
