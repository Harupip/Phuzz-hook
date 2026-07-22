<?php
declare(strict_types=1);
foreach (file('/tmp/phase10-crm.cookies', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
    if (str_starts_with($line, '#HttpOnly_')) $line = substr($line, 10);
    elseif (str_starts_with($line, '#')) continue;
    $parts = explode("\t", $line);
    if (count($parts) >= 7) $_COOKIE[$parts[5]] = urldecode($parts[6]);
}
require '/var/www/html/wp-load.php';
$contract = json_decode((string) file_get_contents('/results/nonce-contract.json'), true, 512, JSON_THROW_ON_ERROR);
$value = trim((string) file_get_contents('/tmp/phase10-crm.nonce'));
$result = $value === '' ? false : wp_verify_nonce($value, $contract['nonce_action']);
$document = [
    'nonce_present' => $value !== '',
    'nonce_action' => $contract['nonce_action'],
    'wp_verify_nonce_result' => $result,
    'valid' => $result === 1 || $result === 2,
];
file_put_contents('/results/nonce-validation.json', json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
exit($document['valid'] ? 0 : 1);
