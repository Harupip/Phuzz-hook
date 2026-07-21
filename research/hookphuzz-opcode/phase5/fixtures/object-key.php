<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
final class Phase5ObjectKey {
    public static int $toStringCalls = 0;
    public function __toString(): string { self::$toStringCalls++; return 'object_key'; }
}
function phase5_object_key(): array {
    try { $_GET[new Phase5ObjectKey()]; }
    catch (TypeError $error) { return ['error' => $error::class, 'to_string_calls' => Phase5ObjectKey::$toStringCalls]; }
    return ['error' => null, 'to_string_calls' => Phase5ObjectKey::$toStringCalls];
}
phase5_response('object-key', phase5_object_key());
