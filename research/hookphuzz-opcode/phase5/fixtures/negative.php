<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
final class Phase5ArrayAccess implements ArrayAccess {
    public function offsetExists(mixed $offset): bool { return true; }
    public function offsetGet(mixed $offset): mixed { return 'value'; }
    public function offsetSet(mixed $offset, mixed $value): void {}
    public function offsetUnset(mixed $offset): void {}
}
function phase5_negative(): void {
    $local = ['local_key' => 'value'];
    $fake_GET = ['fake_key' => 'value'];
    $_get = ['wrong_case' => 'value'];
    $object = (object) ['property' => 'value'];
    $arrayAccess = new Phase5ArrayAccess();
    $local['local_key'];
    $fake_GET['fake_key'];
    $_get['wrong_case'];
    $object->property;
    $arrayAccess['array_access_key'];
}
phase5_negative();
phase5_response('negative');
