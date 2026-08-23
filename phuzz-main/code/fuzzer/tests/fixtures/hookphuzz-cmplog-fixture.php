<?php

function hookphuzz_cmplog_fixture(): array
{
    $mode = (string) ($_GET['mode'] ?? '');
    $other = (string) ($_GET['other'] ?? '');
    $copied = $mode;
    $result = [];

    if ($copied === 'strict_target') {
        $result[] = 'strict';
    }
    if ($copied == 'loose_target') {
        $result[] = 'loose';
    }
    if ($copied !== 'not_strict_target') {
        $result[] = 'not_strict';
    }
    if ($copied != 'not_loose_target') {
        $result[] = 'not_loose';
    }
    if ('reverse_target' === $copied) {
        $result[] = 'reverse';
    }
    switch ($copied) {
        case 'switch_target':
            $result[] = 'switch';
            break;
        case 'switch_other':
            $result[] = 'switch_other';
            break;
    }

    if ('constant_left' === 'constant_right') {
        $result[] = 'constant';
    }
    $unlinked = (string) (getenv('HOOKPHUZZ_UNLINKED') ?: '');
    if ($unlinked === 'unlinked_target') {
        $result[] = 'unlinked';
    }
    if ($copied === 'duplicate_target') {
        $result[] = 'duplicate_one';
    }
    if ($copied === 'duplicate_target') {
        $result[] = 'duplicate_two';
    }
    if ($other === 'other_target') {
        $result[] = 'other';
    }

    return $result;
}

echo json_encode(hookphuzz_cmplog_fixture());
