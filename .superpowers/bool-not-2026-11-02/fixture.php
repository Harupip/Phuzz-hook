<?php
function bool_not_fixture() {
    $value = $_GET['mode'];
    $copied = $value;
    $out = [];
    if (!$copied) {
        $out['not'] = $_GET['new_after_not'] ?? 'new-not-path';
    }
    if ($copied == false) {
        $out['equals_false'] = $_GET['new_after_false'] ?? 'new-false-path';
    }
    $nonce = $_GET['nonce'];
    if (!$nonce) { $out['nonce'] = 'unexpected'; }
    $constant = 'not-input';
    if (!$constant) { $out['constant'] = 'unexpected'; }
    $checked = isset($_GET['guard']);
    if (!$checked) { $out['missing'] = 'guard'; }
    echo json_encode($out);
}
$_GET = json_decode(getenv('HOOKPHUZZ_TEST_PARAMS'), true);
bool_not_fixture();
