<?php
function isset_guard_fixture() {
    $out = ['isset' => isset($_GET['mode']), 'not_isset' => !isset($_GET['mode']),
            'empty' => empty($_GET['mode']), 'not_empty' => !empty($_GET['mode'])];
    if (!isset($_GET['mode'])) {
        $out['hidden'] = $_GET['hidden'] ?? 'new-path';
    }
    echo json_encode($out);
}
parse_str(getenv('HOOKPHUZZ_TEST_QUERY'), $_GET);
isset_guard_fixture();
