<?php
function hookphuzz_fixture_callback() {
    $orderby = sanitize_text_field($_REQUEST['orderby']);
    $sid = absint($_POST['sid']);
    $cnt = intval($_GET['cnt']);
    $avatar = $_FILES['avatar'];
    $theme = filter_input(INPUT_COOKIE, 'theme');
    $action = $_REQUEST['action'];
}

function hookphuzz_json_callback() {
    $payload = json_decode(file_get_contents('php://input'), true);
    $token = $payload['token'];
}
