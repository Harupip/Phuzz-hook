<?php
function empty_forms_fixture() {
    $out = [];
    $out['direct_get'] = empty($_GET['direct']);
    $out['direct_post'] = empty($_POST['direct']);
    $out['nested_string'] = empty($_GET['nested']['value']);
    $out['nested_index'] = empty($_GET['items'][0]);
    $key = 'dynamic';
    $out['dynamic_key'] = empty($_GET[$key]);
    $local = $_GET['local'];
    $out['local_var'] = empty($local);
    $copy = $local;
    $out['copied_var'] = empty($copy);
    $coalesced = $_GET['coalesced'] ?? '';
    $out['coalesced_var'] = empty($coalesced);
    $out['expression'] = empty(trim($_GET['expression']));
    $out['negated'] = !empty($_GET['negated']);
    $out['missing_key'] = empty($_GET['missing']);
    $out['request'] = empty($_REQUEST['request']);
    $out['cookie'] = empty($_COOKIE['cookie']);
    $object = (object) ['value' => $_GET['object']];
    $out['object_property'] = empty($object->value);
    echo json_encode($out);
}
$_GET = ['direct'=>'fuzz','nested'=>['value'=>'fuzz'],'items'=>['fuzz'],'dynamic'=>'fuzz','local'=>'fuzz','coalesced'=>'fuzz','expression'=>'fuzz','negated'=>'fuzz','object'=>'fuzz'];
$_POST = ['direct'=>'fuzz']; $_REQUEST = ['request'=>'fuzz']; $_COOKIE = ['cookie'=>'fuzz'];
empty_forms_fixture();
