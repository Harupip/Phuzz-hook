<?php
function emptiness_conditions_fixture() {
$x = $_GET['x'];
$out = [];
$out["empty direct"] = empty($_GET['x']);
$out["empty local"] = empty($x);
$out["strict empty"] = $x === '';
$out["loose empty"] = $x == '';
$out["not empty"] = $x !== '';
$out["truthiness"] = !$x;
$out["cast bool"] = (bool)$x === false;
$out["loose false"] = $x == false;
$out["strict false"] = $x === false;
$out["null compare"] = $x === null;
$out["is_null"] = is_null($x);
$out["isset"] = !isset($_GET['x']);
$out["array_key_exists"] = !array_key_exists('x', $_GET);
$out["strlen zero"] = strlen($x) === 0;
$out["strlen range"] = strlen($x) < 1;
$out["trim empty"] = trim($x) === '';
$out["count zero"] = count($_GET['items']) === 0;
$out["empty array"] = $_GET['items'] === [];
$out["numeric zero"] = $x == 0;
$out["string zero"] = $x === '0';
$out["fallback"] = $x ?: 'default';
$out["coalesce"] = $x ?? 'default';
$out["filter bool"] = filter_var($x, FILTER_VALIDATE_BOOLEAN) === false;
echo json_encode($out);
}
$_GET = ['x'=>'fuzz', 'items'=>['fuzz']];
emptiness_conditions_fixture();