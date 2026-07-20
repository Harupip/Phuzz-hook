<?php
declare(strict_types=1);
function percentile(array $values, float $p): float { sort($values); if (!$values) return 0; return $values[(int)floor((count($values)-1)*$p)]; }
$dir=$argv[1]??'';$expected=(int)($argv[2]??0);$output=$argv[3]??'';$runId=$argv[4]??'';
if(!$dir||!$expected||!$output||!$runId) exit(2);
$metas=glob($dir.'/*.json')?:[];$fail=[];$failureReasons=[];$latencies=[];$sizes=[];$ids=[];$markers=[];$artifacts=[];$validArtifacts=0;
foreach($metas as $metaFile){
    try{$m=json_decode((string)file_get_contents($metaFile),true,512,JSON_THROW_ON_ERROR);$b=json_decode((string)file_get_contents($m['body']),true,512,JSON_THROW_ON_ERROR);$a=json_decode((string)file_get_contents($m['artifact']),true,512,JSON_THROW_ON_ERROR);}catch(Throwable){$fail[]=basename($metaFile);$failureReasons['malformed']=($failureReasons['malformed']??0)+1;continue;}
    $event=false;foreach($a['events']??[] as $e)if(($e['callback_context']['root_callback']??null)===$m['callback']&&($e['source']??null)===$m['source']&&($e['path']??null)===['phase9_key']){$event=true;break;}
    $reasons=[];
    foreach(['run_id','request_id','controlled_marker'] as $field){$expectedValue=$field==='request_id'?$m['id']:($field==='controlled_marker'?$m['marker']:$runId);if(($a[$field]??null)!==$expectedValue)$reasons[]=$field.'_mismatch';}
    if(($m['run_id']??null)!==$runId)$reasons[]='metadata_stale';
    if(($b['data']['marker_observed']??null)!==$m['marker'])$reasons[]='marker_contamination';
    if(($b['data']['callback']??null)!==$m['callback'])$reasons[]='callback_mismatch';
    if(($b['data']['runtime_source']??null)!==$m['source'])$reasons[]='source_mismatch';
    if(($b['data']['path']??null)!==['phase9_key']||!$event)$reasons[]='path_mismatch';
    if($reasons){$fail[]=$m['id'];foreach($reasons as $reason)$failureReasons[$reason]=($failureReasons[$reason]??0)+1;}else $validArtifacts++;
    $ids[]=$m['id'];$markers[]=$m['marker'];$artifacts[]=$m['artifact'];$latencies[]=(float)$m['seconds'];$sizes[]=filesize($m['artifact']);
}
$duplicateIds=count($ids)-count(array_unique($ids));$duplicateMarkers=count($markers)-count(array_unique($markers));$duplicateArtifacts=count($artifacts)-count(array_unique($artifacts));
if(count($metas)!==$expected)$failureReasons['request_count']=abs($expected-count($metas));
if($duplicateIds)$failureReasons['duplicate_request_ids']=$duplicateIds;
if($duplicateMarkers)$failureReasons['duplicate_markers']=$duplicateMarkers;
if($duplicateArtifacts)$failureReasons['overwritten_artifacts']=$duplicateArtifacts;
$pass=count($metas)===$expected&&$validArtifacts===$expected&&$duplicateIds===0&&$duplicateMarkers===0&&$duplicateArtifacts===0;
$stats=static fn(array $v):array=>['min'=>$v?min($v):0,'median'=>$v?percentile($v,.5):0,'p50'=>$v?percentile($v,.5):0,'p95'=>$v?percentile($v,.95):0,'max'=>$v?max($v):0,'total'=>array_sum($v)];
$result=['schema_version'=>1,'run_id'=>$runId,'status'=>$pass?'PASS':'FAIL','requests_expected'=>$expected,'requests_sent'=>count($metas),'requests_observed'=>count($metas),'valid_artifacts'=>$validArtifacts,'semantic_passes'=>$validArtifacts,'unique_request_ids'=>count(array_unique($ids)),'unique_markers'=>count(array_unique($markers)),'missing_artifacts'=>max(0,$expected-count($artifacts)),'malformed_artifacts'=>$failureReasons['malformed']??0,'duplicate_request_ids'=>$duplicateIds,'overwritten_artifacts'=>$duplicateArtifacts,'stale_artifacts'=>($failureReasons['run_id_mismatch']??0)+($failureReasons['metadata_stale']??0),'cross_request_marker_contamination'=>$failureReasons['marker_contamination']??0,'callback_mismatch'=>$failureReasons['callback_mismatch']??0,'source_or_path_mismatch'=>($failureReasons['source_mismatch']??0)+($failureReasons['path_mismatch']??0),'failures_by_reason'=>$failureReasons,'failures'=>$fail,'artifact_size_bytes'=>$stats($sizes),'latency_seconds'=>$stats($latencies),'passed'=>$pass];
$tmp=$output.'.tmp.'.getmypid();file_put_contents($tmp,json_encode($result,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES),LOCK_EX);rename($tmp,$output);exit($pass?0:1);
