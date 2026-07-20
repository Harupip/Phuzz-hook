<?php
declare(strict_types=1);
function fail(string $m): void { fwrite(STDERR,"source-resolution: $m\n"); exit(1); }
$input=$argv[1]??'';$output=$argv[2]??'';$runId=$argv[3]??''; if(!$input||!$output||!$runId)fail('arguments');
try{$probes=json_decode((string)file_get_contents($input),true,512,JSON_THROW_ON_ERROR);}catch(Throwable){fail('manifest');}
$checks=[];$accepted=[];$winner=null;$requestOrder='';$variablesOrder='';$failed=false;
foreach($probes as $probe){try{$body=json_decode((string)file_get_contents($probe['body']),true,512,JSON_THROW_ON_ERROR);$artifact=json_decode((string)file_get_contents($probe['artifact']),true,512,JSON_THROW_ON_ERROR);}catch(Throwable){fail('invalid evidence '.$probe['id']);}
    $data=$body['data']??[];$expected=$probe['expected_marker'];$callback=$probe['callback'];$event=false;foreach($artifact['events']??[] as $e)if(($e['callback_context']['root_callback']??null)===$callback&&($e['source']??null)===$probe['runtime_source']&&($e['path']??null)===['phase9_key']){$event=true;break;}
    $markerOk=($probe['expect_observed']??true) ? (($data['marker_observed']??null)===$expected) : (($data['marker_observed']??null)===null);
    $ok=($artifact['request_id']??null)===$probe['id']&&($artifact['run_id']??null)===$runId&&($probe['run_id']??$runId)===$runId&&($artifact['controlled_marker']??null)===$expected&&($data['callback']??null)===$callback&&($data['runtime_source']??null)===$probe['runtime_source']&&($data['path']??null)===['phase9_key']&&$markerOk&&$event;
    $label=$probe['label']??$probe['id'];$checks[]=['id'=>$probe['id'],'label'=>$label,'placement'=>$probe['placement'],'expected_marker'=>$expected,'observed_marker'=>$data['marker_observed']??null,'runtime_source'=>$probe['runtime_source'],'callback'=>$callback,'ok'=>$ok];if(!$ok)$failed=true;
    if(in_array($label,['request-query','request-body','request-cookie'],true)){if(($data['marker_observed']??null)===$expected)$accepted[]=$probe['placement'];}
    if($label==='request-precedence')$winner=$data['marker_observed']??null;
    $requestOrder=$probe['request_order'];$variablesOrder=$probe['variables_order'];
}
$rank=['query'=>0,'body'=>1,'cookie'=>2];usort($accepted,static fn($a,$b)=>$rank[$a]<=>$rank[$b]);$winnerPlacement=$winner==='PHASE9_PRECEDENCE_BODY'?'body':($winner==='PHASE9_PRECEDENCE_QUERY'?'query':($winner==='PHASE9_PRECEDENCE_COOKIE'?'cookie':null));
$result=['schema_version'=>1,'run_id'=>$runId,'status'=>$failed?'failed':'validated','runtime_source'=>'REQUEST','accepted_placements'=>$accepted,'precedence_winner'=>$winnerPlacement,'observed_marker'=>$winner,'request_order'=>$requestOrder,'variables_order'=>$variablesOrder,'resolution_method'=>'controlled_http_marker_probe','confidence'=>$failed?'none':'high','checks'=>$checks];$tmp=$output.'.tmp.'.getmypid();file_put_contents($tmp,json_encode($result,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES),LOCK_EX);rename($tmp,$output);if($failed)exit(1);
