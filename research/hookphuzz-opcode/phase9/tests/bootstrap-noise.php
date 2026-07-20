<?php
declare(strict_types=1);
$artifactPath=$argv[1]??'';$output=$argv[2]??'';$runId=$argv[3]??'';
try{$artifact=json_decode((string)file_get_contents($artifactPath),true,512,JSON_THROW_ON_ERROR);}catch(Throwable){fwrite(STDERR,"bootstrap artifact malformed\n");exit(1);}
$ignored=0;$accepted=0;$target='hookphuzz_phase9_get_probe';foreach($artifact['events']??[] as $e){if(($e['path']??null)===['phase9_bootstrap_noise']){if(($e['callback_context']['attributed']??false)===false)$ignored++;else $accepted++;}}
$targetEvents=0;foreach($artifact['events']??[] as $e)if(($e['callback_context']['root_callback']??null)===$target&&($e['path']??null)===['phase9_key']&&($e['source']??null)==='GET')$targetEvents++;
$pass=($artifact['run_id']??null)===$runId&&$ignored>0&&$accepted===0&&$targetEvents>0;
$out=['schema_version'=>1,'run_id'=>$runId,'request_id'=>$artifact['request_id']??null,'status'=>$pass?'PASS':'FAIL','root_callback'=>$target,'ignored_unattributed_events'=>$ignored,'accepted_target_noise_events'=>$accepted,'accepted_target_parameter_events'=>$targetEvents,'artifact'=>$artifactPath,'passed'=>$pass];$tmp=$output.'.tmp.'.getmypid();file_put_contents($tmp,json_encode($out,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES),LOCK_EX);rename($tmp,$output);exit($pass?0:1);
