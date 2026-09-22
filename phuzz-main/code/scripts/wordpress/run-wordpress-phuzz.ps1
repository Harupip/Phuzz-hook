[CmdletBinding()]
param(
    [ValidatePattern('^[a-zA-Z0-9_.-]+$')]
    [string]$PluginSlug = "show-all-comments-in-one-page",
    [switch]$ForcePlugins,
    [switch]$NoFollowLogs,
    [switch]$UseZendDiscovery,
    [ValidatePattern('^[a-zA-Z0-9_./-]+$')]
    [string]$BootstrapConfigSlug = "",
    [ValidateRange(1, 86400)]
    [int]$WebTimeoutSeconds = 240,
    [ValidateRange(1, 86400)]
    [int]$SeedWaitSeconds = 45,
    [ValidateRange(1, 120)]
    [int]$OnlineTimeoutSeconds,
    [ValidateRange(1, 20)]
    [int]$OnlineMaxVersions,
    [ValidateRange(1, 128)]
    [int]$OnlineMaxCandidates,
    [ValidateRange(1, 86400)]
    [int]$OnlineCampaignTimeoutSeconds,
    [ValidateRange(0, 100000)]
    [int]$StopOnVulnCount
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $PSCommandPath
$scriptRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir "..\..")).Path
$settingsReaderPath = Join-Path $scriptDir "read-phuzz-env.ps1"
if (-not (Test-Path -LiteralPath $settingsReaderPath -PathType Leaf)) {
    throw "Missing PHUZZ settings reader: $settingsReaderPath"
}
. $settingsReaderPath
$runtimeSettings = Resolve-PhuzzRuntimeSettings -Path (Join-Path $scriptRoot "phuzz.env") -BoundParameters $PSBoundParameters
$OnlineTimeoutSeconds = $runtimeSettings["OnlineTimeoutSeconds"]
$OnlineMaxVersions = $runtimeSettings["OnlineMaxVersions"]
$OnlineMaxCandidates = $runtimeSettings["OnlineMaxCandidates"]
$OnlineCampaignTimeoutSeconds = $runtimeSettings["OnlineCampaignTimeoutSeconds"]
$StopOnVulnCount = $runtimeSettings["StopOnVulnCount"]
$pluginScript = Join-Path $scriptRoot "web\applications\wordpress\_plugins\download-plugins.ps1"
$fuzzerService = "fuzzer-wordpress-plugin"
$webUrl = "http://localhost:8080/"

$UseZendDiscovery = $true
if (-not $BootstrapConfigSlug) {
    $BootstrapConfigSlug = "wordpress/bootstrap-generated"
}

function Get-ComposeArgs {
    param([string]$OverridePath)

    return @("docker", "compose", "-f", "docker-compose.yml", "-f", $OverridePath)
}

function Invoke-Compose {
    param(
        [string[]]$ComposeArgs,
        [string[]]$AdditionalArgs
    )

    & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] @AdditionalArgs
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose command failed: $($AdditionalArgs -join ' ')"
    }
}

function Reset-ZendRuntimeArtifacts {
    param([string[]]$ComposeArgs)

    $resetCommand = @"
set -eu
rm -rf -- /shared-tmpfs/hook-coverage /shared-tmpfs/fuzzer-findings /shared/opcode-events /shared/hookphuzz-callback-registry.json
mkdir -p /shared-tmpfs/hook-coverage/requests /shared-tmpfs/fuzzer-findings /shared/opcode-events
chown -R www-data:www-data /shared-tmpfs/hook-coverage /shared-tmpfs/fuzzer-findings /shared/opcode-events
"@
    # Windows checkouts must not pass CRLF shell commands to the Linux container.
    $resetCommand = $resetCommand.Replace("`r`n", "`n")
    Write-Host "Resetting Zend runtime artifacts for this campaign"
    Invoke-Compose -ComposeArgs $ComposeArgs -AdditionalArgs @("exec", "-T", "web", "sh", "-lc", $resetCommand)
}

function New-PluginOverrideFile {
    param(
        [string]$PluginSlug,
        [string]$BootstrapConfigSlug,
        [string]$LegacyRunId = "",
        [switch]$UseZendDiscovery,
        [int]$StopOnVulnCount = 0
    )

    $path = Join-Path $env:TEMP ("phuzz-{0}.override.yml" -f $PluginSlug)
    $content = @(
        "services:"
        "  web:"
        "    environment:"
        "      FUZZER_COVERAGE_PATH: /var/www/html/wp-content/plugins/$PluginSlug/"
        "      WP_TARGET_PLUGIN: $PluginSlug"
    )
    if ($UseZendDiscovery -and $PluginSlug -eq "learnpress") {
        $content += "      HOOKPHUZZ_STRICT_NONCE_PROOF: 1"
    }
    if ($UseZendDiscovery) {
        $content += @(
            "    build:"
            "      context: ../.."
            "      dockerfile: phuzz-main/code/web/Dockerfile.zend"
            "    volumes:"
            "      - ./web/applications:/applications/"
            "      - shared-tmpfs:/shared-tmpfs"
            "      - shared-tmpfs:/shared"
        )
    }
    $content += @(
        "  ${fuzzerService}:"
        "    environment:"
        "      FUZZER_CONFIG: $BootstrapConfigSlug"
        "      HOOKPHUZZ_STOP_ON_VULN: $StopOnVulnCount"
    )
    if ($LegacyRunId) {
        $content += "      HOOKPHUZZ_LEGACY_RUN_ID: $LegacyRunId"
    }
    if ($UseZendDiscovery) {
        $content += @(
            "      HOOKPHUZZ_CMPLOG: 1"
            "    volumes:"
            "      - shared-tmpfs:/shared"
        )
    }
    Set-Content -LiteralPath $path -Value $content -Encoding ASCII
    return $path
}

function Assert-PathExists {
    param(
        [string]$Path,
        [string]$Hint
    )

    if (-not (Test-Path $Path)) {
        throw "Missing required file: $Path`n$Hint"
    }
}

function Wait-ForWebReady {
    param(
        [string]$Url,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10
            if ($response.StatusCode -eq 200) {
                Write-Host "Web is ready: $Url"
                return
            }
        } catch {
            Start-Sleep -Seconds 5
            continue
        }

        Start-Sleep -Seconds 5
    }

    throw "Timed out waiting for $Url to return HTTP 200 within $TimeoutSeconds seconds."
}

function Invoke-ZendRestRouteBootstrap {
    param([string]$Url)

    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 20
        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
            Write-Host "Zend REST route bootstrap completed: $Url status=$($response.StatusCode)"
            return
        }
    } catch {
        throw "Zend REST route bootstrap failed for ${Url}: $($_.Exception.Message)"
    }

    throw "Zend REST route bootstrap failed for ${Url}: unexpected HTTP status $($response.StatusCode)"
}

function Invoke-ZendAdminPostFixtureProbe {
    param(
        [string]$Url,
        [string]$LegacyRunId
    )

    $requestId = "$LegacyRunId-admin-post-fixture-probe"
    $headers = @{
        "X-Fuzzer-Covid" = $requestId
        "X-HookPhuzz-Request-ID" = $requestId
        "X-HookPhuzz-Run-ID" = $LegacyRunId
    }
    $body = @{
        action = "hookphuzz_admin_post_test"
        probe = "fixture_value"
    }
    $response = Invoke-WebRequest `
        -Uri "$Url/wp-admin/admin-post.php" `
        -Method Post `
        -Headers $headers `
        -Body $body `
        -UseBasicParsing `
        -TimeoutSec 20
    if ($response.StatusCode -ne 200) {
        throw "Zend admin-post fixture probe failed: status=$($response.StatusCode)"
    }
}

function Get-WebJson {
    param(
        [string[]]$ComposeArgs,
        [string]$ContainerPath
    )

    $raw = & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] exec -T web cat $ContainerPath 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($raw -join "`n"))) {
        throw "Could not read JSON artifact from web container: $ContainerPath"
    }
    return (($raw -join "`n") | ConvertFrom-Json)
}

function Get-LearnPressRuntimeAdminPostCandidate {
    param([string[]]$ComposeArgs)

    $coverage = Get-WebJson -ComposeArgs $ComposeArgs -ContainerPath "/shared-tmpfs/hook-coverage/total_coverage.json"
    $registered = @($coverage.data.registered_callbacks.PSObject.Properties | ForEach-Object { $_.Value })
    $preferredHooks = @(
        "admin_post_lp_async_lp_background_single_course",
        "admin_post_lp_async_lp_background_single_email",
        "admin_post_lp_async_lp_background_single_thim_cache"
    )
    foreach ($hookName in $preferredHooks) {
        $action = $hookName.Substring("admin_post_".Length)
        $match = $registered |
            Where-Object {
                $_.hook_name -eq $hookName -and
                $_.is_active -eq $true -and
                $_.source_file -like "*/plugins/learnpress/*"
            } |
            Select-Object -First 1
        if ($match) {
            return [pscustomobject]@{
                action = $action
                hook_name = [string]$match.hook_name
                callback_id = [string]$match.callback_id
                callback_repr = [string]$match.callback_repr
                source_file = [string]$match.source_file
                auth_mode = "authenticated"
            }
        }
    }
    throw "LearnPress admin-post proof blocked: no preferred authenticated action is registered in the current runtime registry."
}

function Invoke-LearnPressHttpProbe {
    param(
        [string]$Url,
        [string]$LegacyRunId,
        [string]$RequestId,
        [hashtable]$Body
    )

    $headers = @{
        "X-Fuzzer-Covid" = $RequestId
        "X-HookPhuzz-Request-ID" = $RequestId
        "X-HookPhuzz-Run-ID" = $LegacyRunId
    }
    try {
        $response = Invoke-WebRequest `
            -Uri "$Url/wp-admin/admin-post.php" `
            -Method Post `
            -Headers $headers `
            -Body $Body `
            -UseBasicParsing `
            -TimeoutSec 30
        return [pscustomobject]@{
            status_code = [int]$response.StatusCode
            error = $null
        }
    } catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        }
        return [pscustomobject]@{
            status_code = $statusCode
            error = $_.Exception.Message
        }
    }
}

function Copy-WebRequestArtifact {
    param(
        [string[]]$ComposeArgs,
        [string]$RequestId,
        [string]$OutputPath
    )

    $names = & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] exec -T web sh -lc "find /shared-tmpfs/hook-coverage/requests -maxdepth 1 -type f -printf '%f\n'" 2>$null
    foreach ($name in @($names)) {
        $name = [string]$name
        if (-not $name.EndsWith(".json")) { continue }
        $raw = & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] exec -T web cat "/shared-tmpfs/hook-coverage/requests/$name" 2>$null
        if ($LASTEXITCODE -ne 0) { continue }
        try { $artifact = (($raw -join "`n") | ConvertFrom-Json) } catch { continue }
        if ([string]$artifact.request_id -eq $RequestId) {
            New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null
            ($raw -join "`n") | Set-Content -LiteralPath $OutputPath -Encoding UTF8
            return $artifact
        }
    }
    throw "LearnPress admin-post proof blocked: request artifact not found for $RequestId"
}

function Read-WebNonceProofArtifact {
    param(
        [string[]]$ComposeArgs,
        [string]$RequestId
    )

    $path = "/shared-tmpfs/hook-coverage/nonce-proof/$RequestId.json"
    $raw = & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] exec -T web cat $path 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($raw -join "`n"))) {
        throw "LearnPress admin-post proof blocked: nonce gate did not record $RequestId"
    }
    return (($raw -join "`n") | ConvertFrom-Json)
}

function Get-LearnPressCallbackExecution {
    param(
        [object]$Artifact,
        [object]$Candidate,
        [string]$RequestId
    )

    $executed = @($Artifact.hook_coverage.executed_callbacks.PSObject.Properties | ForEach-Object { $_.Value })
    return $executed |
        Where-Object {
            $_.callback_id -eq $Candidate.callback_id -and
            $_.hook_name -eq $Candidate.hook_name -and
            $_.fired_hook -eq $Candidate.hook_name -and
            $_.callback_repr -eq $Candidate.callback_repr -and
            $_.endpoint -eq "ADMIN_POST:$($Candidate.action)" -and
            $_.request_id -eq $RequestId -and
            $_.http_method -eq "POST"
        } |
        Select-Object -First 1
}

function Get-LearnPressObservedParameter {
    param(
        [object]$Artifact,
        [object]$Candidate
    )

    $summary = @($Artifact.callback_summaries) |
        Where-Object { $_.callback -eq $Candidate.callback_repr } |
        Select-Object -First 1
    if (-not $summary) { return $null }
    return @($summary.unique_parameters) |
        Where-Object {
            $_.source -eq "POST" -and
            @($_.path).Count -gt 0 -and
            (@($_.path)[0] -notmatch "^(action|_nonce|nonce|token|cookie|secret|password|authorization)$")
        } |
        Select-Object -First 1
}

function Convert-LearnPressParameterName {
    param([object]$Parameter)

    $path = @($Parameter.path | ForEach-Object { [string]$_ })
    if ($path.Count -eq 1) { return $path[0] }
    $name = $path[0]
    foreach ($part in $path[1..($path.Count - 1)]) { $name += "[$part]" }
    return $name
}

function Invoke-LearnPressNonceEval {
    param(
        [string[]]$ComposeArgs,
        [string]$NonceAction,
        [object]$Candidate
    )

    if ($NonceAction -notmatch '^[A-Za-z0-9_.:-]+$') {
        throw "LearnPress admin-post proof blocked: nonce action contains unsafe characters."
    }
    $callbackClass = ([string]$Candidate.callback_repr -split '->', 2)[0]
    if ($callbackClass -notmatch '^[A-Za-z_][A-Za-z0-9_\\]*$') {
        throw "LearnPress admin-post proof blocked: runtime callback class is unsafe."
    }
    $eval = '<?php $action = (string) getenv("HOOKPHUZZ_NONCE_ACTION"); $core_nonce = wp_create_nonce($action); $ref = new ReflectionClass((string) getenv("HOOKPHUZZ_CALLBACK_CLASS")); $instance_method = $ref->getMethod("instance"); $instance_method->setAccessible(true); $instance = $instance_method->invoke(null); $nonce_method = $ref->getMethod("create_async_nonce"); $nonce_method->setAccessible(true); echo wp_json_encode(array("learnpress_nonce" => $nonce_method->invoke($instance), "core_nonce" => $core_nonce, "verification_result" => wp_verify_nonce($core_nonce, $action), "authenticated_user_id" => (int) get_current_user_id(), "authenticated" => (bool) is_user_logged_in(), "session_token_present" => wp_get_session_token() !== ""));'
    $evalBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($eval))
    $webContainerId = (& docker compose -f docker-compose.yml ps -q web).Trim()
    if ([string]::IsNullOrWhiteSpace($webContainerId)) {
        throw "LearnPress admin-post proof blocked: web container ID is unavailable for nonce eval."
    }
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $raw = & docker exec -e HOOKPHUZZ_STRICT_NONCE_PROOF=1 -e "HOOKPHUZZ_NONCE_ACTION=$NonceAction" -e "HOOKPHUZZ_CALLBACK_CLASS=$callbackClass" -e "HOOKPHUZZ_NONCE_EVAL_B64=$evalBase64" $webContainerId sh -lc 'printf %s "$HOOKPHUZZ_NONCE_EVAL_B64" | base64 -d | /var/www/html/wp-cli.phar eval-file --allow-root -' 2>&1
        $evalExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($evalExitCode -ne 0) {
        throw "LearnPress admin-post proof blocked: original WordPress nonce eval failed."
    }
    $rawText = ($raw | ForEach-Object { [string]$_ }) -join "`n"
    $jsonMatch = [regex]::Match($rawText, '(?m)^\s*(\{.*\})\s*$')
    if (-not $jsonMatch.Success) {
        throw "LearnPress admin-post proof blocked: nonce eval returned no JSON."
    }
    return ($jsonMatch.Groups[1].Value | ConvertFrom-Json)
}

function Invoke-ZendLearnPressAdminPostProof {
    param(
        [string]$Url,
        [string]$ScriptRoot,
        [string]$LegacyRunId,
        [string[]]$ComposeArgs
    )

    $seedOutputDir = Join-Path $ScriptRoot "fuzzer\output\seed_generation"
    $bridgeWorkDir = Join-Path (Join-Path $seedOutputDir "zend-bridge") $LegacyRunId
    $probeDir = Join-Path $bridgeWorkDir "learnpress-probes"
    New-Item -ItemType Directory -Path $probeDir -Force | Out-Null
    $attempts = New-Object System.Collections.Generic.List[object]
    $candidate = Get-LearnPressRuntimeAdminPostCandidate -ComposeArgs $ComposeArgs

    $invalidId = "$LegacyRunId-learnpress-invalid-nonce"
    $invalidResult = Invoke-LearnPressHttpProbe -Url $Url -LegacyRunId $LegacyRunId -RequestId $invalidId -Body @{ action = $candidate.action; _nonce = "hookphuzz-invalid-nonce-sentinel" }
    $invalidArtifactPath = Join-Path $probeDir "$invalidId.json"
    $invalidArtifact = Copy-WebRequestArtifact -ComposeArgs $ComposeArgs -RequestId $invalidId -OutputPath $invalidArtifactPath
    $invalidExecution = Get-LearnPressCallbackExecution -Artifact $invalidArtifact -Candidate $candidate -RequestId $invalidId
    $nonceFailure = Read-WebNonceProofArtifact -ComposeArgs $ComposeArgs -RequestId $invalidId
    if ($nonceFailure.handler_executed -eq $true -or $nonceFailure.nonce_rejected -ne $true) {
        throw "LearnPress admin-post proof blocked: invalid nonce reached the LearnPress handler."
    }
    $nonceAction = [string]$nonceFailure.nonce_action
    $nonceEval = Invoke-LearnPressNonceEval -ComposeArgs $ComposeArgs -NonceAction $nonceAction -Candidate $candidate
    if ([int]$nonceEval.verification_result -notin @(1, 2)) {
        throw "LearnPress admin-post proof blocked: original wp_verify_nonce result was $($nonceEval.verification_result)."
    }
    if ([int]$nonceEval.authenticated_user_id -ne [int]$nonceFailure.authenticated_user_id -or [bool]$nonceEval.authenticated -ne [bool]$nonceFailure.authenticated) {
        throw "LearnPress admin-post proof blocked: nonce mint and HTTP verification contexts differ."
    }
    $nonce = [string]$nonceEval.learnpress_nonce

    $validId = "$LegacyRunId-learnpress-valid-nonce"
    $validResult = Invoke-LearnPressHttpProbe -Url $Url -LegacyRunId $LegacyRunId -RequestId $validId -Body @{ action = $candidate.action; _nonce = $nonce }
    $validArtifactPath = Join-Path $probeDir "$validId.json"
    $validArtifact = Copy-WebRequestArtifact -ComposeArgs $ComposeArgs -RequestId $validId -OutputPath $validArtifactPath
    $validExecution = Get-LearnPressCallbackExecution -Artifact $validArtifact -Candidate $candidate -RequestId $validId
    $validNonceProof = Read-WebNonceProofArtifact -ComposeArgs $ComposeArgs -RequestId $validId
    if (-not $validExecution -or $validNonceProof.handler_executed -ne $true) {
        throw "LearnPress admin-post proof blocked: valid nonce did not reach $($candidate.callback_repr)."
    }
    $observedParameter = Get-LearnPressObservedParameter -Artifact $validArtifact -Candidate $candidate
    $parameterId = $validId
    $parameterArtifactPath = $validArtifactPath
    $parameterArtifact = $validArtifact
    $parameterResult = $validResult
    if ($observedParameter) {
        $parameterName = Convert-LearnPressParameterName -Parameter $observedParameter
        $parameterId = "$LegacyRunId-learnpress-valid-parameter"
        $parameterBody = @{ action = $candidate.action; _nonce = $nonce }
        $parameterBody[$parameterName] = "hookphuzz-probe"
        $parameterResult = Invoke-LearnPressHttpProbe -Url $Url -LegacyRunId $LegacyRunId -RequestId $parameterId -Body $parameterBody
        $parameterArtifactPath = Join-Path $probeDir "$parameterId.json"
        $parameterArtifact = Copy-WebRequestArtifact -ComposeArgs $ComposeArgs -RequestId $parameterId -OutputPath $parameterArtifactPath
        if (-not (Get-LearnPressCallbackExecution -Artifact $parameterArtifact -Candidate $candidate -RequestId $parameterId)) {
            throw "LearnPress admin-post proof blocked: discovered parameter request did not reach target callback."
        }
    }
    if (-not $observedParameter) {
        throw "LearnPress admin-post proof blocked: no callback-attributed POST parameter was observed after nonce validation."
    }

    $proofPath = Join-Path $seedOutputDir "learnpress-admin-post-nonce-proof.json"
    $proof = [ordered]@{
        schema_version = 1
        plugin_slug = "learnpress"
        registered = 1
        direct_http_candidate = 1
        method = "POST"
        endpoint = "/wp-admin/admin-post.php"
        action = $candidate.action
        hook_name = $candidate.hook_name
        callback_id = $candidate.callback_id
        callback_repr = $candidate.callback_repr
        auth_mode = "authenticated"
        authenticated_user_id = [int]$nonceEval.authenticated_user_id
        authenticated_context = [ordered]@{
            is_user_logged_in = [bool]$nonceEval.authenticated
            user_id = [int]$nonceEval.authenticated_user_id
            session_token_present = [bool]$nonceEval.session_token_present
            cookies_sent = @()
        }
        nonce_action = $nonceAction
        nonce_field = "_nonce"
        nonce_value_sha256 = $null
        strict_nonce_mode = $true
        original_wp_verify_nonce = $true
        verification_result = [int]$nonceEval.verification_result
        core_nonce_value_sha256 = $null
        learnpress_nonce_gate = "custom_verify_async_nonce"
        invalid_probe = [ordered]@{
            request_id = $invalidId
            nonce = "hookphuzz-invalid-nonce-sentinel"
            nonce_rejected = $true
            callback_reached = $false
            callback_hook_dispatched = [bool]$invalidExecution
            handler_executed = [bool]$nonceFailure.handler_executed
            response_status = $invalidResult.status_code
            artifact = $invalidArtifactPath
            nonce_artifact = "/shared-tmpfs/hook-coverage/nonce-proof/$invalidId.json"
        }
        valid_probe = [ordered]@{
            request_id = $parameterId
            callback_reached = $true
            action_correlation_exact = $true
            parameter_path = @($observedParameter.path)
            parameter_source = [string]$observedParameter.source
            parameter_path_matched = $true
            handler_executed = [bool]$validNonceProof.handler_executed
            response_status = $parameterResult.status_code
            artifact = $parameterArtifactPath
        }
        fixed_params = @("action", "_nonce")
        fuzzable_params = @()
        final_replay = [ordered]@{ status = "pending" }
        attempts = @($attempts)
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $nonceHash = (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$nonceEval.learnpress_nonce)) | ForEach-Object { $_.ToString("x2") }) -join "")
        $coreNonceHash = (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$nonceEval.core_nonce)) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
    $proof.nonce_value_sha256 = $nonceHash
    $proof.core_nonce_value_sha256 = $coreNonceHash
    $proof | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $proofPath -Encoding UTF8
    return [pscustomobject]@{
        proof_path = $proofPath
        action = $candidate.action
        hook_name = $candidate.hook_name
        callback_id = $candidate.callback_id
        nonce = [string]$nonceEval.learnpress_nonce
        nonce_action = $nonceAction
        parameter_name = Convert-LearnPressParameterName -Parameter $observedParameter
    }
}

function Add-LearnPressNonceToSuggestedSeeds {
    param(
        [string]$SuggestedSeedsPath,
        [object]$Proof
    )

    $document = Get-Content -LiteralPath $SuggestedSeedsPath -Raw | ConvertFrom-Json
    $matches = @($document.suggested_seeds | Where-Object { $_.hook_name -eq $Proof.hook_name -and $_.callback_id -eq $Proof.callback_id })
    if ($matches.Count -ne 1) {
        throw "LearnPress admin-post proof blocked: exact runtime target seed count was $($matches.Count)."
    }
    $seed = $matches[0].seed
    $seed.method = "POST"
    $seed.method_status = "resolved"
    $seed.method_confidence = "runtime_observed"
    $seed.method_source = "runtime_observed"
    $seed.resolved_method = "POST"
    $seed.path = "/wp-admin/admin-post.php"
    $seed.auth_mode = "authenticated"
    if (-not $seed.body) {
        $seed | Add-Member -NotePropertyName "body" -NotePropertyValue ([pscustomobject]@{}) -Force
    }
    $seed.body.action = $Proof.action
    $seed.body._nonce = $Proof.nonce
    $seed.body[$Proof.parameter_name] = "hookphuzz-probe"
    $seed.fixed_params = @($seed.fixed_params + @("action", "_nonce") | Select-Object -Unique)
    $seed.fuzzable_params = @((@($seed.fuzzable_params) + @($Proof.parameter_name)) | Where-Object { $_ -and $_ -notin @("action", "_nonce") } | Select-Object -Unique)
    $seed.input_params = @($seed.input_params | Where-Object { $_.name -notin @("action", "_nonce") })
    $seed.nonce_action = $Proof.nonce_action
    $seed.nonce_context = "authenticated_user_$($Proof.callback_id)"
    $document | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $SuggestedSeedsPath -Encoding UTF8
}

function Export-LiveSeedSuggestions {
    param(
        [string]$ScriptRoot,
        [int]$WaitSeconds,
        [string[]]$ComposeArgs,
        [string]$OutputDir
    )

    $webContainerId = (& $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] ps -q web).Trim()
    if (-not $webContainerId) {
        throw "Could not resolve the running web container for seed export."
    }
    $coverageFileInContainer = "/shared-tmpfs/hook-coverage/total_coverage.json"
    $coverageSnapshot = Join-Path $OutputDir "runtime_coverage_snapshot.json"
    $zendRuntimeExportCli = Join-Path $ScriptRoot "fuzzer\cli\export_zend_seeds.py"
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    $snapshotReady = $false

    Write-Host "Waiting for live hook coverage snapshot to export suggested seeds"
    while ((Get-Date) -lt $deadline) {
        try {
            $snapshot = docker exec $webContainerId sh -c "cat $coverageFileInContainer" 2>$null
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($snapshot)) {
                $snapshot | Set-Content -Path $coverageSnapshot -Encoding UTF8
                New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
                $snapshotReady = $true
                break
            }
        } catch {
        }

        Start-Sleep -Seconds 5
    }

    if (-not $snapshotReady) {
        throw "Timed out waiting for live hook coverage snapshot at $coverageFileInContainer."
    }

    python $zendRuntimeExportCli --coverage-file $coverageSnapshot --output-dir $OutputDir
    if ($LASTEXITCODE -ne 0) {
        throw "Seed export failed."
    }
}

function Initialize-ZendCallbackRegistry {
    param(
        [string]$ScriptRoot,
        [string]$PluginSlug,
        [string]$SeedOutputDir,
        [string]$LegacyRunId,
        [string[]]$ComposeArgs
    )

    $bridgeWorkDir = Join-Path (Join-Path $SeedOutputDir "zend-bridge") $LegacyRunId
    $registryPath = Join-Path $bridgeWorkDir "hookphuzz-callback-registry.json"
    $coverageSnapshot = Join-Path $SeedOutputDir "runtime_coverage_snapshot.json"
    $bridgeCli = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\zend_runtime\bridge_cli.py"

    python $bridgeCli `
        --operation prepare-registry `
        --registry $coverageSnapshot `
        --plugin-slug $PluginSlug `
        --callback-registry-output $registryPath
    if ($LASTEXITCODE -ne 0) {
        throw "Zend callback registry preparation failed."
    }

    $webContainerId = (& $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] ps -q web).Trim()
    if (-not $webContainerId) {
        throw "Could not resolve the running web container for Zend registry copy."
    }
    docker exec $webContainerId sh -lc "mkdir -p /shared/opcode-events && chown www-data:www-data /shared/opcode-events"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not prepare /shared/opcode-events."
    }
    docker cp $registryPath "${webContainerId}:/shared/hookphuzz-callback-registry.json"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not copy Zend callback registry into web container."
    }
}

Push-Location $scriptRoot
$overridePath = $null
$legacyRunId = ""
$learnPressProof = $null
if ($UseZendDiscovery) {
    $safePluginSlug = ($PluginSlug -replace "[^A-Za-z0-9._-]", "-").Trim("-")
    $legacyRunId = $safePluginSlug + "-" + (Get-Date -Format "yyyyMMddTHHmmssZ")
}
try {
    Write-Host "Using WordPress plugin: $PluginSlug"
    $overridePath = New-PluginOverrideFile -PluginSlug $PluginSlug -BootstrapConfigSlug $BootstrapConfigSlug -LegacyRunId $legacyRunId -UseZendDiscovery:$UseZendDiscovery -StopOnVulnCount $StopOnVulnCount
    $composeArgs = Get-ComposeArgs -OverridePath $overridePath

    Write-Host "Checking Docker availability"
    Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("version")

    if ($PluginSlug -eq "show-all-comments-in-one-page") {
        Write-Host "Ensuring default plugin ZIP exists"
        if ($ForcePlugins) {
            & $pluginScript -Force
        } else {
            & $pluginScript
        }
    } else {
        Write-Host "Using local plugin ZIP for $PluginSlug"
        if ($ForcePlugins) {
            Write-Host "-ForcePlugins only applies to the default download script; selected plugin must exist locally."
        }
    }

    $requiredConfig = Join-Path $scriptRoot ("fuzzer\configs\{0}.json" -f $BootstrapConfigSlug.Replace("/", [System.IO.Path]::DirectorySeparatorChar))
    $requiredPlugin = Join-Path $scriptRoot "web\applications\wordpress\_plugins\$PluginSlug.zip"
    $requiredWpCli = Join-Path $scriptRoot "web\applications\wordpress\wp-cli.phar"

    Assert-PathExists -Path $requiredConfig -Hint "Choose an existing bootstrap config slug."
    Assert-PathExists -Path $requiredPlugin -Hint "Choose a plugin ZIP that exists in web\applications\wordpress\_plugins, or add $PluginSlug.zip there."
    Assert-PathExists -Path $requiredWpCli -Hint "The WordPress bootstrap artifact is missing from this checkout."

    Write-Host "Starting db and web containers"
    Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("up", "-d", "db", "web", "--build")

    Write-Host "Waiting for WordPress to answer with HTTP 200"
    Wait-ForWebReady -Url $webUrl -TimeoutSeconds $WebTimeoutSeconds

    if ($UseZendDiscovery) {
        Reset-ZendRuntimeArtifacts -ComposeArgs $composeArgs
    }

    Write-Host "Starting fuzzer container"
    Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("up", "-d", $fuzzerService, "--build")

    if ($UseZendDiscovery) {
        Invoke-ZendRestRouteBootstrap -Url "http://localhost:8080/?rest_route=/"
        if ($PluginSlug -eq "hp-ap") {
            Invoke-ZendAdminPostFixtureProbe -Url "http://localhost:8080" -LegacyRunId $legacyRunId
        }
        if ($PluginSlug -eq "learnpress") {
            $learnPressProof = Invoke-ZendLearnPressAdminPostProof `
                -Url "http://localhost:8080" `
                -ScriptRoot $scriptRoot `
                -LegacyRunId $legacyRunId `
                -ComposeArgs $composeArgs
            Write-Host "LearnPress admin-post nonce proof: $($learnPressProof.proof_path)"
        }
    }

    $onlineSeedOutputDir = Join-Path $scriptRoot ("fuzzer\output\online-seed-generation\{0}" -f $legacyRunId)
    New-Item -ItemType Directory -Path $onlineSeedOutputDir -Force | Out-Null
    Export-LiveSeedSuggestions -ScriptRoot $scriptRoot -WaitSeconds $SeedWaitSeconds -ComposeArgs $composeArgs -OutputDir $onlineSeedOutputDir
    if ($learnPressProof) {
        Add-LearnPressNonceToSuggestedSeeds `
            -SuggestedSeedsPath (Join-Path $onlineSeedOutputDir "suggested_seeds.json") `
            -Proof $learnPressProof
    }
    Initialize-ZendCallbackRegistry `
        -ScriptRoot $scriptRoot `
        -PluginSlug $PluginSlug `
        -SeedOutputDir $onlineSeedOutputDir `
        -LegacyRunId $legacyRunId `
        -ComposeArgs $composeArgs
    . (Join-Path $scriptDir "invoke-online-linked.ps1")
    Invoke-OnlineLinked `
        -ScriptRoot $scriptRoot `
        -PluginSlug $PluginSlug `
        -LegacyRunId $legacyRunId `
        -SuggestedSeedsPath (Join-Path $onlineSeedOutputDir "suggested_seeds.json") `
        -BootstrapConfig $requiredConfig `
        -CallbackRegistry (Join-Path (Join-Path (Join-Path $onlineSeedOutputDir "zend-bridge") $legacyRunId) "hookphuzz-callback-registry.json") `
        -Service $fuzzerService `
        -OnlineTimeoutSeconds $OnlineTimeoutSeconds `
        -OnlineMaxVersions $OnlineMaxVersions `
        -OnlineMaxCandidates $OnlineMaxCandidates `
        -OnlineCampaignTimeoutSeconds $OnlineCampaignTimeoutSeconds `
        -OnlineComparePrompt ([bool]$runtimeSettings["OnlineComparePrompt"]) `
        -OverridePath $overridePath `
        -ComposeArgs $composeArgs
} finally {
    if ($overridePath -and (Test-Path -LiteralPath $overridePath)) {
        Remove-Item -LiteralPath $overridePath -Force
    }
    Pop-Location
}
