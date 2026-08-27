param(
    [ValidatePattern('^[a-zA-Z0-9_.-]+$')]
    [string]$PluginSlug = "show-all-comments-in-one-page",
    [switch]$ForcePlugins,
    [switch]$NoFollowLogs,
    [switch]$RunGeneratedConfigs,
    [switch]$RunOnline,
    [switch]$UseEntrypointPipeline,
    [switch]$UseZendDiscovery,
    [switch]$KeepDebugArtifacts,
    [ValidatePattern('^[a-zA-Z0-9_./-]+$')]
    [string]$BootstrapConfigSlug = "",
    [ValidateRange(1, 86400)]
    [int]$WebTimeoutSeconds = 240,
    [ValidateRange(1, 86400)]
    [int]$SeedWaitSeconds = 45,
    [ValidateRange(1, 30)]
    [int]$GeneratedConfigTimeoutSeconds = 30,
    [ValidateRange(1, 30)]
    [int]$ZendMaxIterations = 5,
    [ValidateRange(1, 60)]
    [int]$OnlineTimeoutSeconds = 60,
    [ValidateRange(1, 20)]
    [int]$OnlineMaxVersions = 2
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $PSCommandPath
$scriptRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir "..\..")).Path
$pluginScript = Join-Path $scriptRoot "web\applications\wordpress\_plugins\download-plugins.ps1"
$fuzzerService = "fuzzer-wordpress-plugin"
$webUrl = "http://localhost:8080/"

if ($UseEntrypointPipeline -and -not $RunGeneratedConfigs) {
    throw "-UseEntrypointPipeline requires -RunGeneratedConfigs."
}
if ($RunOnline -and $RunGeneratedConfigs) {
    throw "-RunOnline cannot be combined with -RunGeneratedConfigs."
}
if ($UseZendDiscovery -and -not ($RunGeneratedConfigs -or $RunOnline)) {
    throw "-UseZendDiscovery requires -RunGeneratedConfigs."
}
if ($UseZendDiscovery -and $UseEntrypointPipeline) {
    throw "-UseZendDiscovery uses the legacy generated flow and cannot be combined with -UseEntrypointPipeline."
}
if ($RunOnline -and -not $UseZendDiscovery) {
    throw "-RunOnline requires -UseZendDiscovery."
}

if (-not $BootstrapConfigSlug) {
    if ($RunGeneratedConfigs) {
        $BootstrapConfigSlug = "wordpress/bootstrap-generated"
    } else {
        $BootstrapConfigSlug = "wordpress/$PluginSlug"
    }
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

function New-PluginOverrideFile {
    param(
        [string]$PluginSlug,
        [string]$BootstrapConfigSlug,
        [string]$LegacyRunId = "",
        [switch]$UseZendDiscovery
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
    $eval = '$action = (string) getenv("HOOKPHUZZ_NONCE_ACTION"); $core_nonce = wp_create_nonce($action); $ref = new ReflectionClass((string) getenv("HOOKPHUZZ_CALLBACK_CLASS")); $instance_method = $ref->getMethod("instance"); $instance_method->setAccessible(true); $instance = $instance_method->invoke(null); $nonce_method = $ref->getMethod("create_async_nonce"); $nonce_method->setAccessible(true); echo wp_json_encode(array("learnpress_nonce" => $nonce_method->invoke($instance), "core_nonce" => $core_nonce, "verification_result" => wp_verify_nonce($core_nonce, $action), "authenticated_user_id" => (int) get_current_user_id(), "authenticated" => (bool) is_user_logged_in(), "session_token_present" => wp_get_session_token() !== ""));'
    $webContainerId = (& docker compose -f docker-compose.yml ps -q web).Trim()
    if ([string]::IsNullOrWhiteSpace($webContainerId)) {
        throw "LearnPress admin-post proof blocked: web container ID is unavailable for nonce eval."
    }
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $raw = & docker exec -e HOOKPHUZZ_STRICT_NONCE_PROOF=1 -e "HOOKPHUZZ_NONCE_ACTION=$NonceAction" -e "HOOKPHUZZ_CALLBACK_CLASS=$callbackClass" $webContainerId /var/www/html/wp-cli.phar eval --allow-root $eval 2>&1
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

function Write-LearnPressFinalProof {
    param(
        [string]$ProofPath,
        [string]$SuggestedSeedsPath,
        [string]$ConfigSummaryPath,
        [string]$RunSummaryPath
    )

    $proof = Get-Content -LiteralPath $ProofPath -Raw | ConvertFrom-Json
    $seeds = Get-Content -LiteralPath $SuggestedSeedsPath -Raw | ConvertFrom-Json
    $targetSeed = @($seeds.suggested_seeds | Where-Object { $_.hook_name -eq $proof.hook_name -and $_.callback_id -eq $proof.callback_id }) | Select-Object -First 1
    $summary = Get-Content -LiteralPath $ConfigSummaryPath -Raw | ConvertFrom-Json
    $generated = @($summary.generated | Where-Object { $_.hook_name -eq $proof.hook_name -and $_.callback_id -eq $proof.callback_id })
    if ($generated.Count -ne 1) { throw "LearnPress admin-post proof blocked: final generated config count was $($generated.Count)." }
    $config = Get-Content -LiteralPath $generated[0].config_path -Raw | ConvertFrom-Json
    $run = Get-Content -LiteralPath $RunSummaryPath -Raw | ConvertFrom-Json
    $runRow = @($run.runs | Where-Object { $_.hook_name -eq $proof.hook_name -and $_.callback_id -eq $proof.callback_id }) | Select-Object -First 1
    $fixed = @($config.body_params.fixed)
    $fuzz = @($config.body_params.fuzz)
    if ($fixed -notcontains "action" -or $fixed -notcontains "_nonce" -or $fuzz.Count -lt 1) {
        throw "LearnPress admin-post proof blocked: final config did not keep action/_nonce fixed with a fuzzable observed parameter."
    }
    if (-not $runRow -or $runRow.callback_reached -ne $true) {
        throw "LearnPress admin-post proof blocked: final replay did not reach the exact callback."
    }
    $unrelated = @($seeds.suggested_seeds | Where-Object { $_.hook_name -match '^admin_post(_nopriv)?_' -and $_.hook_name -ne $proof.hook_name -and $_.generation_status -eq "ambiguous_http_method" })
    $proof.fixed_params = @("action", "_nonce")
    $proof.fuzzable_params = @($fuzz)
    $proof.generated_config = 1
    $proof.final_replay = [ordered]@{
        status = "PASS"
        callback_reached = $true
        matched_artifact = [string]$runRow.matched_artifact
        config_path = [string]$generated[0].config_path
        method = "POST"
        action_correlation_exact = $true
        parameter_path_matched = $true
        strict_nonce_mode = $proof.strict_nonce_mode
    }
    $proof.unrelated_admin_post_fail_closed = ($unrelated.Count -ge 1)
    $proof.acceptance = [ordered]@{
        registered = 1
        direct_http_candidate = 1
        generated_config = 1
        method = "POST"
        action_correlation_exact = $true
        nonce_auth_recorded = $true
        callback_reached = $true
        parameter_path_matched = $true
        final_replay = "PASS"
        unrelated_admin_post_fail_closed = ($unrelated.Count -ge 1)
    }
    $proof | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $ProofPath -Encoding UTF8
}

function Export-LiveSeedSuggestions {
    param(
        [string]$ScriptRoot,
        [int]$WaitSeconds,
        [string[]]$ComposeArgs,
        [string]$PluginSlug,
        [switch]$UseEntrypointPipeline,
        [switch]$RuntimeParametersOnly,
        [string]$OutputDir = ""
    )

    $webContainerId = (& $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] ps -q web).Trim()
    if (-not $webContainerId) {
        throw "Could not resolve the running web container for seed export."
    }

    $coverageFileInContainer = "/shared-tmpfs/hook-coverage/total_coverage.json"
    $coverageSnapshot = Join-Path ([System.IO.Path]::GetTempPath()) "phuzz-live-total-coverage.json"
    if (-not $OutputDir) {
        $OutputDir = Join-Path $ScriptRoot "fuzzer\output\seed_generation"
    }
    $outputDir = $OutputDir
    $exportCli = Join-Path $ScriptRoot "fuzzer\cli\export_seeds.py"
    $zendRuntimeExportCli = Join-Path $ScriptRoot "fuzzer\cli\export_zend_seeds.py"
    $pipelineCli = Join-Path $ScriptRoot "fuzzer\cli\entrypoint_pipeline.py"
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    $snapshotReady = $false
    $pluginSourceTempRoot = $null

    try {
        Write-Host "Waiting for live hook coverage snapshot to export suggested seeds"
        while ((Get-Date) -lt $deadline) {
            try {
                $snapshot = docker exec $webContainerId sh -c "cat $coverageFileInContainer" 2>$null
                if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($snapshot)) {
                    $snapshot | Set-Content -Path $coverageSnapshot -Encoding UTF8
                    $snapshotOutput = Join-Path $outputDir "runtime_coverage_snapshot.json"
                    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
                    $snapshot | Set-Content -Path $snapshotOutput -Encoding UTF8
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

        $sourceArgs = @()
        $pluginSourceTempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("phuzz-plugin-source-{0}" -f ([guid]::NewGuid().ToString("N")))
        $hostSourceRoot = Join-Path $pluginSourceTempRoot $PluginSlug
        $unresolvedSourceReason = $null

        if (-not $RuntimeParametersOnly) {
            New-Item -ItemType Directory -Path $hostSourceRoot -Force | Out-Null
            try {
                docker cp "${webContainerId}:/var/www/html/wp-content/plugins/$PluginSlug/." $hostSourceRoot
                if ($LASTEXITCODE -ne 0) {
                    $unresolvedSourceReason = "source_copy_failed"
                } elseif (-not (Get-ChildItem -LiteralPath $hostSourceRoot -Recurse -Filter *.php -File -ErrorAction SilentlyContinue | Select-Object -First 1)) {
                    $unresolvedSourceReason = "no_php_files"
                } else {
                    $sourceArgs = @(
                        "--container-source-root", "/var/www/html/wp-content/plugins/$PluginSlug",
                        "--host-source-root", $hostSourceRoot,
                        "--source-root", $hostSourceRoot
                    )
                }
            } catch {
                $unresolvedSourceReason = "source_copy_failed"
            }

            if ($unresolvedSourceReason) {
                Write-Warning "Plugin source unavailable for seed extraction: $unresolvedSourceReason"
                $sourceArgs = @("--unresolved-source-reason", $unresolvedSourceReason)
            }
        }

        if ($UseEntrypointPipeline) {
            $outputConfigDir = Join-Path $ScriptRoot "fuzzer\configs\generated-config\$PluginSlug"
            Write-Host "Running entrypoint pipeline into $outputDir"
            $pipelineArgs = @(
                $pipelineCli,
                "--coverage-file", $coverageSnapshot,
                "--plugin-slug", $PluginSlug,
                "--output-dir", $outputDir,
                "--output-config-dir", $outputConfigDir,
                "--minimal-artifacts"
            )
            if ($RuntimeParametersOnly) {
                $pipelineArgs += "--runtime-parameters-only"
            } else {
                $pipelineArgs += $sourceArgs
            }
            python @pipelineArgs
        } else {
            Write-Host "Exporting hook_gap_report.json and suggested_seeds.* to $outputDir"
            if ($RuntimeParametersOnly) {
                $exportArgs = @($zendRuntimeExportCli, "--coverage-file", $coverageSnapshot, "--output-dir", $outputDir)
            } else {
                $exportArgs = @($exportCli, "--coverage-file", $coverageSnapshot, "--output-dir", $outputDir)
                $exportArgs += $sourceArgs
            }
            python @exportArgs
        }
        if ($LASTEXITCODE -ne 0) {
            throw "Seed export failed."
        }
    } finally {
        if ($pluginSourceTempRoot -and (Test-Path -LiteralPath $pluginSourceTempRoot)) {
            try {
                Remove-Item -LiteralPath $pluginSourceTempRoot -Recurse -Force -ErrorAction Stop
            } catch {
                Write-Warning "Plugin source temp cleanup failed: $($_.Exception.Message)"
            }
        }
    }
}

function Convert-LiveSeedSuggestionsToConfigs {
    param(
        [string]$ScriptRoot,
        [string]$PluginSlug,
        [string]$OutputConfigDir = "",
        [string]$SummaryPath = "",
        [string]$SuggestedSeeds = "",
        [switch]$ReplayOnly,
        [switch]$RestRouteFallback
    )

    $seedOutputDir = Join-Path $ScriptRoot "fuzzer\output\seed_generation"
    if (-not $SuggestedSeeds) {
        $SuggestedSeeds = Join-Path $seedOutputDir "suggested_seeds.json"
    }
    if (-not $OutputConfigDir) {
        $OutputConfigDir = Join-Path $ScriptRoot "fuzzer\configs\generated-config\$PluginSlug"
    }
    if (-not $SummaryPath) {
        $SummaryPath = Join-Path $seedOutputDir "generated_config_summary.json"
    }
    $configCli = Join-Path $ScriptRoot "fuzzer\cli\seed_to_config.py"

    Assert-PathExists -Path $SuggestedSeeds -Hint "Run hook seed export before converting seeds into PHUZZ configs."

    Write-Host "Converting supported suggested seeds into PHUZZ configs"
    $configArgs = @(
        $configCli,
        "--suggested-seeds", $SuggestedSeeds,
        "--output-config-dir", $OutputConfigDir,
        "--summary", $SummaryPath
    )
    if ($ReplayOnly) {
        $configArgs += "--replay-only"
    }
    if ($RestRouteFallback) {
        $configArgs += "--rest-route-fallback"
    }
    python @configArgs
}

function Write-EntrypointPluginProofFile {
    param(
        [string]$SeedOutputDir,
        [string]$PluginSlug,
        [string]$RunnerLog
    )

    $pipelinePath = Join-Path $SeedOutputDir "entrypoint_pipeline_summary.json"
    $configPath = Join-Path $SeedOutputDir "generated_config_summary.json"
    $runPath = Join-Path $SeedOutputDir "generated_config_run_summary.json"
    if (-not (Test-Path -LiteralPath $pipelinePath)) {
        return
    }

    $proofDir = Join-Path $SeedOutputDir "entrypoint-proof"
    New-Item -ItemType Directory -Path $proofDir -Force | Out-Null
    $proofPath = Join-Path $proofDir "PLUGIN_GENERATION_PROOF.md"
    $pipeline = Get-Content -LiteralPath $pipelinePath -Raw | ConvertFrom-Json
    $run = $null
    if (Test-Path -LiteralPath $runPath) {
        $run = Get-Content -LiteralPath $runPath -Raw | ConvertFrom-Json
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# Entrypoint generated plugin proof")
    $lines.Add("")
    $lines.Add("Plugin: ``$PluginSlug``")
    $lines.Add("")
    $lines.Add("## Counters")
    $lines.Add("")
    $lines.Add(("- registered: {0}" -f $pipeline.summary.registered))
    $lines.Add(("- direct_http_candidates: {0}" -f $pipeline.summary.direct_http_candidates))
    $lines.Add(("- generated: {0}" -f $pipeline.summary.generated))
    $lines.Add(("- ambiguous_http_method: {0}" -f $pipeline.summary.ambiguous_http_method))
    $lines.Add("")
    $lines.Add("## Generated configs")
    $lines.Add("")

    foreach ($entry in @($pipeline.entrypoints | Where-Object { $_.config_status -eq "generated" })) {
        $lines.Add(("### [{0}] {1}" -f $entry.method, $entry.hook_name))
        $lines.Add("")
        $lines.Add(("- callback: ``{0}``" -f $entry.callback_repr))
        $lines.Add(("- action: ``{0}``" -f $entry.action))
        foreach ($param in @($entry.parameters)) {
            if ($param.name) {
                $lines.Add(("- param: ``{0}`` from ``{1}`` as ``{2}``" -f $param.name, $param.source, $param.location))
            }
        }
        $lines.Add(("- config_slug: ``{0}``" -f $entry.config_slug))
        $lines.Add(("- config_path: ``{0}``" -f $entry.config_path))
        $lines.Add("")
    }

    if ($run) {
        $lines.Add("## Replay")
        $lines.Add("")
        $lines.Add(("- callback_reached: {0}/{1}" -f $run.counts.callback_reached, $run.counts.total))
        foreach ($row in @($run.runs)) {
            if ($row.matched_artifact) {
                $lines.Add(("- matched_artifact: ``{0}``" -f $row.matched_artifact))
            }
        }
        $lines.Add("")
    }

    $lines.Add("## Source artifacts")
    $lines.Add("")
    $lines.Add(("- runtime coverage snapshot: ``{0}``" -f (Join-Path $SeedOutputDir "runtime_coverage_snapshot.json")))
    $lines.Add(("- pipeline summary: ``{0}``" -f $pipelinePath))
    $lines.Add(("- config summary: ``{0}``" -f $configPath))
    $lines.Add(("- replay summary: ``{0}``" -f $runPath))
    if ($RunnerLog) {
        $lines.Add(("- replay log: ``{0}``" -f $RunnerLog))
    }

    $lines | Set-Content -LiteralPath $proofPath -Encoding UTF8
    Write-Host "Entrypoint plugin proof file: $proofPath"
}

function Copy-GeneratedRequestArtifacts {
    param(
        [string[]]$ComposeArgs,
        [string]$RunSummaryPath,
        [string]$OutputDir
    )

    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    $summary = Get-Content -LiteralPath $RunSummaryPath -Raw | ConvertFrom-Json
    $names = New-Object System.Collections.Generic.HashSet[string]
    foreach ($row in @($summary.runs)) {
        if ($row.matched_artifact) {
            [void]$names.Add([string]$row.matched_artifact)
        }
        foreach ($name in @($row.request_artifacts)) {
            if ($name) {
                [void]$names.Add([string]$name)
            }
        }
    }
    foreach ($name in $names) {
        if ([System.IO.Path]::GetFileName($name) -ne $name) {
            throw "Invalid generated request artifact name: $name"
        }
        $target = Join-Path $OutputDir $name
        & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] exec -T web cat "/shared-tmpfs/hook-coverage/requests/$name" |
            Set-Content -LiteralPath $target -Encoding UTF8
        if ($LASTEXITCODE -ne 0) {
            throw "Could not copy generated request artifact: $name"
        }
    }
}

function Copy-ZendOpcodeArtifacts {
    param(
        [string[]]$ComposeArgs,
        [string]$RunSummaryPath,
        [string]$OutputDir
    )

    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    $summary = Get-Content -LiteralPath $RunSummaryPath -Raw | ConvertFrom-Json
    $names = New-Object System.Collections.Generic.HashSet[string]
    foreach ($row in @($summary.runs)) {
        if ($row.matched_artifact) {
            [void]$names.Add([string]$row.matched_artifact)
        }
    }
    foreach ($name in $names) {
        if ([System.IO.Path]::GetFileName($name) -ne $name) {
            throw "Invalid Zend opcode artifact name: $name"
        }
        $target = Join-Path $OutputDir $name
        & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] exec -T web cat "/shared/opcode-events/$name" |
            Set-Content -LiteralPath $target -Encoding UTF8
        if ($LASTEXITCODE -ne 0) {
            throw "Could not copy Zend opcode artifact: $name"
        }
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

function Invoke-ZendDiscoveryBridge {
    param(
        [string]$ScriptRoot,
        [string]$PluginSlug,
        [string]$LegacyRunId,
        [string]$SeedOutputDir,
        [string]$Pass1RunSummary,
        [string[]]$ComposeArgs
    )

    $pluginZip = Join-Path $ScriptRoot "web\applications\wordpress\_plugins\$PluginSlug.zip"
    $rawSuggestedSeeds = Join-Path $SeedOutputDir "suggested_seeds.json"
    $registry = Join-Path $SeedOutputDir "runtime_coverage_snapshot.json"
    $bridgeWorkDir = Join-Path (Join-Path $SeedOutputDir "zend-bridge") $LegacyRunId
    $logsDir = Join-Path $bridgeWorkDir "logs"
    $pass1ArtifactsDir = Join-Path $logsDir "pass1-uopz"
    $zendEventsDir = Join-Path $logsDir "pass1-zend"
    $zendOutputRoot = Join-Path $ScriptRoot "fuzzer\output\zend-discovery"
    $mergedSuggestedSeeds = Join-Path $SeedOutputDir "zend_merged_suggested_seeds.json"
    $outputConfigDir = Join-Path $ScriptRoot "fuzzer\configs\generated-config\$PluginSlug"
    $finalConfigSummary = Join-Path $SeedOutputDir "generated_config_summary.json"
    $bridgeCli = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\zend_runtime\bridge_cli.py"

    Copy-GeneratedRequestArtifacts -ComposeArgs $ComposeArgs -RunSummaryPath $Pass1RunSummary -OutputDir $pass1ArtifactsDir
    Copy-ZendOpcodeArtifacts -ComposeArgs $ComposeArgs -RunSummaryPath $Pass1RunSummary -OutputDir $zendEventsDir

    Write-Host "Running offline Zend enrichment bridge"
    python $bridgeCli `
        --plugin-zip $pluginZip `
        --plugin-slug $PluginSlug `
        --legacy-run-id $LegacyRunId `
        --registry $registry `
        --raw-suggested-seeds $rawSuggestedSeeds `
        --pass1-run-summary $Pass1RunSummary `
        --pass1-artifacts-dir $pass1ArtifactsDir `
        --zend-events-dir $zendEventsDir `
        --zend-output-root $zendOutputRoot `
        --merged-suggested-seeds $mergedSuggestedSeeds `
        --output-config-dir $outputConfigDir `
        --generated-config-summary $finalConfigSummary
    if ($LASTEXITCODE -ne 0) {
        throw "Zend enrichment bridge failed."
    }

    $zendEnrichedSeeds = Join-Path (Join-Path $zendOutputRoot $LegacyRunId) "zend_enriched_seeds.json"
    Write-Host "Zend enriched seeds: $zendEnrichedSeeds"
    Write-Host "Zend merged suggested seeds: $mergedSuggestedSeeds"
}

function Invoke-ZendPass2Verification {
    param(
        [string]$ScriptRoot,
        [string]$LegacyRunId,
        [string]$SeedOutputDir,
        [string]$Pass2RunSummary,
        [string[]]$ComposeArgs
    )

    $bridgeWorkDir = Join-Path (Join-Path $SeedOutputDir "zend-bridge") $LegacyRunId
    $logsDir = Join-Path $bridgeWorkDir "logs"
    $pass2ArtifactsDir = Join-Path $logsDir "pass2-uopz"
    $pass2ZendEventsDir = Join-Path $logsDir "pass2-zend"
    $mergedSuggestedSeeds = Join-Path $SeedOutputDir "zend_merged_suggested_seeds.json"
    $bridgeCli = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\zend_runtime\bridge_cli.py"

    Copy-GeneratedRequestArtifacts -ComposeArgs $ComposeArgs -RunSummaryPath $Pass2RunSummary -OutputDir $pass2ArtifactsDir
    Copy-ZendOpcodeArtifacts -ComposeArgs $ComposeArgs -RunSummaryPath $Pass2RunSummary -OutputDir $pass2ZendEventsDir

    python $bridgeCli `
        --operation verify-pass2 `
        --pass2-run-summary $Pass2RunSummary `
        --merged-suggested-seeds $mergedSuggestedSeeds `
        --zend-events-dir $pass2ZendEventsDir `
        --pass2-artifacts-dir $pass2ArtifactsDir
    if ($LASTEXITCODE -ne 0) {
        throw "Zend Pass 2 runtime verification failed. See $Pass2RunSummary"
    }
}

function Invoke-ZendArtifactRetention {
    param(
        [string]$ScriptRoot,
        [string]$SeedOutputDir,
        [string]$LegacyRunId,
        [string]$TerminalStatus,
        [string]$FinalConfigSummary,
        [string]$FinalRunSummary,
        [string]$ZendDiscoveryRunDir,
        [switch]$KeepDebugArtifacts
    )

    $retentionCli = Join-Path $ScriptRoot "fuzzer\artifacts\retention\generated_runs.py"
    $runDir = Join-Path (Join-Path $SeedOutputDir "zend-bridge") $LegacyRunId
    $retentionArgs = @(
        $retentionCli,
        "--run-dir", $runDir,
        "--terminal-status", $TerminalStatus,
        "--seed-output-dir", $SeedOutputDir,
        "--merged-suggested-seeds", (Join-Path $SeedOutputDir "zend_merged_suggested_seeds.json"),
        "--final-config-summary", $FinalConfigSummary,
        "--final-run-summary", $FinalRunSummary,
        "--zend-discovery-run-dir", $ZendDiscoveryRunDir
    )
    if ($KeepDebugArtifacts) {
        $retentionArgs += "--keep-debug-artifacts"
    }

    python @retentionArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Zend artifact retention failed. Debug artifacts were not safely finalized."
    }
}

function Publish-ZendDirectorySnapshot {
    param(
        [string]$SourceDir,
        [string]$TargetDir
    )

    if (-not (Test-Path -LiteralPath $SourceDir)) {
        throw "Cannot publish missing directory: $SourceDir"
    }
    $parent = Split-Path -Parent $TargetDir
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $tempDir = "$TargetDir.t"
    $oldDir = "$TargetDir.o"
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force
    }
    if (Test-Path -LiteralPath $oldDir) {
        Remove-Item -LiteralPath $oldDir -Recurse -Force
    }
    Copy-Item -LiteralPath $SourceDir -Destination $tempDir -Recurse -Force
    try {
        if (Test-Path -LiteralPath $TargetDir) {
            Move-Item -LiteralPath $TargetDir -Destination $oldDir -Force
        }
        Move-Item -LiteralPath $tempDir -Destination $TargetDir -Force
        if (Test-Path -LiteralPath $oldDir) {
            Remove-Item -LiteralPath $oldDir -Recurse -Force
        }
    } catch {
        if ((Test-Path -LiteralPath $oldDir) -and -not (Test-Path -LiteralPath $TargetDir)) {
            Move-Item -LiteralPath $oldDir -Destination $TargetDir -Force
        }
        if (Test-Path -LiteralPath $tempDir) {
            Remove-Item -LiteralPath $tempDir -Recurse -Force
        }
        throw
    }
}

function Get-ZendTargetDirectoryName {
    param([string]$CandidateKey)

    if ($CandidateKey.Length -gt 16) {
        return $CandidateKey.Substring(0, 16)
    }
    return $CandidateKey
}

function Publish-ZendAggregateTargetState {
    param(
        [object[]]$Targets,
        [string]$SnapshotName,
        [string]$OutputDir
    )

    $stage = Join-Path (Split-Path -Parent $OutputDir) ("$SnapshotName-t")
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    foreach ($target in @($Targets)) {
        $candidateKey = [string]$target.candidate_key
        $targetDirectoryName = if ($target.target_directory) { [string]$target.target_directory } else { Get-ZendTargetDirectoryName -CandidateKey $candidateKey }
        $source = Join-Path (Join-Path (Join-Path (Split-Path -Parent $OutputDir) "targets") $targetDirectoryName) $SnapshotName
        if (Test-Path -LiteralPath $source) {
            Copy-Item -LiteralPath $source -Destination (Join-Path $stage $targetDirectoryName) -Recurse -Force
        }
    }
    Publish-ZendDirectorySnapshot -SourceDir $stage -TargetDir $OutputDir
    Remove-Item -LiteralPath $stage -Recurse -Force
}

function Invoke-ZendConvergence {
    param(
        [string]$ScriptRoot,
        [string]$PluginSlug,
        [string]$LegacyRunId,
        [string]$SeedOutputDir,
        [string]$InitialRunSummary,
        [int]$TimeoutSeconds,
        [int]$MaxIterations,
        [string[]]$ComposeArgs
    )

    $bridgeWorkDir = Join-Path (Join-Path $SeedOutputDir "zend-bridge") $LegacyRunId
    $targetsDir = Join-Path $bridgeWorkDir "targets"
    $rootCurrentDir = Join-Path $bridgeWorkDir "current"
    $rootFinalDir = Join-Path $bridgeWorkDir "final"
    $historyPath = Join-Path $bridgeWorkDir "zend_convergence_summary.json"
    $rawSuggestedSeeds = Join-Path $SeedOutputDir "suggested_seeds.json"
    $registry = Join-Path $bridgeWorkDir "hookphuzz-callback-registry.json"
    $bridgeCli = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\zend_runtime\bridge_cli.py"
    $generatedConfigRunner = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\generated_config_runner.py"
    $finalConfigDir = Join-Path $ScriptRoot "fuzzer\configs\generated-config\$PluginSlug"
    $finalConfigSummary = Join-Path $SeedOutputDir "generated_config_summary.json"
    $finalMergedSuggestedSeeds = Join-Path $SeedOutputDir "zend_merged_suggested_seeds.json"
    $initialConfigSummary = Join-Path $bridgeWorkDir "pass1-generated_config_summary.json"
    $targetsPath = Join-Path $bridgeWorkDir "zend_convergence_targets.json"
    $targetResults = @()
    $finalSeedReports = @()

    python $bridgeCli `
        --operation list-targets `
        --plugin-slug $PluginSlug `
        --legacy-run-id $LegacyRunId `
        --raw-suggested-seeds $rawSuggestedSeeds `
        --generated-config-summary $initialConfigSummary `
        --pass1-run-summary $InitialRunSummary `
        --targets-output $targetsPath
    if ($LASTEXITCODE -ne 0) {
        throw "REPLAY_FAILED: Zend convergence target listing failed."
    }
    $targetList = Get-Content -LiteralPath $targetsPath -Raw | ConvertFrom-Json
    $targets = @($targetList.targets)
    if ($targets.Count -eq 0) {
        throw "REPLAY_FAILED: no generated Zend convergence targets"
    }

    try {
        foreach ($candidate in @($targets)) {
            $targetCandidateKey = [string]$candidate.candidate_key
            if (-not $targetCandidateKey) {
                throw "REPLAY_FAILED: Zend convergence target is missing candidate_key"
            }
            $targetDirectoryName = Get-ZendTargetDirectoryName -CandidateKey $targetCandidateKey
            $candidate | Add-Member -NotePropertyName "target_directory" -NotePropertyValue $targetDirectoryName -Force
            $targetDir = Join-Path $targetsDir $targetDirectoryName
            $targetIterationsDir = Join-Path $targetDir "i"
            $targetCurrentDir = Join-Path $targetDir "cur"
            $targetFinalDir = Join-Path $targetDir "fin"
            $statePath = Join-Path $targetDir "state.json"
            $targetHistoryPath = Join-Path $targetDir "summary.json"
            $targetHistory = @()
            $seenRequestIds = New-Object System.Collections.Generic.HashSet[string]
            $seenConfigHashes = New-Object System.Collections.Generic.HashSet[string]
            $currentRunSummary = $InitialRunSummary
            $currentSeeds = $rawSuggestedSeeds
            $converged = $false
            New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
            @{ known_parameters = @() } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $statePath -Encoding UTF8

            for ($iteration = 0; $iteration -lt $MaxIterations; $iteration++) {
                $iterationDir = Join-Path $targetIterationsDir "$iteration"
                $uopzDir = Join-Path $iterationDir "uopz"
                $zendDir = Join-Path $iterationDir "zend"
                $nextStatePath = Join-Path $iterationDir "state.json"
                $mergedSeedsPath = Join-Path $iterationDir "seeds.json"
                $replayConfigDir = Join-Path $iterationDir "cfg"
                $replayConfigSummary = Join-Path $iterationDir "cfg.json"
                New-Item -ItemType Directory -Path $iterationDir -Force | Out-Null
                Copy-GeneratedRequestArtifacts -ComposeArgs $ComposeArgs -RunSummaryPath $currentRunSummary -OutputDir $uopzDir
                Copy-ZendOpcodeArtifacts -ComposeArgs $ComposeArgs -RunSummaryPath $currentRunSummary -OutputDir $zendDir

                python $bridgeCli `
                    --operation converge-iteration `
                    --plugin-slug $PluginSlug `
                    --legacy-run-id $LegacyRunId `
                    --candidate-key $targetCandidateKey `
                    --registry $registry `
                    --raw-suggested-seeds $currentSeeds `
                    --pass1-run-summary $currentRunSummary `
                    --pass1-artifacts-dir $uopzDir `
                    --zend-events-dir $zendDir `
                    --convergence-state $statePath `
                    --convergence-state-output $nextStatePath `
                    --convergence-merged-seeds $mergedSeedsPath `
                    --output-config-dir $replayConfigDir `
                    --generated-config-summary $replayConfigSummary
                if ($LASTEXITCODE -ne 0) {
                    throw "REPLAY_FAILED: Zend convergence correlation failed for $targetCandidateKey iteration $iteration"
                }

                $state = Get-Content -LiteralPath $nextStatePath -Raw | ConvertFrom-Json
                if ($state.status -eq "REPLAY_FAILED") {
                    throw "REPLAY_FAILED: Zend convergence lost known runtime parameters for $targetCandidateKey iteration $iteration"
                }
                $requestId = [string]$state.request_id
                if (-not $requestId -or -not $seenRequestIds.Add($requestId)) {
                    throw "REPLAY_FAILED: matched artifact request ID is missing or duplicated"
                }
                if ($targetCandidateKey -ne [string]$state.candidate_key) {
                    throw "REPLAY_FAILED: canonical candidate key changed across convergence iterations"
                }
                $targetHistory += [pscustomobject]@{
                    iteration = $iteration
                    candidate_key = $targetCandidateKey
                    request_id = $requestId
                    known_before = @($state.known_before)
                    observed_parameters = @($state.observed_parameters)
                    new_parameters = @($state.new_parameters)
                    missing_parameters = @($state.missing_parameters)
                    known_parameters = @($state.known_parameters)
                    replay_summary = $currentRunSummary
                }
                @{ legacy_run_id = $LegacyRunId; candidate_key = $targetCandidateKey; status = [string]$state.status; iterations = $targetHistory } |
                    ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $targetHistoryPath -Encoding UTF8
                Publish-ZendDirectorySnapshot -SourceDir $iterationDir -TargetDir $targetCurrentDir
                Publish-ZendAggregateTargetState -Targets $targets -SnapshotName "current" -OutputDir $rootCurrentDir

                if ($state.status -eq "CONVERGED") {
                    Publish-ZendDirectorySnapshot -SourceDir $iterationDir -TargetDir $targetFinalDir
                    $finalSeedReports += (Join-Path $targetFinalDir "seeds.json")
                    $converged = $true
                    break
                }
                if ($iteration -ge ($MaxIterations - 1)) {
                    throw "ITERATION_LIMIT: new runtime parameters remain after iteration $iteration"
                }
                $replaySummary = Get-Content -LiteralPath $replayConfigSummary -Raw | ConvertFrom-Json
                if (@($replaySummary.generated).Count -ne 1) {
                    throw "REPLAY_FAILED: Phase 2 requires exactly one generated candidate per target"
                }
                $configPath = [string]$replaySummary.generated[0].config_path
                $configHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
                if (-not $seenConfigHashes.Add($configHash)) {
                    throw "REPEATED_CONFIG: canonical generated config hash repeated"
                }
                $currentSeeds = $mergedSeedsPath
                $statePath = $nextStatePath
                $currentRunSummary = Join-Path $iterationDir "run.json"
                python $generatedConfigRunner `
                    --generated-config-summary $replayConfigSummary `
                    --output-file $currentRunSummary `
                    --timeout-seconds $TimeoutSeconds `
                    --service $fuzzerService `
                    --stop-on-callback `
                    --legacy-run-id $LegacyRunId
                if ($LASTEXITCODE -ne 0) {
                    throw "REPLAY_FAILED: generated convergence replay failed. See $currentRunSummary"
                }
            }
            if (-not $converged) {
                throw "ITERATION_LIMIT: target did not converge within $MaxIterations iterations"
            }
            $targetResults += [pscustomobject]@{
                candidate_key = $targetCandidateKey
                target_directory = $targetDirectoryName
                status = "CONVERGED"
                current = $targetCurrentDir
                final = $targetFinalDir
                iterations = $targetHistory
            }
            @{ legacy_run_id = $LegacyRunId; status = "IN_PROGRESS"; targets = $targetResults } |
                ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $historyPath -Encoding UTF8
        }
        Publish-ZendAggregateTargetState -Targets $targets -SnapshotName "final" -OutputDir $rootFinalDir
        $combinedTemp = Join-Path $bridgeWorkDir "zend_merged_suggested_seeds.final.tmp.json"
        $combineArgs = @(
            $bridgeCli,
            "--operation", "combine-final",
            "--merged-suggested-seeds", $combinedTemp,
            "--expected-count", "$($targets.Count)"
        )
        foreach ($report in $finalSeedReports) {
            $combineArgs += @("--final-seed-report", $report)
        }
        python @combineArgs
        if ($LASTEXITCODE -ne 0) {
            throw "REPLAY_FAILED: could not combine final Zend convergence seed reports"
        }
        Move-Item -LiteralPath $combinedTemp -Destination $finalMergedSuggestedSeeds -Force
        Convert-LiveSeedSuggestionsToConfigs `
            -ScriptRoot $ScriptRoot `
            -PluginSlug $PluginSlug `
            -SuggestedSeeds $finalMergedSuggestedSeeds `
            -OutputConfigDir $finalConfigDir `
            -SummaryPath $finalConfigSummary `
            -RestRouteFallback
        $finalRunSummary = Join-Path $bridgeWorkDir "final-generated_config_run_summary.json"
        python $generatedConfigRunner `
            --generated-config-summary $finalConfigSummary `
            --output-file $finalRunSummary `
            --timeout-seconds $TimeoutSeconds `
            --service $fuzzerService `
            --legacy-run-id $LegacyRunId
        if ($LASTEXITCODE -ne 0) {
            throw "REPLAY_FAILED: final generated convergence replay failed. See $finalRunSummary"
        }
        Invoke-ZendPass2Verification `
            -ScriptRoot $ScriptRoot `
            -LegacyRunId $LegacyRunId `
            -SeedOutputDir $SeedOutputDir `
            -Pass2RunSummary $finalRunSummary `
            -ComposeArgs $ComposeArgs
        @{ legacy_run_id = $LegacyRunId; status = "CONVERGED"; targets = $targetResults; current = $rootCurrentDir; final = $rootFinalDir } |
            ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $historyPath -Encoding UTF8
        return [pscustomobject]@{ ConfigSummary = $finalConfigSummary; RunSummary = $finalRunSummary; HistoryPath = $historyPath }
    } catch {
        $failure = $_.Exception.Message
        $status = if ($failure -match "ITERATION_LIMIT") { "ITERATION_LIMIT" } elseif ($failure -match "REPEATED_CONFIG") { "REPEATED_CONFIG" } else { "REPLAY_FAILED" }
        @{ legacy_run_id = $LegacyRunId; status = $status; error = $failure; targets = $targetResults; current = $rootCurrentDir } |
            ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $historyPath -Encoding UTF8
        throw
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
    $overridePath = New-PluginOverrideFile -PluginSlug $PluginSlug -BootstrapConfigSlug $BootstrapConfigSlug -LegacyRunId $legacyRunId -UseZendDiscovery:$UseZendDiscovery
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

    $onlineSeedOutputDir = ""
    if ($RunOnline) {
        $onlineSeedOutputDir = Join-Path $scriptRoot ("fuzzer\output\online-seed-generation\{0}" -f $legacyRunId)
        New-Item -ItemType Directory -Path $onlineSeedOutputDir -Force | Out-Null
    }
    Export-LiveSeedSuggestions -ScriptRoot $scriptRoot -WaitSeconds $SeedWaitSeconds -ComposeArgs $composeArgs -PluginSlug $PluginSlug -UseEntrypointPipeline:$UseEntrypointPipeline -RuntimeParametersOnly:$UseZendDiscovery -OutputDir $onlineSeedOutputDir
    if ($learnPressProof) {
        Add-LearnPressNonceToSuggestedSeeds `
            -SuggestedSeedsPath (Join-Path $scriptRoot "fuzzer\output\seed_generation\suggested_seeds.json") `
            -Proof $learnPressProof
    }
    if (-not $UseEntrypointPipeline -and -not $RunOnline) {
        Convert-LiveSeedSuggestionsToConfigs -ScriptRoot $scriptRoot -PluginSlug $PluginSlug
    }

    if ($RunOnline) {
        Initialize-ZendCallbackRegistry `
            -ScriptRoot $scriptRoot `
            -PluginSlug $PluginSlug `
            -SeedOutputDir $onlineSeedOutputDir `
            -LegacyRunId $legacyRunId `
            -ComposeArgs $composeArgs
        $seedOutputDir = $onlineSeedOutputDir
        $suggestedSeedsPath = Join-Path $seedOutputDir "suggested_seeds.json"
        $onlineConfigRoot = Join-Path $scriptRoot "fuzzer\configs"
        $onlineRunner = Join-Path $scriptRoot "fuzzer\hook_energy\seed_generation\online_config_runner.py"
        Assert-PathExists -Path $onlineRunner -Hint "The online Zend coordinator is missing from this checkout."

        Write-Host "Stopping bootstrap fuzzer before immutable online v0 starts"
        Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("stop", "--timeout", "30", $fuzzerService)
        Write-Host "Starting bounded online Zend discovery"
        $onlineArgs = @(
            $onlineRunner,
            "--suggested-seeds", $suggestedSeedsPath,
            "--bootstrap-config", $requiredConfig,
            "--config-root", $onlineConfigRoot,
            "--output-root", $seedOutputDir,
            "--plugin-slug", $PluginSlug,
            "--legacy-run-id", $legacyRunId,
            "--max-seconds", "$OnlineTimeoutSeconds",
            "--max-versions", "$OnlineMaxVersions",
            "--service", $fuzzerService
        )
        python @onlineArgs
        $onlineExitCode = $LASTEXITCODE
        $onlineLineagePath = Join-Path (Join-Path $seedOutputDir "online") (Join-Path $legacyRunId "lineage.json")
        Write-Host "Online lineage: $onlineLineagePath"
        if ($onlineExitCode -ne 0) {
            throw "Online Zend discovery failed. See $onlineLineagePath"
        }
    } elseif ($RunGeneratedConfigs) {
        $seedOutputDir = Join-Path $scriptRoot "fuzzer\output\seed_generation"
        $generatedConfigSummary = Join-Path $seedOutputDir "generated_config_summary.json"
        $generatedRunSummary = Join-Path $seedOutputDir "generated_config_run_summary.json"
        $zendRetentionReady = $false
        $zendTerminalStatus = ""
        $zendAuthPartialExpected = $false
        $zendFinalConfigSummary = ""
        $zendFinalRunSummary = ""
        if ($UseZendDiscovery) {
            $bridgeWorkDir = Join-Path (Join-Path $seedOutputDir "zend-bridge") $legacyRunId
            $pass1ConfigDir = Join-Path $bridgeWorkDir "pass1-configs"
            $generatedConfigSummary = Join-Path $bridgeWorkDir "pass1-generated_config_summary.json"
            $generatedRunSummary = Join-Path $bridgeWorkDir "pass1-generated_config_run_summary.json"
            Initialize-ZendCallbackRegistry `
                -ScriptRoot $scriptRoot `
                -PluginSlug $PluginSlug `
                -SeedOutputDir $seedOutputDir `
                -LegacyRunId $legacyRunId `
                -ComposeArgs $composeArgs
            Convert-LiveSeedSuggestionsToConfigs `
                -ScriptRoot $scriptRoot `
                -PluginSlug $PluginSlug `
                -OutputConfigDir $pass1ConfigDir `
                -SummaryPath $generatedConfigSummary `
                -ReplayOnly `
                -RestRouteFallback
        }
        $generatedConfigRunner = Join-Path $scriptRoot "fuzzer\hook_energy\seed_generation\generated_config_runner.py"
        $generatedRunnerLog = $null

        Write-Host "Stopping default fuzzer before generated config batch"
        Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("stop", "--timeout", "30", $fuzzerService)

        Write-Host "Running generated hook configs sequentially"
        if ($UseEntrypointPipeline) {
            $generatedLogDir = Join-Path $seedOutputDir "entrypoint-proof\logs"
            New-Item -ItemType Directory -Path $generatedLogDir -Force | Out-Null
            $generatedRunnerLog = Join-Path $generatedLogDir "generated_config_runner.log"
            $generatedRunnerStdout = Join-Path $generatedLogDir "generated_config_runner.stdout.log"
            $generatedRunnerStderr = Join-Path $generatedLogDir "generated_config_runner.stderr.log"
            $generatedArgs = @(
                $generatedConfigRunner,
                "--generated-config-summary", $generatedConfigSummary,
                "--output-file", $generatedRunSummary,
                "--timeout-seconds", $GeneratedConfigTimeoutSeconds,
                "--service", $fuzzerService
            )
            if ($legacyRunId) {
                $generatedArgs += @("--legacy-run-id", $legacyRunId)
            }
            $generatedProcess = Start-Process `
                -FilePath "python" `
                -ArgumentList $generatedArgs `
                -Wait `
                -PassThru `
                -WindowStyle Hidden `
                -RedirectStandardOutput $generatedRunnerStdout `
                -RedirectStandardError $generatedRunnerStderr
            $generatedExitCode = $generatedProcess.ExitCode
            Get-Content -LiteralPath $generatedRunnerStdout, $generatedRunnerStderr -ErrorAction SilentlyContinue |
                Set-Content -LiteralPath $generatedRunnerLog -Encoding UTF8
        } else {
            $generatedArgs = @(
                $generatedConfigRunner,
                "--generated-config-summary", $generatedConfigSummary,
                "--output-file", $generatedRunSummary,
                "--timeout-seconds", "$GeneratedConfigTimeoutSeconds",
                "--service", $fuzzerService
            )
            if ($legacyRunId) {
                $generatedArgs += @("--legacy-run-id", $legacyRunId)
            }
            if ($UseZendDiscovery) {
                $generatedArgs += "--stop-on-callback"
            }
            python @generatedArgs
            $generatedExitCode = $LASTEXITCODE
        }
        if ($UseEntrypointPipeline) {
            Write-EntrypointPluginProofFile -SeedOutputDir $seedOutputDir -PluginSlug $PluginSlug -RunnerLog $generatedRunnerLog
        }
        if ($generatedExitCode -ne 0) {
            throw "Generated hook config batch failed. See $generatedRunSummary"
        }
        if ($UseZendDiscovery) {
            $pass1RunSummary = Get-Content -LiteralPath $generatedRunSummary -Raw | ConvertFrom-Json
            $zendAuthPartialExpected = [int]$pass1RunSummary.counts.expected_auth_skip -gt 0
        }

        if ($UseZendDiscovery) {
            $zendCandidateCount = @((Get-Content -LiteralPath $generatedConfigSummary -Raw | ConvertFrom-Json).generated).Count
            if ($zendCandidateCount -gt 0) {
                $convergence = Invoke-ZendConvergence `
                    -ScriptRoot $scriptRoot `
                    -PluginSlug $PluginSlug `
                    -LegacyRunId $legacyRunId `
                    -SeedOutputDir $seedOutputDir `
                    -InitialRunSummary $generatedRunSummary `
                    -TimeoutSeconds $GeneratedConfigTimeoutSeconds `
                    -MaxIterations $ZendMaxIterations `
                    -ComposeArgs $composeArgs
                $generatedConfigSummary = $convergence.ConfigSummary
                $generatedRunSummary = $convergence.RunSummary
                $zendRetentionReady = $true
                $zendTerminalStatus = if ($zendAuthPartialExpected) { "PASS_PARTIAL_AUTH_EXPECTED" } else { "PASS" }
                $zendFinalConfigSummary = $generatedConfigSummary
                $zendFinalRunSummary = $generatedRunSummary
                Write-Host "Zend convergence summary: $($convergence.HistoryPath)"
            } else {
                Invoke-ZendDiscoveryBridge `
                    -ScriptRoot $scriptRoot `
                    -PluginSlug $PluginSlug `
                    -LegacyRunId $legacyRunId `
                    -SeedOutputDir $seedOutputDir `
                    -Pass1RunSummary $generatedRunSummary `
                    -ComposeArgs $composeArgs

                $generatedConfigSummary = Join-Path $seedOutputDir "generated_config_summary.json"
                $generatedRunSummary = Join-Path $seedOutputDir "pass2-generated_config_run_summary.json"
                python $generatedConfigRunner `
                    --generated-config-summary $generatedConfigSummary `
                    --output-file $generatedRunSummary `
                    --timeout-seconds $GeneratedConfigTimeoutSeconds `
                    --service $fuzzerService `
                    --legacy-run-id $legacyRunId
                $generatedExitCode = $LASTEXITCODE
                if ($generatedExitCode -ne 0) {
                    throw "Generated hook config Pass 2 failed. See $generatedRunSummary"
                }
                Invoke-ZendPass2Verification `
                    -ScriptRoot $scriptRoot `
                    -LegacyRunId $legacyRunId `
                    -SeedOutputDir $seedOutputDir `
                    -Pass2RunSummary $generatedRunSummary `
                    -ComposeArgs $composeArgs
            }
        }

        if ($learnPressProof -and $zendFinalConfigSummary -and $zendFinalRunSummary) {
            Write-LearnPressFinalProof `
                -ProofPath $learnPressProof.proof_path `
                -SuggestedSeedsPath (Join-Path $seedOutputDir "suggested_seeds.json") `
                -ConfigSummaryPath $zendFinalConfigSummary `
                -RunSummaryPath $zendFinalRunSummary
        }

        if ($UseZendDiscovery -and $zendRetentionReady) {
            Invoke-ZendArtifactRetention `
                -ScriptRoot $scriptRoot `
                -SeedOutputDir $seedOutputDir `
                -LegacyRunId $legacyRunId `
                -TerminalStatus $zendTerminalStatus `
                -FinalConfigSummary $zendFinalConfigSummary `
                -FinalRunSummary $zendFinalRunSummary `
                -ZendDiscoveryRunDir (Join-Path (Join-Path $scriptRoot "fuzzer\output\zend-discovery") $legacyRunId) `
                -KeepDebugArtifacts:$KeepDebugArtifacts
        }

        Write-Host "Generated config run summary: $generatedRunSummary"
    } elseif ($NoFollowLogs) {
        Write-Host "PHUZZ started. To follow logs later, run:"
        Write-Host "  docker compose logs -f $fuzzerService"
        Write-Host "Suggested seed artifacts:"
        Write-Host "  $scriptRoot\fuzzer\output\seed_generation"
        Write-Host "Generated hook config artifacts:"
        Write-Host "  $scriptRoot\fuzzer\configs\generated-config\$PluginSlug"
    } else {
        Write-Host "Following fuzzer logs. Press Ctrl+C to stop following without stopping containers."
        Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("logs", "-f", $fuzzerService)
    }
} finally {
    if ($overridePath -and (Test-Path -LiteralPath $overridePath)) {
        Remove-Item -LiteralPath $overridePath -Force
    }
    Pop-Location
}
