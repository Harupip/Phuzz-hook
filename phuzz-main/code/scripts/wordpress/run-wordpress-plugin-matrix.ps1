param(
    [string[]]$Plugins,
    [switch]$DownloadMissing,
    [switch]$ForceDownload,
    [int]$WebTimeoutSeconds = 240,
    [int]$FuzzWarmupSeconds = 20,
    [string]$ReportPath,
    [string]$JsonReportPath,
    [switch]$Resume
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $PSCommandPath
$scriptRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir "..\..")).Path
$pluginDir = Join-Path $scriptRoot "web\applications\wordpress\_plugins"
$configDir = Join-Path $scriptRoot "fuzzer\configs\wordpress"
$wpCliPath = Join-Path $scriptRoot "web\applications\wordpress\wp-cli.phar"
$fuzzerService = "fuzzer-wordpress-plugin"
$composeBase = @("docker", "compose", "-f", "docker-compose.yml")
$reportRoot = Join-Path $scriptRoot "docs\reports\plugin-matrix"

function Get-PluginMatrix {
    @(
        @{ Slug = "kivicare-clinic-management-system"; Category = "SQLi"; Url = "https://downloads.wordpress.org/plugin/kivicare-clinic-management-system.2.3.8.zip" }
        @{ Slug = "nirweb-support"; Category = "SQLi"; Url = "https://downloads.wordpress.org/plugin/nirweb-support.2.7.6.zip" }
        @{ Slug = "arprice-responsive-pricing-table"; Category = "SQLi"; Url = "https://downloads.wordpress.org/plugin/arprice-responsive-pricing-table.3.6.zip" }
        @{ Slug = "ubigeo-peru"; Category = "SQLi"; Url = "https://downloads.wordpress.org/plugin/ubigeo-peru.3.6.3.zip" }
        @{ Slug = "photo-gallery"; Category = "SQLi"; Url = "https://downloads.wordpress.org/plugin/photo-gallery.1.6.2.zip" }
        @{ Slug = "show-all-comments-in-one-page"; Category = "XSS"; Url = "https://downloads.wordpress.org/plugin/show-all-comments-in-one-page.7.0.0.zip" }
        @{ Slug = "essential-real-estate"; Category = "XSS"; Url = "https://downloads.wordpress.org/plugin/essential-real-estate.3.9.5.zip" }
        @{ Slug = "crm-perks-forms"; Category = "XSS"; Url = "https://downloads.wordpress.org/plugin/crm-perks-forms.1.0.7.zip" }
        @{ Slug = "rezgo"; Category = "XSS"; Url = "https://downloads.wordpress.org/plugin/rezgo.4.1.6.zip" }
        @{ Slug = "gallery-album"; Category = "XSS"; Url = "https://downloads.wordpress.org/plugin/gallery-album.1.9.9.zip" }
        @{ Slug = "usc-e-shop"; Category = "PathTraversal"; Url = "https://downloads.wordpress.org/plugin/usc-e-shop.2.8.4.zip" }
        @{ Slug = "udraw"; Category = "PathTraversal"; Url = "https://downloads.wordpress.org/plugin/udraw.3.3.2.zip"; ExtraDownloads = @(@{ File = "woocommerce.zip"; Url = "https://downloads.wordpress.org/plugin/woocommerce.latest-stable.zip" }) }
        @{ Slug = "seo-local-rank"; Category = "PathTraversal"; Url = "https://downloads.wordpress.org/plugin/seo-local-rank.2.2.2.zip" }
        @{ Slug = "hypercomments"; Category = "PathTraversal"; Url = "https://downloads.wordpress.org/plugin/hypercomments.1.2.1.zip" }
        @{ Slug = "nmedia-user-file-uploader"; Category = "PathTraversal"; Url = "https://downloads.wordpress.org/plugin/nmedia-user-file-uploader.21.2.zip" }
        @{ Slug = "joomsport-sports-league-results-management"; Category = "Deserialization"; Url = "https://downloads.wordpress.org/plugin/joomsport-sports-league-results-management.5.1.7.zip" }
        @{ Slug = "totop-link"; Category = "Deserialization"; Url = "https://downloads.wordpress.org/plugin/totop-link.1.7.zip" }
        @{ Slug = "newsletter-optin-box"; Category = "OpenRedirect"; Url = "https://downloads.wordpress.org/plugin/newsletter-optin-box.1.6.4.zip" }
        @{ Slug = "webp-converter-for-media"; Category = "OpenRedirect"; Url = "https://downloads.wordpress.org/plugin/webp-converter-for-media.4.0.2.zip" }
        @{ Slug = "phastpress"; Category = "OpenRedirect"; Url = "https://downloads.wordpress.org/plugin/phastpress.1.110.zip" }
        @{ Slug = "all-in-one-wp-security-and-firewall"; Category = "OpenRedirect"; Url = "https://downloads.wordpress.org/plugin/all-in-one-wp-security-and-firewall.4.4.0.zip" }
        @{ Slug = "pie-register"; Category = "OpenRedirect"; Url = "https://downloads.wordpress.org/plugin/pie-register.3.7.2.3.zip" }
        @{ Slug = "file-provider"; Category = "SQLi"; Url = "https://downloads.wordpress.org/plugin/file-provider.1.2.3.zip"; Config = "file_provider_sqli" }
    )
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

function Wait-ForWebReady {
    param([int]$TimeoutSeconds)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8080/" -UseBasicParsing -TimeoutSec 10
            if ($response.StatusCode -eq 200) {
                return
            }
        } catch {
        }
        Start-Sleep -Seconds 5
    }

    throw "Timed out waiting for http://localhost:8080/"
}

function Assert-PathExists {
    param(
        [string]$Path,
        [string]$Hint
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Missing required file: $Path`n$Hint"
    }
}

function Ensure-Zip {
    param(
        [hashtable]$Plugin,
        [switch]$DownloadMissing,
        [switch]$ForceDownload
    )

    $downloads = @(
        @{
            File = "$($Plugin.Slug).zip"
            Url = $Plugin.Url
        }
    )

    if ($Plugin.ContainsKey("ExtraDownloads")) {
        $downloads += $Plugin.ExtraDownloads
    }

    $downloadNotes = @()
    foreach ($item in $downloads) {
        $destination = Join-Path $pluginDir $item.File
        if ((Test-Path -LiteralPath $destination) -and -not $ForceDownload) {
            $downloadNotes += "existing:$($item.File)"
            continue
        }

        if (-not $DownloadMissing) {
            throw "Missing ZIP $($item.File). Re-run with -DownloadMissing."
        }

        Write-Host "Downloading $($item.File)"
        Invoke-WebRequest -Uri $item.Url -OutFile $destination
        $downloadNotes += "downloaded:$($item.File)"
    }

    return $downloadNotes
}

function New-OverrideFile {
    param([hashtable]$Plugin)

    $path = Join-Path $env:TEMP ("phuzz-{0}.override.yml" -f $Plugin.Slug)
    $config = if ($Plugin.ContainsKey("Config")) { $Plugin.Config } else { $Plugin.Slug }
    $content = @(
        "services:"
        "  web:"
        "    environment:"
        "      FUZZER_COVERAGE_PATH: /var/www/html/wp-content/plugins/$($Plugin.Slug)/"
        "      WP_TARGET_PLUGIN: $($Plugin.Slug)"
        "  ${fuzzerService}:"
        "    environment:"
        "      FUZZER_CONFIG: wordpress/$config"
    )
    Set-Content -LiteralPath $path -Value $content -Encoding ASCII
    return $path
}

function Get-ActivePlugins {
    param([string[]]$ComposeArgs)

    $output = & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] exec -T web sh -lc "cd /var/www/html && ./wp-cli.phar plugin list --allow-root --status=active --field=name"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to read active plugins."
    }
    return @(
        $output | Where-Object {
            (-not [string]::IsNullOrWhiteSpace($_)) -and
            ($_ -notmatch "Deprecated:") -and
            ($_ -notmatch "Cannot load Zend OPcache")
        }
    )
}

function Get-FuzzerEnvSlug {
    param([string[]]$ComposeArgs)

    $value = & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] exec -T $fuzzerService printenv FUZZER_CONFIG
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to read FUZZER_CONFIG from fuzzer container."
    }
    return ($value | Select-Object -First 1).Trim()
}

function Get-FuzzerLogSample {
    param([string[]]$ComposeArgs)

    $lines = & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] logs $fuzzerService --tail=400
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to read fuzzer logs."
    }
    return @($lines)
}

function ConvertTo-Markdown {
    param(
        [System.Collections.IEnumerable]$Results,
        [string]$GeneratedAt,
        [string]$RunnerPath
    )

    $successful = @($Results | Where-Object { $_.status -eq "success" })
    $failed = @($Results | Where-Object { $_.status -ne "success" })
    $runnerCommand = ".\{0} -DownloadMissing" -f (Split-Path -Leaf $RunnerPath)
    $lines = @()
    $lines += "# WordPress plugin matrix validation"
    $lines += ""
    $lines += "Generated at: $GeneratedAt"
    $lines += ""
    $lines += "Runner:"
    $lines += ""
    $lines += '```powershell'
    $lines += $runnerCommand
    $lines += '```'
    $lines += ""
    $lines += "Success criteria:"
    $lines += ""
    $lines += "- ZIP present or downloaded"
    $lines += "- plugin active in WordPress"
    $lines += "- FUZZER_CONFIG matches the plugin slug"
    $lines += "- fuzzer emits request trace lines"
    $lines += ""
    $lines += "## Successful plugins"
    $lines += ""

    if ($successful.Count -eq 0) {
        $lines += "- None"
    } else {
        foreach ($item in $successful) {
            $lines += "- $($item.slug) ($($item.category)): active + FUZZER_CONFIG=$($item.fuzzer_config) + requests=$($item.request_count)"
            $lines += "  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins $($item.slug)"
        }
    }

    $lines += ""
    $lines += "## Failed plugins"
    $lines += ""

    if ($failed.Count -eq 0) {
        $lines += "- None"
    } else {
        foreach ($item in $failed) {
            $lines += "- $($item.slug) ($($item.category)): $($item.note)"
        }
    }

    $lines += ""
    $lines += "## Detailed results"
    $lines += ""
    $lines += "| Plugin | Category | Status | Requests | Download | Note |"
    $lines += "| --- | --- | --- | ---: | --- | --- |"
    foreach ($item in $Results) {
        $downloadText = ($item.download_notes -join ", ")
        $noteText = ($item.note -replace "\|", "/")
        $lines += "| $($item.slug) | $($item.category) | $($item.status) | $($item.request_count) | $downloadText | $noteText |"
    }

    return $lines -join "`r`n"
}

function Save-Reports {
    param(
        [System.Collections.IEnumerable]$Results,
        [string]$ReportPath,
        [string]$JsonReportPath,
        [string]$RunnerPath
    )

    $markdown = ConvertTo-Markdown -Results $Results -GeneratedAt ((Get-Date).ToString("yyyy-MM-dd HH:mm:ss zzz")) -RunnerPath $RunnerPath
    Set-Content -LiteralPath $ReportPath -Value $markdown -Encoding ASCII
    $Results | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonReportPath -Encoding ASCII
}

$matrix = Get-PluginMatrix
if ($Plugins -and $Plugins.Count -gt 0) {
    $selected = foreach ($pluginName in $Plugins) {
        $match = $matrix | Where-Object { $_.Slug -eq $pluginName }
        if (-not $match) {
            throw "Unknown plugin slug: $pluginName"
        }
        $match
    }
} else {
    $selected = $matrix
}

if (-not $ReportPath) {
    $ReportPath = Join-Path $reportRoot ("wordpress-plugin-matrix-{0}.md" -f (Get-Date -Format "yyyy-MM-dd-HHmmss"))
}

if (-not $JsonReportPath) {
    $JsonReportPath = [System.IO.Path]::ChangeExtension($ReportPath, ".json")
}

$reportParent = Split-Path -Parent $ReportPath
if ($reportParent) {
    New-Item -ItemType Directory -Force -Path $reportParent | Out-Null
}

Assert-PathExists -Path $wpCliPath -Hint "Missing wp-cli.phar in the WordPress application."

$results = New-Object System.Collections.Generic.List[object]

if ($Resume -and (Test-Path -LiteralPath $JsonReportPath)) {
    $existing = Get-Content -LiteralPath $JsonReportPath -Raw | ConvertFrom-Json
    foreach ($item in @($existing)) {
        $results.Add($item)
    }
}

$completedSlugs = @($results | ForEach-Object { $_.slug })
if ($completedSlugs.Count -gt 0) {
    $selected = @($selected | Where-Object { $completedSlugs -notcontains $_.Slug })
}

Push-Location $scriptRoot
try {
    foreach ($plugin in $selected) {
        $slug = $plugin.Slug
        $result = [ordered]@{
            slug = $slug
            category = $plugin.Category
            status = "failed"
            note = ""
            request_count = 0
            fuzzer_config = ""
            active_plugins = @()
            download_notes = @()
            sample_log = @()
        }

        Write-Host "=== $slug ==="
        $overridePath = $null
        try {
            $config = if ($plugin.ContainsKey("Config")) { $plugin.Config } else { $slug }
            Assert-PathExists -Path (Join-Path $configDir "$config.json") -Hint "Missing PHUZZ config for $config."
            $result.download_notes = Ensure-Zip -Plugin $plugin -DownloadMissing:$DownloadMissing -ForceDownload:$ForceDownload
            $overridePath = New-OverrideFile -Plugin $plugin
            $composeArgs = Get-ComposeArgs -OverridePath $overridePath

            Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("down", "--volumes", "--remove-orphans")
            Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("up", "-d", "db", "web", "--build", "--force-recreate")
            Wait-ForWebReady -TimeoutSeconds $WebTimeoutSeconds

            $result.active_plugins = Get-ActivePlugins -ComposeArgs $composeArgs
            if ($result.active_plugins -notcontains $slug) {
                throw "Plugin $slug is not active after WordPress bootstrap."
            }

            Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("up", "-d", $fuzzerService, "--force-recreate")
            Start-Sleep -Seconds $FuzzWarmupSeconds

            $result.fuzzer_config = Get-FuzzerEnvSlug -ComposeArgs $composeArgs
            if ($result.fuzzer_config -ne "wordpress/$config") {
                throw "Fuzzer config mismatch: $($result.fuzzer_config)"
            }

            $logLines = Get-FuzzerLogSample -ComposeArgs $composeArgs
            $traceLines = @($logLines | Where-Object { $_ -match "\[req \d+\]" })
            $result.request_count = $traceLines.Count
            $result.sample_log = $traceLines | Select-Object -First 3
            if ($result.request_count -le 0) {
                throw "No request trace lines observed for $slug."
            }

            $result.status = "success"
            $result.note = "WordPress active and PHUZZ request trace observed."
        } catch {
            $result.note = $_.Exception.Message
        } finally {
            if ($overridePath -and (Test-Path -LiteralPath $overridePath)) {
                Remove-Item -LiteralPath $overridePath -Force
            }
        }

        $results.Add([pscustomobject]$result)
        Save-Reports -Results $results -ReportPath $ReportPath -JsonReportPath $JsonReportPath -RunnerPath $PSCommandPath
    }
} finally {
    Pop-Location
}

Save-Reports -Results $results -ReportPath $ReportPath -JsonReportPath $JsonReportPath -RunnerPath $PSCommandPath

[pscustomobject]@{
    report = $ReportPath
    json = $JsonReportPath
    success = @($results | Where-Object { $_.status -eq "success" }).Count
    failed = @($results | Where-Object { $_.status -ne "success" }).Count
} | ConvertTo-Json -Depth 3
