function Read-PhuzzEnv {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing PHUZZ settings file: $Path"
    }

    $settings = @{}
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $Path) {
        $lineNumber++
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith("#")) {
            continue
        }
        if ($trimmed -notmatch '^(?<key>[A-Za-z_][A-Za-z0-9_]*)=(?<value>.*)$') {
            throw "Invalid PHUZZ setting at ${Path}:$lineNumber. Expected KEY=VALUE."
        }

        $settings[$matches["key"]] = $matches["value"].Trim().Trim('"').Trim("'")
    }

    return $settings
}

function Get-PhuzzIntSetting {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Settings,
        [Parameter(Mandatory)]
        [hashtable]$BoundParameters,
        [Parameter(Mandatory)]
        [string]$ParameterName,
        [Parameter(Mandatory)]
        [string]$Key,
        [Parameter(Mandatory)]
        [int]$Default,
        [Parameter(Mandatory)]
        [int]$Minimum,
        [Parameter(Mandatory)]
        [int]$Maximum
    )

    if ($BoundParameters.ContainsKey($ParameterName)) {
        $value = [int]$BoundParameters[$ParameterName]
    } elseif ($Settings.ContainsKey($Key)) {
        $rawValue = [string]$Settings[$Key]
        $parsedValue = 0
        if (-not [int]::TryParse($rawValue, [ref]$parsedValue)) {
            throw "Invalid PHUZZ setting '$Key' value '$rawValue'. Expected an integer."
        }
        $value = $parsedValue
    } else {
        $value = $Default
    }

    if ($value -lt $Minimum -or $value -gt $Maximum) {
        throw "PHUZZ setting '$Key' must be between $Minimum and $Maximum."
    }

    return $value
}

function Resolve-PhuzzRuntimeSettings {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [hashtable]$BoundParameters
    )

    $settings = Read-PhuzzEnv -Path $Path
    return [ordered]@{
        ZendMaxIterations = Get-PhuzzIntSetting -Settings $settings -BoundParameters $BoundParameters -ParameterName "ZendMaxIterations" -Key "ZEND_MAX_ITERATIONS" -Default 5 -Minimum 1 -Maximum 30
        OnlineTimeoutSeconds = Get-PhuzzIntSetting -Settings $settings -BoundParameters $BoundParameters -ParameterName "OnlineTimeoutSeconds" -Key "ONLINE_TIMEOUT_SECONDS" -Default 120 -Minimum 1 -Maximum 120
        OnlineMaxVersions = Get-PhuzzIntSetting -Settings $settings -BoundParameters $BoundParameters -ParameterName "OnlineMaxVersions" -Key "ONLINE_MAX_VERSIONS" -Default 2 -Minimum 1 -Maximum 20
        OnlineMaxCandidates = Get-PhuzzIntSetting -Settings $settings -BoundParameters $BoundParameters -ParameterName "OnlineMaxCandidates" -Key "ONLINE_MAX_CANDIDATES" -Default 32 -Minimum 1 -Maximum 128
        OnlineCampaignTimeoutSeconds = Get-PhuzzIntSetting -Settings $settings -BoundParameters $BoundParameters -ParameterName "OnlineCampaignTimeoutSeconds" -Key "ONLINE_CAMPAIGN_TIMEOUT_SECONDS" -Default 3600 -Minimum 1 -Maximum 86400
        StopOnVulnCount = Get-PhuzzIntSetting -Settings $settings -BoundParameters $BoundParameters -ParameterName "StopOnVulnCount" -Key "HOOKPHUZZ_STOP_ON_VULN" -Default 0 -Minimum 0 -Maximum 100000
    }
}
