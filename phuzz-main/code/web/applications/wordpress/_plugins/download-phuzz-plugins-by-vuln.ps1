param(
    [ValidateSet("SQLi", "XSS", "PathTraversal", "Deserialization", "OpenRedirect")]
    [string[]]$Category,
    [switch]$All,
    [switch]$Force,
    [switch]$List,
    [switch]$Preview
)

$ErrorActionPreference = "Stop"

$pluginDir = Split-Path -Parent $PSCommandPath

$downloadsByCategory = [ordered]@{
    SQLi = @(
        "kivicare-clinic-management-system",
        "nirweb-support",
        "arprice-responsive-pricing-table",
        "ubigeo-peru",
        "photo-gallery"
    )
    XSS = @(
        "show-all-comments-in-one-page",
        "essential-real-estate",
        "crm-perks-forms",
        "rezgo",
        "gallery-album"
    )
    PathTraversal = @(
        "usc-e-shop",
        "udraw",
        "seo-local-rank",
        "hypercomments",
        "nmedia-user-file-uploader"
    )
    Deserialization = @(
        "joomsport-sports-league-results-management",
        "totop-link"
    )
    OpenRedirect = @(
        "newsletter-optin-box",
        "webp-converter-for-media",
        "phastpress",
        "all-in-one-wp-security-and-firewall",
        "pie-register"
    )
}

function Show-Usage {
    Write-Host "PHUZZ WordPress plugin downloader by vulnerability class"
    Write-Host ""
    Write-Host "Categories:"
    foreach ($entry in $downloadsByCategory.GetEnumerator()) {
        Write-Host ("  - {0}: {1}" -f $entry.Key, ($entry.Value -join ", "))
    }
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\download-phuzz-plugins-by-vuln.ps1 -Category XSS"
    Write-Host "  .\download-phuzz-plugins-by-vuln.ps1 -Category SQLi,OpenRedirect"
    Write-Host "  .\download-phuzz-plugins-by-vuln.ps1 -Category PathTraversal -Preview"
    Write-Host "  .\download-phuzz-plugins-by-vuln.ps1 -All"
    Write-Host "  .\download-phuzz-plugins-by-vuln.ps1 -All -Force"
}

function Get-RequestedPlugins {
    if ($All) {
        return $downloadsByCategory.Values | ForEach-Object { $_ }
    }

    if (-not $Category -or $Category.Count -eq 0) {
        return @()
    }

    $requested = foreach ($name in $Category) {
        $downloadsByCategory[$name]
    }

    return $requested
}

if ($List -or ((-not $All) -and (-not $Category))) {
    Show-Usage
    exit 0
}

$requestedPlugins = Get-RequestedPlugins | Sort-Object -Unique

if (-not $requestedPlugins -or $requestedPlugins.Count -eq 0) {
    throw "No plugins selected. Use -Category <name> or -All."
}

if ($Preview) {
    Write-Host "Selected plugins:"
    foreach ($slug in $requestedPlugins) {
        Write-Host ("  - {0}.zip" -f $slug)
    }
    exit 0
}

foreach ($slug in $requestedPlugins) {
    $destination = Join-Path $pluginDir ("{0}.zip" -f $slug)
    $url = "https://downloads.wordpress.org/plugin/{0}.zip" -f $slug

    if ((Test-Path -LiteralPath $destination) -and -not $Force) {
        Write-Host ("Skip existing {0}.zip" -f $slug)
        continue
    }

    Write-Host ("Downloading {0}.zip" -f $slug)
    Write-Host ("  {0}" -f $url)
    Invoke-WebRequest -Uri $url -OutFile $destination
}

Write-Host ("Done. Plugin ZIPs are in {0}" -f $pluginDir)
