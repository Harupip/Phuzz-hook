param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$pluginDir = Split-Path -Parent $PSCommandPath

$downloads = @(
    @{
        File = "show-all-comments-in-one-page.zip"
        Url = "https://downloads.wordpress.org/plugin/show-all-comments-in-one-page.7.0.0.zip"
        Note = "Default target plugin. Small package."
    }

    # Heavy plugins kept commented out by default.
    # Uncomment when you need them on a fresh machine.
    #@{
    #    File = "seo-local-rank.zip"
    #    Url = "https://downloads.wordpress.org/plugin/seo-local-rank.2.2.2.zip"
    #    Note = "Larger package (~8 MB)."
    #}
    #@{
    #    File = "photo-gallery.zip"
    #    Url = "https://downloads.wordpress.org/plugin/photo-gallery.1.6.2.zip"
    #    Note = "Larger package (~11 MB)."
    #}
)

foreach ($item in $downloads) {
    $destination = Join-Path $pluginDir $item.File

    if ((Test-Path $destination) -and -not $Force) {
        Write-Host "Skip existing $($item.File)"
        continue
    }

    Write-Host "Downloading $($item.File)"
    Write-Host "  $($item.Note)"
    Invoke-WebRequest -Uri $item.Url -OutFile $destination
}

Write-Host "Done. Plugin ZIPs are in $pluginDir"
