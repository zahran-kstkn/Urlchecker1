$ErrorActionPreference = "Stop"

$projectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$outputDirectory = Join-Path $projectDirectory "firefox-build"
$assetNames = @(
	"index.html",
	"app.js",
	"urlhaus-feed.js",
	"analyzer.js",
	"policy.js",
	"content.js",
	"Background.js"
)

New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
foreach ($assetName in $assetNames) {
	Copy-Item -LiteralPath (Join-Path $projectDirectory $assetName) -Destination (Join-Path $outputDirectory $assetName) -Force
}

$manifest = Get-Content -LiteralPath (Join-Path $projectDirectory "manifest.json") -Raw | ConvertFrom-Json
$manifest.background = @{ scripts = @("Background.js") }
$manifestPath = Join-Path $outputDirectory "manifest.json"
$manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Output "Firefox extension files prepared at $outputDirectory"
