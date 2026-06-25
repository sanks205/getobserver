# Cross-compile Observer into self-contained native binaries.
#
# Pure `go build` — no Docker, no CGO, no extra tooling. Each output is a single
# statically-linked executable with zero runtime dependencies: users download
# one file and run it.
#
# Usage:  pwsh scripts/build-release.ps1 [-Version 1.0.0]

param([string]$Version = "0.1.0")
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null

$env:CGO_ENABLED = "0"                      # fully static, cross-compile-safe
$ldflags = "-s -w -X main.version=$Version" # strip debug info + stamp version

$targets = @(
  @{ os = "windows"; arch = "amd64"; ext = ".exe" },
  @{ os = "windows"; arch = "arm64"; ext = ".exe" },
  @{ os = "linux";   arch = "amd64"; ext = "" },
  @{ os = "linux";   arch = "arm64"; ext = "" },
  @{ os = "darwin";  arch = "amd64"; ext = "" },
  @{ os = "darwin";  arch = "arm64"; ext = "" }
)

foreach ($t in $targets) {
  $env:GOOS = $t.os; $env:GOARCH = $t.arch
  $out = Join-Path $dist "observer_$($t.os)_$($t.arch)$($t.ext)"
  Write-Host "Building $($t.os)/$($t.arch) ..."
  go build -trimpath -ldflags $ldflags -o $out ./cmd/cli
  if ($LASTEXITCODE -ne 0) { throw "build failed for $($t.os)/$($t.arch)" }
}

# Checksums for release verification.
$sums = Join-Path $dist "SHA256SUMS.txt"
Get-ChildItem $dist -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | ForEach-Object {
  "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())  $($_.Name)"
} | Set-Content $sums

Remove-Item Env:\GOOS, Env:\GOARCH -ErrorAction SilentlyContinue
Write-Host "`nDone. Binaries in $dist"
Get-ChildItem $dist -File | Select-Object Name, @{n='SizeMB';e={[math]::Round($_.Length/1MB,2)}}
