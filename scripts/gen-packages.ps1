# Generate package-manager manifests (Scoop + Homebrew) for a release.
#
# Reads dist/SHA256SUMS.txt (produced by build-release.ps1) and writes:
#   packaging/scoop/observer.json      - Windows (scoop install)
#   packaging/homebrew/observer.rb     - macOS/Linux (brew install)
#
# Run AFTER build-release.ps1 and AFTER the GitHub release assets are published
# for that version (the manifests point at the release download URLs).
#
# Usage:  powershell -File scripts/gen-packages.ps1 -Version 0.2.0

param([string]$Version = "0.2.0")
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root "dist"
$repo = "sanks205/getobserver"
$base = "https://github.com/$repo/releases/download/v$Version"

# Load "<sha256>  <filename>" pairs from the checksums file.
$h = @{}
Get-Content (Join-Path $dist "SHA256SUMS.txt") | ForEach-Object {
  if ($_ -match '^([0-9a-fA-F]{64})\s+(\S+)$') { $h[$Matches[2]] = $Matches[1].ToLower() }
}
foreach ($f in @("observer_windows_amd64.exe","observer_windows_arm64.exe","observer_darwin_amd64","observer_darwin_arm64","observer_linux_amd64","observer_linux_arm64")) {
  if (-not $h[$f]) { throw "missing hash for $f in dist/SHA256SUMS.txt (run build-release.ps1 first)" }
}

$pkgScoop = Join-Path $root "packaging\scoop"
$pkgBrew  = Join-Path $root "packaging\homebrew"
New-Item -ItemType Directory -Force -Path $pkgScoop, $pkgBrew | Out-Null

$desc = "Offline CLI that scans a codebase for security, runtime & production-health issues - one HTML report, single binary, no setup."

# --- Scoop manifest (hand-built to keep the bin-rename array shape exact) ---
$scoop = @"
{
  "version": "$Version",
  "description": "$desc",
  "homepage": "https://github.com/$repo",
  "license": "MIT",
  "architecture": {
    "64bit": {
      "url": "$base/observer_windows_amd64.exe",
      "hash": "$($h['observer_windows_amd64.exe'])",
      "bin": [["observer_windows_amd64.exe", "observer"]]
    },
    "arm64": {
      "url": "$base/observer_windows_arm64.exe",
      "hash": "$($h['observer_windows_arm64.exe'])",
      "bin": [["observer_windows_arm64.exe", "observer"]]
    }
  },
  "checkver": "github",
  "autoupdate": {
    "architecture": {
      "64bit": { "url": "https://github.com/$repo/releases/download/v`$version/observer_windows_amd64.exe" },
      "arm64": { "url": "https://github.com/$repo/releases/download/v`$version/observer_windows_arm64.exe" }
    }
  }
}
"@

# --- Homebrew formula (prebuilt binaries; custom tap) ---
$brew = @"
class Observer < Formula
  desc "$desc"
  homepage "https://github.com/$repo"
  version "$Version"
  license "MIT"

  on_macos do
    on_arm do
      url "$base/observer_darwin_arm64"
      sha256 "$($h['observer_darwin_arm64'])"
    end
    on_intel do
      url "$base/observer_darwin_amd64"
      sha256 "$($h['observer_darwin_amd64'])"
    end
  end

  on_linux do
    on_arm do
      url "$base/observer_linux_arm64"
      sha256 "$($h['observer_linux_arm64'])"
    end
    on_intel do
      url "$base/observer_linux_amd64"
      sha256 "$($h['observer_linux_amd64'])"
    end
  end

  def install
    bin.install Dir["observer_*"].first => "observer"
  end

  test do
    assert_match "observer", shell_output("#{bin}/observer version")
  end
end
"@

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $pkgScoop "observer.json"), $scoop, $utf8NoBom)
[System.IO.File]::WriteAllText((Join-Path $pkgBrew "observer.rb"), $brew, $utf8NoBom)

Write-Host "Wrote packaging/scoop/observer.json and packaging/homebrew/observer.rb for v$Version"
