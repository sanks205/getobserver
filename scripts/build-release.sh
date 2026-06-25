#!/usr/bin/env bash
# Cross-compile Observer into self-contained native binaries.
#
# Pure `go build` — no Docker, no CGO, no extra tooling. Each output is a single
# statically-linked executable with zero runtime dependencies.
#
# Usage:  ./scripts/build-release.sh [VERSION]
set -euo pipefail

VERSION="${1:-0.1.0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"

export CGO_ENABLED=0
LDFLAGS="-s -w -X main.version=$VERSION"

targets=(
  "windows/amd64/.exe"
  "windows/arm64/.exe"
  "linux/amd64/"
  "linux/arm64/"
  "darwin/amd64/"
  "darwin/arm64/"
)

for t in "${targets[@]}"; do
  IFS='/' read -r os arch ext <<< "$t"
  out="$DIST/observer_${os}_${arch}${ext}"
  echo "Building $os/$arch ..."
  GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" -o "$out" ./cmd/cli
done

# Checksums for release verification.
( cd "$DIST" && sha256sum observer_* > SHA256SUMS.txt 2>/dev/null || shasum -a 256 observer_* > SHA256SUMS.txt )

echo "Done. Binaries in $DIST"
ls -lh "$DIST"
