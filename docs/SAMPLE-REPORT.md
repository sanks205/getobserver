# Public Sample Report

[Open the interactive report](https://sanks205.github.io/getobserver/sample-report.html).

The artifact is checked in as [sample-report.html](sample-report.html). It becomes available at the URL above after these files are deployed through the repository's GitHub Pages configuration.

## What it demonstrates

This is an actual enforced-offline scan of the intentionally insecure, first-party [PHP demo](../examples/php-demo/), not a client audit or a benchmark. It preserves report grouping, findings, filters, theme switching, printing, remediation guidance, and Community Edition branding.

The report is rendered by a post-release v0.8.2 Community source build with corrected severity-grade wording and purchase links. It is not claimed to be the byte-for-byte output of the original published binary.

## Publication changes

The generation script:

- Adds a public-demo banner.
- Removes absolute workstation paths.
- Replaces local editor links with pinned public GitHub source links.
- Leaves the finding data and heuristic scores unchanged.
- Verifies that the fake demonstration token is not exposed unredacted.
- Rejects changed fixtures until the pinned public source reference and canonical fixture digest are updated.

Only public synthetic fixtures are used. No customer source, logs, license data, or private project report is included.

## Reproduce

Requires Go 1.26+ and Python 3.10+.

~~~powershell
go build -o observer-preview.exe ./cmd/cli
python scripts/generate-sample-report.py --observer ./observer-preview.exe
~~~

On macOS/Linux, build without the .exe suffix and pass that executable path.

The script runs an enforced-offline scan with rule-based guidance, then writes the public HTML and [provenance metadata](sample-report-provenance.json). Keep build outputs outside source uploads.

## Interpretation

The synthetic fixture contains deliberately risky patterns. Its scores and counts are demonstrations, not claims about real-project accuracy. See the [DVWA reference scan](benchmarks/DVWA-v0.8.2.md) for a separate pinned external-project run and reviewed limitations.
