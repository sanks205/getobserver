# Observer v0.8.2

Observer v0.8.2 improves the report presentation, responsive dashboard experience, and Community Edition report branding.

## Highlights

- Added responsive dashboard layout improvements.
- Improved security score trend rendering across screen sizes.
- Improved report detail page layout and readability.
- Added Observer Community Edition watermarking to Community HTML reports.
- Added Observer logo and edition label to printed Community reports.
- Improved report structure for better PDF and print output.
- Added clearer findings presentation and report navigation.
- Removed obsolete `tests/ai_test.go`.
- Updated release and packaging metadata for v0.8.2.
- Preserved the distinction between Community and Pro report capabilities.

## Community Edition

The Community Edition remains open source and provides:

- Offline code auditing.
- Rule-based security and code-quality analysis.
- HTML report generation.
- Printable and PDF-compatible reports.
- Responsive local dashboard.
- CI workflow integration.
- SARIF report generation.
- Community Edition watermarking.

## Pro Edition

Observer Pro is distributed separately through Gumroad and includes additional capabilities such as:

- Deeper audit reporting.
- Professional native PDF reports.
- Advanced report presentation.
- Scheduled scanning.
- Annual license activation.
- Machine-bound license verification.
- Offline license expiry and renewal checks.
- Pro-only packaging and distribution.

Observer Pro is not included in the public Community source repository.

## Compatibility

- Windows, Linux, and macOS release targets remain supported where binaries are available.
- No external cloud service is required for the core audit process.
- Existing audit commands and report generation workflows remain compatible.

## Important Notes

The GitHub Actions audit workflow may fail when the configured quality gate detects findings. This is expected behavior when the scanned repository contains intentional insecure examples, test fixtures, or demo code.

Reports and SARIF artifacts are still uploaded when the workflow is configured to continue after the audit step.

## Upgrade Notes

If upgrading from v0.8.1:

1. Replace the previous Community Edition files with the v0.8.2 files.
2. Review the updated dashboard and report templates.
3. Review the updated workflow behavior if using GitHub Actions.
4. Remove obsolete `tests/ai_test.go` if it still exists in the repository.
5. Regenerate reports after upgrading to use the latest layout and watermark behavior.
