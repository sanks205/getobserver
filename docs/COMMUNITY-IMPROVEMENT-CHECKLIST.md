# Community Documentation, Trust, and Detection Evidence Checklist

Updated: 2026-10-31. Status distinguishes local implementation from publication. None of the remaining work is inherently impossible.

## Completed documentation fixes already uploaded

- [x] Remove the problematic promotional HTML from the README.
- [x] Repair the broken privacy sentence.
- [x] Put SHA-256 verification beside binary downloads.
- [x] Verify all six published v0.8.2 binaries and update package manifests.
- [x] Remove obsolete package purchases and one-time pricing from current Community pages.
- [x] Use one annual all-access Observer Pro subscription at $89/year and the current URL.
- [x] Remove misleading remediation-provider claims; guidance is deterministic and local.
- [x] Remove internal architecture, phase roadmap, old repository tree, and hosted-service plans from the README.

## Implemented locally in this follow-up

- [x] Align the landing-page lead with client and legacy codebase audits.
- [x] Generate a real, sanitized, interactive report from public first-party fixtures.
- [x] Replace sample editor links with pinned public-source links.
- [x] Add sample provenance and a regeneration script.
- [x] Add README and landing-page links to the prepared sample report.
- [x] Inventory 54 distinct built-in analyzer rule IDs from Go syntax.
- [x] Add an inventory freshness check to Community CI.
- [x] Document language/framework signals separately from analysis coverage.
- [x] Explain A-E severity grades, numerical scores, CWE/OWASP tags, and limits.
- [x] Fix long remediation text widening the report at a 390px viewport.
- [x] Remove the report tooltip's unsupported standards-alignment claim.
- [x] Run a published v0.8.2 binary against a pinned DVWA source snapshot.
- [x] Record input/tool hashes, configuration, sanitized finding locations, and repeatable commands.
- [x] Review selected detections, non-executable text, guarded paths, and missed patterns.
- [x] Prepare complete Homebrew tap and Scoop bucket files locally.
- [x] Document signing/notarization prerequisites without claiming unsigned builds are signed.

## Validation and publication

- [x] Finish follow-up tests, inventory checks, static document checks, and sample browser checks.
- [ ] Upload the reviewed follow-up Community files.
- [ ] Confirm GitHub Pages serves sample-report.html and both sample links work.
- [ ] Publish and test the separate homebrew-observer repository.
- [ ] Publish and test the separate scoop-observer repository.
- [ ] Rebuild and release changed report templates with new checksums in the next patch release.

## Pending signing and distribution work

- [ ] Configure an authorized Windows publisher-signing identity and release runner.
- [ ] Sign, timestamp, and verify Windows artifacts.
- [ ] Configure an authorized Apple Developer identity, notarization access, and macOS runner.
- [ ] Sign/notarize the chosen macOS distribution format and verify on a clean Mac.
- [ ] Generate final checksums after signing and update package manifests.
- [ ] Define release provenance/signature verification if adding Linux or cross-platform attestations.

These depend on external account identities, publishing, and platform validation. Local documentation cannot substitute for them. See [distribution trust](DISTRIBUTION-TRUST.md).

## Follow-up detection work identified by the reference scan

- [ ] Reduce dangerous-function matches in non-executable PHP/HTML prose.
- [ ] Evaluate detection of PHP SQL string interpolation beyond concatenation.
- [ ] Evaluate buffered HTML output for reflected-XSS detection.
- [ ] Improve context around guarded command execution and sanitized input.
- [ ] Review labeled vulnerable and safe corpora independently before measuring precision or recall.
- [ ] Expand evidence beyond one PHP-focused reference project.

These are feasible analyzer improvements requiring regression fixtures and a separate patch review. They were not silently folded into the published v0.8.2 benchmark.

## Claims that should not be made

- [x] Do not equate grades or OWASP tags with certification or compliance.
- [x] Do not call finding totals verified vulnerabilities.
- [x] Do not infer an overall false-positive rate from a selected sample.
- [x] Do not claim a tap, bucket, signature, notarization, or public sample URL is live before publication and verification.

## References

- [Public sample](SAMPLE-REPORT.md)
- [Rule inventory](RULE-INVENTORY.md)
- [Coverage](COVERAGE.md)
- [Rating methodology](RATING-METHODOLOGY.md)
- [DVWA reference run](benchmarks/DVWA-v0.8.2.md)

## Validation record

The proposed files were overlaid on an isolated copy of GitHub main at 4a9c0eed5610fbdc939087010982bf7061498204. Tests, vet, inventory freshness, and a source build passed there. Browser checks passed for the landing page and report at 1440px and 390px, including filters, theme, public source links, details, and print-state restoration. Two published-binary DVWA runs produced identical normalized findings. Static document checks and packaging checks passed. Nothing was published in this follow-up.
