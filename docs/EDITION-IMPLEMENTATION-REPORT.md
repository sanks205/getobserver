# Edition Restructuring Implementation Report

## Scope

This phase performs the source-led edition audit and compatible first changes. It does not move Community functionality, alter prices, change license formats, or implement proposed major Pro features.

## Implemented

- Added a verified Community/Pro feature inventory and canonical matrix.
- Documented private-repository separation, entitlement IDs, activation behavior, and security limitations.
- Centralized all four published Gumroad URLs in the private licensing package; the bundle is the default upgrade destination.
- Added `license.HasAny()` for features intentionally included with every paid purchase.
- Corrected history/SBOM gating so a Scheduled-Scans-only customer is treated as a paid Pro customer.
- Added tests for Gumroad product mappings, primary/product URLs, and malformed signed-key rejection.
- Drafted accurate Gumroad copy without changing live listings or prices.
- Added comparison-validation and future-feature evaluation documents.

## Deferred or approval-gated

- No existing entitlement, activation protocol, feature ID, or signing format changed.
- No post-scan promotional CLI output was added.
- No major dashboard redesign or new paid feature was implemented.
- Full cached-license compatibility fixtures require isolated-store test seams and remain pending.
- The SonarQube comparison remains unverified until source evidence is supplied.

## Known risks

- Local HMAC integrity is not an independent cryptographic identity because its symmetric material ships in the Pro binary.
- Repository separation is procedural and must be checked before every release.
- History and SBOM are “any paid purchase” benefits rather than first-class entitlements; changing that later would require compatibility review.

## Verification

Completed on 2026-10-17: Community and Pro `go test ./...`, `go vet ./...`, and `git diff --check`; targeted license, premium-rule, PDF, and history tests (schedule/SBOM currently compile without dedicated tests); 63-file Community synchronization; 14-file local Markdown-link validation; and HTTP 200 checks for all four Gumroad product pages. Remaining smoke, artifact, and compatibility checks stay open in `docs/RELEASE-READINESS-CHECKLIST.md`.
