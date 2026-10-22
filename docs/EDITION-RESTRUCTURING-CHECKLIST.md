# Community and Pro Restructuring Checklist

Status: `[x]` complete, `[~]` in progress, `[ ]` pending, `[A]` approval required.

## Phase 1 - Verified audit
- [x] Inventory Community CLI, scanners, reports, dashboard, CI, AI, exports, and offline controls.
- [x] Inventory Pro rules, PDF, scheduler, history, SBOM, licensing, activation, and packaging.
- [x] Record implementation status, code ownership, tests, dependencies, and documentation gaps.
- [x] Confirm Pro code is absent from the public Community tree.
- [x] Identify entitlement and compatibility risks before changing production behavior.

## Phase 2 - Canonical edition model
- [x] Define Community as a useful free local audit workflow without artificial limits.
- [x] Define Pro around deeper framework checks, integrated recurring audits, and client-ready deliverables.
- [x] Preserve Community dashboard history, CI, deterministic guidance, exports, baselines, and changed-code scans.
- [x] Document that external cron, Task Scheduler, and CI can automate Community.
- [x] Make the $89 All-Access Bundle the primary upgrade destination without changing prices.

## Phase 3 - Compatible architecture improvements
- [x] Centralize current Gumroad product URLs in the private Pro licensing package.
- [x] Add tests for published product-to-entitlement mappings and malformed signed keys.
- [x] Fix the any-paid-feature check so Scheduled Scans licenses also unlock history and SBOM.
- [~] Added isolated-store cached Gumroad entitlement/tamper tests; legacy signed-license compatibility fixtures remain pending.
- [A] Do not change license formats, keys, signing algorithms, or purchased entitlements without a compatibility proposal.

## Phase 4 - Upgrade experience
- [x] Keep upgrade messages tied to attempted locked features.
- [x] Point generic upgrade actions to the All-Access Bundle.
- [x] Preserve the unobstructed Community dashboard and scan results.
- [ ] Add noninteractive/TTY-aware post-scan upgrade text only after explicit product approval.

## Phase 5 - Documentation and sales clarity
- [x] Create the canonical Free vs Pro matrix.
- [x] Document architecture and entitlement boundaries.
- [x] Draft all four Gumroad listings at current approved prices.
- [x] Create a reproducibility checklist for the SonarQube comparison.
- [x] Restructure README and PRODUCT copy around the canonical matrix.
- [ ] Validate every internal Markdown link in CI.

## Phase 6 - Future Pro discovery
- [x] Evaluate professional snapshot comparison, multi-project client reporting, and custom templates.
- [A] Require user validation and approval before implementing any major candidate.

## Phase 7 - Verification and release
- [x] Run Community and Pro `go test ./...` and `go vet ./...`.
- [x] Run Community-to-Pro synchronization check.
- [~] Run targeted entitlement, PDF, premium-rule, and history tests; schedule and SBOM compile but still need dedicated tests.
- [x] Validate documentation links, product URLs, and example commands.
- [x] Prepare exact Community GitHub and private Pro upload lists.
- [ ] Update release notes only if these changes are included in a new release.
