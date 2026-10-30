# Community Release Readiness Checklist

Updated for the v0.8.2 documentation and current annual Pro offer.

Unchecked items require evidence for the exact upload or release. Earlier test results do not automatically validate later changes.

## Community documentation

- [x] README, product overview, landing page, edition comparison, and marketing copy agree.
- [x] Current Pro offer is one annual all-access subscription at $89/year.
- [x] Current purchase links use https://observerly1.gumroad.com/l/observer-pro-offline-code-audit.
- [x] No obsolete purchase URLs or separate add-on prices remain in current pages.
- [x] Historical reports are clearly marked as superseded.
- [x] Remediation is described as deterministic, rule-based, and local.
- [x] Privacy wording distinguishes offline scanning from optional network features and Pro activation.
- [x] Markdown fences, tables, internal links, and HTML structure pass sanity checks.
- [x] No unsupported benchmark, compliance, signing, tap, or bucket claim is added.

## Release metadata and distribution

- [x] VERSION agrees with the intended release.
- [x] Package manifests point to published v0.8.2 binaries.
- [x] Manifest checksums match the published checksum file and GitHub asset digests.
- [x] Downloaded release assets match their SHA-256 digests.
- [x] Unsigned-binary status and verification instructions appear beside downloads.
- [ ] New builds are published separately when changing embedded report templates.
- [ ] Existing release asset checksums are not reused for newly rebuilt binaries.

## Functional validation

- [x] Community go test ./... passes; report rendering is covered by the offline smoke check.
- [x] CLI version, help, and offline report generation smoke checks pass.
- [x] Report retains Community Edition branding and the current upgrade destination.
- [ ] Broader Community tests and vet pass where required for a new binary release.
- [ ] Dashboard and landing-page rendering are reviewed on desktop and mobile.

## Upload boundaries

- [x] Upload contains only the reviewed Community file list.
- [x] Pro source, license data, private identifiers, signing material, and generators are excluded.
- [x] Local binaries, logs, caches, backups, and generated validation reports are excluded.
- [x] Unrelated local changes are excluded.
- [x] Newer GitHub files are preserved rather than replaced with older local copies.

## Deferred private Pro work

- [ ] Audit private application purchase URLs and customer documentation.
- [ ] Validate annual activation, machine binding, expiry, renewal, and legacy compatibility.
- [ ] Run the private Pro synchronization and release checks.

## Validation record

On 2026-10-31, Community go test ./..., a source build, version/help checks, and an enforced-offline PHP-demo report passed. All six published v0.8.2 binary checksums matched SHA256SUMS.txt and GitHub asset digests. Static document checks passed. Browser review, release-wide vet, and publication of rebuilt binaries remain separate checks.
