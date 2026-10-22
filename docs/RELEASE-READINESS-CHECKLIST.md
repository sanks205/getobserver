# Edition Release Readiness Checklist

## Community
- [ ] `gofmt` reports no substantive formatting changes.
- [x] `go test ./...` passes.
- [x] `go vet ./...` passes.
- [ ] CLI version, doctor, help, HTML, JSON, CSV, SARIF, baseline, gate, diff, and attestation smoke checks pass.
- [ ] Dashboard starts on localhost and can scan, list history, and open a report.
- [x] Community tree contains no Pro packages, private key material, Gumroad product IDs, or key generator.

## Pro
- [x] `go test ./...` passes.
- [x] `go vet ./...` passes.
- [x] Product-to-entitlement mapping tests pass.
- [x] Invalid/malformed licenses fail closed.
- [x] Individual PDF, scheduling, and premium-rule product mappings remain isolated.
- [x] All-Access maps to all three current sellable features.
- [ ] Legacy signed-key loading remains covered or manually verified with a non-production fixture.
- [ ] PDF, schedule, premium rules, history, SBOM, and signed-attestation smoke tests pass.
- [ ] Unlicensed attempts show useful guidance and do not execute paid behavior.
- [x] Community synchronization check passes.

## Documentation and distribution
- [x] README, PRODUCT, edition matrix, activation guide, and Gumroad drafts agree.
- [x] All four Gumroad URLs and approved prices are unchanged and reachable.
- [x] Markdown internal links resolve.
- [x] Example commands match current CLI help.
- [x] Framework claims match the 24-rule tested inventory.
- [x] No new benchmark claim is published; comparison claims require the evidence checklist.
- [ ] Community and Pro binaries report the intended version.
- [ ] Checksums match exact release artifacts and package manifests.
- [ ] Generated binaries, reports, keys, caches, and local acceptance artifacts are excluded from source uploads.
