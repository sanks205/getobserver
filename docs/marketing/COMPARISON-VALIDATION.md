# SonarQube Comparison Validation

## Current conclusion

A marketing image reportedly compares finding counts for Monica, WordPress, Juice Shop, and FinDocAnalyzer. No source dataset, command transcript, tool configuration, version manifest, or manual validation record was found in the Community or Pro repositories. The counts are therefore **not reproducible from repository evidence** and must not be presented as proof that either tool is more accurate or secure.

## Evidence required before publication

For each project record:

- Repository URL and immutable commit SHA (or private-project version identifier).
- Included/excluded paths, generated/test/vendor handling, and total files scanned.
- Observer edition/version, exact command, enabled optional engines, rule configuration, and network mode.
- SonarQube edition/version, quality profile, plugins, language analyzers, exclusions, and scan command.
- Raw machine-readable outputs retained privately where licensing permits.
- Normalized categories and severity mapping; raw counts must not be compared without taxonomy notes.
- Duplicate handling and whether dependency, secret, configuration, and code findings are in scope.
- A manually reviewed sample with true positive, false positive, uncertain, and out-of-scope labels.
- Known limitations and reviewer identity/date.

## Publication rules

Use wording such as “the tools reported different scopes and categories under this configuration.” Do not claim superior accuracy from a smaller or larger count. Do not use production secrets or proprietary code in public evidence. Re-run the benchmark for material rule or version changes.

## Verification checklist

- [ ] All four source revisions are available and legally usable.
- [ ] Exact Observer and SonarQube versions/configurations are recorded.
- [ ] Commands run from clean environments are captured.
- [ ] Scope and exclusions are equivalent or differences are explicit.
- [ ] Results are normalized by category before comparison.
- [ ] At least a representative sample is manually adjudicated.
- [ ] Infographic wording is reviewed against the evidence.
- [ ] Supporting methodology is linked from any published image.
