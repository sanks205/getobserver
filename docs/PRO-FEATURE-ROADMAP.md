# Proposed Pro Feature Roadmap

These are evaluations, not committed features.

## Professional audit comparison

- **Problem:** consultants need to explain remediation progress between two assessments.
- **Overlap:** Community already stores scan history and issue deltas.
- **Pro value:** stable finding matching, new/resolved/persistent/severity-changed sections, management summary, and professional PDF export.
- **Buyer:** consultants, agencies, security leads.
- **Dependencies:** snapshot schema/versioning, deterministic fingerprints, PDF comparison model.
- **Complexity:** medium-high; false matching would damage trust.
- **Privacy:** local only; no telemetry required.
- **Testing:** migration fixtures, rename/move cases, severity changes, large reports.
- **Validation needed:** yes; interview at least five target users before implementation.

## Multi-project client reporting

- **Problem:** agencies cannot summarize risk across several applications for one client.
- **Overlap:** Community dashboard lists multiple projects but has no client model or consolidated deliverable.
- **Pro value:** local client grouping, portfolio risk summary, remediation status, consolidated export.
- **Buyer:** agencies and fractional security teams.
- **Dependencies:** client/project metadata, aggregation, permissions assumptions, report rendering.
- **Complexity:** high.
- **Privacy:** client metadata remains local; exports require explicit user action.
- **Testing:** aggregation correctness, duplicate projects, deletion, large portfolios, redaction.
- **Validation needed:** yes, before schema design.

## Custom audit templates

- **Problem:** professional assessors need repeatable methodology and client-specific presentation.
- **Overlap:** Pro PDF already accepts identity metadata and branding.
- **Pro value:** reusable local profiles, optional sections, methodology text, presentation settings.
- **Buyer:** repeat auditors and agencies.
- **Dependencies:** versioned declarative schema and strict input validation.
- **Complexity:** medium; arbitrary executable templates should be avoided.
- **Privacy/security:** prevent local file disclosure, script execution, and unsafe links.
- **Testing:** schema compatibility, malformed profiles, pagination, deterministic rendering.
- **Validation needed:** yes; collect real sanitized templates first.

## Recommended order

Validate Professional Audit Comparison first. It builds on existing snapshots and PDF strengths while adding value beyond Community deltas. Do not implement any candidate until approved.
