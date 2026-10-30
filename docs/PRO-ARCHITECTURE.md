# Community and Pro Architecture Boundaries

## Repository separation

Community is the public MIT repository. Pro is distributed separately from a private repository containing shared engine code and private licensing, premium-rule, PDF, scheduling, history-review, and SBOM packages.

Pro source, signing secrets, license generators, customer activation data, and private product identifiers must not enter Community uploads.

## Current commercial model

Observer Pro is **one annual all-access subscription at $89/year**. The subscription covers all current Pro capabilities; internal feature gates do not represent separately purchasable products.

[Get Observer Pro](https://observerly1.gumroad.com/l/observer-pro-offline-code-audit)

The private Pro implementation must route current purchase actions to this destination. Updating Community does not itself change a previously distributed Pro binary.

## Feature boundaries

Community retains local scans, core rules, rule-based guidance, local dashboard history and deltas, exports, CI, baselines, changed-code scans, and external automation.

Pro adds premium framework rules, professional PDF reporting, integrated recurring scans, Git-history secret review, CycloneDX SBOM export, and a local HMAC attestation companion.

See the [edition comparison](FREE-VS-PRO.md).

## Activation and lifecycle

The v0.8.2 Pro release documentation describes annual activation, machine-bound verification, local expiry checking, and renewal handling. Initial activation requires an online check; cached activation must not be described as perpetual subscription access.

Pro lifecycle behavior belongs to the private repository and requires separate implementation validation. This Community documentation update does not claim to have completed that private implementation audit.

## Legacy compatibility

Stable internal feature identifiers and legacy-license readers may remain for compatibility with existing purchases. They are not a public sales catalog.

Do not remove prior customers' purchased rights, change signing formats, or invalidate cached records as a side effect of updating sales copy.

## Security boundaries

- Private signing material must never be distributed.
- Public verification keys can be distributed where required.
- Feature access must be enforced in execution paths, not only in browser controls.
- A client-side HMAC companion is local tamper evidence, not independent identity or certification.
- Core offline scanning and online license lifecycle requirements must be explained separately.
