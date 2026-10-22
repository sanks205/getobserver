# Pro Architecture and Entitlement Boundaries

## Repository separation

Community is the public MIT repository. Pro is a private repository containing a synchronized copy of shared engine files plus private packages: `internal/license`, `internal/prorules`, `internal/propdf`, `internal/schedule`, `internal/history`, and `internal/sbom`. `scripts/community-paths.txt` and `scripts/sync-community.ps1` define and check the shared boundary. There are no edition build tags.

## Entitlements

| Stable ID | Product | Primary gates |
|---|---|---|
| `branded-pdf` | Professional PDF | `--pdf`, report metadata/branding, HMAC attestation companion |
| `scheduled-scans` | Scheduled Scans | `observer schedule`, dashboard scheduler |
| `premium-rules` | Premium Rules | automatic `internal/prorules` augmentation |

The All-Access product grants all three. History and SBOM are bundle-level conveniences intentionally available with any active paid entitlement; they are not separate issued feature IDs.

## Activation

Gumroad keys are checked once against known product IDs, then cached locally for offline use. Seller-issued signed keys use Ed25519 and verify offline with an embedded public key. Existing feature IDs and legacy key storage must remain stable. Invalid or modified records fail closed.

## Security boundaries

- The Ed25519 private signing key must never enter either repository or customer package.
- The public verification key is safe to distribute.
- Cached Gumroad integrity and HMAC attestation use a client-side symmetric value. This deters casual editing but cannot be represented as a secret unavailable to a determined binary owner.
- Pro source, key generator, product IDs, and implementation details stay out of public Community releases.
- No entitlement check may exist only in JavaScript; server/CLI execution paths enforce gates.

## Upgrade links

Product URLs are centralized in `internal/license`. `BuyURL` intentionally targets the $89 All-Access Bundle; individual URLs remain available for accurate product-specific documentation.

## Compatibility policy

Do not rename stable feature IDs, rotate signing formats, invalidate cached Gumroad entries, or remove legacy-key reading without a migration plan and regression fixtures. Expanding access to correct a documented entitlement is compatible; restricting an issued entitlement is high risk and requires approval.
