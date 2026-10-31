# Distribution Trust and Publishing Checklist

Current binaries are unsigned. Matching SHA-256 values establish consistency with the published release checksum, not verified publisher identity.

## Completed interim protection

- Checksum commands appear beside README downloads.
- All six published v0.8.2 binaries were downloaded and matched against SHA256SUMS.txt and GitHub asset digests.
- Package definitions use the exact v0.8.2 release assets and their matching checksums.
- Unsupported raw-formula installation commands were removed from the README.
- Sample reports use public synthetic fixtures and contain no workstation paths.

## Homebrew tap

Prepared layout: a repository named homebrew-observer containing Formula/observer.rb.

After that repository exists, the intended installation is:

~~~sh
brew tap sanks205/observer
brew install sanks205/observer/observer
observer version
brew test sanks205/observer/observer
~~~

Do not advertise this as available until the repository is published and tested on supported macOS and Linux architectures. Use [scripts/prepare-package-repositories.py](../scripts/prepare-package-repositories.py) to prepare complete repository files locally.

[Homebrew tap documentation](https://docs.brew.sh/Taps) explains the repository naming and fully qualified formula convention.

## Scoop bucket

Prepared layout: a repository named scoop-observer containing bucket/observer.json.

After publishing and validating the bucket:

~~~powershell
scoop bucket add observer https://github.com/sanks205/scoop-observer
scoop install observer/observer
observer version
~~~

A checked-in application manifest alone is not a hosted bucket. See the [Scoop bucket documentation](https://github.com/ScoopInstaller/Scoop/wiki/Buckets).

## Windows signing

Required external input: a suitable publisher code-signing identity and access to its signing service or certificate/key mechanism. No credentials were requested from local stores or added to the repository.

Release work remains:

1. Configure signing on an appropriate Windows runner using protected credentials.
2. Sign each Windows artifact and apply a trusted timestamp.
3. Verify the final signature using SignTool's Authenticode policy.
4. Generate checksums from the final signed bytes.
5. Update package manifests and publish the exact verified files.

Reference: [Microsoft SignTool documentation](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool).

## macOS signing and notarization

Required external input: an appropriate Apple Developer signing identity and authorized notarization credentials, plus a macOS release runner.

Release work remains:

1. Sign the CLI with the chosen Developer ID configuration and validate it.
2. Package it in a supported distribution container and submit it for notarization.
3. Inspect the notarization result and verify distribution behavior on a clean Mac.
4. Use a supported container when stapling is required; do not assume a ticket can be stapled directly to a raw CLI executable.
5. Generate checksums from the final distribution bytes and update manifests.

Reference: [Apple notarization documentation](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).

## Release provenance

A future release can additionally publish attestations or detached signatures. That requires defining the signing identity and verification process. It is not equivalent to an operating-system-trusted signature or notarization.

Rebuild changed report templates in the next patch release rather than silently replacing existing v0.8.2 assets. New binary bytes require new checksums.

## Status

The tap and bucket are prepared locally but are not claimed as published. Signing and notarization are pending the external identities and platform validation above. None of these is technically impossible; they are release and account setup tasks.
