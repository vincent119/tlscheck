# Changelog

[English](CHANGELOG.md) | [繁體中文](CHANGELOG.zh-TW.md)

This file records user-facing changes in published versions. The first release is grouped by capability rather than by development commit.

## [0.1.0] - 2026-11-20

First published release.

### Added

- Remote TLS handshake diagnostics, certificate-chain inspection, system-trust verification, hostname checks, and expiry checks. Targets support DNS, Unicode domains, IPv4, IPv6, and custom ports.
- Local PEM/DER certificate and CA inspection, supported private-key validation, and certificate/private-key pairing without exposing private-key material in reports.
- PKCS#7/P7B certificate containers and PKCS#12/PFX containers containing one private key with certificates, or certificates only. PFX passwords can be read without echo or from a protected file.
- Batch target files with per-target connection-IP and candidate-certificate mappings. Execution is sequential by default, with optional concurrency and reports in input order.
- Deployment checks that connect to a specified IP while retaining the target identity for verification, and compare the remote leaf certificate with a local candidate.
- Expiry warnings, configurable warning days, and `--fail-on-expiry-warning` to return exit code 1 when an expiry warning occurs. Warnings alone do not change the exit code.
- Table, JSON, offline HTML, and Markdown reports. Tables default to `--detail summary`; `--detail full` retains all details. Failures, warnings, and verification limits remain visible in summary mode.
- English, Traditional Chinese, and Simplified Chinese messages; Cobra command completion for Bash, Zsh, Fish, and PowerShell; an interactive language/theme menu that saves only on confirmation.
- Protected report-file output that checks input/configuration aliases and destination changes before committing a write.
- macOS and Windows archives for amd64 and arm64, with a published SHA-256 checksum file.

### Limitations

- Homebrew/Scoop packages are not published or verified. Linux has no release archive. Windows arm64 is cross-built; native execution remains unverified.
- Some keyboard Tab completion, interactive Console restoration, browser cleanup, and visual-layout checks still require manual acceptance. Successful automated tests do not close those items.
- PFX supports the limited modern encryption profile documented in the [README](README.md#local-files-and-pfx-passwords), with BMP-only passwords. Legacy encryption and standalone encrypted private-key decryption are unsupported.
- CSR/private-key/self-signed-certificate generation and custom trust roots are unsupported. Archives are unsigned and unnotarized.

[0.1.0]: https://github.com/vincent119/tlscheck/releases/tag/v0.1.0
