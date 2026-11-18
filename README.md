# tlscheck

[English](README.md) | [繁體中文](README.zh-TW.md)

tlscheck is a Go CLI for diagnosing remote TLS certificates and checking local certificates and private-key pairs. It reports handshake facts separately from system trust and keeps local keys out of remote connections.

## Build and start

Requires Go 1.27.0 or newer. Development validation currently uses Go 1.27.4 on macOS arm64. Run these commands from the repository root; GNU Make is optional.

macOS:

```sh
go build -o bin/tlscheck ./cmd/tlscheck
./bin/tlscheck
./bin/tlscheck --version
```

Windows, using PowerShell:

```powershell
go build -o bin/tlscheck.exe ./cmd/tlscheck
.\bin\tlscheck.exe
.\bin\tlscheck.exe --version
```

No arguments prints help and exits with 0. An unmodified development build reports version `development` and source commit `unknown`. Use `--version` alone; unknown flags, including `--help` and `--language`, or mixing `--version` with targets returns 2. Prefix a local filename beginning with `-` with `./` or `.\`.

Source builds are available. Four-target local snapshot packaging and macOS arm64 manual archive installation are validated. Published release archives, Homebrew/Scoop installation, signing, notarization, and Windows native execution remain unverified. See [installation and release maintenance](docs/releasing.md) for pending package information and verification boundaries.

## Check targets and files

Examples below require your own local files or access to the indicated service. Public-network examples are illustrative, not installation or connectivity evidence.

macOS:

```sh
./bin/tlscheck example.com 'https://example.com:8443/'
./bin/tlscheck 192.0.2.10 '[2001:db8::1]:443' '例子.測試'
./bin/tlscheck ./local/site.pem ./local/intermediate.pem ./local/site.key
./bin/tlscheck ./local/root.cer
./bin/tlscheck ./local/site.pem example.com ./local/site.key
./bin/tlscheck ./local/missing.pem
printf '%s\n' "$?"
```

Windows PowerShell:

```powershell
.\bin\tlscheck.exe example.com 'https://example.com:8443/'
.\bin\tlscheck.exe 192.0.2.10 '[2001:db8::1]:443' '例子.測試'
.\bin\tlscheck.exe .\local\site.pem .\local\intermediate.pem .\local\site.key
.\bin\tlscheck.exe .\local\root.cer
.\bin\tlscheck.exe .\local\site.pem example.com .\local\site.key
.\bin\tlscheck.exe .\local\missing.pem
$LASTEXITCODE
```

The IP examples use documentation addresses and need replacement with reachable targets. The missing-file example returns 2. A site certificate and key can match while trust verification still fails.

An existing file takes precedence over network interpretation. Missing explicit paths and missing `.pem`, `.cer`, `.crt`, or `.key` filenames are file errors, not network targets. Only regular files are accepted. Other inputs are interpreted as DNS names, Unicode IDN names normalized through IDNA, IPv4, IPv6, `localhost`, or single-label hostnames. IPv6 zone identifiers are unsupported.

HTTPS URLs must use standard `https://`; the default port is 443 and explicit ports must be integers from 1 to 65535. A trailing slash is accepted. URL user information, path, query and fragment are automatically discarded before connection and reporting. Other URL schemes are unsupported. Avoid putting credentials in commands: your shell history can retain the original input even when the report removes it.

| Local object | Supported formats | Encodings |
|---|---|---|
| X.509 certificate, including CA | Certificate | PEM, DER |
| RSA private key | PKCS#1, PKCS#8 | PEM, DER |
| ECDSA private key | SEC1, PKCS#8; NIST P-224/P-256/P-384/P-521 | PEM, DER |
| Ed25519 private key | PKCS#8 | PEM, DER |

Multiple PEM blocks are accepted. Valid objects are retained when another block is damaged or unsupported; the final exit code is 2. Encrypted private keys are unsupported, are not decrypted, and do not trigger a password prompt. PKCS#12/PFX and other key algorithms are not supported.

## Language configuration

Only `language` in `config.json` selects the UI language. There are no language flags or language environment-variable overrides, and the working directory is not searched. The platform configuration directory itself is resolved by `os.UserConfigDir()`.

| Platform | Configuration file |
|---|---|
| macOS | `~/Library/Application Support/tlscheck/config.json` |
| Windows | `%AppData%\tlscheck\config.json` |

The application never creates, modifies or deletes this file. To choose a language, manually create the directory and file in an editor. Save UTF-8 without BOM and select one of these complete JSON objects:

```json
{"language":"en"}
```

```json
{"language":"zh-TW"}
```

```json
{"language":"zh-CN"}
```

| Condition | Behavior |
|---|---|
| File absent, `language` absent, or empty string | English, without a warning |
| Directory resolution/read/stat/close error or nonregular file | English warning and fallback |
| More than 64 KiB of actual data | English warning and fallback |
| Invalid JSON/UTF-8, nonobject root, trailing data | English warning and fallback |
| Nonstring value, including `null`, unknown/duplicate key | English warning and fallback |
| Any value other than exact `en`, `zh-TW`, `zh-CN` or empty string | English warning and fallback |

Configuration warnings go to stderr and do not alone change the exit code. Missing translations fall back to English. Hostnames, paths, algorithms and public certificate values retain their original text; unsafe terminal controls and URL additions are removed for display.

## Trust and key pairing

All local files contribute to a common certificate/key collection. Remote targets are checked independently and sequentially. Local keys are not sent for client authentication and are never paired with remote certificates.

Trust uses the operating system trust store. A root supplied as input is only a candidate issuer; it does not become trusted automatically. The peer-presented chain describes what the server sent, while a verified chain exists only after successful trust verification. A completed handshake or a valid issuer signature alone does not establish trust. Local certificate checks have no hostname input, so name validation is reported as not performed.

A standalone CA must pass its applicable validity/CA constraints and establish a trusted system path. No trusted path is a check failure (1); inability to access or execute the trust machinery is an execution error (2). On macOS, standalone CA verification uses the built-in `/usr/bin/security` with CA/basic X.509 policy and network issuer fetching disabled, followed by Go chain checks. Only certificates enter protected temporary files; private keys do not. Platform policies may add checks; tlscheck does not actively fetch AIA issuers or perform CRL/OCSP checks itself.

Pairing compares complete standardized public-key DER, not algorithm names or key sizes. All matching relationships are listed. Duplicate certificate sources are preserved; keys remain separate by source. A key alone or certificates alone do not require pairing. When keys and site certificates coexist, every key and site certificate must have a match. CA certificates may match a key but do not require one; CA-plus-key without a site does not require full coverage. Invalid keys cannot produce successful matches.

RSA uses standard validity checks. ECDSA checks scalar range, curve membership and consistency between scalar and public point. Ed25519 checks length and seed-derived consistency. Checks cover the parsed representation, not source fields discarded or normalized by the parser. They do not establish randomness quality, secrecy, cryptographic strength or every security property. Reports expose public metadata, not private-key bytes.

## Results and limits

| Exit code | Meaning |
|---|---|
| 0 | Applicable checks passed, help/version succeeded, or only expiry/configuration warnings |
| 1 | Certificate/key/trust/pairing check failure |
| 2 | Input, parsing, unsupported format, connection, timeout, cancellation or output error |

The highest severity wins: 2 > 1 > 0. Individual input failures do not stop remaining inputs; invalid CLI flag combinations are rejected before checking. States are passed, failed and not performed. Not performed is neither a pass nor an independent failure. Summary counts describe the displayed checks, not the number of input files.

Full reports and verification failures go to stdout. Configuration warnings and execution diagnostics go to stderr; an execution error can appear in both the report and the diagnostic stream.

Each local certificate/key file is limited to 10 MiB of actual reads. Each remote target has a shared 10-second DNS/TCP/TLS handshake deadline, not a separate 10 seconds per stage. Platform trust operations can have platform-specific cancellation limits. Dates use UTC; remaining days are floored, so a recently expired certificate can show -1 day. A nonexpired certificate expiring within 30 × 24 hours produces a warning; that warning alone does not change the exit code.

Output is plain text without color or animation. tlscheck does not request, renew or deploy certificates, inspect web content, scan cipher suites, decrypt keys, or manage system trust. Planned initial release artifacts are unsigned and unnotarized; no signed/notarized distribution is currently verified.

## Development and maintenance

From the repository root, on either platform with Go installed:

```text
go test ./...
go test -race ./...
go vet ./...
git diff --check
```

Race detection requires a supported native Go toolchain and its C toolchain. Tests create synthetic certificates and loopback TLS servers; they do not depend on public services or add roots to the system store. Windows-native tests and installation remain unverified. macOS arm64 native execution and Windows amd64 cross-builds have been checked; cross-building is not a Windows runtime test.

Optional GNU Make targets are `make help`, `make build`, `make test`, `make vet`, `make check`, and `make fmt`. `make build` writes `bin/tlscheck`; Windows users should use the explicit PowerShell build above for the `.exe` suffix. Keep generated binaries in `bin/`, release outputs in `dist/`, and private local files in ignored `local/`. Certificate/key extensions are not globally ignored, allowing intentional synthetic fixtures.

See the bilingual [release maintenance guide](docs/releasing.md) for packaging, upgrade, verification and retry status. When changing behavior, update both README files and corresponding maintenance instructions together.

## License

[Apache License 2.0](LICENSE). The license retains its official English text.
