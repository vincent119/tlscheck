# tlscheck

tlscheck checks remote TLS certificates, local certificate chains, and certificate/private-key pairs. Use it to investigate a TLS failure, check expiry before a deployment, or confirm that a server is presenting the certificate you expected.

[![CI](https://img.shields.io/github/actions/workflow/status/vincent119/tlscheck/ci.yml?branch=main&label=CI&logo=githubactions)](https://github.com/vincent119/tlscheck/actions/workflows/ci.yml)
[![Go vulnerability scan](https://img.shields.io/github/actions/workflow/status/vincent119/tlscheck/go-vulnerability.yml?branch=main&label=Go%20vulnerability%20scan&logo=githubactions)](https://github.com/vincent119/tlscheck/actions/workflows/go-vulnerability.yml)
[![Go](https://img.shields.io/badge/Go-1.27.0%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-vincent119%2Ftlscheck-181717?logo=github)](https://github.com/vincent119/tlscheck)
[![Stars](https://img.shields.io/github/stars/vincent119/tlscheck?style=flat&logo=github)](https://github.com/vincent119/tlscheck/stargazers)

[English](README.md) | [繁體中文](README.zh-TW.md)

[Changelog](CHANGELOG.md)

The default report is a table. JSON, offline HTML, and Markdown are also available, with messages in English, Traditional Chinese, or Simplified Chinese. Remote checks keep handshake facts separate from trust verification and never use local private keys for client authentication.

## Installation

The package commands below are the intended installation interface. **Homebrew/Scoop packages are not published or verified yet. Use these commands after the packages are published.** Download macOS/Windows binaries and `checksums.txt` from [GitHub Releases](https://github.com/vincent119/tlscheck/releases). For now, [build from source](#build-from-source). Archive checks and release preparation are in the [release guide](docs/releasing.md).

### Windows (Scoop)

```powershell
scoop bucket add tlscheck 'https://github.com/vincent119/scoop-bucket'
scoop install tlscheck/tlscheck
tlscheck --version
```

### macOS (Homebrew)

```sh
brew tap vincent119/tap
brew install vincent119/tap/tlscheck
tlscheck --version
```

### Linux

No Linux package or release archive is configured yet. The current Homebrew Formula is macOS-only, so it cannot be used as a Linuxbrew install. See [source builds](#build-from-source) for the available build instructions.

## Everyday checks

The examples use the installed `tlscheck` command. For a source build, substitute `./bin/tlscheck` on macOS/Linux or `.\bin\tlscheck.exe` on Windows. Remote targets need network access, and local paths must refer to your own files.

```sh
tlscheck example.com 'https://example.com:8443/'
tlscheck --local ./local/site.pem --local ./local/chain.pem --local ./local/site.key
tlscheck --local ./local/site.pem --detail full -L zh-TW
tlscheck --remote example.com --expiry-warning-days 14 --fail-on-expiry-warning
```

`summary` is the default table detail. It keeps failures, warnings, and verification limits visible while reducing repeated successful checks. Use `--detail full` for every detail and diagnostic code. Detail selection affects only table output.

Expiry warnings start at 30 days. A warning alone leaves the exit code unchanged. Add `--fail-on-expiry-warning` to make a warning fail the check with exit code 1, including warnings on parsed CA and intermediate certificates. Setting `--expiry-warning-days 0` disables this policy and expiry warnings. Expired-certificate checks still run.

Existing files take precedence during automatic input detection. Use `--remote` to force a network target or `--local` to force a file. For a filename beginning with `-`, prefix it with `./` or `.\`, or put it after `--`.

Targets accept DNS names, Unicode domains through IDNA, IPv4, IPv6, `localhost`, and single-label hostnames. IPv6 with a port uses brackets, such as `[2001:db8::1]:8443`. Zone identifiers are rejected. These IP examples are documentation addresses and must be replaced with reachable targets.

URLs require standard `https://`. The default port is 443, and an explicit port must be in 1–65535. User information, paths, queries, and fragments are removed before connecting and reporting. Shell history can still retain the original command, so keep credentials out of target URLs.

## Batch targets and deployment checks

A targets file is UTF-8, with one remote target per line. Blank lines and whole-line `#` comments are ignored. Entries are target values, not shell commands or CLI flags.

```text
# targets.txt
example.com
https://example.org:8443/
```

```sh
tlscheck --targets-file ./targets.txt
tlscheck --targets-file ./targets.txt --concurrency 4 -f json
tlscheck --targets-file ./targets.txt --connect-ip 0=192.0.2.10 --compare-cert 0=./local/expected.pem
tlscheck --remote example.com --compare-cert 0=./local/expected.pem
```

Remote checks run sequentially by default. With `--concurrency` set to 1–32, reports retain input order even when checks finish in a different order, including runs that mix repeated `--targets-file` lists with direct remote or local inputs.

Mappings use `INDEX=VALUE`. Indices start at 0 after every list has been expanded, and local inputs and invalid nonempty target lines also occupy an index. Repeated hostnames remain separate occurrences. Split a mapping at its first `=`, so candidate paths can contain spaces, further equals signs, or Windows drive letters.

`--connect-ip INDEX=IP` changes the connection address for that target while retaining the original port and using the original hostname for both SNI and name verification. It skips DNS and does not fall back to another address. The value must be a plain IPv4 or IPv6 literal, without brackets, a zone, or a port. Reports distinguish the requested IP from the observed peer address.

`--compare-cert INDEX=PATH` compares the candidate with the leaf certificate from the same TLS handshake. It compares complete certificate DER. Renewed certificates differ even with the same public key. A candidate can be a PEM/DER certificate or a PEM chain with exactly one distinct non-CA certificate after DER deduplication, and it must contain no private keys, damaged blocks, other containers, or additional leaves. Candidate certificates do not enter the local pairing collection or the trust store.

A match can coexist with a trust failure. Different certificates return 1, while a connection failure returns 2 and leaves the comparison unperformed if no leaf was observed. Duplicate mappings, local or invalid target indices, and out-of-range indices are rejected before network checks.

## Local files and PFX passwords

| Object | Formats | Encoding |
|---|---|---|
| X.509 certificate, including CA | Certificate or PEM chain | PEM, DER |
| RSA private key | PKCS#1, PKCS#8 | PEM, DER |
| ECDSA private key | SEC1, PKCS#8, with NIST P-224/P-256/P-384/P-521 | PEM, DER |
| Ed25519 private key | PKCS#8 | PEM, DER |
| PKCS#7 / P7B | Certificate-only SignedData | PEM, DER |
| PKCS#12 / PFX | One private key with certificates, or certificates only | DER |

Ordinary PEM parsing retains valid objects when another block is damaged or unsupported, and returns 2. PFX decoding is atomic, so a failed container does not contribute partial keys or certificates. Standalone encrypted private-key files are unsupported. PFX decryption is limited to the supported container format.

```sh
tlscheck --local ./local/chain.p7b
tlscheck --local ./local/identity.pfx --ask-password 0
tlscheck --local ./local/identity.pfx --password-file '0=./local/pfx-password.txt'
```

A PFX with no password binding is tried with an empty password. `--ask-password INDEX` reads without echo and requires a terminal. There is no plaintext password flag or password environment variable. Password files must be regular files with restricted permissions, and cannot alias inputs, candidate files, target lists, or configuration. On Unix, the current user must own the file with owner-only permissions such as `0600`. Windows accepts owners and allowed ACL entries only for the current user, SYSTEM, or Administrators.

Password files contain UTF-8 without BOM. One final LF or CRLF is removed, while other whitespace is preserved. Passwords are limited to 4 KiB and BMP characters, excluding NUL, and non-BMP characters such as emoji are rejected. PFX supports PBES2 with PBKDF2-HMAC-SHA-256 and AES-256-CBC, plus SHA-256 MAC. Legacy RC2/3DES and SHA-1 profiles are unsupported. Use a modern PFX export if an older container is rejected.

## Options

| Option | Short | Default or purpose |
|---|---|---|
| `[target-or-file]...` | | Automatic detection, existing files first |
| `--remote TARGET` | `-r` | Remote input, repeatable |
| `--local PATH` | `-l` | Local file, repeatable |
| `--targets-file PATH` | | Target list, repeatable |
| `--concurrency N` | | 1, range 1–32 |
| `--connect-ip INDEX=IP` | | Per-target connection address, repeatable |
| `--compare-cert INDEX=PATH` | | Per-target expected certificate, repeatable |
| `--password-file INDEX=PATH` | | Protected PFX password file, repeatable |
| `--ask-password INDEX` | | Hidden PFX password prompt, repeatable |
| `--language CODE` | `-L` | One-run `en`, `zh-TW`, or `zh-CN` override |
| `--format FORMAT` | `-f` | `table`, `json`, `html`, or `markdown`, default `table` |
| `--detail LEVEL` | | `summary` or `full`, default `summary`, table only |
| `--output PATH` | `-o` | `-` for stdout |
| `--overwrite` | | Allow replacing an existing report |
| `--timeout DURATION` | `-t` | 10s per target, range 1ms–5m |
| `--expiry-warning-days N` | | 30, range 0–36500, 0 disables warnings |
| `--fail-on-expiry-warning` | | Expiry warnings become failures |
| `--settings` | `-s` | Interactive language and menu theme settings |
| `--help` | `-h` | Show help |
| `--version` | `-V` | Show version |
| `--` | | Treat remaining tokens as positional inputs |

Each repeatable flag takes one value per occurrence. Other flags cannot repeat. Boolean flags take no value, so forms such as `--overwrite=true` are rejected. Help and version can accompany a language override, but cannot mix with execution flags or check targets. `--settings` is a separate action, and `--settings --help` shows its help without opening the menu. No arguments prints help and returns 0.

## Save a report

```sh
tlscheck --local ./local/site.pem -f json -o ./report.json
tlscheck --local ./local/site.pem -f html -o ./report.html --overwrite
tlscheck --local ./local/site.pem -f markdown
```

Select the format with `--format` rather than the filename extension, then use `--output` to write the report to a file and leave stdout empty. The parent directory must exist. Existing files require `--overwrite`, and `~` is not expanded.

Output rejects symlinks, special files, and aliases of protected input, candidate, list, password, or configuration files. Reports are serialized before a temporary-file write and commit. Replacement preserves the required native security attributes or fails safely. Detected destination changes stop the write. The final snapshot check and rename do not provide compare-and-swap protection against arbitrary external writers.

JSON uses `schema_version: 1`, stable codes and identifiers, UTC timestamps, `[]` for empty collections, and `null` for unobserved facts. Messages follow the selected language. New modes add optional `inputs[].list_source`, `remote[].connection`, and `remote[].comparison` fields. They are omitted when unused. Consumers that reject unknown fields must account for these additions. `summary.check_exit_code` covers checks, and a later output failure can still make the process return 2.

HTML is a standalone offline document with no JavaScript or external resources. It does not open a browser. All formats exclude private-key material, and target URL credentials and queries are removed. Per-input counts can overlap because local inputs share checks, so use the global summary for totals.

## Language and completion

Use `-L zh-TW`, `-L zh-CN`, or `-L en` for a one-run override that bypasses configuration reads and leaves the saved language unchanged. Otherwise, the JSON language setting takes precedence over default English. There is no configuration-path or language environment override.

| Platform | Configuration file |
|---|---|
| macOS | `~/Library/Application Support/tlscheck/config.json` |
| Windows | `%AppData%\tlscheck\config.json` |

```json
{"language":"zh-TW","theme":"normal"}
```

`--settings` needs terminal stdin and stderr. Use arrows, Enter, Esc, Ctrl+C, or `t` for theme selection. Only **Save and exit** writes `config.json`. Cancel leaves it unchanged. Themes `normal`, `dark`, and `light` affect the menu only. Repair malformed configurations before saving. Missing settings use English and the normal theme. Invalid or unreadable settings produce a warning on stderr, with safe defaults, and do not alone change the exit code. The configuration limit is 64 KiB.

Load completion in the current shell:

```sh
# Bash, after loading a compatible bash-completion package
source <(tlscheck completion bash)
# Zsh, after compinit
source <(tlscheck completion zsh)
# Fish
tlscheck completion fish | source
```

```powershell
tlscheck completion powershell | Out-String | Invoke-Expression
```

All four shells accept `--no-descriptions` and a language override when generating scripts. Completion performs no certificate checks and reads no configuration or certificate contents. Filename completion may list directories. A PowerShell no-candidate placeholder preserves the word and suppresses filename fallback, with a possible extra space at an empty cursor. Real Windows keyboard Tab, menu saving, and Console restoration still need manual acceptance. Bash/Fish interactive coverage also remains incomplete.

## Trust, results, and limits

Local files share a certificate/key collection. Pairing compares standardized public-key DER and lists all matches. A standalone key or certificate does not require a pair, and remote certificates are never paired with local keys. With keys and site certificates together, every key and site certificate must have a match. CA certificates can match keys but do not require one.

Trust comes from the operating system store. Supplying a root file does not install or trust it. Local certificate checks have no hostname input. Remote checks verify the original target identity, and a completed handshake alone does not establish trust. On macOS, standalone CA verification uses `/usr/bin/security` with network issuer fetching disabled, followed by Go chain checks. tlscheck does not actively fetch AIA issuers or perform CRL/OCSP revocation checks.

| Exit code | Meaning |
|---|---|
| 0 | Applicable checks passed, or help, completion, or settings completed |
| 1 | Certificate, key, trust, pairing, comparison, or enabled expiry-policy failure |
| 2 | Input, parsing, unsupported format, network, timeout, cancellation, or output error |

The highest code wins: 2 > 1 > 0. Warnings alone return 0 unless the expiry failure policy is enabled. Unperformed checks are shown as such. Input errors can leave other valid inputs available, while invalid flags, mappings, and global resource limits stop execution before network checks. Configuration warnings and execution diagnostics use stderr. Reports use stdout unless `--output` selects a file.

| Resource | Limit |
|---|---|
| Local file or comparison candidate | 10 MiB of actual reads per file |
| Target lists | 1 MiB per file, 8 KiB per line, up to 200 files and 8 MiB total |
| Expanded inputs in batch mode | 1,000, including local inputs and invalid target entries |
| Remote target | Shared DNS/TCP/TLS deadline, default 10s |

PFX decoding also bounds ASN.1 depth, bag/certificate counts, decrypted bytes, and derivation work. Dates are UTC, and remaining days are floored. Platform trust APIs have platform-specific cancellation limits.

tlscheck does not generate CSRs, keys, or certificates, renew deployments, scan website content or cipher suites, or manage system trust. Cryptographic checks concern parsed objects and public-key consistency. They do not establish key secrecy or randomness quality.

## Build from source

Go 1.27.0 or newer is required, and CI uses Go 1.27.4. Clone the repository and work from its root:

```sh
git clone https://github.com/vincent119/tlscheck.git
cd tlscheck
```

Windows PowerShell:

```powershell
go build -o bin/tlscheck.exe ./cmd/tlscheck
.\bin\tlscheck.exe --version
.\bin\tlscheck.exe --help
```

macOS / Linux:

```sh
go build -o bin/tlscheck ./cmd/tlscheck
./bin/tlscheck --version
./bin/tlscheck --help
```

Linux amd64/arm64 cross-builds pass, but native Linux execution and installation remain unverified. Linux is outside the macOS/Windows release archive matrix. A plain source build reports `development` and `unknown` unless version metadata is injected. See the [platform status](docs/releasing.md#platform-status).

## Development and verification

```sh
go test ./...
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...
git diff --check
```

The dedicated workflow runs `govulncheck` against the [Go vulnerability database](https://go.dev/security/vuln/database) for all four packaged targets, failing when it reports an applicable reachable vulnerability or cannot complete the scan for the configured Go version and target. Its badge reflects workflow runs, not a guarantee that all security issues have been found. Check the workflow run for the exact source commit being released. No coverage percentage is published.

The [2026-11-20 cross-platform run](https://github.com/vincent119/tlscheck/actions/runs/44693571937), at commit `6394a47`, passed seven jobs covering packaging, native ordinary/race tests, isolated archive installation, configuration preservation, and HTML-script regressions. macOS arm64/amd64 and Windows amd64 have native CI evidence. Windows arm64 has cross-build evidence only. Interactive Console checks, manual HTML/table readability, and real package-manager installation/upgrades remain outside that evidence. Race detection needs a supported native Go and C toolchain.

Use `make help` for optional GNU Make commands. Binaries go in `bin/`, snapshot archives in `dist/`, and private local inputs can go in the ignored `local/` directory. Read the [release maintenance guide](docs/releasing.md) for packaging and retry procedures. This README describes the current CLI. Release archives require version and checksum verification. Signing and notarization are not provided.

## License

[Apache License 2.0](LICENSE).
