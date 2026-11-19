# tlscheck

[English](README.md) | [繁體中文](README.zh-TW.md)

tlscheck is a Go CLI for diagnosing remote TLS certificates and checking local certificates and private-key pairs. It reports handshake facts separately from system trust and keeps local keys out of remote connections.

## Build and start

Requires Go 1.27.0 or newer. CI has validated Go 1.27.4 on macOS arm64/amd64 and Windows amd64. Run these commands from the repository root; GNU Make is optional.

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

No arguments prints help and exits with 0. An unmodified development build reports version `development` and source commit `unknown`. Use `--help`/`-h` for help and `--version`/`-V` for version information; either can accompany `--language`/`-L`, but cannot mix with check targets or execution flags. Unknown flags and invalid combinations return 2. Prefix local filenames beginning with `-` with `./` or `.\`, or place them after `--`.

Source builds are available. The 2026-11-18 [cross-platform CI run](https://github.com/vincent119/tlscheck/actions/runs/44285001106) (source `a1cff07`) passed four-target snapshot packaging and checksums, plus native tests, isolated archive installation/same-version reinstallation, and configuration-preservation checks on macOS arm64/amd64 and Windows amd64. Windows arm64 is cross-build only. Published releases, Homebrew/Scoop installation and upgrades, signing, and notarization remain unverified; real Console operation and full interactive shell completion still need acceptance testing. See [installation and release maintenance](docs/releasing.md) for evidence and limits.

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

## Complete options and output

| Option | Short | Default / purpose |
|---|---|---|
| `[target-or-file]...` | | Auto-detect; existing files take precedence |
| `--remote TARGET` | `-r` | Force remote; repeatable; never reads a same-named local file |
| `--local PATH` | `-l` | Force local; repeatable; missing files never become remote targets |
| `--language CODE` | `-L` | One-run en / zh-TW / zh-CN override |
| `--format FORMAT` | `-f` | table (default) / json / html / markdown |
| `--output PATH` | `-o` | `-` (stdout) |
| `--overwrite` | | Off; requires output other than `-` |
| `--timeout DURATION` | `-t` | 10s; 1ms–5m |
| `--expiry-warning-days DAYS` | | 30; 0–36500; 0 disables warnings |
| `--settings` | `-s` | Independent interactive language/theme settings |
| `--help` | `-h` | Help, exit 0 |
| `--version` | `-V` | Version, exit 0 |
| `--` | | All following tokens are positional inputs |

Positional, remote and local inputs retain command-line occurrence order and duplicates. Each remote/local flag takes one value without splitting commas. Other flags cannot repeat; valueless boolean flags cannot use forms such as `--overwrite=true`. Required values cannot be omitted or empty, including `--remote=`/`--local=`; these errors never create a report. Settings cannot mix with check or language flags; `--settings --help` works without opening the menu. A language override alone shows help; execution flags without a target return 2.

```sh
./bin/tlscheck -r example.com --local ./local/site.pem -L zh-TW
./bin/tlscheck 'https://example.com:8443/' -t 5s --expiry-warning-days 14
./bin/tlscheck -l ./local/site.pem -f json -o ./report.json
./bin/tlscheck -l ./local/site.pem -f html -o ./report.html --overwrite
./bin/tlscheck -l ./local/site.pem -f markdown
./bin/tlscheck --settings
```

Format is never inferred from the extension. The output parent must already exist; `~` is not expanded. Existing destinations require `--overwrite`. Directories, special files, symlinks, and destinations aliasing inputs/configuration through identity or hardlinks are rejected. Reports serialize completely before temporary-file writing, syncing, closing and committing. Output errors return 2. JSON `summary.check_exit_code` describes checks only; the process may additionally return 2 for I/O failures. New macOS reports use 0600 without inherited ACLs; overwrites preserve native ACLs, owner and group. Writes fail safely if security attributes cannot be preserved or ACL restrictions would prevent commit/failure cleanup. Windows uses protected DACLs and checks existing security attributes. Read-only destinations are replaced atomically relative to the retained directory handle, preserving read-only attributes and DACLs without first deleting the original or clearing its read-only attribute. Unsupported Windows/filesystem combinations fail safely; read-only replacement, DACL preservation, and failure cleanup passed Windows amd64 CI regressions. Detected destination snapshot changes stop the write; the final snapshot check and rename are not a compare-and-swap guarantee against arbitrary external processes.

JSON is one UTF-8 object with two-space indentation and a final newline, using integer `schema_version: 1`. Root fields are `tool`, `generated_at` (UTC), `language`, ordered `inputs`, `local`, `remote`, and `summary`. Status values remain `passed`/`failed`/`not_performed`, and severities `none`/`verification`/`execution`. Codes are stable and messages localized; empty collections are `[]`, unobserved TLS is `null`. `advice` is `null` or `{ "code": "advice.…", "message": "…" }`, with language-independent codes. Table/HTML/Markdown include per-input results and highest severity, plus a key-ID/certificate-ID pair table; derived views do not increment global counts. Table displays backslashes as `\\` and pipes as `\u007c`; other formats keep their own safe representation. Certificates use full SHA-256 IDs; private keys expose only per-source IDs and public metadata. Private-key material and original full URLs never enter the report. HTML is standalone, loads no external resources, executes no JavaScript, and never opens a browser automatically.

## Shell completion

`completion` is a reserved helper command. Use `-r completion` or `-- completion` for that hostname, or `-l completion` for that filename. `completion SHELL --help`/`-h` shows shell-level help. Hidden completion never echoes raw errors; generated debug functions do not write files, and `BASH_COMP_DEBUG_FILE` does not enable writing. Completion never connects or reads configuration/certificate contents; filename completion may enumerate directories. Bash requires a compatible bash-completion package to be loaded, providing `_get_comp_words_by_ref`/`_init_completion`; sourcing the generated script alone does not supply this shell dependency. This machine lacks that package, so Bash evidence covers syntax and protocol only.

All four shells accept `--no-descriptions` and `-L`/`--language`, but no execution flags.

```sh
# Bash
source <(./bin/tlscheck completion bash)
# Zsh
source <(./bin/tlscheck completion zsh)
# Fish
./bin/tlscheck completion fish | source
# Generate without descriptions
./bin/tlscheck completion zsh --no-descriptions
```

PowerShell:

```powershell
.\bin\tlscheck.exe completion powershell | Out-String | Invoke-Expression
```

These activate completion in the current shell; add the applicable command to your own startup file for persistence. Script generation and available local-shell syntax validation do not establish native Windows/Fish interactive success.

## Language configuration

Use `--language en|zh-TW|zh-CN`/`-L` for a one-run override, ahead of JSON and default English. A valid CLI language bypasses configuration reads and is never saved. There are no language environment-variable or configuration-path overrides. The platform directory is resolved by `os.UserConfigDir()`.

| Platform | Configuration file |
|---|---|
| macOS | `~/Library/Application Support/tlscheck/config.json` |
| Windows | `%AppData%\tlscheck\config.json` |

Run `tlscheck --settings`/`-s` for interactive language and theme settings. Both stdin and stderr must be terminals; the menu uses stderr and leaves stdout empty. Use arrows, Enter, Esc (back/cancel), Ctrl+C (cancel), or `t` (theme). A macOS terminal disconnect exits without saving. Only **Save and exit** writes configuration; cancel leaves it unchanged. Repair malformed or unknown-field configurations manually before saving. Themes `normal`, `dark`, and `light` affect only the menu. Alternatively create UTF-8 JSON without BOM:

```json
{"language":"en"}
```

```json
{"language":"zh-TW","theme":"normal"}
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

Missing or empty theme uses normal; an unsupported theme warns and falls back to normal. Ordinary checks, queries and completion never write configuration.

Table/HTML/Markdown localize input modes, severities, check names, stages, and URI redaction reasons. JSON identifiers, stored settings, certificate values, and paths remain unchanged. Language options retain their native names; theme options use localized labels. If both local and English templates fail, the final safe message follows the effective language; unsupported languages use English and internal message IDs are never echoed.

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
| 0 | Applicable checks passed, help/version/completion succeeded, settings saved/cancelled, or only expiry/configuration warnings |
| 1 | Certificate/key/trust/pairing check failure |
| 2 | Input, parsing, unsupported format, connection, timeout, cancellation or output error |

The highest severity wins: 2 > 1 > 0. Individual input failures do not stop remaining inputs; invalid CLI flag combinations are rejected before checking. States are passed, failed and not performed. Not performed is neither a pass nor an independent failure. Summary counts describe the displayed checks, not the number of input files.

Table reports and verification failures go to stdout by default. With `--output PATH`, the full report goes only to that file, with no saved banner on stdout. Configuration warnings and execution diagnostics go to stderr; an execution error can appear in both the report and the diagnostic stream.

Each local certificate/key file is limited to 10 MiB of actual reads. Each remote target has a shared DNS/TCP/TLS handshake deadline, default 10 seconds and configurable with `--timeout`/`-t` from 1ms to 5m, not a separate 10 seconds per stage. Platform trust operations can have platform-specific cancellation limits. Dates use UTC; remaining days are floored, so a recently expired certificate can show -1 day. A nonexpired certificate expiring within 30 × 24 hours produces a warning by default; `--expiry-warning-days` accepts 0–36500, where 0 disables warnings but preserves expiry validation; that warning alone does not change the exit code.

Reports support table, JSON, standalone offline HTML, and GFM Markdown without terminal color or animation. tlscheck does not request, renew or deploy certificates, inspect web content, scan cipher suites, decrypt keys, or manage system trust. Planned initial release artifacts are unsigned and unnotarized; no signed/notarized distribution is currently verified.

## Development and maintenance

From the repository root, on either platform with Go installed:

```text
go test ./...
go test -race ./...
go vet ./...
git diff --check
```

Race detection requires a supported native Go toolchain and its C toolchain. Tests create synthetic certificates and loopback TLS servers; they do not depend on public services or add roots to the system store. macOS arm64/amd64 and Windows amd64 passed native Go tests, race detection, vet, Python regressions, isolated archive installation/same-version reinstallation, and CLI version checks. All four snapshot targets were built and verified; Windows arm64 is cross-build only. Real Console operation, full interactive shell completion, and package-manager installation/upgrades still need acceptance testing.

Optional GNU Make targets are `make help`, `make build`, `make test`, `make vet`, `make check`, and `make fmt`. `make build` writes `bin/tlscheck`; Windows users should use the explicit PowerShell build above for the `.exe` suffix. Keep generated binaries in `bin/`, release outputs in `dist/`, and private local files in ignored `local/`. Certificate/key extensions are not globally ignored, allowing intentional synthetic fixtures.

See the bilingual [release maintenance guide](docs/releasing.md) for packaging, upgrade, verification and retry status. When changing behavior, update both README files and corresponding maintenance instructions together.

## License

[Apache License 2.0](LICENSE). The license retains its official English text.
