# Installation and release maintenance

[English](releasing.md) | [繁體中文](releasing.zh-TW.md) | [README](../README.md)

This guide is for maintainers preparing macOS and Windows distribution and users evaluating installation options. The CLI can be built from source. The 2026-11-18 [cross-platform CI run](https://github.com/vincent119/tlscheck/actions/runs/44285001106) (source `a1cff07676d94c4ac7e663bec5ea83c8584d42a9`, attempt 1) passed all jobs: four-target snapshot packaging and checksums, plus native tests and isolated installation/same-version reinstallation on macOS arm64/amd64 and Windows amd64. Windows arm64 is cross-build only; official releases, package-manager installation/upgrades, and real interactive operation remain unverified. Do not interpret the templates below as available packages.

## Available installation and upgrade

Use the source-build commands in the [README](../README.md). To upgrade a local build, retain a copy of the previous binary, build the reviewed source revision, check `--version`, then replace your executable after validation. The configuration file is outside the repository; ordinary checks do not modify it, and only an explicit save in `--settings` writes it. Restoring the previous binary rolls back the executable; no database migration is involved.

Release archive installation will require a confirmed version, real download URL, matching platform/architecture and SHA-256 checksum from the release. On macOS compare the archive using `shasum -a 256`; on Windows PowerShell use `Get-FileHash -Algorithm SHA256`. A checksum establishes integrity relative to the published checksum, not publisher authentication. Initial artifacts are planned to be unsigned and unnotarized. CI verified snapshot archive names, contents, checksums, and isolated installation on three native platforms. Official release downloads, Gatekeeper handling, and upgrades between published versions still require separate validation.

## Package-manager templates, not ready to run

The destinations are confirmed as `vincent119/homebrew-tap` (`Formula/tlscheck.rb`) and `vincent119/scoop-bucket` (`bucket/tlscheck.json`). A published tlscheck package, release URL and installation are not yet verified. The following commands describe the intended interface; wait for a validated release before running them.

Homebrew on macOS, prospective install and upgrade:

```sh
brew tap vincent119/tap
brew install vincent119/tap/tlscheck
brew update
brew upgrade vincent119/tap/tlscheck
tlscheck --version
```

Scoop on Windows PowerShell, prospective install and upgrade:

```powershell
scoop bucket add tlscheck 'https://github.com/vincent119/scoop-bucket'
scoop install tlscheck/tlscheck
scoop update
scoop update tlscheck
tlscheck --version
```

Existing `config.json` contents must remain unchanged through install and upgrade. Package-manager rollback instructions require actual formula/manifest and version-retention evidence; they are not verified yet.

## Development validation

Run the Go test, race, vet and whitespace commands from the README before packaging. Keep test materials synthetic and private inputs outside tracked files. The application uses no public services in automated tests, but loopback binding is needed for TLS tests.

The CI run above passed Go tests, race detection, vet, 27 Python regressions, native CLI version checks, and isolated snapshot installation/same-version reinstallation with configuration-preservation checks on macOS arm64/amd64 and Windows amd64. All four darwin/windows × amd64/arm64 targets were built and their SHA-256 checksums verified; Windows arm64 is cross-build only. Real Windows Console operation, Bash interaction with compatible completion dependencies loaded, Fish syntax and interaction, Windows PowerShell completion, and Homebrew/Scoop installation/upgrades still need acceptance records.

Local acceptance on 2026-11-19: Zsh 5.9 passed 10 actual Tab cases covering flags/values, equals syntax, `--`, stop conditions, and filenames with spaces/Unicode; only the hidden completion protocol ran, with configuration and the debug sentinel unchanged. Five macOS CLI/PTY scenarios covering arrows, language/theme previews, Esc, Ctrl+C, and cancellation passed with empty stdout, exit code 0, restored terminal configuration fields, and unchanged real configuration. Saving remains covered by isolated tests; no user configuration was saved. The empty-candidate compatibility issue is fixed locally on PowerShell 7.5.2: 30 native-engine checks passed across scripts with and without descriptions; Go regressions additionally cover equals syntax, quotes, a cursor inside the line, and unchanged AST arguments. The placeholder preserves an existing word, or adds one space at an empty cursor, without adding arguments or enabling file fallback; normal local/output filename completion is retained. Unknown generator templates stop output, without private reflection or dependency upgrades. The Windows engine/Console still needs native validation; the earlier passing CI does not validate this new fix on Windows. Bash lacks compatible bash-completion and Fish is not installed, so full interaction remains unverified for both.

## Release preparation and retry boundaries

GitHub Actions CI and the GoReleaser v2.14.3 four-target trial build passed in the hosted run above. Its successful regressions cover the previous tool PATH, Windows file-replacement/IPv6, and Python encoding failures. This work has not performed an official release. Before a release, confirm tool versions, workflow permissions, real tap/bucket destinations and owners, version injection (`main.version`, `main.commit`), architecture matrix, archive contents, SHA-256 output and both language documents plus LICENSE. The initial target is v0.1.0, not an assertion that this version exists.

Keep nonpublishing builds separate from tag creation, pushing, GitHub Releases and package-repository writes. Publishing needs explicit authorization. No release command is supplied until its configuration and permissions have been verified.

On failure, record the source commit, intended version, failed stage and artifacts already published. Retry only the failed stage after checking existing assets and package versions. Do not recreate tags, overwrite different bytes under the same version, duplicate published assets, or downgrade a tap/bucket blindly. Prerelease filtering and idempotent retries must be tested with the actual workflow. Confirm downloads, checksums, package versions, installation, `--version` and unchanged configuration before declaring success.

## Validation record and pending checks

| Evidence | Current status |
|---|---|
| macOS arm64/amd64 native tests, race detection, CLI version | Passed CI |
| Windows amd64 native tests, race detection, DACL/read-only replacement, CLI version | Passed CI |
| Timeout options and expiry before DNS regressions | Named PASS without Skip in the latest normal/race runs on three platforms; Windows native verification complete |
| Isolated snapshot installation/same-version reinstallation and configuration preservation on three native targets | Passed CI; upgrades between published versions unverified |
| Four-target snapshot archives and SHA-256 | Passed CI; not officially published; Windows arm64 is cross-build only |
| Named PowerShell main/subcase PASS without Skip | Verified six normal/race JSON files across three platforms; see evidence below |
| Real Console and full interactive shell completion | Pending; see development-validation scope |
| Homebrew tap / Scoop bucket owners and repositories | Confirmed; no remote writes performed |
| Homebrew/Scoop installation, cross-version upgrades and configuration preservation | Not verified |
| Publishing, remote retry and prerelease behavior | Controlled regressions passed; actual publishing workflow unverified |

Update this guide and its Chinese counterpart together when actual packaging and installation evidence becomes available. Do not mark distribution instructions complete solely because a command template exists.

### Named PowerShell test evidence

Native CI separately runs `go test -json -count=1 ./...` and `go test -race -json -count=1 ./...`, using `pipefail` and `tee` to preserve events and Go failures. Before testing, it checks that `pwsh` runs and prints its version; it does not install it automatically.

`scripts/check_go_test_events.py` verifies each JSONL independently. In the exact package `github.com/vincent119/tlscheck/internal/app`, `TestPowerShellEmptyCandidatesDoNotFallbackToFiles`, `/包含描述`, and `/不含描述` must each have `run` followed by `pass`, with a completed package `pass`. Skips within the main test subtree, any test/build failure, missing events, duplicate or out-of-order events, malformed UTF-8/JSON, and size-limit violations fail verification. Package `ok` or PASS in output text cannot replace structured events.

Each native job attempts to upload `go-test-events-<matrix.os>` on success or failure, containing only `go-test.jsonl` and `go-test-race.jsonl`, retained for seven days. Early failures may leave no event files; that is not a passing verification. After downloading, run from the repository root:

```bash
python3 -B scripts/check_go_test_events.py go-test.jsonl go-test-race.jsonl
```

Verified [CI 44454812073, attempt 2](https://github.com/vincent119/tlscheck/actions/runs/44454812073/attempts/2), at commit `9e7bc08118ed1ef0d441872cf2ea26c690c972d2`, with all four jobs successful. After downloading the three `go-test-events-<matrix.os>` artifacts, each of the six JSONL files was independently checked again:

| Native platform | Normal tests | Race tests |
|---|---|---|
| macOS arm64 (macos-15) | Main test and both subcases PASS, no Skip | Main test and both subcases PASS, no Skip |
| macOS amd64 (macos-15-intel) | Main test and both subcases PASS, no Skip | Main test and both subcases PASS, no Skip |
| Windows amd64 (windows-2025) | Main test and both subcases PASS, no Skip | Main test and both subcases PASS, no Skip |

All 18 required named passes have preceding `run` events and completed package `pass` events, with no Skip in the main test subtree. The first macOS amd64 attempt failed on Go proxy DNS; successful events were obtained after the rerun. Closure relies on raw JSON, not package success in the older CI 44452386656. This completes the cross-platform engine portion of S09-T10. Real Windows Console/keyboard Tab, the settings menu, and other outstanding shell acceptance checks remain pending, so S09-T10 and S09 as a whole remain open.

### Native timeout regression acceptance

[CI 44463960289](https://github.com/vincent119/tlscheck/actions/runs/44463960289) passed on its first attempt at commit `1bae9a18a85c60fd40bf38eedc24e1a948fd48a2`. All six normal/race JSON files across three platforms were individually checked: in `internal/check`, `TestRemoteTimeoutOptionUsesSharedDeadline`, `/最小期限`, `/自訂期限`, and `TestRemoteTimeoutBeforeDNSKeepsExecutionFailure` each have named `run`→`pass` events without Skip. The existing `TestRemoteSharesOneDeadlineAcrossNetworkStages` also passed by name, and all packages completed successfully.

This closes S03-V03 for Windows amd64 native normal/race verification. Tests use the standard `testing/synctest` virtual clock, retain the 1 ms minimum and verify a custom timeout, removing the scheduling assumption that DNS must begin within a real millisecond. Expiry before DNS must prevent DNS/dialing and still report an execution error with exit code 2. Product behavior for the shared deadline, timeout range, and exit codes is unchanged. The Windows race failure in CI 44462742449 remains pre-fix evidence; cross-compilation is not substituted for this native result.

This CI result does not provide real Windows Console, keyboard Tab, or settings-menu acceptance, nor the outstanding Bash/Fish shell checks. Those items and official package installation/upgrades remain pending.

## Command references

Template syntax was checked against the official [Homebrew tap documentation](https://docs.brew.sh/Taps), [Homebrew command reference](https://docs.brew.sh/Manpage), [Scoop buckets](https://github.com/ScoopInstaller/Scoop/wiki/Buckets) and [Scoop commands](https://github.com/ScoopInstaller/Scoop/wiki/Commands). This does not verify any tlscheck package or installation.

## Implemented local validation

Use Go 1.27.4, GoReleaser 2.14.3 and Python 3. Run from the repository root:

```sh
goreleaser check
python3 -B -m unittest discover -s scripts -v
goreleaser release --snapshot --clean --skip=publish
python3 -B scripts/release.py verify
python3 -B scripts/install_check.py
```

The first four commands produce and check `dist/tlscheck_0.0.0-snapshot_<source>...` artifacts using the naming template `tlscheck_<version>_<os>_<arch>`. The exact snapshot version is `0.0.0-snapshot-<short-commit>-dirty`; the suffix is deliberately retained for all snapshots, including clean CI checkouts, to distinguish them from official tagged builds. GoReleaser sets its commit metadata from HEAD; a snapshot can include uncommitted changes and must not be presented as that commit's official release. `--clean` replaces only `dist/`; preserve any artifacts you need first. The configuration disables GoReleaser publishing entirely; the explicit publisher is a separate program.

`install_check.py` installs the native executable in a temporary directory, repeats replacement as a local reinstall/upgrade check, runs `--version`, and verifies the real configuration and an isolated sentinel are unchanged. It does not install Homebrew/Scoop packages or prove an upgrade between distinct published versions. Archive names include `darwin`/`windows` and `amd64`/`arm64`; macOS archives are tar.gz, Windows archives are zip. Each includes the executable, LICENSE, both README files and both maintenance documents. `checksums.txt` contains SHA-256 for all four archives. File timestamps are fixed to the source commit for repeatable builds.

To generate local Formula and manifest files for this snapshot, substitute its exact version including the leading `v`; this only writes `dist/tlscheck.rb` and `dist/tlscheck.json`. Snapshot URLs in these files do not exist on GitHub and must not be published as stable packages.

```text
python3 -B scripts/release.py packages --tag v0.0.0-snapshot-SHORTCOMMIT-dirty
```

Optional Make targets: `make release-check`, `make snapshot`, `make verify-packages`. Python is maintenance tooling only, not a runtime requirement for the CLI.

Python maintenance tools and tests explicitly use UTF-8 for text files and captured subprocess text. Both CI and release workflows set `PYTHONUTF8=1` and `PYTHONIOENCODING=utf-8` globally, preventing the Windows default code page from breaking Chinese YAML or log messages. Before running the Python commands manually, configure the current terminal session:

```bash
export PYTHONUTF8=1 PYTHONIOENCODING=utf-8
```

Windows PowerShell:

```powershell
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
```

These settings apply only to the current session and its children, without changing user-wide settings. Encoding regressions disable UTF-8 mode in a child process, treat implicit-encoding warnings as errors, and check installation/lint boundaries and Chinese stdout/stderr. The Windows amd64 CI run above separately passed these regressions; local simulation and native execution are recorded as distinct evidence.


## Protected release workflow

`.github/workflows/ci.yml` tests on `macos-15` (arm64), `macos-15-intel` (amd64) and `windows-2025` (amd64). Native jobs download and install the snapshot archive in isolation; Windows arm64 remains cross-build only. The successful run above confirms all three native jobs and the packages job; it does not cover real Console/full completion interaction or package-manager acceptance. Actions are pinned to commit SHAs, Go to 1.27.4 and GoReleaser to 2.14.3.

`.github/workflows/release.yml` accepts a pushed `v*` tag or a manual rerun on that tag. It requires the reusable CI checks, repository variable `ENABLE_RELEASE=true` and the `release` environment. Configure required reviewers and tag restrictions on that environment before enabling the variable. No environment or secret has been created by this change. Set `PACKAGE_REPOSITORY_TOKEN` as a fine-grained credential limited to contents read/write on `vincent119/homebrew-tap` and `vincent119/scoop-bucket`; main-repository publication uses the job's `GITHUB_TOKEN` with contents write. The script reads it as `GH_TOKEN`. Do not provide secrets to pull-request checks.

The publisher additionally requires `--execute`, `RELEASE_APPROVED` equal to the exact tag, clean source, HEAD/tag equality and matching GoReleaser metadata. It creates a draft, pins its source commit in the body, fills only missing assets, downloads and compares every asset, then marks the release published. An existing release with unknown source or different same-name bytes stops. A package update rechecks the published assets, skips prereleases and newer stable versions, accepts identical same-version content, rejects conflicting same-version content and uses GitHub Contents API SHA conditions against concurrent changes. Release jobs share one noncancelling concurrency group to serialize package updates.

Retry by rerunning the same tag workflow after reviewing the failed stage. The release must retain its source marker. Do not delete it to bypass a mismatch. A package failure after a successful Release leaves that Release intact; a rerun verifies it and continues. Controlled tests simulate these transitions without contacting GitHub. Real remote retry and package-manager install/upgrade remain pending. Current artifacts are unsigned and unnotarized.

## Review fixes and retry details

The publisher enumerates authenticated Release pages to locate both drafts and published releases. Multiple releases for one tag are rejected. Only a source-verified, still-unpublished draft may have an empty `state=starter` asset removed and retried; normal uploaded assets, nonempty failed assets and published-release conflicts remain protected. Before the final publish request, the newest stable version is compared and `make_latest` is set explicitly, so publishing an older version does not replace Latest. Prereleases never become the stable Latest.

The shared release concurrency group uses `queue: max` and `cancel-in-progress: false`. GitHub allows up to 100 pending runs; overflow can still be canceled and queue order is not guaranteed to match tag/version order. Version comparisons remain necessary. Actionlint 1.7.12 does not yet recognize this official property. CI uses `scripts/lint_workflows.py` to validate the exact concurrency contract and accept only that precise unknown-field diagnostic at the expected file/line; all other errors remain fatal. Run it with `python3 -B scripts/lint_workflows.py` after installing the pinned Actionlint. Once the tool supports the property, the wrapper still validates the queue contract with no diagnostic exception needed. Hosted queue behavior remains untested locally.

Certificate SAN URIs are displayed individually. Hierarchical URI identity paths, including SPIFFE paths, are preserved; user information, query and fragment are removed. Opaque or invalid URIs are represented by `[URI]` instead of reflecting potentially embedded credentials. General public text and local paths are not guessed to be network URLs; terminal controls are removed.

## CLI compatibility update

See [README](../README.md) for table-default reporting, four formats and protected output, forced local/remote inputs, language overrides, settings and four-shell completion. Ordinary commands still never write configuration; explicit settings save is the exception. Automated Windows amd64 ACL/commit regressions passed; real Windows Console operation and full interactive shell completion still need acceptance testing. Windows arm64 is cross-build only. Official publishing still requires separate authorization.

The eight CLI review fixes have regression coverage for completion debug writes, empty flag values, shell help, terminal disconnect, ACL preservation/failure cleanup, advice codes, table delimiters, and per-input summaries. macOS ACL handling uses bounded native attribute calls; CLI runtime does not depend on chmod/Python, which are test tools only. Windows DACL, read-only atomic replacement, and failure-cleanup regressions passed in the Windows amd64 CI run above; this does not validate every Windows/filesystem combination.

## CI packaging-tool PATH fix

The pinned action adds its installation directory to later steps only when `install-only: true`. CI now explicitly installs v2.14.3, then runs `goreleaser --version`, `goreleaser check`, and the existing snapshot in shell steps. The action SHA, read-only contents permissions, `--snapshot --skip=publish`, and release.disable remain unchanged. Regression checks cover installation/execution order and nonpublishing behavior; the packages job above passed tool-version, configuration, workflow-syntax, and four-target trial-build checks.

Behavior reference: [pinned action source](https://github.com/goreleaser/goreleaser-action/blob/e435ccd777264be153ace6237001ef4d979d3a7a/src/main.ts).
