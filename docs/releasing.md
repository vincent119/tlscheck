# Installation and release maintenance

[English](releasing.md) | [繁體中文](releasing.zh-TW.md) | [README](../README.md)

This guide is for maintainers preparing macOS and Windows distribution and users evaluating installation options. The CLI can currently be built from source. Local snapshot packaging has been verified; remote workflow execution, downloadable releases and package-manager installation have not. Do not interpret the templates below as available packages.

## Available installation and upgrade

Use the source-build commands in the [README](../README.md). To upgrade a local build, retain a copy of the previous binary, build the reviewed source revision, check `--version`, then replace your executable after validation. The configuration file is outside the repository and is not modified by the application. Restoring the previous binary rolls back the executable; no database migration is involved.

Release archive installation will require a confirmed version, real download URL, matching platform/architecture and SHA-256 checksum from the release. On macOS compare the archive using `shasum -a 256`; on Windows PowerShell use `Get-FileHash -Algorithm SHA256`. A checksum establishes integrity relative to the published checksum, not publisher authentication. Initial artifacts are planned to be unsigned and unnotarized. Archive names, contents, checksums, Gatekeeper handling and Windows installation must be verified against actual artifacts before this route is documented as ready.

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

Current evidence separates macOS arm64 native execution from Windows amd64 cross-building. PowerShell syntax can be checked on macOS without proving Windows execution. Windows native tests, the four planned targets (darwin/windows × amd64/arm64), archive installation and package upgrades require their own evidence.

## Release preparation and retry boundaries

GitHub Actions workflows and GoReleaser v2.14.3 configuration are implemented. Local snapshot builds and checksum checks passed. A previous hosted packages job failed; this PATH fix has not been pushed, so the complete native matrix remains unverified. No publishing has occurred. Before a release, confirm tool versions, workflow permissions, real tap/bucket destinations and owners, version injection (`main.version`, `main.commit`), architecture matrix, archive contents, SHA-256 output and both language documents plus LICENSE. The initial target is v0.1.0, not an assertion that this version exists.

Keep nonpublishing builds separate from tag creation, pushing, GitHub Releases and package-repository writes. Publishing needs explicit authorization. No release command is supplied until its configuration and permissions have been verified.

On failure, record the source commit, intended version, failed stage and artifacts already published. Retry only the failed stage after checking existing assets and package versions. Do not recreate tags, overwrite different bytes under the same version, duplicate published assets, or downgrade a tap/bucket blindly. Prerelease filtering and idempotent retries must be tested with the actual workflow. Confirm downloads, checksums, package versions, installation, `--version` and unchanged configuration before declaring success.

## Completion record still required

| Evidence | Current status |
|---|---|
| Source build and CLI help/version on macOS arm64 | Verified |
| Windows amd64 cross-build | Verified; not a native runtime test |
| Windows native execution and installation | Not verified |
| Four-target local snapshot archives and checksums | Verified locally; not published |
| Homebrew tap / Scoop bucket owners and repositories | Confirmed; no remote writes performed |
| Package install, upgrade and config preservation | Not verified |
| Publishing, retry and prerelease behavior | Not verified |

Update this guide and its Chinese counterpart together when actual packaging and installation evidence becomes available. Do not mark distribution instructions complete solely because a command template exists.

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

These settings apply only to the current session and its children, without changing user-wide settings. Encoding regressions disable UTF-8 mode in a child process, treat implicit-encoding warnings as errors, and check installation/lint boundaries and Chinese stdout/stderr. This does not establish native Windows CI success.


## Protected release workflow

`.github/workflows/ci.yml` tests on `macos-15` (arm64), `macos-15-intel` (amd64) and `windows-2025` (amd64). Native jobs download and install the snapshot archive in isolation; Windows arm64 remains cross-build only. The local machine cannot establish that these hosted jobs have passed. Actions are pinned to commit SHAs, Go to 1.27.4 and GoReleaser to 2.14.3.

`.github/workflows/release.yml` accepts a pushed `v*` tag or a manual rerun on that tag. It requires the reusable CI checks, repository variable `ENABLE_RELEASE=true` and the `release` environment. Configure required reviewers and tag restrictions on that environment before enabling the variable. No environment or secret has been created by this change. Set `PACKAGE_REPOSITORY_TOKEN` as a fine-grained credential limited to contents read/write on `vincent119/homebrew-tap` and `vincent119/scoop-bucket`; main-repository publication uses the job's `GITHUB_TOKEN` with contents write. The script reads it as `GH_TOKEN`. Do not provide secrets to pull-request checks.

The publisher additionally requires `--execute`, `RELEASE_APPROVED` equal to the exact tag, clean source, HEAD/tag equality and matching GoReleaser metadata. It creates a draft, pins its source commit in the body, fills only missing assets, downloads and compares every asset, then marks the release published. An existing release with unknown source or different same-name bytes stops. A package update rechecks the published assets, skips prereleases and newer stable versions, accepts identical same-version content, rejects conflicting same-version content and uses GitHub Contents API SHA conditions against concurrent changes. Release jobs share one noncancelling concurrency group to serialize package updates.

Retry by rerunning the same tag workflow after reviewing the failed stage. The release must retain its source marker. Do not delete it to bypass a mismatch. A package failure after a successful Release leaves that Release intact; a rerun verifies it and continues. Controlled tests simulate these transitions without contacting GitHub. Real remote retry, package-manager install/upgrade and Windows native results remain pending. Current artifacts are unsigned and unnotarized.

## Review fixes and retry details

The publisher enumerates authenticated Release pages to locate both drafts and published releases. Multiple releases for one tag are rejected. Only a source-verified, still-unpublished draft may have an empty `state=starter` asset removed and retried; normal uploaded assets, nonempty failed assets and published-release conflicts remain protected. Before the final publish request, the newest stable version is compared and `make_latest` is set explicitly, so publishing an older version does not replace Latest. Prereleases never become the stable Latest.

The shared release concurrency group uses `queue: max` and `cancel-in-progress: false`. GitHub allows up to 100 pending runs; overflow can still be canceled and queue order is not guaranteed to match tag/version order. Version comparisons remain necessary. Actionlint 1.7.12 does not yet recognize this official property. CI uses `scripts/lint_workflows.py` to validate the exact concurrency contract and accept only that precise unknown-field diagnostic at the expected file/line; all other errors remain fatal. Run it with `python3 -B scripts/lint_workflows.py` after installing the pinned Actionlint. Once the tool supports the property, the wrapper still validates the queue contract with no diagnostic exception needed. Hosted queue behavior remains untested locally.

Certificate SAN URIs are displayed individually. Hierarchical URI identity paths, including SPIFFE paths, are preserved; user information, query and fragment are removed. Opaque or invalid URIs are represented by `[URI]` instead of reflecting potentially embedded credentials. General public text and local paths are not guessed to be network URLs; terminal controls are removed.

## CLI compatibility update

See [README](../README.md) for table-default reporting, four formats and protected output, forced local/remote inputs, language overrides, settings and four-shell completion. Ordinary commands still never write configuration; explicit settings save is the exception. Native Windows Console/ACL/commit behavior, interactive Fish and native execution on all four targets need platform evidence. This change does not modify CI or create a release.

The eight CLI review fixes have regression coverage for completion debug writes, empty flag values, shell help, terminal disconnect, ACL preservation/failure cleanup, advice codes, table delimiters, and per-input summaries. macOS ACL handling uses bounded native attribute calls; CLI runtime does not depend on chmod/Python, which are test tools only. Windows DACL native test sources cross-compile; native Windows execution remains unverified.

## CI packaging-tool PATH fix

The pinned action adds its installation directory to later steps only when `install-only: true`. CI now explicitly installs v2.14.3, then runs `goreleaser --version`, `goreleaser check`, and the existing snapshot in shell steps. The action SHA, read-only contents permissions, `--snapshot --skip=publish`, and release.disable remain unchanged. Regression checks cover installation/execution order and nonpublishing behavior; local success does not establish hosted-runner success.

Behavior reference: [pinned action source](https://github.com/goreleaser/goreleaser-action/blob/e435ccd777264be153ace6237001ef4d979d3a7a/src/main.ts).
