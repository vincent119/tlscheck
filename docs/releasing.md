# Installation and release preflight

[English](releasing.md) | [繁體中文](releasing.zh-TW.md) | [README](../README.md)

Start with the platform installation below. Maintainers should complete the release checklist before creating a tag or enabling publication. This guide documents the current controls and the evidence still needed, without authorizing a release.

## Package installation

**Homebrew/Scoop packages are not published or verified yet.** Download macOS/Windows archives and SHA-256 checksums from [GitHub Releases](https://github.com/vincent119/tlscheck/releases). These are the intended user installation commands, to use after the package and its release assets are verified. Source builds are covered [later in this guide](#source-builds), and the [README installation section](../README.md#installation) uses the same commands.

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

Linux has no package or release archive in the current matrix. The Homebrew Formula has only an `on_macos` definition and does not provide a Linuxbrew installation. Use the [source-build instructions](../README.md#build-from-source) with the stated native-acceptance limits.

## Platform status

| Platform | Source build | Native CI / installation | Release archive plan |
|---|---|---|---|
| Windows amd64 | Verified | Ordinary/race tests and isolated snapshot install/reinstall passed | ZIP |
| Windows arm64 | Cross-build verified | Native acceptance pending | ZIP, cross-built |
| macOS amd64 / arm64 | Verified | Ordinary/race tests and isolated snapshot install/reinstall passed | tar.gz |
| Linux amd64 / arm64 | Cross-build verified | Native acceptance pending | Not configured |

Use [GitHub Releases](https://github.com/vincent119/tlscheck/releases) to select a published version and its assets. The [2026-11-20 CI run](https://github.com/vincent119/tlscheck/actions/runs/44693571937), source `6394a47`, passed seven jobs across packaging, macOS/Windows native tests, and HTML-script regressions. It does not cover the current uncommitted changes or prove a published installation. Windows arm64 remains cross-build only. Manual Console, browser cleanup, and layout acceptance remain separate.

The [README](../README.md) owns the CLI, formats, PFX password rules, and language settings. Use the version and source commit recorded with an acceptance result when deciding whether it applies to a release candidate.

## Verify archives and upgrade

After a release exists, select the exact OS, architecture, version, and real download URL. Compare the downloaded archive with that release's `checksums.txt` before extracting it.

macOS:

```sh
shasum -a 256 tlscheck_*.tar.gz
```

Windows PowerShell:

```powershell
Get-FileHash .\tlscheck_*.zip -Algorithm SHA256
```

A matching checksum establishes agreement with the published hash. It does not authenticate the publisher. Current distribution plans are unsigned and unnotarized. Real release downloads, Gatekeeper behavior, and upgrades between published versions have not been accepted yet.

Keep the previous executable until the replacement passes `--version` and a local check. Preserve `config.json` before and after installation. Ordinary CLI checks do not write it, and only an explicit settings save does. Restoring the old executable rolls back the binary, with no database migration.

Homebrew and Scoop destinations are `vincent119/homebrew-tap` (`Formula/tlscheck.rb`) and `vincent119/scoop-bucket` (`bucket/tlscheck.json`). After verified packages are published, upgrades use:

macOS Homebrew:

```sh
brew update
brew upgrade vincent119/tap/tlscheck
tlscheck --version
```

Windows PowerShell Scoop:

```powershell
scoop update
scoop update tlscheck
tlscheck --version
```

Package-manager rollback needs verified package versions and retention behavior. Do not assume that replacing a source-built binary proves a Homebrew/Scoop upgrade or rollback.

## Source builds

[Build instructions](../README.md#build-from-source) cover Windows PowerShell, macOS, and Linux with Go 1.27.0 or newer. A plain source build reports `development` and `unknown` unless version metadata is injected. Linux amd64/arm64 cross-builds have been checked, while native Linux installation is unverified. Use explicit binary paths or an existing PATH directory without changing shell profiles during acceptance.

## Before a release

Every row below is a release preparation requirement. Record the candidate commit, version, build configuration, results, and links to evidence. An unresolved required check stops preparation until it passes or its scope is explicitly decided by the release owner. Paused acceptance work does not become a pass.

| Step | Required check | Evidence / stop condition |
|---|---|---|
| 1. Freeze the candidate | Reviewed source, clean worktree, chosen version, tag/source agreement | Record full commit and intended tag. Uncommitted content cannot be published as that commit. |
| 2. Run code checks | Native ordinary/race tests, vet, Python/workflow regressions | Check actual named results and expected platforms. Missing, failed, or skipped required cases stop the release. |
| 3. Check known Go vulnerabilities | All four packaged targets, matching candidate commit and configured Go toolchain | Require successful `govulncheck` results. Preserve findings and execution errors. Do not substitute an old green badge. |
| 4. Build and inspect archives | Pinned GoReleaser, four target archives, metadata, files, SHA-256 | Verify source/version and archive contents, including both README and maintenance documents. |
| 5. Check installation and acceptance | Isolated installation, configuration preservation, intended upgrade path, applicable manual checks | List OS/architecture and remaining Console/browser/layout gaps explicitly. |
| 6. Check release controls | Release owner approval, environment reviewers/tag restrictions, package destinations and credentials | Verify the settings before enabling publication. Never put token values in logs or evidence. |
| 7. Publish and verify | Exact authorized tag, downloaded assets, package versions, installation result | Publication and package updates are separate stages. A partial failure is not a completed release. |

### Local checks

Go 1.27.4, GoReleaser 2.14.3, and Python 3 match the current workflows. Use a native Go/C toolchain for race detection. Run from the repository root:

```sh
git status --short
git rev-parse HEAD
go test ./...
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...
git diff --check
```

The local `govulncheck` command scans the active Go build target. The separate [Go vulnerability workflow](../.github/workflows/go-vulnerability.yml) scans darwin/windows × amd64/arm64 with `CGO_ENABLED=0` using pinned govulncheck v1.10.0. Tools are installed for the runner host before target settings are applied to the scan. The text-mode exit code is the gate, because JSON/SARIF modes have different exit semantics.

Four-target source scans passed locally with Go 1.27.4 and reported no reachable known vulnerabilities. Verify the remote workflow result for the exact candidate commit before publication. A scan covers known vulnerabilities for its toolchain, target, and database state, rather than establishing complete security.

**Release wiring:** [release.yml](../.github/workflows/release.yml) currently waits for reusable [ci.yml](../.github/workflows/ci.yml). It does not automatically wait for the independent vulnerability workflow. The maintainer must verify successful scans for the same source commit before creating the release tag. This documentation update does not add an automated dependency or change publication permissions.

### Package without publishing

Set Python UTF-8 behavior for the current session before running maintenance tools.

macOS / Linux shell:

```sh
export PYTHONUTF8=1 PYTHONIOENCODING=utf-8
```

Windows PowerShell:

```powershell
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
```

Preserve any files you need from `dist/` first. `--clean` replaces that output directory.

```sh
goreleaser --version
goreleaser check
python3 -B -m unittest discover -s scripts -v
goreleaser release --snapshot --clean --skip=publish
python3 -B scripts/release.py verify
```

On a supported native macOS/Windows host, verify the matching snapshot installation:

```sh
python3 -B scripts/install_check.py
```

Do not run the native installation check on Linux expecting a Linux archive. The configured matrix produces four archives for macOS/Windows only. A Linux host can cross-build those archives without proving native installation.

Snapshot versions use `0.0.0-snapshot-<short-commit>-dirty`, including clean CI runs. A snapshot can include uncommitted files, so its HEAD metadata alone does not identify its full content. Archives are named `tlscheck_<version>_<os>_<arch>`, with macOS tar.gz and Windows ZIP. Each contains the binary, LICENSE, both README files, and both maintenance guides. `checksums.txt` covers all four archives.

`install_check.py` installs and reinstalls in a temporary directory, checks `--version`, and verifies real configuration and an isolated sentinel are unchanged. It proves neither package-manager installation nor a cross-version upgrade. GoReleaser has publishing disabled in [.goreleaser.yaml](../.goreleaser.yaml). `scripts/release.py verify` performs local archive validation.

`packages --tag` generates local `dist/tlscheck.rb` and `dist/tlscheck.json`. The tag must match the exact archive version with a leading `v`. Snapshot URLs are not real GitHub downloads and must never be submitted as stable package updates. Use `python3 -B scripts/release.py --help` for the stage interface.

For workflow lint, install the pinned Actionlint v1.7.12 and run `python3 -B scripts/lint_workflows.py`. The wrapper accepts only the precise unsupported `queue: max` diagnostic after checking its contract. All other diagnostics remain failures.

## Publication controls and retry

The [release workflow](../.github/workflows/release.yml) starts on a pushed `v*` tag or manual dispatch. Its publication job additionally requires a tag ref, `ENABLE_RELEASE=true`, successful reusable CI, and the `release` environment. Package updates additionally require manual dispatch with `update_packages=true`, which defaults to false. Tag-triggered releases never update Homebrew/Scoop automatically. Configure required reviewers and tag restrictions before enabling the variable. This document does not create those settings or grant permission to publish.

The main repository uses the publication job's `GITHUB_TOKEN` with contents write, exposed to the publisher as `GH_TOKEN`. `PACKAGE_REPOSITORY_TOKEN` must be a fine-grained credential limited to the two approved package repositories. Pull-request checks receive no publication secrets.

The publisher requires `--execute`, `RELEASE_APPROVED` equal to the exact tag, a clean worktree, HEAD equal to the tag commit, and matching GoReleaser metadata. It creates a draft, records the source commit, uploads missing assets, downloads and compares every asset, and then publishes. Unknown sources, unexpected assets, or different bytes under an existing name stop the process.

Package updates recheck the published assets. Prereleases leave stable packages unchanged. Newer package versions are not downgraded, identical same-version content is accepted, and conflicting same-version content is rejected. GitHub Contents API SHA conditions protect against concurrent updates. All release jobs share the noncancelling `tlscheck-stable-release` concurrency group with `queue: max`. Queue order is not assumed to be version order, so version checks remain necessary.

| Failure stage | Retry rule |
|---|---|
| Code checks, vulnerability scan, or packaging | Correct the cause and repeat the failed check against the candidate. Keep the original result. |
| Draft assets incomplete | Reverify source and all existing assets before filling missing ones. Only a source-verified unpublished draft can have an empty `starter` asset removed and retried. |
| Published assets conflict | Stop for review. Do not overwrite assets, recreate the tag, or delete source markers. |
| Release succeeded, package update failed | Keep the Release intact. Rerun the same authorized tag workflow after reviewing the failed stage. |
| Old version is retried | Compare stable versions again. Older versions must not replace Latest or downgrade packages. |

A successful release needs actual download, checksum, version, package installation/upgrade, and configuration-preservation evidence for the agreed scope. Controlled FakeAPI tests cover retry decisions, not live GitHub publication. Cross-version upgrades, real remote retries, signing/notarization, and the remaining manual checks still need their own acceptance records. See the [README](../README.md) for the current CLI contract.
