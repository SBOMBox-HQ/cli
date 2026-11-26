# SBOMBox CLI

Generate, score, check and upload software bills of materials (SBOMs) from the command line. Works offline for everything except signing in and uploading.

## Install

```sh
curl -fsSL https://sbombox.com/install.sh | sh
```

The installer sets up the CLI and an SBOM generator (syft). If you already have a generator, install the CLI on its own:

```sh
uv tool install sbombox
```

Requires Python 3.12 or newer.

## Quick start

```sh
sbombox generate --dir . --output sbom.json     # make an SBOM for this project
sbombox score sbom.json                         # quality score from 0 to 10
sbombox compliance sbom.json --profile ntia     # check against a ruleset
sbombox fix sbom.json --output sbom.fixed.json  # repair common defects
```

To upload to SBOMBox:

```sh
sbombox login
sbombox push sbom.json
```

In CI, use the [GitHub Action](https://github.com/sbombox-hq/action) or run `sbombox ci` to let pipelines upload with their OIDC identity instead of a stored token. `sbombox check --fail-under 7` makes a quick local or pre-commit gate.

## Commands

| | |
|---|---|
| Set up | `login`, `logout`, `whoami`, `init`, `projects`, `ci` |
| Create and assess | `generate`, `check`, `score`, `compliance`, `list`, `fix`, `share` |
| Publish | `push`, `status` |
| Configure | `upgrade`, `config` |

Run `sbombox <command> --help` for options.

Compliance rulesets: NTIA minimum elements (`ntia-2021`), CISA (`cisa-2025`, `cisa-2026`), EU CRA readiness (`cra-readiness`), BSI TR-03183-2 (`bsi-tr-03183-2@2.1.0` and earlier), FSCT v3 (`fsct-v3`) and OpenChain Telco (`openchain-telco`).

## Usage data

To learn which commands are used and where they fail, the CLI sends anonymous usage data to SBOMBox: the command name, whether it succeeded, its exit code and duration, the CLI version, the OS, the CI provider if any, and a random installation ID. It never sends file names or paths, project or repository names, account details, tokens, or anything from an SBOM. Events are sent in small batches at most once an hour and never slow a command down.

The first time you run `sbombox` in a terminal it asks whether to share this. You can change your answer at any time:

| To | Do this |
|---|---|
| Turn it off for your user | `sbombox config --telemetry off` |
| Turn it back on | `sbombox config --telemetry on` |
| See whether it is on, and why | `sbombox config --telemetry status` |
| Skip it for one run | `sbombox --no-telemetry <command>` |
| Turn it off in CI or a container | `SBOMBOX_NO_TELEMETRY=1` or `DO_NOT_TRACK=1` |
| Turn it off for a repository | `telemetry: false` in `.sbombox.yml` |

In CI nothing asks; set one of the environment variables to opt out. Self-hosted installs send it to their own API (`SBOMBOX_API_URL`). Details: [sbombox.com/privacy](https://sbombox.com/privacy#tools).

## Links

- Docs: [sbombox.com/docs/cli](https://sbombox.com/docs/cli)
- Source and issues: [github.com/sbombox-hq/cli](https://github.com/sbombox-hq/cli)
- Security reports: see [SECURITY.md](https://github.com/sbombox-hq/cli/blob/main/SECURITY.md)

Licensed under Apache-2.0.
