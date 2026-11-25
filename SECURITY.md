# Security policy

The SBOMBox CLI runs on developer machines and in CI and handles your SBOMs and API credentials, so we treat its security as seriously as the SBOMBox platform's.

## Reporting a vulnerability

**Please don't open a public issue, discussion or pull request for a security problem.**

Report it privately, either way:

- **GitHub:** use **Report a vulnerability** on this repository's [Security tab](https://github.com/sbombox-hq/cli/security/advisories/new).
- **Email:** `dpo@sbombox.com`. The same channel is listed in [sbombox.com/.well-known/security.txt](https://sbombox.com/.well-known/security.txt).

Please include:

- What the issue is and what an attacker could do with it.
- Steps to reproduce, or a proof of concept.
- The CLI version (`sbombox --version`) or commit SHA you tested.
- Whether the issue is already public.

## What to expect

- **Acknowledgement** within 3 business days.
- **A fix** within 14 days for confirmed critical and high-severity issues, depending on complexity.
- **Coordinated disclosure.** We publish a GitHub security advisory once a fix is released, and credit you unless you'd rather stay anonymous.
- **Safe harbor.** We won't pursue legal action against researchers who report in good faith and follow this policy.

## Supported versions

Security fixes go into the latest release on PyPI. The SBOMBox API can refuse CLI versions below a minimum, so an unsafe version can be retired for everyone; upgrade with `uv tool upgrade sbombox` or re-run the installer.

## Scope

In scope: the `sbombox` and `sbombox-core` packages, the release workflow, and how they handle tokens, credentials and SBOM files. The SBOMBox API, web app and GitHub Action are covered by the same reporting channel and policy. Issues in third-party generators the CLI runs, such as syft, should go to those projects first.
