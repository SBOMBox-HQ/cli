# SBOMBox CLI

Generate, score, check and upload SBOMs from the command line.

This repository holds two Python packages, released together at the same version:

| Package | PyPI | What it is |
|---|---|---|
| `packages/cli` | [`sbombox`](https://pypi.org/project/sbombox/) | The `sbombox` command |
| `packages/core` | [`sbombox-core`](https://pypi.org/project/sbombox-core/) | Library to parse, validate, score and check compliance of SBOMs |

## Install

```sh
curl -fsSL https://sbombox.com/install.sh | sh
```

The installer sets up the CLI and an SBOM generator (syft). To install the CLI only:

```sh
uv tool install sbombox
```

Docs: [sbombox.com/docs/cli](https://sbombox.com/docs/cli). In CI, use the [GitHub Action](https://github.com/sbombox-hq/action).

## Develop

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12+.

```sh
uv sync --all-packages --all-extras
uv run pytest
uv run sbombox --help
```

## Release

1. Set the same `version` in `packages/core/pyproject.toml` and `packages/cli/pyproject.toml`.
2. Merge to `main`, then push a matching tag: `git tag v0.2.0 && git push origin v0.2.0`.
3. [`publish.yml`](.github/workflows/publish.yml) tests, builds and publishes both packages to PyPI through trusted publishing (no stored token), with build-provenance attestations, and creates a GitHub release with the wheels, `SHA256SUMS` and the CLI's own SBOM.

Releases run in the `pypi` environment; add required reviewers there if a release should need a second approval.

## Security

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
