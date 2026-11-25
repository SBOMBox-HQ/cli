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

### First release

PyPI keeps only one *pending* trusted publisher per repository, workflow and environment, so the two projects are set up one after the other:

1. On pypi.org, under **Account → Publishing**, add a pending publisher for `sbombox-core`: owner `SBOMBox-HQ`, repository `cli`, workflow `publish.yml`, environment `pypi`.
2. Push the first tag. The workflow publishes `sbombox-core`, which creates the project, then fails on `sbombox`. That is expected.
3. Add the same publisher for `sbombox`. PyPI now accepts it, because the `sbombox-core` one is no longer pending.
4. Re-run the failed jobs of that workflow run. `sbombox-core` is skipped as already published, `sbombox` is published, and the GitHub release is created.

Later releases need nothing beyond pushing the tag.

## Security

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
