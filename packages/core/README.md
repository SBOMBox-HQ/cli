# sbombox-core

Parse, validate, score, fix and check the compliance of software bills of materials (SBOMs) in CycloneDX and SPDX. This is the library behind the [SBOMBox CLI](https://pypi.org/project/sbombox/) and the SBOMBox platform.

- **Offline.** Nothing is fetched over the network, including schemas.
- **No framework dependencies.** Embed it in any Python 3.12+ application.
- **Formats.** CycloneDX (JSON, XML, YAML) and SPDX (JSON, tag-value), detected automatically.

## Install

```sh
pip install sbombox-core
```

## Usage

```python
from sbombox_core import load, validate_sbom, score, check_compliance, fix

sbom = load("bom.json")                  # path, bytes or text; format auto-detected

result = score(sbom)
print(result.total, result.grade)        # e.g. 8.12 B

report = validate_sbom(sbom)             # semantic findings; never raises
print(report.valid, len(report.issues))

ntia = check_compliance(sbom, "ntia-2021")
print(ntia.status)

fixed = fix(sbom)                        # repair common defects
```

Compliance rulesets: `ntia-2021`, `cisa-2025`, `cisa-2026`, `cra-readiness`, `bsi-tr-03183-2@2.1.0` (and earlier versions), `fsct-v3` and `openchain-telco`.

Lower-level entry points: `parse_sbom` for the parser, `validate_document` for schema and semantic validation of a raw document, `diff` to compare two SBOMs, and `sbombox_core.model` for the data model.

## Links

- Source and issues: [github.com/sbombox-hq/cli](https://github.com/sbombox-hq/cli)
- Docs: [sbombox.com/docs](https://sbombox.com/docs)

Licensed under Apache-2.0.
