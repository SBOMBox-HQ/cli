"""Reference SBOM documents, one per supported serialisation.

Every fixture is deliberately small but *complete*: each carries the fields the
parser is expected to map (purls, hashes, licenses in both the ``id`` and the
``expression`` spelling, suppliers, external references, dependency edges,
vulnerabilities, services) so that a mapping regression shows up as a failed
assertion rather than as silent data loss.

They are also deliberately imperfect in places - a digest too short for its
algorithm, a ``dependsOn`` pointing at nothing - because a validator with
nothing to find proves nothing.  Those defects are warnings, not errors, so the
documents stay "valid" in the sense a caller cares about: usable.
"""

from __future__ import annotations

import json
from typing import Any

#: CycloneDX 1.6, JSON.  Uses the 1.5+ ``metadata.tools.components`` shape.
CDX_JSON: dict[str, Any] = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "version": 1,
    "metadata": {
        "timestamp": "2024-05-01T10:00:00Z",
        "tools": {"components": [{"type": "application", "name": "syft", "version": "1.4.1"}]},
        "authors": [{"name": "Jane Doe", "email": "jane@example.com"}],
        "component": {
            "bom-ref": "pkg:generic/acme-app@1.0.0",
            "type": "application",
            "name": "acme-app",
            "version": "1.0.0",
        },
        "supplier": {"name": "Acme Inc", "url": ["https://acme.example.com"]},
    },
    "components": [
        {
            "bom-ref": "pkg:npm/express@4.18.2",
            "type": "library",
            "name": "express",
            "version": "4.18.2",
            "purl": "pkg:npm/express@4.18.2",
            "supplier": {"name": "TJ Holowaychuk"},
            "licenses": [{"license": {"id": "MIT"}}],
            "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
            "externalReferences": [{"type": "website", "url": "https://expressjs.com"}],
            "properties": [{"name": "syft:language", "value": "javascript"}],
            "scope": "required",
        },
        {
            "bom-ref": "pkg:pypi/requests@2.31.0",
            "type": "library",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
            "licenses": [{"expression": "Apache-2.0 AND MIT"}],
        },
    ],
    "dependencies": [
        {"ref": "pkg:generic/acme-app@1.0.0", "dependsOn": ["pkg:npm/express@4.18.2"]},
        {"ref": "pkg:npm/express@4.18.2", "dependsOn": ["pkg:pypi/requests@2.31.0", "missing-ref"]},
    ],
    "vulnerabilities": [
        {
            "bom-ref": "vuln-1",
            "id": "CVE-2022-24999",
            "source": {"name": "NVD", "url": "https://nvd.nist.gov"},
            "ratings": [{"source": {"name": "NVD"}, "score": 7.5, "severity": "high", "method": "CVSSv31"}],
            "description": "qs prototype pollution",
            "recommendation": "Upgrade express",
            "advisories": [{"title": "GHSA", "url": "https://github.com/advisories/GHSA-2022"}],
            "affects": [{"ref": "pkg:npm/express@4.18.2"}],
        }
    ],
    "services": [
        {
            "bom-ref": "svc-1",
            "name": "api",
            "version": "1.0",
            "endpoints": ["https://api.example.com/v1"],
            "authenticated": True,
            "x-trust-boundary": True,
            "data": [{"flow": "inbound", "classification": "public", "name": "requests"}],
        }
    ],
    "externalReferences": [{"type": "vcs", "url": "https://github.com/acme/app"}],
}

#: ``CDX_JSON`` with one unrepresentable record appended.  A component with no
#: name cannot become a :class:`Component`, so the parser drops it and records
#: the drop rather than failing the whole document - real-world SBOMs are full of
#: such records, and losing the other 400 components because of one is not an
#: acceptable trade.
CDX_JSON_SALVAGE: dict[str, Any] = {
    **CDX_JSON,
    "components": [*CDX_JSON["components"], {"bom-ref": "broken", "type": "library"}],
}

#: CycloneDX 1.5, XML.  The legacy ``<tools><tool>`` spelling, and a hash that
#: is too short for its algorithm, so the semantic layer has something to find.
CDX_XML: bytes = b"""<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" serialNumber="urn:uuid:1" version="1">
  <metadata>
    <timestamp>2024-05-01T10:00:00Z</timestamp>
    <tools>
      <tool><vendor>anchore</vendor><name>syft</name><version>0.90.0</version></tool>
    </tools>
    <component type="application" bom-ref="app-1">
      <name>acme-app</name><version>1.0.0</version>
    </component>
  </metadata>
  <components>
    <component type="library" bom-ref="pkg:npm/express@4.18.2">
      <name>express</name>
      <version>4.18.2</version>
      <purl>pkg:npm/express@4.18.2</purl>
      <licenses><license><id>MIT</id></license></licenses>
      <hashes><hash alg="SHA-256">bbbb</hash></hashes>
      <externalReferences>
        <externalReference type="website"><url>https://expressjs.com</url></externalReference>
      </externalReferences>
      <properties><property name="k">v</property></properties>
    </component>
    <component type="library" bom-ref="pkg:pypi/requests@2.31.0">
      <name>requests</name><version>2.31.0</version>
      <purl>pkg:pypi/requests@2.31.0</purl>
      <licenses><expression>Apache-2.0 AND MIT</expression></licenses>
    </component>
  </components>
  <dependencies>
    <dependency ref="app-1">
      <dependency ref="pkg:npm/express@4.18.2"/>
    </dependency>
  </dependencies>
  <vulnerabilities>
    <vulnerability bom-ref="v1">
      <id>CVE-2022-24999</id>
      <source name="NVD"/>
      <ratings>
        <rating><score>7.5</score><severity>high</severity><method>CVSSv31</method></rating>
      </ratings>
      <description>qs prototype pollution</description>
      <recommendations><recommendation>Upgrade</recommendation></recommendations>
      <affects><target><ref>pkg:npm/express@4.18.2</ref></target></affects>
    </vulnerability>
  </vulnerabilities>
</bom>
"""

#: CycloneDX 1.4, YAML - the oldest supported spec version and the one format
#: that is neither JSON nor XML.
CDX_YAML: str = """bomFormat: CycloneDX
specVersion: "1.4"
version: 1
metadata:
  timestamp: "2024-05-01T10:00:00Z"
components:
  - type: library
    bom-ref: pkg:npm/express@4.18.2
    name: express
    version: 4.18.2
    purl: pkg:npm/express@4.18.2
    licenses:
      - license:
          id: MIT
"""

#: SPDX 2.3, JSON.  Carries a ``DEPENDENCY_OF`` edge alongside the
#: ``DEPENDS_ON`` ones so the inverse relationship is exercised.
SPDX_JSON: dict[str, Any] = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "acme-app-1.0.0",
    "documentNamespace": "https://spdx.org/spdxdocs/acme-app-1.0.0",
    "creationInfo": {
        "created": "2024-05-01T10:00:00Z",
        "creators": ["Tool: syft-1.4.1", "Organization: Acme Inc", "Person: Jane Doe (jane@example.com)"],
        "licenseListVersion": "3.21",
    },
    "documentDescribes": ["SPDXRef-Package-app"],
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-app",
            "name": "acme-app",
            "versionInfo": "1.0.0",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "copyrightText": "Copyright Acme",
            "supplier": "Organization: Acme Inc",
            "primaryPackagePurpose": "APPLICATION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:generic/acme-app@1.0.0",
                }
            ],
        },
        {
            "SPDXID": "SPDXRef-Package-express",
            "name": "express",
            "versionInfo": "4.18.2",
            "downloadLocation": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
            "licenseConcluded": "MIT",
            "licenseDeclared": "NOASSERTION",
            "originator": "Person: TJ Holowaychuk",
            "checksums": [{"algorithm": "SHA256", "checksumValue": "a" * 64}],
            "homepage": "https://expressjs.com",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:npm/express@4.18.2",
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:express:express:4.18.2:*:*:*:*:*:*:*",
                },
            ],
        },
        {
            "SPDXID": "SPDXRef-Package-requests",
            "name": "requests",
            "versionInfo": "2.31.0",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "Apache-2.0 AND MIT",
        },
    ],
    "relationships": [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-app",
        },
        {
            "spdxElementId": "SPDXRef-Package-app",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-Package-express",
        },
        {
            "spdxElementId": "SPDXRef-Package-express",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-Package-requests",
        },
        {
            "spdxElementId": "SPDXRef-Package-requests",
            "relationshipType": "DEPENDENCY_OF",
            "relatedSpdxElement": "SPDXRef-Package-express",
        },
    ],
}

#: SPDX 3.0.1, JSON-LD.  A completely different vocabulary - ``@graph`` of
#: typed elements, ``from``/``to`` relationship endpoints, ``packageVersion``,
#: structured license objects - normalised onto the 2.x shape before mapping.
SPDX3_JSONLD: dict[str, Any] = {
    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
    "@graph": [
        {
            "@type": "SpdxDocument",
            "spdxId": "SPDXRef-DOCUMENT",
            "name": "acme-app",
            "elementNamespace": "https://spdx.org/spdxdocs/acme-3",
            "specVersion": "3.0.1",
            "creationInfo": {
                "@type": "CreationInfo",
                "created": "2024-05-01T10:00:00Z",
                "createdBy": [{"@type": "Person", "name": "Jane Doe"}],
                "createdUsing": [{"@type": "Tool", "name": "sbombox", "version": "0.1.0"}],
                "specVersion": "3.0.1",
            },
            "element": ["SPDXRef-Package-app"],
        },
        {
            "@type": "software_Package",
            "spdxId": "SPDXRef-Package-app",
            "name": "acme-app",
            "packageVersion": "1.0.0",
            "downloadLocation": "https://acme.example.com/app.tgz",
            "licenseDeclared": {"@type": "ListedLicense", "licenseId": "Apache-2.0"},
            "primaryPackagePurpose": "application",
            "externalRef": [
                {
                    "@type": "externalMap",
                    "externalRefType": "purl",
                    "externalRefLocator": "pkg:generic/acme-app@1.0.0",
                }
            ],
            "checksum": [{"@type": "Checksum", "algorithm": "sha256", "checksumValue": "c" * 64}],
            "relationship": [{"relationshipType": "DEPENDS_ON", "to": ["SPDXRef-Package-lib"]}],
        },
        {
            "@type": "software_Package",
            "spdxId": "SPDXRef-Package-lib",
            "name": "acme-lib",
            "packageVersion": "2.1.0",
            "licenseDeclared": "MIT",
        },
    ],
}

#: SPDX 2.2, RDF/XML.  Everything is a URI, and relationship types are
#: camelCase (``dependsOn``) rather than ``DEPENDS_ON``.
SPDX_RDF: bytes = b"""<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:spdx="http://spdx.org/rdf/terms#"
         xmlns:doap="http://usefulinc.com/ns/doap#">
  <spdx:SpdxDocument rdf:about="https://spdx.org/spdxdocs/acme-2.2#SPDXRef-DOCUMENT">
    <spdx:specVersion>SPDX-2.2</spdx:specVersion>
    <spdx:name>acme-app</spdx:name>
    <spdx:dataLicense rdf:resource="http://spdx.org/licenses/CC0-1.0"/>
    <spdx:creationInfo>
      <spdx:CreationInfo>
        <spdx:created>2024-05-01T10:00:00Z</spdx:created>
        <spdx:creator>Tool: spdx-tools-1.0</spdx:creator>
        <spdx:licenseListVersion>3.17</spdx:licenseListVersion>
      </spdx:CreationInfo>
    </spdx:creationInfo>
    <spdx:relationship>
      <spdx:Relationship>
        <spdx:relationshipType rdf:resource="http://spdx.org/rdf/terms#relationshipType/describes"/>
        <spdx:relatedSpdxElement rdf:resource="https://spdx.org/spdxdocs/acme-2.2#SPDXRef-Package-app"/>
      </spdx:Relationship>
    </spdx:relationship>
  </spdx:SpdxDocument>
  <spdx:Package rdf:about="https://spdx.org/spdxdocs/acme-2.2#SPDXRef-Package-app">
    <spdx:name>acme-app</spdx:name>
    <spdx:versionInfo>1.0.0</spdx:versionInfo>
    <spdx:downloadLocation>NOASSERTION</spdx:downloadLocation>
    <spdx:licenseConcluded rdf:resource="http://spdx.org/licenses/Apache-2.0"/>
    <spdx:licenseDeclared rdf:resource="http://spdx.org/licenses/Apache-2.0"/>
    <spdx:supplier>Organization: Acme Inc</spdx:supplier>
    <spdx:checksum>
      <spdx:Checksum>
        <spdx:algorithm rdf:resource="http://spdx.org/rdf/terms#checksumAlgorithm_sha256"/>
        <spdx:checksumValue>dddd</spdx:checksumValue>
      </spdx:Checksum>
    </spdx:checksum>
    <spdx:externalRef>
      <spdx:ExternalRef>
        <spdx:referenceCategory rdf:resource="http://spdx.org/rdf/terms#referenceCategory_packageManager"/>
        <spdx:referenceType rdf:resource="http://spdx.org/rdf/references/purl"/>
        <spdx:referenceLocator>pkg:generic/acme-app@1.0.0</spdx:referenceLocator>
      </spdx:ExternalRef>
    </spdx:externalRef>
    <spdx:relationship>
      <spdx:Relationship>
        <spdx:relationshipType rdf:resource="http://spdx.org/rdf/terms#relationshipType/dependsOn"/>
        <spdx:relatedSpdxElement rdf:resource="https://spdx.org/spdxdocs/acme-2.2#SPDXRef-Package-lib"/>
      </spdx:Relationship>
    </spdx:relationship>
  </spdx:Package>
  <spdx:Package rdf:about="https://spdx.org/spdxdocs/acme-2.2#SPDXRef-Package-lib">
    <spdx:name>acme-lib</spdx:name>
    <spdx:versionInfo>2.0.0</spdx:versionInfo>
    <spdx:licenseConcluded>MIT</spdx:licenseConcluded>
  </spdx:Package>
</rdf:RDF>
"""

#: SPDX 2.3, tag-value.  No nesting at all, and a continuation line in
#: ``PackageDescription`` that must be folded back into one string.
SPDX_TAG_VALUE: str = """SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: acme-app-1.0.0
DocumentNamespace: https://spdx.org/spdxdocs/acme-tv
Creator: Tool: syft-1.4.1
Creator: Organization: Acme Inc
Created: 2024-05-01T10:00:00Z
CreatorComment: generated offline

PackageName: acme-app
SPDXID: SPDXRef-Package-app
PackageVersion: 1.0.0
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: Apache-2.0
PackageLicenseDeclared: Apache-2.0
PackageCopyrightText: Copyright Acme
PackageSupplier: Organization: Acme Inc
PrimaryPackagePurpose: APPLICATION
ExternalRef: PACKAGE-MANAGER purl pkg:generic/acme-app@1.0.0
PackageDescription: A multi line
 description here
Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-app

PackageName: express
SPDXID: SPDXRef-Package-express
PackageVersion: 4.18.2
PackageDownloadLocation: https://registry.npmjs.org/express/-/express-4.18.2.tgz
PackageLicenseConcluded: MIT
PackageChecksum: SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Relationship: SPDXRef-Package-app DEPENDS_ON SPDXRef-Package-express
"""

#: Every supported serialisation, as ``parse_sbom`` receives it.
DOCUMENTS: dict[str, bytes | str] = {
    "cyclonedx-json": json.dumps(CDX_JSON),
    "cyclonedx-xml": CDX_XML,
    "cyclonedx-yaml": CDX_YAML,
    "spdx-json": json.dumps(SPDX_JSON),
    "spdx3-jsonld": json.dumps(SPDX3_JSONLD),
    "spdx-rdf": SPDX_RDF,
    "spdx-tag-value": SPDX_TAG_VALUE,
}

#: ``(format, spec_version)`` each document must be sniffed as.
DETECTED: dict[str, tuple[str, str]] = {
    "cyclonedx-json": ("cyclonedx", "1.6"),
    "cyclonedx-xml": ("cyclonedx", "1.5"),
    "cyclonedx-yaml": ("cyclonedx", "1.4"),
    "spdx-json": ("spdx", "2.3"),
    "spdx3-jsonld": ("spdx", "3.0.1"),
    "spdx-rdf": ("spdx", "2.2"),
    "spdx-tag-value": ("spdx", "2.3"),
}
