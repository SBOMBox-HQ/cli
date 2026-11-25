"""Pydantic models for the normalised SBOM domain.

The layout mirrors the domain rather than any single specification:

``sbom``
    The document itself (:class:`Sbom`) and which spec it came from.
``component``, ``common``, ``metadata``, ``dependency``, ``service``
    The parts of a document.
``vulnerability``, ``vex``
    Security information attached to those parts.
``results``
    The outputs of scoring, compliance, diff and fix runs.

Import from :mod:`sbombox_core.model` (or from :mod:`sbombox_core` for the
handful of top-level names) rather than reaching into submodules.
"""

from __future__ import annotations

from sbombox_core.model.common import (
    Contact,
    ExternalReference,
    Hash,
    HashAlgorithm,
    License,
    LicenseChoice,
    Property,
    Supplier,
)
from sbombox_core.model.component import COMPONENT_TYPE_ALIASES, Component, ComponentType
from sbombox_core.model.dependency import Dependency
from sbombox_core.model.metadata import Metadata, Tool, split_name_email
from sbombox_core.model.results import (
    ComplianceResult,
    ComponentChange,
    DiffResult,
    FixChange,
    FixResult,
    Grade,
    RequirementResult,
    ScoreCategory,
    ScoreFeature,
    ScoreResult,
)
from sbombox_core.model.sbom import Sbom, SbomFormat
from sbombox_core.model.service import Service, ServiceData, ServiceDataFlow
from sbombox_core.model.vex import VexJustification, VexStatement, VexStatus
from sbombox_core.model.vulnerability import (
    Advisory,
    AffectedTarget,
    AffectedVersion,
    Severity,
    Vulnerability,
    VulnerabilityRating,
    VulnerabilitySource,
)

__all__ = [
    "COMPONENT_TYPE_ALIASES",
    "Advisory",
    "AffectedTarget",
    "AffectedVersion",
    "ComplianceResult",
    "Component",
    "ComponentChange",
    "ComponentType",
    "Contact",
    "Dependency",
    "DiffResult",
    "ExternalReference",
    "FixChange",
    "FixResult",
    "Grade",
    "Hash",
    "HashAlgorithm",
    "License",
    "LicenseChoice",
    "Metadata",
    "Property",
    "RequirementResult",
    "Sbom",
    "SbomFormat",
    "ScoreCategory",
    "ScoreFeature",
    "ScoreResult",
    "Service",
    "ServiceData",
    "ServiceDataFlow",
    "Severity",
    "Supplier",
    "Tool",
    "VexJustification",
    "VexStatement",
    "VexStatus",
    "Vulnerability",
    "VulnerabilityRating",
    "VulnerabilitySource",
    "split_name_email",
]
