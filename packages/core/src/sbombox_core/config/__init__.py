"""Scoring configuration - YAML template generation and validation.

Generates and validates scoring configuration templates that control which
features are enabled and their weights within each category.

Usage::

    from sbombox_core.config import generate_template, validate_config
    template = generate_template()
    is_valid = validate_config(template)
"""

from __future__ import annotations

from typing import Any

__all__ = ["generate_template", "validate_config", "DEFAULT_CONFIG"]

DEFAULT_CONFIG: dict[str, Any] = {
    "version": "1.0",
    "profile": "default",
    "categories": {
        "identification": {
            "enabled": True,
            "weight": 1.5,
            "features": {
                "purl_coverage": {"enabled": True},
                "cpe_coverage": {"enabled": True},
                "version_coverage": {"enabled": True},
                "name_coverage": {"enabled": True},
            },
        },
        "provenance": {
            "enabled": True,
            "weight": 1.0,
            "features": {
                "supplier_coverage": {"enabled": True},
                "author_coverage": {"enabled": True},
                "publisher_coverage": {"enabled": True},
                "any_provenance": {"enabled": True},
            },
        },
        "integrity": {
            "enabled": True,
            "weight": 1.5,
            "features": {
                "hash_coverage": {"enabled": True},
                "strong_hash_coverage": {"enabled": True},
            },
        },
        "completeness": {
            "enabled": True,
            "weight": 1.0,
            "features": {
                "graph_coverage": {"enabled": True},
                "graph_density": {"enabled": True},
            },
        },
        "licensing": {
            "enabled": True,
            "weight": 1.0,
            "features": {
                "license_coverage": {"enabled": True},
                "valid_spdx": {"enabled": True},
            },
        },
        "vulnerability": {
            "enabled": True,
            "weight": 0.5,
            "features": {
                "no_embedded_vulns": {"enabled": True},
            },
        },
        "structural": {
            "enabled": True,
            "weight": 0.5,
            "features": {
                "valid_format": {"enabled": True},
                "spec_version": {"enabled": True},
                "metadata_timestamp": {"enabled": True},
                "root_component": {"enabled": True},
            },
        },
        "component_quality": {
            "enabled": True,
            "weight": 1.0,
            "features": {
                "version_declared": {"enabled": True},
                "minimal_identity": {"enabled": True},
            },
        },
    },
}


def generate_template() -> dict[str, Any]:
    """Return a default scoring configuration template."""
    import copy

    return copy.deepcopy(DEFAULT_CONFIG)


def validate_config(config: dict[str, Any]) -> list[str]:
    """Validate a scoring configuration and return a list of errors.

    Returns an empty list when the configuration is valid.
    """
    errors: list[str] = []

    if "categories" not in config:
        errors.append("Missing 'categories' section.")
        return errors

    categories = config["categories"]
    if not isinstance(categories, dict):
        errors.append("'categories' must be a mapping.")
        return errors

    for cat_name, cat_config in categories.items():
        if not isinstance(cat_config, dict):
            errors.append(f"Category '{cat_name}' must be a mapping.")
            continue

        weight = cat_config.get("weight")
        if weight is not None:
            if not isinstance(weight, (int, float)) or weight < 0 or weight > 10:
                errors.append(f"Category '{cat_name}': weight must be 0-10, got {weight}.")

        features = cat_config.get("features", {})
        if not isinstance(features, dict):
            errors.append(f"Category '{cat_name}': 'features' must be a mapping.")
            continue

        for feat_name, feat_config in features.items():
            if not isinstance(feat_config, dict):
                errors.append(f"Category '{cat_name}', feature '{feat_name}': must be a mapping.")

    return errors
