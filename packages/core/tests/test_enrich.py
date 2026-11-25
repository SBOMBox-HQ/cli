"""Tests for the sbombox_core.enrich adapters."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from sbombox_core.model.component import Component
from sbombox_core.enrich import (
    ADAPTERS,
    _enrich_crates,
    _enrich_deps_dev,
    _enrich_ecosystems,
    _enrich_maven,
    _enrich_npm,
    _enrich_pypi,
    enrich_component,
)


# ------------------------------------------------------------------ helpers


def _make_mock_client(json_data: dict, status_code: int = 200) -> MagicMock:
    """Return a mock that quacks like the ``(client, owned)`` tuple from ``_get_client``."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = json_data
    mock_resp.raise_for_status = MagicMock()

    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp
    mock_client.post.return_value = mock_resp
    return mock_client


def _patch_client(mock_client: MagicMock):
    """Patch ``_get_client`` so adapters use *mock_client* without opening a real connection."""
    return patch("sbombox_core.enrich._get_client", return_value=(mock_client, False))


def _parsed(**overrides: str) -> MagicMock:
    """Minimal stand-in for a ``PackageURL`` returned by ``parse_purl``."""
    defaults = dict(type="pypi", name="requests", version="2.28.0", namespace=None)
    defaults.update(overrides)
    m = MagicMock()
    for k, v in defaults.items():
        setattr(m, k, v)
    return m


# --------------------------------------------------------------- PyPI


class TestEnrichPypi:
    def test_enrich_pypi_success(self) -> None:
        component = Component(name="requests", version="2.28.0")
        payload = {
            "info": {
                "summary": "HTTP for humans",
                "author": "Kenneth Reitz",
                "license": "Apache-2.0",
            },
            "urls": [{"digests": {"sha256": "deadbeef" * 8}}],
        }
        mock_client = _make_mock_client(payload)

        with _patch_client(mock_client):
            result = _enrich_pypi(component, _parsed())

        assert result is component
        assert result.description == "HTTP for humans"
        assert result.supplier is not None
        assert result.supplier.name == "Kenneth Reitz"
        assert len(result.licenses) == 1
        assert result.licenses[0].expression == "Apache-2.0"
        assert len(result.hashes) == 1
        assert result.hashes[0].alg == "SHA-256"

    def test_enrich_pypi_network_error_returns_unchanged(self) -> None:
        component = Component(name="requests", version="2.28.0")
        mock_client = MagicMock()
        mock_client.get.side_effect = httpx.RequestError("connection refused", request=MagicMock())

        with _patch_client(mock_client):
            result = _enrich_pypi(component, _parsed())

        assert result is component
        assert result.description is None
        assert result.supplier is None
        assert result.licenses == []
        assert result.hashes == []


# ---------------------------------------------------------------- npm


class TestEnrichNpm:
    def test_enrich_npm_success(self) -> None:
        component = Component(name="lodash", version="4.17.21")
        payload = {
            "description": "Lodash modular utilities",
            "author": {"name": "John-David Dalton"},
            "license": "MIT",
            "dist": {"shasum": "abc123"},
        }
        mock_client = _make_mock_client(payload)

        with _patch_client(mock_client):
            result = _enrich_npm(component, _parsed(type="npm", name="lodash", version="4.17.21"))

        assert result is component
        assert result.description == "Lodash modular utilities"
        assert result.supplier is not None
        assert result.supplier.name == "John-David Dalton"
        assert len(result.licenses) == 1
        assert result.licenses[0].expression == "MIT"
        assert len(result.hashes) == 1
        assert result.hashes[0].alg == "SHA-1"

    def test_enrich_npm_network_error_returns_unchanged(self) -> None:
        component = Component(name="lodash", version="4.17.21")
        mock_client = MagicMock()
        mock_client.get.side_effect = httpx.RequestError("timeout", request=MagicMock())

        with _patch_client(mock_client):
            result = _enrich_npm(component, _parsed(type="npm", name="lodash", version="4.17.21"))

        assert result is component
        assert result.description is None


# ------------------------------------------------------------- crates.io


class TestEnrichCrates:
    def test_enrich_crates_success(self) -> None:
        component = Component(name="serde", version="1.0.0")
        payload = {
            "crate": {
                "description": "A serialization framework",
                "created_by": "dtolnay",
            },
            "version": {
                "license": "MIT OR Apache-2.0",
                "published_by": {"name": "dtolnay"},
            },
        }
        mock_client = _make_mock_client(payload)

        with _patch_client(mock_client):
            result = _enrich_crates(
                component, _parsed(type="cargo", name="serde", version="1.0.0")
            )

        assert result is component
        assert result.description == "A serialization framework"
        assert result.supplier is not None
        assert result.supplier.name == "dtolnay"
        assert len(result.licenses) == 1
        assert result.licenses[0].expression == "MIT OR Apache-2.0"


# --------------------------------------------------------------- Maven


class TestEnrichMaven:
    def test_enrich_maven_success(self) -> None:
        component = Component(
            name="commons-lang3",
            version="3.12.0",
            purl="pkg:maven/org.apache.commons/commons-lang3@3.12.0",
        )
        payload = {
            "response": {
                "docs": [{"description": "Apache Commons Lang"}],
            },
        }
        mock_client = _make_mock_client(payload)

        with _patch_client(mock_client):
            result = _enrich_maven(
                component,
                _parsed(type="maven", name="commons-lang3", version="3.12.0", namespace="org.apache.commons"),
            )

        assert result is component
        assert result.description == "Apache Commons Lang"


# ------------------------------------------------------------- deps.dev


class TestEnrichDepsDev:
    def test_enrich_deps_dev_success(self) -> None:
        component = Component(name="requests", version="2.28.0")
        payload = {"license": ["Apache-2.0"]}
        mock_client = _make_mock_client(payload)

        with _patch_client(mock_client):
            result = _enrich_deps_dev(component, _parsed())

        assert result is component
        assert len(result.licenses) == 1
        assert "Apache-2.0" in result.licenses[0].expression


# ---------------------------------------------------------- ecosyste.ms


class TestEnrichEcosystems:
    def test_enrich_ecosystems_success(self) -> None:
        component = Component(name="requests", version="2.28.0")
        payload = {
            "description": "HTTP library",
            "licenses": ["MIT"],
            "maintainers": [{"name": "kennethreitz"}],
        }
        mock_client = _make_mock_client(payload)

        with _patch_client(mock_client):
            result = _enrich_ecosystems(component, _parsed())

        assert result is component
        assert result.description == "HTTP library"
        assert len(result.licenses) == 1
        assert result.licenses[0].expression == "MIT"
        assert result.supplier is not None
        assert result.supplier.name == "kennethreitz"


# -------------------------------------------------------- dispatch / edge


class TestEnrichComponentDispatch:
    def test_enrich_component_dispatches_to_adapter(self) -> None:
        component = Component(
            name="requests",
            version="2.28.0",
            purl="pkg:pypi/requests@2.28.0",
        )
        mock_adapter = MagicMock(return_value=component)
        with patch.dict(ADAPTERS, {"pypi": mock_adapter}):
            result = enrich_component(component)

        mock_adapter.assert_called_once()
        assert result is component

    def test_enrich_unknown_ecosystem_returns_unchanged(self) -> None:
        component = Component(
            name="mystery",
            version="1.0",
            purl="pkg:unknown/mystery@1.0",
        )
        result = enrich_component(component)
        assert result is component
        assert result.description is None

    def test_enrich_no_purl_returns_unchanged(self) -> None:
        component = Component(name="orphan", version="0.1")
        result = enrich_component(component)
        assert result is component
