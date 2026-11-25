"""Server-driven update notices and the 426 upgrade path."""
from __future__ import annotations

import httpx
import pytest

from sbombox_cli.api_client import EXIT_UPGRADE, ApiClient, ApiError
from sbombox_cli.config import CliConfig
from sbombox_cli.update_check import parse_version, update_notice


def test_parse_version() -> None:
    assert parse_version("0.2.0") == (0, 2, 0)
    assert parse_version("v1.2") == (1, 2, 0)
    assert parse_version("0.0.0+unknown") == (0, 0, 0)
    assert parse_version("nope") is None


def test_newer_release_is_announced() -> None:
    message = update_notice({"latest_version": "0.3.0", "min_supported_version": None}, current="0.2.0")
    assert message and "0.3.0 is available" in message


def test_below_minimum_is_unsupported() -> None:
    message = update_notice({"latest_version": "0.3.0", "min_supported_version": "0.2.5"}, current="0.2.0")
    assert message and "no longer supported" in message


def test_up_to_date_is_silent() -> None:
    assert update_notice({"latest_version": "0.2.0"}, current="0.2.0") is None
    assert update_notice(None, current="0.2.0") is None


def test_server_426_maps_to_exit_6(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(426, json={"detail": "sbombox 0.1.0 is no longer supported"})

    client = ApiClient(CliConfig(api_url="https://api.test", token="t"))
    client._client = httpx.Client(base_url="https://api.test", transport=httpx.MockTransport(handler))
    with pytest.raises(ApiError) as exc:
        client.whoami()
    assert exc.value.exit_code == EXIT_UPGRADE
    assert "no longer supported" in str(exc.value)
