"""Configuration loader for the SBOMBox CLI.

Reads settings from ``.sbombox.yml`` (if present in the current directory) and
environment variables.  Env vars always take precedence over file values.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from ruamel.yaml import YAML

_DEFAULT_API_URL = "https://api.sbombox.com"
_CONFIG_FILENAME = ".sbombox.yml"

# Environment-variable names -------------------------------------------------

_ENV_TOKEN = "SBOMBOX_TOKEN"
_ENV_PROJECT = "SBOMBOX_PROJECT"
_ENV_API_URL = "SBOMBOX_API_URL"


def _load_yaml(path: Path) -> Dict[str, Any]:
    """Return parsed YAML dict or empty dict when file is missing/empty."""
    if not path.is_file():
        return {}
    yaml = YAML()
    data = yaml.load(path)
    return data if isinstance(data, dict) else {}


@dataclass
class CliConfig:
    """Resolved CLI configuration."""

    api_url: str = _DEFAULT_API_URL
    token: Optional[str] = None
    project_id: Optional[str] = None
    default_format: str = "spdx"
    _raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    # -- factory --------------------------------------------------------------

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> CliConfig:
        """Build config from file + env vars.

        Parameters
        ----------
        config_path:
            Override the default ``.sbombox.yml`` lookup path.  Mainly useful
            for testing.
        """
        path = config_path or Path.cwd() / _CONFIG_FILENAME
        raw = _load_yaml(path)

        api_url = raw.get("api_url", _DEFAULT_API_URL)
        token = raw.get("token")
        project_id = raw.get("project_id")
        default_format = raw.get("default_format", "spdx")

        # Env-var overrides ------------------------------------------------
        if os.environ.get(_ENV_API_URL):
            api_url = os.environ[_ENV_API_URL]
        if os.environ.get(_ENV_TOKEN):
            token = os.environ[_ENV_TOKEN]
        if os.environ.get(_ENV_PROJECT):
            project_id = os.environ[_ENV_PROJECT]

        # Fall back to the token saved by ``sbombox login`` (keyring, then a
        # 0600 file) when neither the config file nor the environment sets one.
        if not token:
            from sbombox_cli.auth import load_token

            token = load_token()

        return cls(
            api_url=api_url,
            token=token,
            project_id=project_id,
            default_format=default_format,
            _raw=raw,
        )


def load_config(config_path: Optional[Path] = None) -> CliConfig:
    """Load the effective CLI configuration.

    Thin module-level wrapper so commands can ``from sbombox_cli.config import
    load_config`` without depending on the dataclass name.
    """
    return CliConfig.load(config_path)
