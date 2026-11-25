"""SBOMBox CLI package.

Command-line interface for generating, scoring, and managing SBOMs. Built on
Typer + Rich; the heavy lifting is delegated to :mod:`sbombox_core`.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    # Single source of truth: the version in packages/cli/pyproject.toml, as
    # installed. Never hardcode it here, or the two drift apart.
    __version__ = version("sbombox")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without install
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
