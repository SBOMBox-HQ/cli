"""SPDX license identifier helpers built on ``license-expression``.

The SPDX license list is loaded once per process and cached: it contains a few
thousand symbols, so re-reading it while walking a large SBOM would dominate
runtime.
"""

from __future__ import annotations

from functools import lru_cache

from license_expression import ExpressionError, LicenseExpression, LicenseSymbol, Licensing, get_spdx_licensing

__all__ = [
    "SPDX_NOASSERTION",
    "SPDX_NONE",
    "extract_license_ids",
    "is_valid_spdx_license",
    "normalize_license_expression",
]

#: SPDX reserved value meaning "the license could not be determined".
SPDX_NOASSERTION = "NOASSERTION"
#: SPDX reserved value meaning "no license is applicable".
SPDX_NONE = "NONE"

_RESERVED_VALUES = frozenset({SPDX_NOASSERTION, SPDX_NONE})


@lru_cache(maxsize=1)
def _spdx_licensing() -> Licensing:
    """Return the cached SPDX-aware :class:`~license_expression.Licensing`."""
    licensing: Licensing = get_spdx_licensing()
    return licensing


@lru_cache(maxsize=1)
def _plain_licensing() -> Licensing:
    """Return a cached generic licensing engine for expression normalisation."""
    return Licensing()


def is_valid_spdx_license(license_id: str) -> bool:
    """Return ``True`` when *license_id* is a known SPDX license or exception.

    Accepts a bare identifier (``Apache-2.0``), an ``or-later`` suffix
    (``GPL-2.0+``) and full expressions (``MIT OR Apache-2.0``).  The SPDX
    reserved values ``NOASSERTION`` and ``NONE`` are treated as valid because
    they are legal document content, even though they are not licenses.

    Matching is case-insensitive in line with the SPDX specification's
    recommendation that identifiers be compared without regard to case.
    """
    if not license_id or not isinstance(license_id, str):
        return False

    candidate = license_id.strip()
    if not candidate:
        return False
    if candidate.upper() in _RESERVED_VALUES:
        return True

    licensing = _spdx_licensing()

    # Fast path: exact or case-folded symbol hit.
    if candidate in licensing.known_symbols or candidate.lower() in licensing.known_symbols:
        return True

    # ``LicenseRef-*`` and ``DocumentRef-*`` are user-defined but valid SPDX.
    if candidate.startswith(("LicenseRef-", "DocumentRef-", "AdditionRef-")):
        return True

    try:
        licensing.parse(candidate, validate=True)
    except ExpressionError:
        return False
    except Exception:  # noqa: BLE001 - any parse failure means "not valid"
        return False
    return True


def normalize_license_expression(expr: str) -> str:
    """Normalise *expr* into canonical SPDX form.

    Operators are upper-cased, redundant parentheses removed and known
    identifiers rendered with their canonical spelling
    (``apache-2.0`` -> ``Apache-2.0``).  Unparseable input is returned
    stripped but otherwise unchanged - normalisation must never lose data.
    """
    if not expr or not isinstance(expr, str):
        return ""

    candidate = expr.strip()
    if not candidate:
        return ""
    if candidate.upper() in _RESERVED_VALUES:
        return candidate.upper()

    licensing = _spdx_licensing()
    try:
        parsed: LicenseExpression | None = licensing.parse(candidate, validate=True)
    except Exception:  # noqa: BLE001 - fall through to the generic renderer
        parsed = None

    if parsed is not None:
        return str(parsed.render())

    # Unknown identifiers: still tidy up the boolean operators.
    try:
        generic = _plain_licensing().parse(candidate, validate=False)
    except Exception:  # noqa: BLE001
        return candidate
    if generic is None:
        return candidate
    return str(generic.render())


def extract_license_ids(expression: str) -> list[str]:
    """Return the individual license identifiers contained in *expression*.

    Operators and parentheses are discarded, duplicates removed and the order
    the identifiers appear in preserved.  Returns an empty list for empty input.
    """
    if not expression or not isinstance(expression, str):
        return []

    candidate = expression.strip()
    if not candidate:
        return []
    if candidate.upper() in _RESERVED_VALUES:
        return [candidate.upper()]

    parsed = None
    for licensing in (_spdx_licensing(), _plain_licensing()):
        try:
            parsed = licensing.parse(candidate, validate=False)
        except Exception:  # noqa: BLE001 - try the next engine
            parsed = None
        if parsed is not None:
            break

    if parsed is None:
        return [candidate]

    seen: dict[str, None] = {}
    for symbol in parsed.symbols:
        key = getattr(symbol, "key", None) or str(symbol)
        if isinstance(symbol, LicenseSymbol) and symbol.obj is not None:
            # Prefer the canonical SPDX spelling over the (lower-cased) key.
            canonical = getattr(symbol.obj, "spdx_license_key", None) or getattr(symbol.obj, "key", None)
            key = canonical or key
        if key:
            seen.setdefault(str(key), None)

    # ``symbols`` walks the parse tree, and the licensing engine is free to
    # canonicalise that tree, so a parenthesised expression can come back
    # re-ordered.  Sorting by first appearance in the source text keeps the
    # documented order and makes the result independent of the grouping.
    lowered = candidate.lower()
    return sorted(seen, key=lambda identifier: (_first_appearance(identifier, lowered), identifier))


def _first_appearance(identifier: str, lowered_expression: str) -> int:
    """Return where *identifier* first occurs, or a sort-last sentinel.

    The sentinel matters because a canonicalised spelling need not occur
    verbatim in the source (``Apache 2.0`` normalises to ``Apache-2.0``); such
    an identifier has no position to claim, so it goes to the end rather than
    to the front where ``str.find``'s ``-1`` would otherwise put it.
    """
    index = lowered_expression.find(identifier.lower())
    return index if index >= 0 else len(lowered_expression)
