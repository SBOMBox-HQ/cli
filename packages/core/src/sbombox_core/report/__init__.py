"""Report generation - output SBOM analysis in various formats.

Supported formats:
    - ``basic`` - short text summary.
    - ``detailed`` - full text report.
    - ``json`` - machine-readable JSON.
    - ``sarif`` - SARIF 2.1.0 for tool integration.
    - ``junit`` - JUnit XML for CI systems.
    - ``html`` - standalone HTML report.

Usage::

    from sbombox_core.report import render
    text = render(score_result, fmt="basic")
"""

from __future__ import annotations

import json
from typing import Any

from sbombox_core.model.results import ComplianceResult, ScoreResult

__all__ = ["render", "render_report"]


def render(
    result: ScoreResult | ComplianceResult,
    fmt: str = "basic",
) -> str:
    """Render a scoring or compliance result to the requested format.

    Args:
        result: A :class:`ScoreResult` or :class:`ComplianceResult`.
        fmt: Output format - ``"basic"``, ``"detailed"``, ``"json"``,
            ``"sarif"``, ``"junit"``, ``"html"``.

    Returns:
        The rendered report as a string.
    """
    fmt_lower = fmt.lower().strip()
    renderer = _RENDERERS.get(fmt_lower)
    if renderer is None:
        raise ValueError(f"Unknown report format: {fmt!r}. Choose from: {', '.join(sorted(_RENDERERS))}")
    return renderer(result)


#: Alias for callers that prefer an explicit verb.
render_report = render


# --------------------------------------------------------- format renderers


def _render_basic(result: ScoreResult | ComplianceResult) -> str:
    """Short text summary."""
    if isinstance(result, ScoreResult):
        return (
            f"SBOM Score: {result.total}/10 (Grade {result.grade})\n"
            f"Categories: {len(result.categories)}\n"
            f"Profile: {result.profile or 'default'}"
        )
    # ComplianceResult
    return (
        f"Compliance: {result.status}\n"
        f"Profile: {result.profile} {result.profile_version}\n"
        f"Required: {result.required_score}/10 | Optional: {result.optional_score}/10\n"
        f"Overall: {result.overall}/10\n"
        f"Requirements: {len(result.requirements)}"
    )


def _render_detailed(result: ScoreResult | ComplianceResult) -> str:
    """Full text report."""
    lines: list[str] = []
    if isinstance(result, ScoreResult):
        lines.append(f"SBOM Quality Score: {result.total}/10 (Grade {result.grade})")
        lines.append(f"Profile: {result.profile or 'default'}")
        lines.append(f"Core version: {result.core_version}")
        lines.append("")
        for cat in result.categories:
            lines.append(f"  {cat.name}: {cat.score}/10 (weight {cat.weight})")
            for feat in cat.features:
                lines.append(f"    - {feat.name}: {feat.score}/10 ({feat.numerator}/{feat.denominator})")
    else:
        lines.append(f"Compliance: {result.status}")
        lines.append(f"Profile: {result.profile} {result.profile_version}")
        lines.append(f"Required: {result.required_score}/10 | Optional: {result.optional_score}/10")
        lines.append(f"Overall: {result.overall}/10")
        lines.append("")
        for req in result.requirements:
            status_icon = {"pass": "✓", "partial": "~", "fail": "✗"}.get(req.status, "?")
            lines.append(f"  [{status_icon}] {req.id}: {req.title} ({req.status})")
            if req.message:
                lines.append(f"      {req.message}")
            if req.fix_hint and req.status != "pass":
                lines.append(f"      Fix: {req.fix_hint}")
    return "\n".join(lines)


def _render_json(result: ScoreResult | ComplianceResult) -> str:
    """Machine-readable JSON."""
    return result.model_dump_json(indent=2)


def _render_sarif(result: ScoreResult | ComplianceResult) -> str:
    """SARIF 2.1.0 for tool integration."""
    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "sbombox-core", "version": result.core_version}},
                "results": [],
            }
        ],
    }

    if isinstance(result, ScoreResult):
        for cat in result.categories:
            for feat in cat.features:
                if feat.score < 7.0:
                    sarif["runs"][0]["results"].append({
                        "ruleId": f"{cat.name}.{feat.name}",
                        "level": "warning" if feat.score >= 4.0 else "error",
                        "message": {"text": f"{feat.name}: {feat.score}/10 ({feat.numerator}/{feat.denominator})"},
                    })
    else:
        for req in result.requirements:
            if req.status != "pass":
                sarif["runs"][0]["results"].append({
                    "ruleId": req.id,
                    "level": "warning" if req.status == "partial" else "error",
                    "message": {"text": req.message or req.title},
                })

    return json.dumps(sarif, indent=2)


def _render_junit(result: ScoreResult | ComplianceResult) -> str:
    """JUnit XML for CI systems."""
    lines: list[str] = ['<?xml version="1.0" encoding="UTF-8"?>']

    if isinstance(result, ScoreResult):
        total_tests = sum(len(c.features) for c in result.categories)
        failures = sum(1 for c in result.categories for f in c.features if f.score < 7.0)
        lines.append(f'<testsuites tests="{total_tests}" failures="{failures}">')
        lines.append(f'  <testsuite name="sbom-score" tests="{total_tests}" failures="{failures}">')
        for cat in result.categories:
            for feat in cat.features:
                name = f"{cat.name}.{feat.name}"
                if feat.score < 7.0:
                    lines.append(f'    <testcase name="{name}"><failure message="{feat.score}/10"/></testcase>')
                else:
                    lines.append(f'    <testcase name="{name}"/>')
        lines.append("  </testsuite>")
    else:
        total_tests = len(result.requirements)
        failures = sum(1 for r in result.requirements if r.status == "fail")
        lines.append(f'<testsuites tests="{total_tests}" failures="{failures}">')
        lines.append(f'  <testsuite name="compliance-{result.profile}" tests="{total_tests}" failures="{failures}">')
        for req in result.requirements:
            if req.status == "fail":
                lines.append(f'    <testcase name="{req.id}"><failure message="{req.message}"/></testcase>')
            elif req.status == "partial":
                lines.append(f'    <testcase name="{req.id}"><failure message="{req.message}"/></testcase>')
            else:
                lines.append(f'    <testcase name="{req.id}"/>')
        lines.append("  </testsuite>")

    lines.append("</testsuites>")
    return "\n".join(lines)


def _render_html(result: ScoreResult | ComplianceResult) -> str:
    """Standalone HTML report."""
    if isinstance(result, ScoreResult):
        body = _html_score(result)
    else:
        body = _html_compliance(result)

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>SBOMBox Report</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; }}
h1 {{ color: #1a1a2e; }} .grade {{ font-size: 3rem; font-weight: bold; }}
.pass {{ color: #2d6a4f; }} .partial {{ color: #e9c46a; }} .fail {{ color: #e76f51; }}
table {{ border-collapse: collapse; width: 100%; }} th, td {{ border: 1px solid #ddd; padding: 0.5rem; text-align: left; }}
</style></head>
<body>{body}</body></html>"""


def _html_score(result: ScoreResult) -> str:
    grade_class = "pass" if result.total >= 7 else ("partial" if result.total >= 4 else "fail")
    rows = ""
    for cat in result.categories:
        for feat in cat.features:
            rows += f"<tr><td>{cat.name}</td><td>{feat.name}</td><td>{feat.score}/10</td><td>{feat.numerator}/{feat.denominator}</td></tr>"
    return f"""
<h1>SBOM Quality Report</h1>
<p class="grade {grade_class}">{result.total}/10 (Grade {result.grade})</p>
<table><tr><th>Category</th><th>Feature</th><th>Score</th><th>Coverage</th></tr>{rows}</table>"""


def _html_compliance(result: ComplianceResult) -> str:
    status_class = "pass" if result.status == "conforms" else ("partial" if result.status == "minor_gaps" else "fail")
    rows = ""
    for req in result.requirements:
        icon = {"pass": "✓", "partial": "~", "fail": "✗"}.get(req.status, "?")
        rows += f'<tr><td>{icon}</td><td>{req.id}</td><td>{req.title}</td><td class="{req.status}">{req.status}</td></tr>'
    return f"""
<h1>Compliance Report</h1>
<p class="grade {status_class}">{result.status}</p>
<p>Profile: {result.profile} {result.profile_version}</p>
<p>Required: {result.required_score}/10 | Optional: {result.optional_score}/10 | Overall: {result.overall}/10</p>
<table><tr><th></th><th>ID</th><th>Requirement</th><th>Status</th></tr>{rows}</table>"""


# --------------------------------------------------------- registry

_RENDERERS = {
    "basic": _render_basic,
    "detailed": _render_detailed,
    "json": _render_json,
    "sarif": _render_sarif,
    "junit": _render_junit,
    "html": _render_html,
}
