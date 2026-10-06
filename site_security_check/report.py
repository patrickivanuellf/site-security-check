"""Scoring and report rendering for one or several scanned sites."""
from __future__ import annotations

import json
from collections import OrderedDict
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from . import __version__
from .checks import FAIL, PASS, SKIP, WARN, WEIGHTS, Result

Scan = Tuple[str, List[Result]]  # (site label, results)

_COLORS = {PASS: "\033[32m", WARN: "\033[33m", FAIL: "\033[31m", SKIP: "\033[90m"}
_RESET = "\033[0m"


def score(results: List[Result]) -> int:
    """0-100. PASS earns full weight, WARN half, FAIL none. SKIP is ignored."""
    total = earned = 0.0
    for r in results:
        if r.status == SKIP:
            continue
        weight = WEIGHTS[r.severity]
        total += weight
        if r.status == PASS:
            earned += weight
        elif r.status == WARN:
            earned += weight / 2
    return round(100 * earned / total) if total else 0


def summary(results: List[Result]) -> Dict[str, int]:
    counts = {PASS: 0, WARN: 0, FAIL: 0, SKIP: 0}
    for r in results:
        counts[r.status] += 1
    return counts


def _group(results: List[Result]) -> "OrderedDict[str, List[Result]]":
    grouped: "OrderedDict[str, List[Result]]" = OrderedDict()
    for r in results:
        grouped.setdefault(r.category, []).append(r)
    return grouped


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def render_text(scans: List[Scan], color: bool = False,
                generated_at: Optional[str] = None) -> str:
    def paint(status: str) -> str:
        label = f"{status:<4}"
        return f"{_COLORS[status]}{label}{_RESET}" if color else label

    lines = [f"Site Security Check v{__version__}",
             f"Generated: {generated_at or _now()}", ""]
    for label, results in scans:
        lines.append(f"=== {label} ===")
        for category, items in _group(results).items():
            lines.append(f"[{category}]")
            for r in items:
                lines.append(f"  {paint(r.status)}  {r.id:<8} {r.title}")
                if r.status != PASS and r.detail:
                    lines.append(f"            {r.detail}")
                if r.status in (FAIL, WARN) and r.fix:
                    lines.append(f"            fix: {r.fix}")
        s = summary(results)
        lines.append("")
        lines.append(f"Summary: {s[PASS]} passed, {s[WARN]} warnings, "
                     f"{s[FAIL]} failed, {s[SKIP]} skipped")
        lines.append(f"Score:   {score(results)}/100")
        lines.append("")
    if len(scans) > 1:
        lines.append("Overview")
        for label, results in scans:
            lines.append(f"  {score(results):>3}/100  {label}")
    return "\n".join(lines).rstrip() + "\n"


def render_json(scans: List[Scan], generated_at: Optional[str] = None) -> str:
    payload = {
        "tool": "site-security-check",
        "version": __version__,
        "generated_at": generated_at or _now(),
        "sites": [
            {"site": label, "score": score(results), "summary": summary(results),
             "results": [asdict(r) for r in results]}
            for label, results in scans
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(scans: List[Scan], generated_at: Optional[str] = None) -> str:
    lines = ["# Site Security Check Report", "",
             f"- **Generated:** {generated_at or _now()}", ""]
    if len(scans) > 1:
        lines += ["| Site | Score |", "|---|---|"]
        lines += [f"| {_cell(label)} | {score(results)}/100 |" for label, results in scans]
        lines.append("")
    for label, results in scans:
        s = summary(results)
        lines += [f"## {label}", "",
                  f"**Score: {score(results)}/100** ({s[PASS]} passed, {s[WARN]} warnings, "
                  f"{s[FAIL]} failed, {s[SKIP]} skipped)", ""]
        for category, items in _group(results).items():
            lines += [f"### {category}", "", "| Status | ID | Check | Detail |", "|---|---|---|---|"]
            lines += [f"| {r.status} | {r.id} | {_cell(r.title)} | {_cell(r.detail)} |" for r in items]
            lines.append("")
        todo = [r for r in results if r.status in (FAIL, WARN) and r.fix]
        if todo:
            lines += ["### Recommendations", ""]
            lines += [f"{i}. **{r.id}** ({r.status}): {r.fix}" for i, r in enumerate(todo, 1)]
            lines.append("")
    return "\n".join(lines)
