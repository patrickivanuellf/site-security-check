"""Command line interface."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .checks import scan
from .net import parse_target
from .report import render_json, render_markdown, render_text, score


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="site_security_check",
        description="Read-only security configuration check for websites.",
        epilog="Only scan sites you own or have written permission to test.",
    )
    p.add_argument("targets", nargs="*", help="domain or URL, e.g. example.com")
    p.add_argument("-f", "--file", help="text file with one target per line (# comments allowed)")
    p.add_argument("--format", choices=["text", "json", "md"], default="text",
                   help="report format (default: text)")
    p.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    p.add_argument("--fail-under", type=int, metavar="SCORE",
                   help="exit with status 1 if any site scores below SCORE (useful in CI)")
    p.add_argument("--timeout", type=float, default=8.0, help="network timeout in seconds (default: 8)")
    p.add_argument("--cafile", help="extra CA certificate to trust (for internal or self-signed sites)")
    p.add_argument("--check-ads-txt", action="store_true",
                   help="also validate /ads.txt (for ad-supported sites)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _read_targets(args) -> list:
    raw = list(args.targets)
    if args.file:
        for line in Path(args.file).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                raw.append(line)
    return raw


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        raw_targets = _read_targets(args)
        targets = [parse_target(t) for t in raw_targets]
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not targets:
        print("error: give at least one target (or --file)", file=sys.stderr)
        return 2

    scans = [(t.label, scan(t, args.cafile, args.timeout, args.check_ads_txt)) for t in targets]

    if args.format == "json":
        text = render_json(scans)
    elif args.format == "md":
        text = render_markdown(scans)
    else:
        use_color = (args.output is None and sys.stdout.isatty()
                     and "NO_COLOR" not in os.environ)
        text = render_text(scans, color=use_color)

    if args.output:
        Path(args.output).write_text(text)
    else:
        sys.stdout.write(text)

    if args.fail_under is not None and any(score(r) < args.fail_under for _, r in scans):
        return 1
    return 0
