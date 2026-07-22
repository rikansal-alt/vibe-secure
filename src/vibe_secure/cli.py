"""CLI for vibe-secure."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .investigator import DEFAULT_MODEL, InvestigationError, investigate
from .report import render_html, render_json, render_text
from .scanner import scan


def cmd_scan(args, agent_only=False) -> int:
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2
    result = scan(root, agent_only=agent_only)
    if getattr(args, "html", None) is not None:
        html_doc = render_html(result, root=root.name)
        if args.html in ("-", ""):
            print(html_doc)
        else:
            Path(args.html).write_text(html_doc, encoding="utf-8")
            print(f"wrote HTML report to {args.html}", file=sys.stderr)
    else:
        print(render_json(result) if args.json else render_text(result))
    if args.strict and result.findings:
        return 1
    return 1 if result.high_count > 0 else 0


def cmd_agent(args) -> int:
    return cmd_scan(args, agent_only=True)


def cmd_investigate(args) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: repository path not found: {root}", file=sys.stderr)
        return 2
    try:
        result = investigate(root, model=args.model)
    except InvestigationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(result.to_json() if args.json else result.report)
    return 1 if result.static_high_count or result.vulnerable_authorization_count else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vibe-secure",
        description="Scan vibe-coded apps AND the agent config that built them.")
    p.add_argument("-V", "--version", action="version",
                   version=f"vibe-secure {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="full scan: app holes + agent-layer config")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--json", action="store_true")
    s.add_argument("--html", nargs="?", const="-", metavar="FILE",
                   help="write a self-contained HTML report to FILE (or stdout if omitted)")
    s.add_argument("--strict", action="store_true",
                   help="exit non-zero on any finding, not just high severity")
    s.set_defaults(func=cmd_scan)

    a = sub.add_parser("agent", help="agent-layer only (MCP trust, auto-run, rules)")
    a.add_argument("path", nargs="?", default=".")
    a.add_argument("--json", action="store_true")
    a.add_argument("--html", nargs="?", const="-", metavar="FILE",
                   help="write a self-contained HTML report to FILE (or stdout if omitted)")
    a.add_argument("--strict", action="store_true")
    a.set_defaults(func=cmd_agent)

    i = sub.add_parser("investigate", help="read-only AI investigation of scanner findings")
    i.add_argument("path", nargs="?", default=".")
    i.add_argument("--model", default=DEFAULT_MODEL,
                   help=f"OpenAI model (default: {DEFAULT_MODEL})")
    i.add_argument("--json", action="store_true")
    i.set_defaults(func=cmd_investigate)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not getattr(args, "command", None):
        build_parser().print_help()
        return 0
    try:
        return args.func(args)
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
