"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .llm import ProviderError, generate_note
from .models import Case
from .render import to_json, to_markdown
from .triage import triage


def load_case(path: Path) -> Case:
    return Case.from_dict(json.loads(path.read_text(encoding="utf-8")))


def run(args: argparse.Namespace) -> int:
    case = load_case(args.case)
    result = triage(case)

    note = None
    if args.note or args.llm != "offline":
        try:
            note = generate_note(case, result, provider_name=args.llm)
        except ProviderError as exc:
            print(f"warning: {exc} — falling back to the offline note", file=sys.stderr)
            note = generate_note(case, result, provider_name="offline")

    output = to_json(case, result, note) if args.format == "json" else to_markdown(case, result, note)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(output)

    if args.fail_on_true_positive and result.verdict == "likely_true_positive":
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-triage-copilot",
        description="Turn a raw alert case into a structured, ATT&CK-mapped triage note.",
    )
    parser.add_argument("--version", action="version", version=f"soc-triage-copilot {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    triage_cmd = sub.add_parser("triage", help="triage a case file (JSON)")
    triage_cmd.add_argument("case", type=Path, help="path to the case JSON")
    triage_cmd.add_argument("--format", choices=("markdown", "json"), default="markdown")
    triage_cmd.add_argument("--out", type=Path, help="write the report to a file")
    triage_cmd.add_argument("--llm", default="offline",
                            choices=("offline", "openai", "azure", "ollama"),
                            help="provider for the analyst note (default: offline, no network)")
    triage_cmd.add_argument("--note", action="store_true",
                            help="include the analyst note even with the offline provider")
    triage_cmd.add_argument("--fail-on-true-positive", action="store_true",
                            help="exit 2 when the verdict is likely_true_positive (for automation)")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "triage":
        if not args.case.exists():
            print(f"error: {args.case} not found", file=sys.stderr)
            return 1
        return run(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
