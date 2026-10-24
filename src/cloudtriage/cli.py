"""CLI separating analysis, preview, human approval, and optional Jira submission."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import date
from pathlib import Path

from .agent import DeterministicPlanner, OpenAIPlanner
from .approval import Approvals
from .audit import Audit, verify
from .jira import preview, submit, validate_intent
from .models import digest, load_json
from .pipeline import run, write_json


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Synthetic cloud triage; no cloud write capability")
    sub = root.add_subparsers(dest="command", required=True)
    for name in ("demo", "triage"):
        p = sub.add_parser(name)
        p.add_argument("--out", type=Path, required=True, help="new output directory")
        if name == "triage":
            p.add_argument("--findings", type=Path)
            p.add_argument("--as-of", type=date.fromisoformat, default=date.today())
            p.add_argument("--intel", choices=("fixture", "live"), default="fixture")
            p.add_argument(
                "--provider", choices=("deterministic", "openai"), default="deterministic"
            )
            p.add_argument("--allow-model-egress", action="store_true")
    p = sub.add_parser("verify-audit")
    p.add_argument("path", type=Path)
    p = sub.add_parser("jira-preview")
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--finding-id", required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--project", required=True)
    p.add_argument("--out", type=Path, required=True)
    for name in ("approve", "jira-submit"):
        p = sub.add_parser(name)
        p.add_argument("--intent", type=Path, required=True)
        p.add_argument("--ledger", type=Path, required=True)
        if name == "approve":
            p.add_argument("--reviewer", required=True, help="local self-asserted reviewer alias")
        else:
            p.add_argument("--out", type=Path, required=True, help="new receipt directory")
    return root


def execute(args: argparse.Namespace) -> None:
    if args.command in {"demo", "triage"}:
        provider = getattr(args, "provider", "deterministic")
        factory = DeterministicPlanner
        if provider == "openai":
            if not args.allow_model_egress:
                raise PermissionError(
                    "explicit --allow-model-egress required; review minimized fields"
                )
            api_key, model = (
                os.environ.get("OPENAI_API_KEY", ""),
                os.environ.get("OPENAI_MODEL", ""),
            )
            if not api_key or not model:
                raise ValueError("OPENAI_API_KEY and explicit OPENAI_MODEL are required")

            def factory():
                return OpenAIPlanner(api_key, model)

        report = run(
            args.out,
            findings_path=getattr(args, "findings", None),
            as_of=getattr(args, "as_of", date(2026, 10, 23)),
            intel_mode=getattr(args, "intel", "fixture"),
            provider=provider,
            planner_factory=factory,
        )
        print(json.dumps(report["summary"], indent=2))
        print(f"Report: {args.out.resolve() / 'report.html'}")
    elif args.command == "verify-audit":
        print(f"Verified {verify(args.path)} hash-linked events")
    elif args.command == "jira-preview":
        report = load_json(args.report)
        result = next(r for r in report["results"] if r["finding"]["id"] == args.finding_id)
        intent = preview(result, args.host, args.project)
        write_json(args.out, intent)
        print(f"Dry run only. Intent digest: {digest(intent)}")
    else:
        envelope = load_json(args.intent)
        validate_intent(envelope)
        if args.command == "approve":
            print(json.dumps(envelope, indent=2))
            key = digest(envelope)
            if not sys.stdin.isatty():
                raise PermissionError("approval requires an interactive human terminal")
            confirmation = input(f"Review target and full payload. Type APPROVE {key}: ")
            with Approvals(args.ledger) as approvals:
                approvals.approve(envelope, args.reviewer, confirmation)
            print("Approved this exact Jira intent for one attempt within one hour.")
        else:
            email, token = os.environ.get("JIRA_EMAIL", ""), os.environ.get("JIRA_API_TOKEN", "")
            if not email or not token:
                raise ValueError("JIRA_EMAIL and JIRA_API_TOKEN required")
            args.out.mkdir(parents=True, exist_ok=False)
            audit = Audit()
            try:
                with Approvals(args.ledger) as approvals:
                    receipt = submit(envelope, approvals, email, token, audit)
                write_json(args.out / "receipt.json", receipt)
                print(receipt["url"])
            finally:
                audit.write(args.out / "audit.jsonl")


def main() -> int:
    args = parser().parse_args()
    try:
        execute(args)
        return 0
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, sqlite3.Error, StopIteration):
        # Do not print remote bodies, credentials, arbitrary scanner strings or model responses.
        print(
            "Operation rejected or failed. Check input contract, options, approvals and service "
            "availability. No automatic remote retry. See docs/RUNBOOK.md.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
