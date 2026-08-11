from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path
from typing import Sequence

from .models import Ticket
from .runtime import REPOSITORY_ROOT, build_pipeline


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the local support-ticket PoC")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--demo", action="store_true", help="run happy, risky and degraded paths")
    source.add_argument("--input", type=Path, help="process one ticket JSON file")
    parser.add_argument("--classifier", choices=("ml", "rules"), default="ml")
    parser.add_argument("--db", type=Path, help="optional persistent SQLite path")
    parser.add_argument(
        "--simulate-generator-outage",
        action="store_true",
        help="use approved-template fallback for an otherwise safe ticket",
    )
    return parser


def _process(pipeline, ticket: Ticket) -> dict:
    started = time.perf_counter()
    decision = pipeline.process(ticket)
    payload = decision.to_dict()
    payload["local_latency_ms"] = round((time.perf_counter() - started) * 1_000, 3)
    return payload


def _run(args: argparse.Namespace, db_path: Path) -> list[dict]:
    if args.demo:
        cases = [
            (REPOSITORY_ROOT / "examples" / "happy_ticket.json", True),
            (REPOSITORY_ROOT / "examples" / "risky_ticket.json", True),
            (REPOSITORY_ROOT / "examples" / "degraded_ticket.json", False),
        ]
        results = []
        for path, generator_available in cases:
            pipeline = build_pipeline(
                db_path=db_path,
                classifier_mode=args.classifier,
                generator_available=(
                    generator_available and not args.simulate_generator_outage
                ),
            )
            ticket = Ticket.from_dict(json.loads(path.read_text(encoding="utf-8")))
            results.append(_process(pipeline, ticket))
        return results
    pipeline = build_pipeline(
        db_path=db_path,
        classifier_mode=args.classifier,
        generator_available=not args.simulate_generator_outage,
    )
    ticket = Ticket.from_dict(json.loads(args.input.read_text(encoding="utf-8")))
    return [_process(pipeline, ticket)]


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.db:
        results = _run(args, args.db)
    else:
        with tempfile.TemporaryDirectory(prefix="ticket-poc-") as directory:
            results = _run(args, Path(directory) / "decisions.sqlite3")
    print(json.dumps(results if args.demo else results[0], ensure_ascii=False, indent=2))
    return 0
