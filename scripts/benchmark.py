from __future__ import annotations

import argparse
import json
import platform
import tempfile
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import numpy as np

from ticket_automation.models import Ticket
from ticket_automation.runtime import REPOSITORY_ROOT, build_pipeline


def benchmark(*, iterations: int = 500, warmup: int = 25) -> dict:
    if iterations < 100:
        raise ValueError("Use at least 100 measured iterations")
    example_paths = (
        REPOSITORY_ROOT / "examples" / "happy_ticket.json",
        REPOSITORY_ROOT / "examples" / "risky_ticket.json",
        REPOSITORY_ROOT / "examples" / "degraded_ticket.json",
    )
    examples = [
        Ticket.from_dict(json.loads(path.read_text(encoding="utf-8"))) for path in example_paths
    ]
    with tempfile.TemporaryDirectory(prefix="ticket-benchmark-") as directory:
        build_started = time.perf_counter()
        pipeline = build_pipeline(db_path=Path(directory) / "benchmark.sqlite3")
        build_ms = (time.perf_counter() - build_started) * 1_000
        for index in range(warmup):
            source = examples[index % len(examples)]
            pipeline.process(
                replace(source, event_id=f"WARM-E-{index}", ticket_id=f"WARM-T-{index}")
            )

        latencies_ms: list[float] = []
        actions: Counter[str] = Counter()
        measured_started = time.perf_counter()
        for index in range(iterations):
            source = examples[index % len(examples)]
            ticket = replace(source, event_id=f"BENCH-E-{index}", ticket_id=f"BENCH-T-{index}")
            started = time.perf_counter()
            decision = pipeline.process(ticket)
            latencies_ms.append((time.perf_counter() - started) * 1_000)
            actions[decision.action] += 1
        elapsed = time.perf_counter() - measured_started

    p50, p95, p99 = np.percentile(latencies_ms, [50, 95, 99])
    throughput = iterations / elapsed
    return {
        "schema_version": 1,
        "scope": "single-process local PoC; warm model; local SQLite; no network or broker",
        "production_slo_claim": False,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "workload": {
            "warmup_iterations": warmup,
            "measured_iterations": iterations,
            "mix": "round-robin safe FAQ, risky payment, safe verification-code",
            "model_initialization_excluded_from_request_latency": True,
        },
        "model_initialization_ms": round(build_ms, 3),
        "latency_ms": {
            "p50": round(float(p50), 3),
            "p95": round(float(p95), 3),
            "p99": round(float(p99), 3),
            "max": round(max(latencies_ms), 3),
            "mean": round(float(np.mean(latencies_ms)), 3),
        },
        "throughput_tickets_per_second": round(throughput, 2),
        "headroom_vs_case_peak_33_3_rps": round(throughput / 33.3, 2),
        "action_counts": dict(sorted(actions.items())),
        "p99_below_500ms": bool(p99 < 500.0),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark the warm local PoC path")
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--warmup", type=int, default=25)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    report = benchmark(iterations=args.iterations, warmup=args.warmup)
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["p99_below_500ms"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
