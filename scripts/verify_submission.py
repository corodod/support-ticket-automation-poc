from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from pathlib import Path

from scripts.benchmark import benchmark
from scripts.evaluate import evaluate
from ticket_automation.incidents import find_incident_candidates
from ticket_automation.models import Ticket
from ticket_automation.runtime import REPOSITORY_ROOT, build_pipeline


class VerificationError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _run(command: list[str]) -> None:
    result = subprocess.run(
        command,
        cwd=REPOSITORY_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode:
        output = (result.stdout + result.stderr).strip()
        raise VerificationError(f"Command failed: {' '.join(command)}\n{output}")


def _visible_files(suffixes: tuple[str, ...]) -> list[Path]:
    return [
        path
        for path in REPOSITORY_ROOT.rglob("*")
        if path.is_file()
        and path.suffix in suffixes
        and not any(part.startswith(".") for part in path.relative_to(REPOSITORY_ROOT).parts)
        and "egg-info" not in str(path)
    ]


def _check_manifest(*, allow_missing_ai_usage: bool) -> None:
    required = (
        "README.md",
        "docs/product.md",
        "docs/architecture.md",
        "docs/ml.md",
        "docs/monitoring.md",
        "docs/risks-and-ops.md",
        "docs/diagrams/system.mmd",
        "docs/diagrams/system.svg",
        "WORKLOG.md",
        "SELF_REVIEW.md",
    )
    for relative in required:
        path = REPOSITORY_ROOT / relative
        _require(path.is_file() and path.stat().st_size > 0, f"Missing required file: {relative}")

    ai_usage = REPOSITORY_ROOT / "AI_USAGE.md"
    if ai_usage.exists():
        _require(ai_usage.stat().st_size >= 200, "AI_USAGE.md is unexpectedly short")
    elif not allow_missing_ai_usage:
        raise VerificationError("AI_USAGE.md is required in final submission")

    readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
    for marker in ("ticket-poc --demo", "scripts.evaluate", "scripts.verify_submission"):
        _require(marker in readme, f"README misses runnable command: {marker}")
    for value in ("Пользователь", "Оператор", "Бизнес"):
        _require(value in readme, f"README misses business-value dimension: {value}")

    worklog = (REPOSITORY_ROOT / "WORKLOG.md").read_text(encoding="utf-8")
    sentences = re.findall(r"(?m)^\d+\.\s+.+[.!?]$", worklog)
    _require(5 <= len(sentences) <= 10, "WORKLOG must contain 5–10 numbered sentences")

    product = (REPOSITORY_ROOT / "docs" / "product.md").read_text(encoding="utf-8")
    product_words = len(re.findall(r"\b\w+\b", product, flags=re.UNICODE))
    _require(650 <= product_words <= 1_500, "product.md must stay a compact 1–1.5 page design")
    self_review = (REPOSITORY_ROOT / "SELF_REVIEW.md").read_text(encoding="utf-8").lower()
    _require("останов" in self_review, "SELF_REVIEW must answer what stops the project")


def _check_data_and_diagram() -> None:
    for path in _visible_files((".json",)):
        json.loads(path.read_text(encoding="utf-8"))
    for path in _visible_files((".jsonl",)):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line)
            _require(isinstance(value, dict), f"{path}:{line_number} must be a JSON object")

    source = (REPOSITORY_ROOT / "docs" / "diagrams" / "system.mmd").read_text(encoding="utf-8")
    _require(source.lstrip().startswith("flowchart"), "Mermaid source is not a flowchart")
    root = ET.parse(REPOSITORY_ROOT / "docs" / "diagrams" / "system.svg").getroot()
    _require(root.tag.endswith("svg"), "Rendered system.svg is invalid")


def _check_markdown_links() -> None:
    for path in _visible_files((".md",)):
        text = path.read_text(encoding="utf-8")
        for target in re.findall(r"!?\[[^]]*\]\(([^)]+)\)", text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            local_target = target.split("#", 1)[0].strip("<>")
            resolved = (path.parent / local_target).resolve()
            _require(resolved.exists(), f"Broken local link in {path}: {target}")


def _check_repository(*, skip_git_clean: bool) -> None:
    commit_count = int(
        subprocess.check_output(
            ["git", "rev-list", "--count", "HEAD"], cwd=REPOSITORY_ROOT, text=True
        ).strip()
    )
    _require(4 <= commit_count <= 6, f"Expected 4–6 commits, found {commit_count}")
    _run(["git", "remote", "get-url", "origin"])

    tracked = subprocess.check_output(
        ["git", "ls-files"], cwd=REPOSITORY_ROOT, text=True
    ).splitlines()
    forbidden_fragments = (
        ".venv/",
        "__pycache__/",
        ".egg-info/",
        "mlruns/",
        ".sqlite3",
        ".env",
    )
    bad = [path for path in tracked if any(fragment in path for fragment in forbidden_fragments)]
    _require(not bad, f"Generated/private files are tracked: {bad}")

    secret_patterns = (
        re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
        re.compile(r"ghp_[A-Za-z0-9]{20,}"),
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    )
    for path in _visible_files((".py", ".md", ".json", ".jsonl", ".toml", ".yml")):
        text = path.read_text(encoding="utf-8", errors="replace")
        _require(
            not any(pattern.search(text) for pattern in secret_patterns),
            f"Possible secret in {path}",
        )

    if not skip_git_clean:
        status = subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=REPOSITORY_ROOT,
            text=True,
        ).strip()
        _require(not status, f"Working tree is not clean:\n{status}")


def _check_runtime() -> None:
    if shutil.which("ruff"):
        _run(["ruff", "check", "."])
        _run(["ruff", "format", "--check", "."])
    _run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])

    report = evaluate()
    _require(report["all_hard_gates_passed"], "Offline evaluation hard gates failed")
    committed = json.loads(
        (REPOSITORY_ROOT / "reports" / "evaluation.json").read_text(encoding="utf-8")
    )
    _require(report == committed, "reports/evaluation.json is stale")

    examples = {
        "happy_ticket.json": (True, "auto_reply", "auto_reply_pending"),
        "risky_ticket.json": (True, "human_review", "payments_priority"),
        "degraded_ticket.json": (False, "operator_suggest", "operator_suggest_queue"),
    }
    with tempfile.TemporaryDirectory(prefix="submission-demo-") as directory:
        db_path = Path(directory) / "decisions.sqlite3"
        for filename, (generator_available, action, route) in examples.items():
            pipeline = build_pipeline(
                db_path=db_path,
                generator_available=generator_available,
            )
            payload = json.loads(
                (REPOSITORY_ROOT / "examples" / filename).read_text(encoding="utf-8")
            )
            decision = pipeline.process(Ticket.from_dict(payload))
            _require(
                decision.action == action and decision.route == route, f"Demo failed: {filename}"
            )
            if filename == "degraded_ticket.json":
                _require(
                    decision.generation_mode == "approved_template_suggest_fallback"
                    and decision.delivery_state == "not_user_visible",
                    "Degraded demo did not use a non-user-visible approved suggestion",
                )

    batch = json.loads(
        (REPOSITORY_ROOT / "examples" / "incident_batch.json").read_text(encoding="utf-8")
    )
    incidents = find_incident_candidates(Ticket.from_dict(item) for item in batch)
    _require(len(incidents) == 1 and not incidents[0].auto_close_allowed, "Incident demo failed")

    benchmark_report = benchmark(iterations=100, warmup=10)
    _require(benchmark_report["p99_below_500ms"], "Local benchmark p99 exceeds 500 ms")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify the take-home submission")
    parser.add_argument("--allow-missing-ai-usage", action="store_true")
    parser.add_argument("--skip-git-clean", action="store_true")
    parser.add_argument("--structural-only", action="store_true")
    args = parser.parse_args(argv)

    try:
        _check_manifest(allow_missing_ai_usage=args.allow_missing_ai_usage)
        _check_data_and_diagram()
        _check_markdown_links()
        _check_repository(skip_git_clean=args.skip_git_clean)
        if not args.structural_only:
            _check_runtime()
    except (VerificationError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        return 1

    if args.allow_missing_ai_usage and not (REPOSITORY_ROOT / "AI_USAGE.md").exists():
        print("[WARN] AI_USAGE.md is intentionally absent; final-mode will require it")
    print("[PASS] manifest, data, links, git history and runtime evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
