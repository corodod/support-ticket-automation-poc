from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from ticket_automation.incidents import find_incident_candidates
from ticket_automation.models import Ticket
from ticket_automation.runtime import REPOSITORY_ROOT


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect redacted incident candidates")
    parser.add_argument(
        "--input",
        type=Path,
        default=REPOSITORY_ROOT / "examples" / "incident_batch.json",
    )
    args = parser.parse_args(argv)
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    tickets = [Ticket.from_dict(item) for item in payload]
    result = [candidate.to_dict() for candidate in find_incident_candidates(tickets)]
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
