from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PolicyConfig:
    policy_version: str
    classifier_abstain_confidence: float
    classifier_abstain_margin: float
    automation_confidence: float
    automation_margin: float
    retrieval_score: float
    retrieval_margin: float
    max_response_chars: int

    @classmethod
    def load(cls, path: Path) -> "PolicyConfig":
        payload = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            policy_version=str(payload["policy_version"]),
            classifier_abstain_confidence=float(
                payload["classifier_abstain_confidence"]
            ),
            classifier_abstain_margin=float(payload["classifier_abstain_margin"]),
            automation_confidence=float(payload["automation_confidence"]),
            automation_margin=float(payload["automation_margin"]),
            retrieval_score=float(payload["retrieval_score"]),
            retrieval_margin=float(payload["retrieval_margin"]),
            max_response_chars=int(payload["max_response_chars"]),
        )
