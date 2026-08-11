from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class IntentPolicy:
    mode: str
    automation_confidence: float
    automation_margin: float


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
    intent_policies: dict[str, IntentPolicy]

    @classmethod
    def load(cls, path: Path) -> PolicyConfig:
        payload = json.loads(path.read_text(encoding="utf-8"))
        config = cls(
            policy_version=str(payload["policy_version"]),
            classifier_abstain_confidence=float(payload["classifier_abstain_confidence"]),
            classifier_abstain_margin=float(payload["classifier_abstain_margin"]),
            automation_confidence=float(payload["automation_confidence"]),
            automation_margin=float(payload["automation_margin"]),
            retrieval_score=float(payload["retrieval_score"]),
            retrieval_margin=float(payload["retrieval_margin"]),
            max_response_chars=int(payload["max_response_chars"]),
            intent_policies={
                str(intent): IntentPolicy(
                    mode=str(values["mode"]),
                    automation_confidence=float(
                        values.get("automation_confidence", payload["automation_confidence"])
                    ),
                    automation_margin=float(
                        values.get("automation_margin", payload["automation_margin"])
                    ),
                )
                for intent, values in payload["intent_policies"].items()
            },
        )
        config._validate()
        return config

    def _validate(self) -> None:
        if not self.policy_version.strip():
            raise ValueError("policy_version must not be empty")
        thresholds = {
            "classifier_abstain_confidence": self.classifier_abstain_confidence,
            "classifier_abstain_margin": self.classifier_abstain_margin,
            "automation_confidence": self.automation_confidence,
            "automation_margin": self.automation_margin,
            "retrieval_score": self.retrieval_score,
            "retrieval_margin": self.retrieval_margin,
        }
        for name, value in thresholds.items():
            if not math.isfinite(value) or not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be finite and within [0, 1]")
        if self.max_response_chars <= 0:
            raise ValueError("max_response_chars must be positive")
        if not self.intent_policies:
            raise ValueError("intent_policies must not be empty")
        allowed_modes = {"auto_template", "operator_suggest", "human_only"}
        for intent, policy in self.intent_policies.items():
            if policy.mode not in allowed_modes:
                raise ValueError(f"Unsupported mode for {intent}: {policy.mode}")
            for name, value in (
                ("automation_confidence", policy.automation_confidence),
                ("automation_margin", policy.automation_margin),
            ):
                if not math.isfinite(value) or not 0.0 <= value <= 1.0:
                    raise ValueError(f"{intent}.{name} must be finite and within [0, 1]")
