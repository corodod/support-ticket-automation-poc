from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Ticket:
    event_id: str
    ticket_id: str
    channel: str
    text: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Ticket:
        if not isinstance(payload, dict):
            raise TypeError("Ticket payload must be a JSON object")
        required = ("event_id", "ticket_id", "channel", "text")
        missing = [name for name in required if not str(payload.get(name, "")).strip()]
        if missing:
            raise ValueError(f"Missing required ticket fields: {', '.join(missing)}")
        values = {name: str(payload[name]).strip() for name in required}
        if len(values["event_id"]) > 128 or len(values["ticket_id"]) > 128:
            raise ValueError("event_id and ticket_id must be at most 128 characters")
        if len(values["channel"]) > 32:
            raise ValueError("channel must be at most 32 characters")
        if len(values["text"]) > 10_000:
            raise ValueError("ticket text must be at most 10000 characters")
        return cls(**values)


@dataclass(frozen=True)
class KnowledgeArticle:
    article_id: str
    topic: str
    intent: str
    title: str
    answer: str
    keywords: tuple[str, ...]
    status: str
    auto_reply_allowed: bool
    version: int
    valid_until: str


@dataclass(frozen=True)
class ClassificationResult:
    topic: str
    intent: str
    confidence: float
    second_confidence: float
    margin: float
    classifier_version: str
    abstained: bool


@dataclass(frozen=True)
class RetrievalResult:
    article: KnowledgeArticle | None
    top_score: float
    second_score: float
    margin: float
    index_version: str
    ranked_article_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class RiskAssessment:
    level: str
    business_risk: str
    pii_types: tuple[str, ...]
    prompt_injection_suspected: bool
    auto_reply_prohibited: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class GenerationContext:
    redacted_text: str
    topic: str
    intent: str
    article_id: str
    approved_answer: str


@dataclass(frozen=True)
class GenerationResult:
    draft: str
    mode: str
    generator_version: str


@dataclass(frozen=True)
class PolicyCheckResult:
    allowed: bool
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class Decision:
    event_id: str
    ticket_id: str
    topic: str
    intent: str
    confidence: float
    classification_margin: float
    risk_level: str
    risk_reasons: tuple[str, ...]
    action: str
    route: str
    article_id: str | None
    retrieval_score: float
    retrieval_margin: float
    draft: str | None
    generation_mode: str | None
    degraded_mode: bool
    reason_codes: tuple[str, ...]
    component_versions: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
