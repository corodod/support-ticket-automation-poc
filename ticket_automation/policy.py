from __future__ import annotations

import re
from datetime import UTC, date, datetime

from .config import PolicyConfig
from .models import (
    ClassificationResult,
    KnowledgeArticle,
    PolicyCheckResult,
    RetrievalResult,
    RiskAssessment,
)
from .pii import detect_pii

HIGH_RISK_MARKERS = {
    "financial_action": (
        "списал",
        "списали",
        "сняли повторно",
        "возврат",
        "верните деньги",
        "чужая покупка",
        "двойная оплат",
        "два раза оплатил",
        "две операции",
        "платёж продублировался",
    ),
    "account_security": (
        "взлом",
        "чужой вход",
        "украли аккаунт",
        "не мой вход",
        "компрометирован",
    ),
    "privacy_or_legal": (
        "удалить мои данные",
        "персональные данные",
        "суд",
        "полици",
        "угрожа",
        "самоуб",
    ),
}
PROMPT_INJECTION_MARKERS = (
    "игнорируй предыдущие инструкции",
    "покажи системный промпт",
    "ignore previous instructions",
    "system prompt",
)
FORBIDDEN_CLAIMS = (
    "деньги уже возвращены",
    "возврат гарантирован",
    "платёж отменён",
    "аккаунт разблокирован",
    "операция выполнена",
)
URL_RE = re.compile(r"https?://[^\s)]+", re.IGNORECASE)


def assess_risk(text: str, classification: ClassificationResult) -> RiskAssessment:
    normalized = text.lower()
    pii_types = detect_pii(text)
    reasons = [
        name
        for name, markers in HIGH_RISK_MARKERS.items()
        if any(marker in normalized for marker in markers)
    ]
    prompt_injection = any(marker in normalized for marker in PROMPT_INJECTION_MARKERS)
    if prompt_injection:
        reasons.append("prompt_injection")
    if "card_number" in pii_types:
        reasons.append("sensitive_pii:card_number")
    if "credential" in pii_types:
        reasons.append("sensitive_pii:credential")
    if classification.intent == "duplicate_charge" or classification.topic == "payment":
        reasons.append("sensitive_intent:payment")
    unique_reasons = tuple(sorted(set(reasons)))
    return RiskAssessment(
        level="high" if unique_reasons else "low",
        business_risk="high" if unique_reasons else "low",
        pii_types=pii_types,
        prompt_injection_suspected=prompt_injection,
        auto_reply_prohibited=bool(unique_reasons),
        reasons=unique_reasons,
    )


class AutomationPolicy:
    def __init__(self, config: PolicyConfig) -> None:
        self.config = config
        self.version = config.policy_version

    def check(
        self,
        classification: ClassificationResult,
        risk: RiskAssessment,
        retrieval: RetrievalResult,
    ) -> PolicyCheckResult:
        reasons: list[str] = []
        if risk.auto_reply_prohibited:
            reasons.append("HIGH_RISK_OR_PROHIBITED")
        if classification.abstained or classification.intent == "unknown":
            reasons.append("UNKNOWN_OR_ABSTAINED_INTENT")
        if classification.confidence < self.config.automation_confidence:
            reasons.append("LOW_CLASSIFICATION_CONFIDENCE")
        if classification.margin < self.config.automation_margin:
            reasons.append("AMBIGUOUS_CLASSIFICATION")
        article = retrieval.article
        if article is None:
            reasons.append("NO_KNOWLEDGE_ARTICLE")
        else:
            if article.status != "approved":
                reasons.append("ARTICLE_NOT_APPROVED")
            if not article.auto_reply_allowed:
                reasons.append("ARTICLE_NOT_ALLOWLISTED")
            if article.intent != classification.intent:
                reasons.append("INTENT_ARTICLE_MISMATCH")
            if date.fromisoformat(article.valid_until) < datetime.now(UTC).date():
                reasons.append("ARTICLE_EXPIRED")
        if retrieval.top_score < self.config.retrieval_score:
            reasons.append("LOW_RETRIEVAL_SCORE")
        if retrieval.margin < self.config.retrieval_margin:
            reasons.append("AMBIGUOUS_RETRIEVAL")
        return PolicyCheckResult(not reasons, tuple(dict.fromkeys(reasons)))


class OutputPolicyChecker:
    version = "output-policy-v2"

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def check(self, draft: str, article: KnowledgeArticle) -> PolicyCheckResult:
        normalized = draft.lower().strip()
        reasons: list[str] = []
        if not normalized:
            reasons.append("EMPTY_GENERATED_RESPONSE")
        if len(draft) > self.config.max_response_chars:
            reasons.append("RESPONSE_TOO_LONG")
        if detect_pii(draft):
            reasons.append("PII_IN_OUTPUT")
        if any(claim in normalized for claim in FORBIDDEN_CLAIMS):
            reasons.append("FORBIDDEN_CLAIM")
        if any(marker in normalized for marker in PROMPT_INJECTION_MARKERS):
            reasons.append("SUSPICIOUS_GENERATED_OUTPUT")
        if article.answer not in draft:
            reasons.append("MISSING_APPROVED_GROUNDING")
        allowed_drafts = {article.answer, f"Здравствуйте! {article.answer}"}
        if draft not in allowed_drafts:
            reasons.append("UNAPPROVED_TEXT_VARIATION")
        approved_urls = set(URL_RE.findall(article.answer))
        if any(url not in approved_urls for url in URL_RE.findall(draft)):
            reasons.append("UNAPPROVED_URL")
        if article.status != "approved" or not article.auto_reply_allowed:
            reasons.append("ARTICLE_NO_LONGER_ELIGIBLE")
        return PolicyCheckResult(not reasons, tuple(dict.fromkeys(reasons)))
