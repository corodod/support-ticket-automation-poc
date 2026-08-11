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

RISK_ENGINE_VERSION = "hard-risk-v4"
RISK_PATTERNS = {
    "financial_action": (
        re.compile(r"\b(?:плат[её]ж|оплат|спис|транзакц)\w*", re.IGNORECASE),
        re.compile(r"\b(?:деньг|сумм)\w*", re.IGNORECASE),
        re.compile(
            r"\b(?:верн(?:ите|уть|ули|ул|ула)|возврат\w*)\b.{0,30}"
            r"\b(?:деньг|плат[её]ж|оплат|сумм)\w*",
            re.IGNORECASE,
        ),
        re.compile(r"\b(?:чуж(?:ая|ую)|двойн\w*|дважды)\b.{0,30}\bпокуп\w*", re.IGNORECASE),
        re.compile(
            r"\bкарт\w*.{0,20}\b(?:заблок|украл|утер|потер)\w*|"
            r"\b(?:заблок|украл|утер|потер)\w*.{0,20}\bкарт\w*",
            re.IGNORECASE,
        ),
    ),
    "account_security": (
        re.compile(r"\b(?:взлом\w*|компрометир\w*)", re.IGNORECASE),
        re.compile(r"\bчуж\w*\s+(?:вход|доступ|сесси)\w*", re.IGNORECASE),
        re.compile(
            r"\b(?:вход|запрос|код|доступ|сесси|аккаунт|профил)\w*.{0,20}"
            r"\bне\s+мо(?:й|я|е|ё)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bне\s+мо(?:й|я|е|ё)\b.{0,20}"
            r"\b(?:вход|запрос|код|доступ|сесси|аккаунт|профил)\w*",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:sim|сим)\w*.{0,20}\b(?:украл|утер|потер)\w*|"
            r"\b(?:украл|утер|потер)\w*.{0,20}\b(?:sim|сим)\w*",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:аккаунт|профил)\w*.{0,30}\b(?:украл|угнал|захват|мошенн|чуж)\w*",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:украл|угнал|захват|мошенн)\w*.{0,30}\b(?:аккаунт|профил)\w*",
            re.IGNORECASE,
        ),
        re.compile(r"\bмошенн\w*.{0,30}\bполуч\w*.{0,15}\bдоступ\w*", re.IGNORECASE),
    ),
    "privacy_request": (
        re.compile(
            r"\b(?:удал|стер)\w*.{0,30}\b(?:данн|информац|истори|аккаунт|профил)\w*",
            re.IGNORECASE,
        ),
        re.compile(r"\bперсональн\w*\s+данн\w*", re.IGNORECASE),
    ),
    "legal_request": (
        re.compile(r"\bсуд(?:а|е|ом|у)?\b", re.IGNORECASE),
        re.compile(r"\b(?:полици|адвокат|претензи)\w*", re.IGNORECASE),
    ),
    "threat_or_abuse": (
        re.compile(
            r"\b(?:угрож|шантаж|насили|избил|избива|изнасил|бьют|преслед)\w*",
            re.IGNORECASE,
        ),
        re.compile(r"\bменя\s+хотят\s+убить\b", re.IGNORECASE),
    ),
    "self_harm": (
        re.compile(r"\b(?:самоуб|суицид)\w*", re.IGNORECASE),
        re.compile(r"\bне\s+хочу\s+жить\b", re.IGNORECASE),
        re.compile(r"\bпоконч\w*\s+с\s+соб\w*", re.IGNORECASE),
        re.compile(r"\b(?:причин|нанес)\w*.{0,20}\bсеб\w*.{0,15}\bвред\w*", re.IGNORECASE),
        re.compile(r"\bнавред\w*.{0,20}\bсеб\w*", re.IGNORECASE),
        re.compile(r"\bубью\s+себя\b", re.IGNORECASE),
        re.compile(r"\bсебя\s+убить\b", re.IGNORECASE),
        re.compile(r"\bвскро\w*.{0,12}\bвен\w*", re.IGNORECASE),
        re.compile(r"\bхочу\s+(?:умереть|смерти)\b", re.IGNORECASE),
        re.compile(r"\b(?:i\s+)?want\s+to\s+die\b", re.IGNORECASE),
        re.compile(r"\b(?:kill|hurt)\s+myself\b", re.IGNORECASE),
    ),
}
PROMPT_INJECTION_MARKERS = (
    "игнорируй предыдущие инструкции",
    "покажи системный промпт",
    "ignore previous instructions",
    "system prompt",
)
OBFUSCATION_PATTERNS = (
    re.compile(r"\b(?:[a-zа-яё]{1,3}-){2,}[a-zа-яё]{1,3}\b", re.IGNORECASE),
    re.compile(r"(?:\b[a-zа-яё]\b\s+){3,}\b[a-zа-яё]\b", re.IGNORECASE),
)
FORBIDDEN_CLAIMS = (
    "деньги уже возвращены",
    "возврат гарантирован",
    "платёж отменён",
    "аккаунт разблокирован",
    "операция выполнена",
)
URL_RE = re.compile(r"https?://[^\s)]+", re.IGNORECASE)

INTENT_SCOPE_PATTERNS = {
    "change_language": re.compile(
        r"\b(?:язык\w*|локализац\w*|русск\w*|английск\w*)", re.IGNORECASE
    ),
    "change_notifications": re.compile(r"\b(?:уведомлен\w*|push|пуш\w*)", re.IGNORECASE),
    "password_reset": re.compile(r"\b(?:парол\w*|восстанов\w*\s+доступ\w*)", re.IGNORECASE),
    "verification_code": re.compile(
        r"\b(?:код\w*.{0,25}(?:подтверж|вход|авторизац|провероч)|"
        r"(?:подтверж|вход|авторизац|провероч)\w*.{0,25}код\w*)",
        re.IGNORECASE,
    ),
    "duplicate_charge": re.compile(
        r"\b(?:двойн\w*\s+списан\w*|дважды\s+спис\w*|спис\w*.{0,20}два\s+раза)",
        re.IGNORECASE,
    ),
    "service_unavailable": re.compile(
        r"\b(?:сервис|сайт|приложен)\w*.{0,30}(?:не\s+работ|не\s+откры|недоступ|завис|"
        r"не\s+запуск)|\b(?:не\s+работ|не\s+откры|недоступ|завис|не\s+запуск)\w*"
        r".{0,30}\b(?:сервис|сайт|приложен)\w*",
        re.IGNORECASE,
    ),
}
SCOPE_COMMON_WORDS = {
    "а",
    "без",
    "в",
    "во",
    "вы",
    "где",
    "дайте",
    "для",
    "до",
    "email",
    "ещё",
    "еще",
    "за",
    "заказа",
    "из",
    "или",
    "и",
    "как",
    "к",
    "ли",
    "long_number",
    "мне",
    "phone",
    "мой",
    "моя",
    "мое",
    "моё",
    "мои",
    "на",
    "не",
    "ничего",
    "но",
    "номер",
    "нужен",
    "нужна",
    "нужно",
    "он",
    "она",
    "оно",
    "они",
    "от",
    "ответить",
    "ответьте",
    "пожалуйста",
    "по",
    "после",
    "почта",
    "заказ",
    "почему",
    "про",
    "с",
    "со",
    "спасибо",
    "пишет",
    "спрашивает",
    "телефон",
    "у",
    "через",
    "что",
    "это",
    "я",
}
SCOPE_COMMON_PREFIXES = (
    "здравств",
    "инструкц",
    "мог",
    "мобильн",
    "мож",
    "нуж",
    "обсуд",
    "пиш",
    "помог",
    "подскаж",
    "привет",
    "расскаж",
    "скаж",
    "спраш",
    "верс",
    "хоч",
)
INTENT_ALLOWED_PREFIXES = {
    "change_language": (
        "английск",
        "выб",
        "друг",
        "испанск",
        "итальянск",
        "измен",
        "интерфейс",
        "китайск",
        "локализац",
        "настройк",
        "немецк",
        "переключ",
        "помен",
        "постав",
        "приложен",
        "русск",
        "смен",
        "турецк",
        "французск",
        "язык",
    ),
    "change_notifications": (
        "включ",
        "измен",
        "настройк",
        "обратно",
        "отключ",
        "push",
        "пуш",
        "реклам",
        "сообщен",
        "убрать",
        "уведомлен",
        "управ",
        "приложен",
    ),
    "password_reset": (
        "аккаунт",
        "восстанов",
        "вход",
        "доступ",
        "забыл",
        "парол",
        "помн",
        "профил",
        "работ",
        "сброс",
        "смен",
        "способ",
    ),
    "verification_code": (
        "авторизац",
        "вход",
        "запрос",
        "ист",
        "код",
        "нов",
        "получ",
        "приход",
        "приш",
        "провероч",
        "подтверж",
    ),
    "duplicate_charge": ("дважды", "двойн", "деньг", "карт", "оплат", "спис"),
    "service_unavailable": (
        "выда",
        "завис",
        "запуск",
        "обновл",
        "откры",
        "ошиб",
        "приложен",
        "работ",
        "сайт",
        "сервис",
        "старт",
    ),
}
INTENT_CLAUSE_EVIDENCE_PREFIXES = {
    "change_language": (
        "английск",
        "интерфейс",
        "испанск",
        "итальянск",
        "китайск",
        "локализац",
        "немецк",
        "русск",
        "турецк",
        "французск",
        "язык",
    ),
    "change_notifications": ("push", "пуш", "уведомлен"),
    "password_reset": ("восстанов", "доступ", "парол", "сброс"),
    "verification_code": (
        "авторизац",
        "код",
        "нов",
        "получ",
        "приход",
        "приш",
        "провероч",
        "подтверж",
    ),
    "duplicate_charge": ("дважды", "двойн", "оплат", "спис"),
    "service_unavailable": (
        "завис",
        "запуск",
        "откры",
        "ошиб",
        "работ",
        "сайт",
        "сервис",
    ),
}
_SCOPE_CLAUSE_SPLIT_RE = re.compile(r"(?:[.!?;:,]+|\b(?:а|и|или|но)\b)", re.IGNORECASE)
_EXPLICIT_CONTEXT_MARKERS = {"email", "long_number", "phone"}
_BENIGN_DISCOURSE_PREFIXES = ("здравств", "пожалуй", "привет", "спасибо")
_LANGUAGE_ACTION_PREFIXES = ("выб", "измен", "переключ", "помен", "постав", "смен")
_NON_LANGUAGE_OBJECT_PREFIXES = (
    "аккаунт",
    "заказ",
    "карт",
    "номер",
    "почт",
    "приложен",
    "профил",
    "телефон",
)


def _scope_token_allowed(token: str, intent: str) -> bool:
    if token in SCOPE_COMMON_WORDS:
        return True
    allowed_prefixes = (*SCOPE_COMMON_PREFIXES, *INTENT_ALLOWED_PREFIXES.get(intent, ()))
    return any(token.startswith(prefix) for prefix in allowed_prefixes)


def _scope_tokens(text: str) -> list[str]:
    return [token.lower() for token in re.findall(r"[a-zа-яё_]+", text, flags=re.IGNORECASE)]


def _scope_clause_supported(clause: str, intent: str) -> bool:
    tokens = _scope_tokens(clause)
    if not tokens:
        return True
    evidence = INTENT_CLAUSE_EVIDENCE_PREFIXES.get(intent, ())
    if any(token.startswith(prefix) for token in tokens for prefix in evidence):
        return True
    if _EXPLICIT_CONTEXT_MARKERS.intersection(tokens):
        return True
    return all(
        any(token.startswith(prefix) for prefix in _BENIGN_DISCOURSE_PREFIXES) for token in tokens
    )


def _has_unsupported_script(text: str) -> bool:
    """The PoC serves Russian text plus bounded Latin tokens; other scripts fail closed."""
    for character in text:
        if not character.isalpha():
            continue
        lowered = character.lower()
        if "a" <= lowered <= "z" or "а" <= lowered <= "я" or lowered == "ё":
            continue
        return True
    return False


def _risk_queue(reasons: set[str]) -> str:
    if reasons.intersection({"self_harm", "suspicious_obfuscation", "threat_or_abuse"}):
        return "safety_priority"
    if reasons.intersection(
        {"account_security", "sensitive_pii:credential", "sensitive_pii:one_time_code"}
    ):
        return "security_priority"
    if reasons.intersection(
        {
            "privacy_request",
            "legal_request",
            "sensitive_pii:russian_passport",
            "sensitive_pii:snils",
        }
    ):
        return "restricted_priority"
    if "financial_action" in reasons or "sensitive_pii:card_number" in reasons:
        return "payments_priority"
    return "risk_queue"


def assess_risk(text: str, classification: ClassificationResult | None = None) -> RiskAssessment:
    del classification  # kept for compatibility; ML output never lowers or creates hard risk
    normalized = text.lower()
    pii_types = detect_pii(text)
    reasons = [
        name for name, patterns in RISK_PATTERNS.items() if any(p.search(text) for p in patterns)
    ]
    prompt_injection = any(marker in normalized for marker in PROMPT_INJECTION_MARKERS)
    if prompt_injection:
        reasons.append("prompt_injection")
    if any(pattern.search(text) for pattern in OBFUSCATION_PATTERNS):
        reasons.append("suspicious_obfuscation")
    if "card_number" in pii_types:
        reasons.append("sensitive_pii:card_number")
    if "credential" in pii_types:
        reasons.append("sensitive_pii:credential")
    if "one_time_code" in pii_types:
        reasons.append("sensitive_pii:one_time_code")
    for pii_type in ("russian_passport", "snils"):
        if pii_type in pii_types:
            reasons.append(f"sensitive_pii:{pii_type}")
    unique_reasons = tuple(sorted(set(reasons)))
    reason_set = set(unique_reasons)
    return RiskAssessment(
        level="high" if unique_reasons else "low",
        business_risk="high" if unique_reasons else "low",
        severity="critical"
        if reason_set.intersection({"self_harm", "account_security"})
        else ("high" if unique_reasons else "low"),
        human_queue=_risk_queue(reason_set) if unique_reasons else "general_queue",
        pii_types=pii_types,
        prompt_injection_suspected=prompt_injection,
        auto_reply_prohibited=bool(unique_reasons),
        reasons=unique_reasons,
        engine_version=RISK_ENGINE_VERSION,
    )


def assess_scope(text: str, classification: ClassificationResult) -> PolicyCheckResult:
    """Require the whole request, not one attractive phrase, to fit one known intent."""
    reasons: list[str] = []
    if _has_unsupported_script(text):
        reasons.append("UNSUPPORTED_LANGUAGE_OR_SCRIPT")
    detected = {intent for intent, pattern in INTENT_SCOPE_PATTERNS.items() if pattern.search(text)}
    if len(detected) > 1:
        reasons.append("MULTIPLE_INTENTS")
    if classification.intent not in detected:
        reasons.append("SAFE_SCOPE_NOT_CONFIRMED")

    tokens = _scope_tokens(text)
    if any(not _scope_token_allowed(token, classification.intent) for token in tokens):
        reasons.append("UNSUPPORTED_SCOPE")
    if classification.intent == "change_language":
        action_indexes = [
            index
            for index, token in enumerate(tokens)
            if any(token.startswith(prefix) for prefix in _LANGUAGE_ACTION_PREFIXES)
        ]
        action_count = len(action_indexes)
        if action_count > 1:
            reasons.append("MULTIPLE_ACTIONS")
        language_evidence = INTENT_CLAUSE_EVIDENCE_PREFIXES["change_language"]
        for action_index in action_indexes:
            following = tokens[action_index + 1 :]
            has_following_language = any(
                token.startswith(prefix) for token in following for prefix in language_evidence
            )
            has_following_other_object = any(
                token.startswith(prefix)
                for token in following
                for prefix in _NON_LANGUAGE_OBJECT_PREFIXES
            )
            if not has_following_language and has_following_other_object:
                reasons.append("UNSUPPORTED_SCOPE")
    clauses = _SCOPE_CLAUSE_SPLIT_RE.split(text)
    if any(not _scope_clause_supported(clause, classification.intent) for clause in clauses):
        reasons.append("UNSUPPORTED_SCOPE")
    if classification.intent == "change_language":
        language_evidence = INTENT_CLAUSE_EVIDENCE_PREFIXES["change_language"]
        for clause in clauses:
            clause_tokens = _scope_tokens(clause)
            evidence_indexes = [
                index
                for index, token in enumerate(clause_tokens)
                if any(token.startswith(prefix) for prefix in language_evidence)
            ]
            if not evidence_indexes:
                continue
            tail = clause_tokens[max(evidence_indexes) + 1 :]
            non_language_objects = [
                token
                for token in tail
                if any(token.startswith(prefix) for prefix in _NON_LANGUAGE_OBJECT_PREFIXES)
            ]
            non_app_objects = [
                token for token in non_language_objects if not token.startswith("приложен")
            ]
            action_after_language = any(
                token.startswith(prefix) for token in tail for prefix in _LANGUAGE_ACTION_PREFIXES
            )
            if non_app_objects or (non_language_objects and action_after_language):
                reasons.append("UNSUPPORTED_SCOPE")
    return PolicyCheckResult(not reasons, tuple(dict.fromkeys(reasons)))


class AutomationPolicy:
    def __init__(self, config: PolicyConfig) -> None:
        self.config = config
        self.version = config.policy_version

    @staticmethod
    def _article_reasons(
        classification: ClassificationResult,
        retrieval: RetrievalResult,
        *,
        require_auto_allowlist: bool,
    ) -> list[str]:
        reasons: list[str] = []
        article = retrieval.article
        if article is None:
            return ["NO_KNOWLEDGE_ARTICLE"]
        if article.status != "approved":
            reasons.append("ARTICLE_NOT_APPROVED")
        if require_auto_allowlist and not article.auto_reply_allowed:
            reasons.append("ARTICLE_NOT_ALLOWLISTED")
        if article.intent != classification.intent:
            reasons.append("CLASSIFIER_RETRIEVAL_DISAGREEMENT")
        try:
            expired = date.fromisoformat(article.valid_until) < datetime.now(UTC).date()
        except ValueError:
            reasons.append("ARTICLE_VALIDITY_INVALID")
        else:
            if expired:
                reasons.append("ARTICLE_EXPIRED")
        return reasons

    def check_auto(
        self,
        classification: ClassificationResult,
        risk: RiskAssessment,
        retrieval: RetrievalResult,
        scope: PolicyCheckResult | None = None,
    ) -> PolicyCheckResult:
        reasons: list[str] = []
        if risk.auto_reply_prohibited:
            reasons.append("HIGH_RISK_OR_PROHIBITED")
        if scope is None:
            reasons.append("MISSING_SCOPE_ASSESSMENT")
        elif not scope.allowed:
            reasons.extend(scope.reason_codes)
        if classification.abstained or classification.intent == "unknown":
            reasons.append("UNKNOWN_OR_ABSTAINED_INTENT")
        intent_policy = self.config.intent_policies.get(classification.intent)
        if intent_policy is None or intent_policy.mode != "auto_template":
            reasons.append("INTENT_NOT_AUTO_ENABLED")
        confidence_gate = (
            intent_policy.automation_confidence
            if intent_policy is not None
            else self.config.automation_confidence
        )
        margin_gate = (
            intent_policy.automation_margin
            if intent_policy is not None
            else self.config.automation_margin
        )
        if classification.confidence < confidence_gate:
            reasons.append("LOW_CLASSIFICATION_CONFIDENCE")
        if classification.margin < margin_gate:
            reasons.append("AMBIGUOUS_CLASSIFICATION")
        reasons.extend(
            self._article_reasons(classification, retrieval, require_auto_allowlist=True)
        )
        if retrieval.top_score < self.config.retrieval_score:
            reasons.append("LOW_RETRIEVAL_SCORE")
        if retrieval.margin < self.config.retrieval_margin:
            reasons.append("AMBIGUOUS_RETRIEVAL")
        return PolicyCheckResult(not reasons, tuple(dict.fromkeys(reasons)))

    def check_suggest(
        self,
        classification: ClassificationResult,
        risk: RiskAssessment,
        retrieval: RetrievalResult,
        scope: PolicyCheckResult | None = None,
    ) -> PolicyCheckResult:
        reasons: list[str] = []
        if risk.auto_reply_prohibited:
            reasons.append("HIGH_RISK_OR_PROHIBITED")
        if scope is None:
            reasons.append("MISSING_SCOPE_ASSESSMENT")
        elif not scope.allowed:
            reasons.extend(scope.reason_codes)
        if classification.abstained or classification.intent == "unknown":
            reasons.append("UNKNOWN_OR_ABSTAINED_INTENT")
        intent_policy = self.config.intent_policies.get(classification.intent)
        if intent_policy is None or intent_policy.mode == "human_only":
            reasons.append("INTENT_HUMAN_ONLY")
        if classification.confidence < self.config.classifier_abstain_confidence:
            reasons.append("LOW_SUGGESTION_CONFIDENCE")
        if classification.margin < self.config.classifier_abstain_margin:
            reasons.append("AMBIGUOUS_SUGGESTION")
        reasons.extend(
            self._article_reasons(classification, retrieval, require_auto_allowlist=False)
        )
        if retrieval.top_score < self.config.retrieval_score:
            reasons.append("LOW_RETRIEVAL_SCORE")
        if retrieval.margin < self.config.retrieval_margin:
            reasons.append("AMBIGUOUS_RETRIEVAL")
        return PolicyCheckResult(not reasons, tuple(dict.fromkeys(reasons)))

    def check(
        self,
        classification: ClassificationResult,
        risk: RiskAssessment,
        retrieval: RetrievalResult,
        scope: PolicyCheckResult | None = None,
    ) -> PolicyCheckResult:
        """Compatibility alias; missing full-request scope always fails closed."""
        return self.check_auto(classification, risk, retrieval, scope)


class OutputPolicyChecker:
    version = "output-policy-v3"

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def check(
        self,
        draft: str,
        article: KnowledgeArticle,
        *,
        require_auto_allowlist: bool = True,
    ) -> PolicyCheckResult:
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
        if article.status != "approved" or (
            require_auto_allowlist and not article.auto_reply_allowed
        ):
            reasons.append("ARTICLE_NO_LONGER_ELIGIBLE")
        return PolicyCheckResult(not reasons, tuple(dict.fromkeys(reasons)))
