from __future__ import annotations

import json
from pathlib import Path

from .audit import build_audit_event, input_sha256
from .classifier import IntentClassifier
from .generation import (
    DraftGenerator,
    GeneratorUnavailable,
    approved_template_fallback,
)
from .models import (
    Decision,
    GenerationContext,
    GenerationResult,
    KnowledgeArticle,
    RetrievalResult,
    RiskAssessment,
    Ticket,
)
from .pii import redact_pii
from .policy import AutomationPolicy, OutputPolicyChecker, assess_risk
from .retrieval import KnowledgeRetriever
from .storage import SQLiteDecisionStore


class TicketPipeline:
    def __init__(
        self,
        *,
        classifier: IntentClassifier,
        retriever: KnowledgeRetriever,
        generator: DraftGenerator,
        automation_policy: AutomationPolicy,
        output_policy: OutputPolicyChecker,
        store: SQLiteDecisionStore,
    ) -> None:
        self.classifier = classifier
        self.retriever = retriever
        self.generator = generator
        self.automation_policy = automation_policy
        self.output_policy = output_policy
        self.store = store

    def process(self, ticket: Ticket) -> Decision:
        payload_hash = input_sha256(ticket)
        existing = self.store.get_decision(ticket.event_id, payload_hash)
        if existing is not None:
            return existing

        sanitized_text = redact_pii(ticket.text)
        classification = self.classifier.predict(sanitized_text)
        risk = assess_risk(ticket.text, classification)
        retrieval = self.retriever.retrieve(sanitized_text, classification.topic)
        precheck = self.automation_policy.check(classification, risk, retrieval)
        generation: GenerationResult | None = None

        if not precheck.allowed:
            decision = self._human_decision(
                ticket, classification, risk, retrieval, precheck.reason_codes
            )
        else:
            article = retrieval.article
            assert article is not None
            context = GenerationContext(
                redacted_text=sanitized_text,
                topic=classification.topic,
                intent=classification.intent,
                article_id=article.article_id,
                approved_answer=article.answer,
            )
            try:
                generation = self.generator.generate(context)
                degraded = False
            except GeneratorUnavailable:
                generation = approved_template_fallback(context)
                degraded = True
            output_check = self.output_policy.check(generation.draft, article)
            if not output_check.allowed:
                decision = self._human_decision(
                    ticket,
                    classification,
                    risk,
                    retrieval,
                    ("OUTPUT_POLICY_REJECTED", *output_check.reason_codes),
                )
            else:
                decision = Decision(
                    event_id=ticket.event_id,
                    ticket_id=ticket.ticket_id,
                    topic=classification.topic,
                    intent=classification.intent,
                    confidence=classification.confidence,
                    classification_margin=classification.margin,
                    risk_level=risk.level,
                    risk_reasons=risk.reasons,
                    action="auto_reply",
                    route="resolved_automatically",
                    article_id=article.article_id,
                    retrieval_score=retrieval.top_score,
                    retrieval_margin=retrieval.margin,
                    draft=generation.draft,
                    generation_mode=generation.mode,
                    degraded_mode=degraded,
                    reason_codes=(
                        "SAFE_APPROVED_TEMPLATE_FALLBACK"
                        if degraded
                        else "ALL_SAFETY_GATES_PASSED",
                    ),
                    component_versions=self._versions(
                        classification.classifier_version,
                        retrieval.index_version,
                        generation.generator_version,
                    ),
                )

        audit_event = build_audit_event(
            ticket=ticket,
            classification=classification,
            risk=risk,
            retrieval=retrieval,
            generation=generation,
            decision=decision,
        )
        return self.store.persist(
            decision=decision,
            audit_event=audit_event,
            input_hash=payload_hash,
        )

    def _human_decision(
        self,
        ticket: Ticket,
        classification,
        risk: RiskAssessment,
        retrieval: RetrievalResult,
        reason_codes: tuple[str, ...],
    ) -> Decision:
        route = (
            "payments_priority"
            if classification.topic == "payment" or "financial_action" in risk.reasons
            else "risk_queue"
            if risk.level == "high"
            else "general_queue"
        )
        return Decision(
            event_id=ticket.event_id,
            ticket_id=ticket.ticket_id,
            topic=classification.topic,
            intent=classification.intent,
            confidence=classification.confidence,
            classification_margin=classification.margin,
            risk_level=risk.level,
            risk_reasons=risk.reasons,
            action="human_review",
            route=route,
            article_id=retrieval.article.article_id if retrieval.article else None,
            retrieval_score=retrieval.top_score,
            retrieval_margin=retrieval.margin,
            draft=None,
            generation_mode=None,
            degraded_mode=False,
            reason_codes=tuple(reason_codes),
            component_versions=self._versions(
                classification.classifier_version,
                retrieval.index_version,
                "not_called",
            ),
        )

    def _versions(self, classifier: str, retriever: str, generator: str) -> dict[str, str]:
        return {
            "runtime": "poc-runtime-v1",
            "schema": "decision-v1",
            "classifier": classifier,
            "retriever": retriever,
            "generator": generator,
            "automation_policy": self.automation_policy.version,
            "output_policy": self.output_policy.version,
        }


def load_knowledge_base(path: Path) -> tuple[KnowledgeArticle, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return tuple(
        KnowledgeArticle(
            article_id=str(item["article_id"]),
            topic=str(item["topic"]),
            intent=str(item["intent"]),
            title=str(item["title"]),
            answer=str(item["answer"]),
            keywords=tuple(str(keyword) for keyword in item["keywords"]),
            status=str(item["status"]),
            auto_reply_allowed=bool(item["auto_reply_allowed"]),
            version=int(item["version"]),
            valid_until=str(item["valid_until"]),
        )
        for item in payload
    )
