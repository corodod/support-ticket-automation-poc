from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .audit import build_audit_event, input_sha256
from .classifier import IntentClassifier
from .generation import (
    DraftGenerator,
    GeneratorUnavailable,
    approved_suggestion_fallback,
    approved_template_direct,
)
from .models import (
    ClassificationResult,
    Decision,
    GenerationContext,
    GenerationResult,
    KnowledgeArticle,
    RetrievalResult,
    RiskAssessment,
    Ticket,
)
from .pii import redact_pii
from .policy import AutomationPolicy, OutputPolicyChecker, assess_risk, assess_scope
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
        risk = assess_risk(ticket.text)
        generation: GenerationResult | None = None

        if risk.auto_reply_prohibited:
            classification = self._not_called_classification("hard-risk")
            retrieval = self._not_called_retrieval()
            decision = self._human_decision(
                ticket,
                classification,
                risk,
                retrieval,
                ("HARD_RISK_EARLY_EXIT", *risk.reasons),
            )
        else:
            classification = self.classifier.predict(sanitized_text)
            if classification.abstained or classification.intent == "unknown":
                retrieval = self._not_called_retrieval()
                decision = self._human_decision(
                    ticket,
                    classification,
                    risk,
                    retrieval,
                    ("UNKNOWN_OR_ABSTAINED_INTENT", "RETRIEVAL_SKIPPED"),
                )
            else:
                scope = assess_scope(sanitized_text, classification)
                if not scope.allowed:
                    retrieval = self._not_called_retrieval()
                    decision = self._human_decision(
                        ticket,
                        classification,
                        risk,
                        retrieval,
                        (*scope.reason_codes, "RETRIEVAL_SKIPPED"),
                    )
                else:
                    retrieval = self.retriever.retrieve(sanitized_text, classification.topic)
                    auto_check = self.automation_policy.check_auto(
                        classification, risk, retrieval, scope
                    )
                    suggest_check = self.automation_policy.check_suggest(
                        classification, risk, retrieval, scope
                    )
                    if auto_check.allowed:
                        article = retrieval.article
                        assert article is not None
                        context = self._generation_context(sanitized_text, classification, article)
                        generation = approved_template_direct(context)
                        output_check = self.output_policy.check(generation.draft, article)
                        if output_check.allowed:
                            decision = self._auto_decision(
                                ticket, classification, risk, retrieval, generation
                            )
                        else:
                            decision = self._human_decision(
                                ticket,
                                classification,
                                risk,
                                retrieval,
                                ("OUTPUT_POLICY_REJECTED", *output_check.reason_codes),
                                candidate_action="auto_template",
                                generation=generation,
                            )
                    elif suggest_check.allowed:
                        article = retrieval.article
                        assert article is not None
                        context = self._generation_context(sanitized_text, classification, article)
                        try:
                            generation = self.generator.generate(context)
                            degraded = False
                        except GeneratorUnavailable:
                            generation = approved_suggestion_fallback(context)
                            degraded = True
                        output_check = self.output_policy.check(
                            generation.draft,
                            article,
                            require_auto_allowlist=False,
                        )
                        if output_check.allowed:
                            decision = self._suggest_decision(
                                ticket,
                                classification,
                                risk,
                                retrieval,
                                generation,
                                degraded=degraded,
                                auto_reason_codes=auto_check.reason_codes,
                            )
                        else:
                            decision = self._human_decision(
                                ticket,
                                classification,
                                risk,
                                retrieval,
                                ("OUTPUT_POLICY_REJECTED", *output_check.reason_codes),
                                candidate_action="operator_suggest",
                                generation=generation,
                            )
                    else:
                        decision = self._human_decision(
                            ticket,
                            classification,
                            risk,
                            retrieval,
                            tuple(
                                dict.fromkeys(
                                    (*auto_check.reason_codes, *suggest_check.reason_codes)
                                )
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

    @staticmethod
    def _generation_context(
        sanitized_text: str,
        classification: ClassificationResult,
        article: KnowledgeArticle,
    ) -> GenerationContext:
        return GenerationContext(
            redacted_text=sanitized_text,
            topic=classification.topic,
            intent=classification.intent,
            article_id=article.article_id,
            approved_answer=article.answer,
        )

    def _auto_decision(
        self,
        ticket: Ticket,
        classification: ClassificationResult,
        risk: RiskAssessment,
        retrieval: RetrievalResult,
        generation: GenerationResult,
    ) -> Decision:
        article = retrieval.article
        assert article is not None
        return Decision(
            event_id=ticket.event_id,
            ticket_id=ticket.ticket_id,
            topic=classification.topic,
            intent=classification.intent,
            confidence=classification.confidence,
            classification_margin=classification.margin,
            risk_level=risk.level,
            risk_reasons=risk.reasons,
            candidate_action="auto_template",
            action="auto_reply",
            route="auto_reply_pending",
            delivery_state="send_pending",
            resolution_outcome="unknown",
            article_id=article.article_id,
            article_version=article.version,
            retrieval_score=retrieval.top_score,
            retrieval_margin=retrieval.margin,
            draft=generation.draft,
            template_sha256=self._sha256(generation.draft),
            generation_mode=generation.mode,
            degraded_mode=False,
            reason_codes=("ALL_SAFETY_GATES_PASSED",),
            component_versions=self._versions(
                classification.classifier_version,
                retrieval.index_version,
                generation.generator_version,
                risk.engine_version,
            ),
        )

    def _suggest_decision(
        self,
        ticket: Ticket,
        classification: ClassificationResult,
        risk: RiskAssessment,
        retrieval: RetrievalResult,
        generation: GenerationResult,
        *,
        degraded: bool,
        auto_reason_codes: tuple[str, ...],
    ) -> Decision:
        article = retrieval.article
        assert article is not None
        route = (
            "incident_operator_queue"
            if classification.topic == "service_incident"
            else "operator_suggest_queue"
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
            candidate_action="operator_suggest",
            action="operator_suggest",
            route=route,
            delivery_state="not_user_visible",
            resolution_outcome="unknown",
            article_id=article.article_id,
            article_version=article.version,
            retrieval_score=retrieval.top_score,
            retrieval_margin=retrieval.margin,
            draft=generation.draft,
            template_sha256=self._sha256(generation.draft),
            generation_mode=generation.mode,
            degraded_mode=degraded,
            reason_codes=tuple(dict.fromkeys(("OPERATOR_SUGGESTION_ONLY", *auto_reason_codes))),
            component_versions=self._versions(
                classification.classifier_version,
                retrieval.index_version,
                generation.generator_version,
                risk.engine_version,
            ),
        )

    def _human_decision(
        self,
        ticket: Ticket,
        classification: ClassificationResult,
        risk: RiskAssessment,
        retrieval: RetrievalResult,
        reason_codes: tuple[str, ...],
        *,
        candidate_action: str = "human_only",
        generation: GenerationResult | None = None,
    ) -> Decision:
        route = risk.human_queue
        untrusted_scope_reasons = {
            "MULTIPLE_ACTIONS",
            "MULTIPLE_INTENTS",
            "SAFE_SCOPE_NOT_CONFIRMED",
            "UNKNOWN_OR_ABSTAINED_INTENT",
            "UNSUPPORTED_LANGUAGE_OR_SCRIPT",
            "UNSUPPORTED_SCOPE",
        }
        if risk.level != "high" and not untrusted_scope_reasons.intersection(reason_codes):
            if classification.topic == "payment":
                route = "payments_priority"
            elif classification.topic == "service_incident":
                route = "incident_operator_queue"
        return Decision(
            event_id=ticket.event_id,
            ticket_id=ticket.ticket_id,
            topic=classification.topic,
            intent=classification.intent,
            confidence=classification.confidence,
            classification_margin=classification.margin,
            risk_level=risk.level,
            risk_reasons=risk.reasons,
            candidate_action=candidate_action,
            action="human_review",
            route=route,
            delivery_state="not_requested",
            resolution_outcome="unknown",
            article_id=retrieval.article.article_id if retrieval.article else None,
            article_version=retrieval.article.version if retrieval.article else None,
            retrieval_score=retrieval.top_score,
            retrieval_margin=retrieval.margin,
            draft=None,
            template_sha256=None,
            generation_mode=generation.mode if generation else None,
            degraded_mode=False,
            reason_codes=tuple(reason_codes),
            component_versions=self._versions(
                classification.classifier_version,
                retrieval.index_version,
                generation.generator_version if generation else "not_called",
                risk.engine_version,
            ),
        )

    @staticmethod
    def _not_called_classification(reason: str) -> ClassificationResult:
        return ClassificationResult(
            topic="not_evaluated",
            intent="not_evaluated",
            confidence=0.0,
            second_confidence=0.0,
            margin=0.0,
            classifier_version=f"not_called:{reason}",
            abstained=True,
        )

    def _not_called_retrieval(self) -> RetrievalResult:
        return RetrievalResult(
            article=None,
            top_score=0.0,
            second_score=0.0,
            margin=0.0,
            index_version=f"not_called:{self.retriever.version}",
            ranked_article_ids=(),
        )

    @staticmethod
    def _sha256(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _versions(
        self,
        classifier: str,
        retriever: str,
        generator: str,
        risk_engine: str,
    ) -> dict[str, str]:
        return {
            "runtime": "poc-runtime-v2",
            "schema": "decision-v2",
            "redactor": "pii-redactor-v3",
            "risk_engine": risk_engine,
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
