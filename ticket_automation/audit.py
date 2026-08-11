from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .models import (
    ClassificationResult,
    Decision,
    GenerationResult,
    RetrievalResult,
    RiskAssessment,
    Ticket,
)


def input_sha256(ticket: Ticket) -> str:
    canonical_payload = json.dumps(
        {
            "channel": ticket.channel,
            "event_id": ticket.event_id,
            "text": ticket.text,
            "ticket_id": ticket.ticket_id,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


def build_audit_event(
    *,
    ticket: Ticket,
    classification: ClassificationResult,
    risk: RiskAssessment,
    retrieval: RetrievalResult,
    generation: GenerationResult | None,
    decision: Decision,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "event_id": ticket.event_id,
        "ticket_id": ticket.ticket_id,
        "channel": ticket.channel,
        "input_sha256": input_sha256(ticket),
        "input_length": len(ticket.text),
        "classification": {
            "topic": classification.topic,
            "intent": classification.intent,
            "confidence": classification.confidence,
            "second_confidence": classification.second_confidence,
            "margin": classification.margin,
            "abstained": classification.abstained,
            "version": classification.classifier_version,
        },
        "risk": {
            "level": risk.level,
            "pii_types": risk.pii_types,
            "prompt_injection_suspected": risk.prompt_injection_suspected,
            "reasons": risk.reasons,
        },
        "retrieval": {
            "article_id": retrieval.article.article_id if retrieval.article else None,
            "top_score": retrieval.top_score,
            "second_score": retrieval.second_score,
            "margin": retrieval.margin,
            "version": retrieval.index_version,
        },
        "generation": {
            "mode": generation.mode if generation else None,
            "version": generation.generator_version if generation else None,
            "draft_sha256": (
                hashlib.sha256(generation.draft.encode("utf-8")).hexdigest()
                if generation
                else None
            ),
        },
        "decision": {
            "action": decision.action,
            "route": decision.route,
            "reason_codes": decision.reason_codes,
            "component_versions": decision.component_versions,
        },
    }
