from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import accuracy_score, f1_score, recall_score

from ticket_automation.config import PolicyConfig
from ticket_automation.models import Ticket
from ticket_automation.pii import (
    CARD_CANDIDATE_RE,
    EMAIL_RE,
    PHONE_RE,
    SECRET_RE,
    redact_pii,
)
from ticket_automation.runtime import REPOSITORY_ROOT, build_pipeline


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _round(value: float) -> float:
    return round(float(value), 4)


def _expected_calibration_error(
    confidences: np.ndarray, correctness: np.ndarray, bins: int = 10
) -> float:
    error = 0.0
    for lower in np.linspace(0.0, 1.0, bins + 1)[:-1]:
        upper = lower + 1.0 / bins
        include = (confidences > lower) & (confidences <= upper)
        if not np.any(include):
            continue
        error += float(np.mean(include)) * abs(
            float(np.mean(correctness[include])) - float(np.mean(confidences[include]))
        )
    return error


def _validation_metrics(pipeline, validation_path: Path) -> dict[str, Any]:
    rows = _jsonl(validation_path)
    texts = [row["text"] for row in rows]
    expected = np.array([row["intent"] for row in rows])
    classifier = pipeline.classifier
    probabilities = classifier.model.predict_proba(texts)
    classes = np.asarray(classifier.model.classes_, dtype=str)
    raw_predicted = classes[np.argmax(probabilities, axis=1)]
    confidences = np.max(probabilities, axis=1)
    sorted_probabilities = np.sort(probabilities, axis=1)
    margins = sorted_probabilities[:, -1] - sorted_probabilities[:, -2]
    correctness = raw_predicted == expected
    selective = [classifier.predict(text) for text in texts]
    accepted = np.array([not result.abstained for result in selective])
    selective_predicted = np.array([result.intent for result in selective])
    labels = sorted(set(expected.tolist()))
    per_class = recall_score(
        expected,
        raw_predicted,
        labels=labels,
        average=None,
        zero_division=0,
    )
    one_hot = np.zeros_like(probabilities)
    class_to_index = {name: index for index, name in enumerate(classes)}
    for row_index, name in enumerate(expected):
        one_hot[row_index, class_to_index[name]] = 1.0
    safe_intents = np.isin(expected, ("change_language", "verification_code"))
    scenarios: dict[str, dict[str, float]] = {}
    for confidence_gate, margin_gate in ((0.45, 0.15), (0.65, 0.35), (0.75, 0.50)):
        automated = (
            (confidences >= confidence_gate)
            & (margins >= margin_gate)
            & np.isin(raw_predicted, ("change_language", "verification_code"))
        )
        scenarios[f"confidence_{confidence_gate:.2f}_margin_{margin_gate:.2f}"] = {
            "classifier_candidate_coverage_all": _round(np.mean(automated)),
            "eligible_safe_coverage": _round(np.mean(automated[safe_intents])),
            "expected_safe_precision": _round(np.mean(safe_intents[automated]))
            if np.any(automated)
            else 0.0,
            "intent_correct_precision": _round(np.mean((raw_predicted == expected)[automated]))
            if np.any(automated)
            else 0.0,
        }
    return {
        "rows": len(rows),
        "closed_set_accuracy": _round(accuracy_score(expected, raw_predicted)),
        "closed_set_macro_f1": _round(
            f1_score(expected, raw_predicted, average="macro", zero_division=0)
        ),
        "per_class_recall": {
            label: _round(score) for label, score in zip(labels, per_class, strict=True)
        },
        "multiclass_brier_score": _round(np.mean(np.sum((probabilities - one_hot) ** 2, axis=1))),
        "expected_calibration_error_10_bins": _round(
            _expected_calibration_error(confidences, correctness)
        ),
        "selective_coverage": _round(np.mean(accepted)),
        "selective_accuracy": _round(
            accuracy_score(expected[accepted], selective_predicted[accepted])
            if np.any(accepted)
            else 0.0
        ),
        "abstained": int(np.sum(~accepted)),
        "classifier_only_risk_coverage_scenarios": scenarios,
    }


def _sensitive_literals(text: str) -> tuple[str, ...]:
    matches: list[str] = []
    for pattern in (EMAIL_RE, PHONE_RE, CARD_CANDIDATE_RE, SECRET_RE):
        matches.extend(match.group() for match in pattern.finditer(text))
    return tuple(matches)


def _golden_metrics(pipeline, golden_path: Path) -> dict[str, Any]:
    rows = _jsonl(golden_path)
    predictions = []
    retrieval_ranks: list[int] = []
    pii_leaks = 0
    reason_codes: Counter[str] = Counter()
    mismatches: list[dict[str, str]] = []

    for row in rows:
        ticket = Ticket.from_dict(row)
        decision = pipeline.process(ticket)
        predictions.append(decision)
        reason_codes.update(decision.reason_codes)
        if decision.action != row["expected_action"] or decision.risk_level != row["expected_risk"]:
            mismatches.append(
                {
                    "event_id": ticket.event_id,
                    "expected_action": row["expected_action"],
                    "actual_action": decision.action,
                    "expected_risk": row["expected_risk"],
                    "actual_risk": decision.risk_level,
                }
            )
        expected_article = row["expected_article_id"]
        if expected_article:
            classification = pipeline.classifier.predict(redact_pii(ticket.text))
            retrieval = pipeline.retriever.retrieve(redact_pii(ticket.text), classification.topic)
            try:
                retrieval_ranks.append(retrieval.ranked_article_ids.index(expected_article) + 1)
            except ValueError:
                retrieval_ranks.append(0)
        audit_json = json.dumps(
            pipeline.store.audit_payload(ticket.event_id), ensure_ascii=False, sort_keys=True
        )
        decision_json = json.dumps(decision.to_dict(), ensure_ascii=False, sort_keys=True)
        outbox_json = json.dumps(
            pipeline.store.outbox_payload(ticket.event_id), ensure_ascii=False, sort_keys=True
        )
        checked_surfaces = audit_json + decision_json + outbox_json
        if any(value in checked_surfaces for value in _sensitive_literals(ticket.text)):
            pii_leaks += 1

    risky = [index for index, row in enumerate(rows) if row["expected_risk"] == "high"]
    predicted_high = [
        index for index, result in enumerate(predictions) if result.risk_level == "high"
    ]
    auto = [index for index, result in enumerate(predictions) if result.action == "auto_reply"]
    eligible = [index for index, row in enumerate(rows) if row["expected_action"] == "auto_reply"]
    oos = [index for index, row in enumerate(rows) if row["slice"] == "oos"]
    unsafe = [
        rows[index]["event_id"]
        for index, result in enumerate(predictions)
        if rows[index]["expected_action"] == "human_review" and result.action == "auto_reply"
    ]
    intent_indexes = [index for index, row in enumerate(rows) if row["expected_intent"] is not None]
    expected_intents = [rows[index]["expected_intent"] for index in intent_indexes]
    predicted_intents = [predictions[index].intent for index in intent_indexes]
    reciprocal_ranks = [1.0 / rank if rank else 0.0 for rank in retrieval_ranks]
    return {
        "rows": len(rows),
        "intent_macro_f1_on_labeled_rows": _round(
            f1_score(expected_intents, predicted_intents, average="macro", zero_division=0)
        ),
        "action_accuracy": _round(
            np.mean(
                [
                    result.action == row["expected_action"]
                    for result, row in zip(predictions, rows, strict=True)
                ]
            )
        ),
        "risk_detection_recall": _round(
            np.mean([predictions[index].risk_level == "high" for index in risky])
        ),
        "risk_detection_precision": _round(
            np.mean([rows[index]["expected_risk"] == "high" for index in predicted_high])
            if predicted_high
            else 0.0
        ),
        "risky_escalation_recall": _round(
            np.mean([predictions[index].action == "human_review" for index in risky])
        ),
        "unsafe_auto_replies": len(unsafe),
        "unsafe_event_ids": unsafe,
        "unsafe_rate_upper_95_bound_rule_of_three": _round(3.0 / len(auto)) if auto else 1.0,
        "safe_auto_reply_precision": _round(
            np.mean([rows[index]["expected_action"] == "auto_reply" for index in auto])
            if auto
            else 0.0
        ),
        "automation_coverage_all": _round(len(auto) / len(rows)),
        "auto_reply_count": len(auto),
        "eligible_safe_coverage": _round(
            np.mean([predictions[index].action == "auto_reply" for index in eligible])
        ),
        "oos_auto_reply_rate": _round(
            np.mean([predictions[index].action == "auto_reply" for index in oos])
        ),
        "oos_classifier_accept_rate": _round(
            np.mean([predictions[index].intent != "unknown" for index in oos])
        ),
        "retrieval_recall_at_1": _round(np.mean([rank == 1 for rank in retrieval_ranks])),
        "retrieval_mrr": _round(np.mean(reciprocal_ranks)),
        "retrieval_evaluated_rows": len(retrieval_ranks),
        "pii_leakage_cases": pii_leaks,
        "pii_surfaces_checked": ["decision", "audit", "outbox/outbound draft"],
        "reason_code_counts": dict(sorted(reason_codes.items())),
        "mismatches": mismatches,
    }


def evaluate() -> dict[str, Any]:
    train_path = REPOSITORY_ROOT / "data" / "ml" / "train.jsonl"
    validation_path = REPOSITORY_ROOT / "data" / "ml" / "validation.jsonl"
    redteam_path = REPOSITORY_ROOT / "data" / "redteam.jsonl"
    golden_path = REPOSITORY_ROOT / "data" / "golden.jsonl"
    config_path = REPOSITORY_ROOT / "config" / "policy.json"
    with tempfile.TemporaryDirectory(prefix="ticket-eval-") as directory:
        pipeline = build_pipeline(db_path=Path(directory) / "evaluation.sqlite3")
        validation = _validation_metrics(pipeline, validation_path)
        redteam = _golden_metrics(pipeline, redteam_path)
        golden = _golden_metrics(pipeline, golden_path)
        versions = {
            "classifier": pipeline.classifier.version,
            "retriever": pipeline.retriever.version,
            "automation_policy": pipeline.automation_policy.version,
            "output_policy": pipeline.output_policy.version,
        }
    gates = {
        "no_unsafe_auto_replies": all(
            report["unsafe_auto_replies"] == 0 for report in (redteam, golden)
        ),
        "all_risky_cases_escalated": all(
            report["risky_escalation_recall"] == 1.0 for report in (redteam, golden)
        ),
        "all_expected_high_risk_detected": all(
            report["risk_detection_recall"] == 1.0 for report in (redteam, golden)
        ),
        "no_oos_auto_replies": all(
            report["oos_auto_reply_rate"] == 0.0 for report in (redteam, golden)
        ),
        "no_raw_pii_in_decision_audit_outbox": all(
            report["pii_leakage_cases"] == 0 for report in (redteam, golden)
        ),
        "all_auto_replies_expected_safe": all(
            report["safe_auto_reply_precision"] == 1.0 for report in (redteam, golden)
        ),
    }
    return {
        "schema_version": 1,
        "scope": "synthetic behavioral regression; not a production quality estimate",
        "data": {
            "train_rows": len(_jsonl(train_path)),
            "train_sha256": _sha256(train_path),
            "validation_sha256": _sha256(validation_path),
            "validation_used_for_threshold_selection": True,
            "redteam_sha256": _sha256(redteam_path),
            "redteam_used_during_development": True,
            "golden_sha256": _sha256(golden_path),
            "golden_used_for_threshold_selection": False,
        },
        "policy": asdict(PolicyConfig.load(config_path)),
        "versions": versions,
        "validation_classifier": validation,
        "redteam_end_to_end": redteam,
        "golden_end_to_end": golden,
        "hard_gates": gates,
        "all_hard_gates_passed": all(gates.values()),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run offline ML and safety evaluation")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    report = evaluate()
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["all_hard_gates_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
