from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Protocol

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .models import ClassificationResult


INTENT_TO_TOPIC = {
    "change_language": "settings",
    "change_notifications": "settings",
    "password_reset": "account_access",
    "verification_code": "account_access",
    "duplicate_charge": "payment",
    "service_unavailable": "service_incident",
}

RULES = {
    "change_language": ("язык", "локализац"),
    "change_notifications": ("уведомлен", "push", "пуш"),
    "password_reset": ("парол", "восстановить доступ"),
    "verification_code": ("код подтверж", "код для входа", "проверочный код"),
    "duplicate_charge": ("дважды спис", "двойное спис", "списали два раза"),
    "service_unavailable": ("не работает", "не открывается", "недоступ", "зависает"),
}


class IntentClassifier(Protocol):
    version: str

    def predict(self, text: str) -> ClassificationResult: ...


def _normalize(text: str) -> str:
    return " ".join(re.findall(r"[a-zа-яё0-9]+", text.lower()))


class RuleIntentClassifier:
    version = "rules-v1"

    def predict(self, text: str) -> ClassificationResult:
        normalized = _normalize(text)
        ranked = sorted(
            ((intent, sum(marker in normalized for marker in markers)) for intent, markers in RULES.items()),
            key=lambda item: item[1],
            reverse=True,
        )
        best_intent, best_hits = ranked[0]
        second_hits = ranked[1][1]
        if best_hits == 0 or best_hits == second_hits:
            return ClassificationResult(
                topic="other",
                intent="unknown",
                confidence=0.40,
                second_confidence=0.40,
                margin=0.0,
                classifier_version=self.version,
                abstained=True,
            )
        confidence = min(0.95, 0.70 + 0.10 * best_hits)
        second = 0.40 if second_hits == 0 else min(0.90, 0.70 + 0.10 * second_hits)
        return ClassificationResult(
            topic=INTENT_TO_TOPIC[best_intent],
            intent=best_intent,
            confidence=round(confidence, 4),
            second_confidence=round(second, 4),
            margin=round(confidence - second, 4),
            classifier_version=self.version,
            abstained=False,
        )


class SklearnIntentClassifier:
    def __init__(
        self,
        dataset_path: Path,
        *,
        abstain_confidence: float,
        abstain_margin: float,
    ) -> None:
        rows = [
            json.loads(line)
            for line in dataset_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if len({row["intent"] for row in rows}) < 2:
            raise ValueError("Training data must contain at least two intent classes")
        self.model = Pipeline(
            [
                (
                    "tfidf",
                    TfidfVectorizer(
                        analyzer="char_wb",
                        ngram_range=(3, 5),
                        sublinear_tf=True,
                        max_features=20_000,
                    ),
                ),
                (
                    "classifier",
                    LogisticRegression(
                        max_iter=2_000,
                        class_weight="balanced",
                        random_state=42,
                    ),
                ),
            ]
        )
        self.model.fit([row["text"] for row in rows], [row["intent"] for row in rows])
        dataset_hash = hashlib.sha256(dataset_path.read_bytes()).hexdigest()[:12]
        self.version = f"tfidf-logreg-v1-{dataset_hash}"
        self.abstain_confidence = abstain_confidence
        self.abstain_margin = abstain_margin

    def predict(self, text: str) -> ClassificationResult:
        probabilities = self.model.predict_proba([text])[0]
        classes = [str(value) for value in self.model.classes_]
        ranked = sorted(zip(classes, probabilities, strict=True), key=lambda item: item[1], reverse=True)
        best_intent, best_probability = ranked[0]
        second_probability = float(ranked[1][1]) if len(ranked) > 1 else 0.0
        best_probability = float(best_probability)
        margin = best_probability - second_probability
        abstained = (
            best_probability < self.abstain_confidence or margin < self.abstain_margin
        )
        return ClassificationResult(
            topic="other" if abstained else INTENT_TO_TOPIC[best_intent],
            intent="unknown" if abstained else best_intent,
            confidence=round(best_probability, 4),
            second_confidence=round(second_probability, 4),
            margin=round(margin, 4),
            classifier_version=self.version,
            abstained=abstained,
        )
