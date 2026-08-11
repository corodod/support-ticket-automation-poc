from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ticket_automation.classifier import RuleIntentClassifier
from ticket_automation.incidents import find_incident_candidates
from ticket_automation.models import Ticket
from ticket_automation.pii import detect_pii, is_luhn_valid, redact_pii
from ticket_automation.policy import assess_risk
from ticket_automation.runtime import REPOSITORY_ROOT, build_pipeline


class ComponentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="component-test-")
        cls.pipeline = build_pipeline(db_path=Path(cls.temporary.name) / "components.sqlite3")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_luhn_distinguishes_card_from_long_identifier(self) -> None:
        self.assertTrue(is_luhn_valid("4111 1111 1111 1111"))
        self.assertFalse(is_luhn_valid("1234 5678 9012 3456"))
        self.assertIn("card_number", detect_pii("карта 4111 1111 1111 1111"))
        self.assertIn(
            "long_numeric_identifier",
            detect_pii("заказ 1234 5678 9012 3456"),
        )
        self.assertEqual(
            redact_pii("заказ 1234 5678 9012 3456"),
            "заказ [LONG_NUMBER]",
        )

    def test_email_phone_and_credential_redaction(self) -> None:
        text = "user@example.com, +7 999 123-45-67, token=abcdef123456"
        self.assertEqual(detect_pii(text), ("email", "phone", "credential"))
        redacted = redact_pii(text)
        self.assertNotIn("example.com", redacted)
        self.assertNotIn("123-45-67", redacted)
        self.assertNotIn("abcdef123456", redacted)

    def test_rule_classifier_abstains_on_tie_or_unknown(self) -> None:
        classifier = RuleIntentClassifier()
        result = classifier.predict("Хочу изменить язык и уведомления")
        self.assertTrue(result.abstained)
        self.assertEqual(result.intent, "unknown")

    def test_ticket_input_validation(self) -> None:
        with self.assertRaisesRegex(TypeError, "JSON object"):
            Ticket.from_dict([])
        with self.assertRaisesRegex(ValueError, "Missing required"):
            Ticket.from_dict({"event_id": "E"})
        with self.assertRaisesRegex(ValueError, "at most 10000"):
            Ticket.from_dict(
                {"event_id": "E", "ticket_id": "T", "channel": "chat", "text": "x" * 10_001}
            )

    def test_output_policy_rejects_pii_claims_urls_and_missing_grounding(self) -> None:
        article = self.pipeline.retriever.articles[0]
        checker = self.pipeline.output_policy
        cases = {
            "Здравствуйте, user@example.com. " + article.answer: "PII_IN_OUTPUT",
            "Деньги уже возвращены. " + article.answer: "FORBIDDEN_CLAIM",
            article.answer + " Подробнее: https://evil.example": "UNAPPROVED_URL",
            "Откройте другой раздел настроек.": "MISSING_APPROVED_GROUNDING",
        }
        for draft, reason in cases.items():
            with self.subTest(reason=reason):
                result = checker.check(draft, article)
                self.assertFalse(result.allowed)
                self.assertIn(reason, result.reason_codes)

    def test_expired_and_non_allowlisted_articles_are_blocked(self) -> None:
        classification = self.pipeline.classifier.predict("Как изменить язык приложения?")
        risk = self.pipeline.automation_policy.check
        retrieval = self.pipeline.retriever.retrieve(
            "Как изменить язык приложения?", classification.topic
        )
        low_risk = assess_risk("Как изменить язык приложения?", classification)
        for article, expected_reason in (
            (replace(retrieval.article, valid_until="2020-01-01"), "ARTICLE_EXPIRED"),
            (replace(retrieval.article, auto_reply_allowed=False), "ARTICLE_NOT_ALLOWLISTED"),
            (replace(retrieval.article, status="draft"), "ARTICLE_NOT_APPROVED"),
        ):
            with self.subTest(expected_reason=expected_reason):
                altered = replace(retrieval, article=article)
                result = risk(classification, low_risk, altered)
                self.assertFalse(result.allowed)
                self.assertIn(expected_reason, result.reason_codes)

    def test_retrieval_regression_for_notifications(self) -> None:
        classification = self.pipeline.classifier.predict("Как изменить настройки уведомлений?")
        result = self.pipeline.retriever.retrieve(
            "Как изменить настройки уведомлений?", classification.topic
        )
        self.assertEqual(result.article.article_id, "KB-SETTINGS-NOTIFICATIONS-001")
        self.assertEqual(result.ranked_article_ids[0], "KB-SETTINGS-NOTIFICATIONS-001")

    def test_incident_detector_deduplicates_before_counting(self) -> None:
        payload = json.loads(
            (REPOSITORY_ROOT / "examples" / "incident_batch.json").read_text(encoding="utf-8")
        )
        candidates = find_incident_candidates(Ticket.from_dict(item) for item in payload)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].size, 4)
        self.assertFalse(candidates[0].auto_close_allowed)
        self.assertEqual(len(set(candidates[0].event_ids)), 4)

    def test_unrelated_messages_do_not_form_incident(self) -> None:
        tickets = (
            Ticket("E1", "T1", "chat", "Как изменить язык?"),
            Ticket("E2", "T2", "chat", "Не приходит код"),
            Ticket("E3", "T3", "chat", "Верните деньги"),
        )
        self.assertEqual(find_incident_candidates(tickets), ())


if __name__ == "__main__":
    unittest.main()
