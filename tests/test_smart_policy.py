from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ticket_automation.generation import MockDraftGenerator
from ticket_automation.models import PolicyCheckResult, RetrievalResult, Ticket
from ticket_automation.pipeline import TicketPipeline
from ticket_automation.runtime import build_pipeline
from ticket_automation.storage import SQLiteDecisionStore


class CountingGenerator(MockDraftGenerator):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def generate(self, context):
        self.calls += 1
        return super().generate(context)


class ExplodingClassifier:
    version = "must-not-run"

    def predict(self, text):
        raise AssertionError("hard-risk path called classifier")


class ExplodingRetriever:
    version = "must-not-run"

    def retrieve(self, text, topic):
        raise AssertionError("hard-risk path called retrieval")


class ExplodingGenerator:
    version = "must-not-run"

    def generate(self, context):
        raise AssertionError("hard-risk path called generator")


class RejectingOutputPolicy:
    version = "reject-all-v1"

    def check(self, draft, article, **kwargs):
        return PolicyCheckResult(False, ("FORCED_OUTPUT_REJECTION",))


class ConflictingRetriever:
    def __init__(self, articles) -> None:
        self.articles = articles
        self.version = "conflicting-retriever-v1"
        self.article = next(item for item in articles if item.intent == "verification_code")

    def retrieve(self, text, topic):
        return RetrievalResult(
            article=self.article,
            top_score=0.9,
            second_score=0.1,
            margin=0.8,
            index_version=self.version,
            ranked_article_ids=(self.article.article_id,),
        )


class SmartPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bootstrap = tempfile.TemporaryDirectory(prefix="smart-bootstrap-")
        cls.base = build_pipeline(db_path=Path(cls.bootstrap.name) / "base.sqlite3")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.bootstrap.cleanup()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="smart-policy-")
        self.db_path = Path(self.temporary.name) / "decisions.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def pipeline(self, *, generator=None, retriever=None, output_policy=None) -> TicketPipeline:
        return TicketPipeline(
            classifier=self.base.classifier,
            retriever=retriever or self.base.retriever,
            generator=generator or MockDraftGenerator(),
            automation_policy=self.base.automation_policy,
            output_policy=output_policy or self.base.output_policy,
            store=SQLiteDecisionStore(self.db_path),
        )

    @staticmethod
    def ticket(event_id: str, text: str) -> Ticket:
        return Ticket(event_id, f"T-{event_id}", "chat", text)

    def test_safe_auto_bypasses_generator_and_is_not_marked_resolved(self) -> None:
        generator = CountingGenerator()
        pipeline = self.pipeline(generator=generator)

        decision = pipeline.process(self.ticket("E-DIRECT", "Как изменить язык приложения?"))

        article = next(
            item for item in pipeline.retriever.articles if item.intent == "change_language"
        )
        self.assertEqual(generator.calls, 0)
        self.assertEqual(decision.candidate_action, "auto_template")
        self.assertEqual(decision.effective_action, "auto_reply")
        self.assertEqual(decision.delivery_state, "send_pending")
        self.assertEqual(decision.resolution_outcome, "unknown")
        self.assertEqual(decision.draft, article.answer)
        self.assertNotEqual(decision.route, "resolved_automatically")

    def test_operator_suggest_is_a_separate_non_user_visible_lane(self) -> None:
        decision = self.pipeline().process(
            self.ticket("E-SUGGEST", "Забыл пароль, подскажите способ восстановления")
        )

        self.assertEqual(decision.candidate_action, "operator_suggest")
        self.assertEqual(decision.action, "operator_suggest")
        self.assertEqual(decision.delivery_state, "not_user_visible")
        self.assertEqual(decision.resolution_outcome, "unknown")
        self.assertIsNotNone(decision.draft)

    def test_risky_clause_mutations_always_remove_auto_capability(self) -> None:
        suffixes = {
            "Хочу стереть всю информацию обо мне": ("privacy_request", "restricted_priority"),
            "Я причиню себе вред": ("self_harm", "safety_priority"),
            "Мне нужно вернуть деньги": ("financial_action", "payments_priority"),
            "Мой аккаунт украли": ("account_security", "security_priority"),
        }
        for base_index, base in enumerate(
            ("Как изменить язык приложения?", "Не приходит код подтверждения для входа")
        ):
            for suffix_index, (suffix, (reason, route)) in enumerate(suffixes.items()):
                with self.subTest(base=base, suffix=suffix):
                    decision = self.pipeline().process(
                        self.ticket(f"E-MUT-{base_index}-{suffix_index}", f"{base} {suffix}")
                    )
                    self.assertEqual(decision.candidate_action, "human_only")
                    self.assertEqual(decision.action, "human_review")
                    self.assertEqual(decision.route, route)
                    self.assertIn(reason, decision.risk_reasons)
                    self.assertIsNone(decision.draft)

    def test_scope_gate_rejects_second_or_unexplained_request(self) -> None:
        cases = {
            "Как изменить язык и отключить уведомления?": "MULTIPLE_INTENTS",
            "Как изменить язык и почему курьер опоздал?": "UNSUPPORTED_SCOPE",
        }
        for index, (text, reason) in enumerate(cases.items()):
            with self.subTest(text=text):
                decision = self.pipeline().process(self.ticket(f"E-SCOPE-{index}", text))
                self.assertEqual(decision.action, "human_review")
                self.assertIn(reason, decision.reason_codes)
                self.assertIn("not_called:", decision.component_versions["retriever"])

    def test_same_clause_and_unsupported_script_adversaries_never_auto_reply(self) -> None:
        cases = (
            "Как сменить язык и меня шантажируют",
            "Как сменить язык и я собираюсь навредить себе",
            "Как сменить язык и заблокировать утерянную карту",
            "Как сменить язык и сообщить о насилии",
            "Как сменить язык и отменить подписку",
            "Не приходит код подтверждения и SIM-карту украли",
            "Не приходит код подтверждения и вход не мой",
            "Как изменить язык и сменить номер телефона",
            "Как изменить язык поменять почту",
            "Как изменить язык сменить мой номер",
            "Как изменить язык поставить приложение",
            "Русский язык помогите поменять почту",
            "Русский язык помогите сменить номер телефона",
            "Русский язык помогите поставить приложение",
            "Как изменить язык хочу заказать телефон",
            "Как изменить язык хочу обсудить номер заказа",
            "Как сменить язык я у-бь-ю се-бя",
            "Как сменить язык у-да-ли-ть ак-ка-ун-т",
            "Как сменить язык and delete my account",
            "Как сменить язык I will kill myself",
            "Как сменить язык。我要删除账户",
            "Как сменить язык وحذف حسابي",
        )
        for index, text in enumerate(cases):
            with self.subTest(text=text):
                decision = self.pipeline().process(self.ticket(f"E-ADV-{index}", text))
                self.assertEqual(decision.candidate_action, "human_only")
                self.assertEqual(decision.action, "human_review")
                self.assertIsNone(decision.draft)

        account_decision = self.pipeline().process(self.ticket("E-ACCOUNT-CLAUSE", cases[6]))
        self.assertIn("account_security", account_decision.risk_reasons)
        self.assertEqual(account_decision.route, "security_priority")

        for index, text in enumerate(cases[-2:]):
            decision = self.pipeline().process(self.ticket(f"E-SCRIPT-{index}", text))
            self.assertIn("UNSUPPORTED_LANGUAGE_OR_SCRIPT", decision.reason_codes)

    def test_critical_scope_adversaries_keep_their_priority_route(self) -> None:
        cases = {
            "Меня шантажируют. Как сменить язык": ("threat_or_abuse", "safety_priority"),
            "Я собираюсь навредить себе. Как сменить язык": (
                "self_harm",
                "safety_priority",
            ),
            "Хочу заблокировать утерянную карту и сменить язык": (
                "financial_action",
                "payments_priority",
            ),
            "SIM-карту украли. Не приходит код подтверждения": (
                "account_security",
                "security_priority",
            ),
            "Забыл пароль, но доступ не мой": ("account_security", "security_priority"),
            "Я хочу покончить с собой. Как сменить язык": (
                "self_harm",
                "safety_priority",
            ),
            "Я вскрою вены. Как сменить язык": ("self_harm", "safety_priority"),
            "Меня изнасиловали. Как сменить язык": (
                "threat_or_abuse",
                "safety_priority",
            ),
            "Аккаунт угнали, мошенники получили доступ": (
                "account_security",
                "security_priority",
            ),
        }
        for index, (text, (reason, route)) in enumerate(cases.items()):
            with self.subTest(text=text):
                decision = self.pipeline().process(self.ticket(f"E-TRIAGE-{index}", text))
                self.assertEqual(decision.candidate_action, "human_only")
                self.assertEqual(decision.route, route)
                self.assertIn(reason, decision.risk_reasons)
                self.assertIsNone(decision.draft)

    def test_obfuscated_risk_never_reaches_any_suggestion_lane(self) -> None:
        cases = (
            "Забыл пароль я у-бь-ю се-бя",
            "Не приходит код подтверждения я у-бь-ю се-бя",
            "Сервис не работает я у-бь-ю се-бя",
            "Забыл пароль у б ь ю с е б я",
        )
        for index, text in enumerate(cases):
            with self.subTest(text=text):
                decision = self.pipeline().process(self.ticket(f"E-OBF-{index}", text))
                self.assertEqual(decision.candidate_action, "human_only")
                self.assertEqual(decision.action, "human_review")
                self.assertEqual(decision.route, "safety_priority")
                self.assertIn("suspicious_obfuscation", decision.risk_reasons)
                self.assertIsNone(decision.draft)

    def test_card_separator_variants_are_never_auto_replied(self) -> None:
        for index, card in enumerate(
            (
                "4111  1111  1111  1111",
                "4111.1111.1111.1111",
                "4111–1111–1111–1111",
                "4111—1111—1111—1111",
            )
        ):
            with self.subTest(card=card):
                decision = self.pipeline().process(
                    self.ticket(f"E-CARD-SEPARATOR-{index}", f"Как изменить язык {card}")
                )
                self.assertEqual(decision.action, "human_review")
                self.assertEqual(decision.route, "payments_priority")
                self.assertIn("sensitive_pii:card_number", decision.risk_reasons)

    def test_benign_contact_context_remains_auto_eligible(self) -> None:
        cases = (
            "Моя почта helper@example.test. Как изменить язык приложения?",
            "Как изменить язык приложения? Телефон +7 999 123-45-67",
        )
        for index, text in enumerate(cases):
            with self.subTest(text=text):
                decision = self.pipeline().process(self.ticket(f"E-BENIGN-{index}", text))
                self.assertEqual(decision.action, "auto_reply")

    def test_hard_risk_exits_before_classifier_retrieval_and_generator(self) -> None:
        pipeline = TicketPipeline(
            classifier=ExplodingClassifier(),
            retriever=ExplodingRetriever(),
            generator=ExplodingGenerator(),
            automation_policy=self.base.automation_policy,
            output_policy=self.base.output_policy,
            store=SQLiteDecisionStore(self.db_path),
        )

        decision = pipeline.process(
            self.ticket("E-EARLY", "Карта 4111 1111 1111 1111: верните деньги")
        )

        self.assertEqual(decision.action, "human_review")
        self.assertEqual(decision.route, "payments_priority")
        self.assertEqual(decision.component_versions["classifier"], "not_called:hard-risk")
        self.assertIn("not_called:", decision.component_versions["retriever"])
        self.assertEqual(pipeline.store.counts(), {"decisions": 1, "audit_events": 1, "outbox": 1})

    def test_classifier_retrieval_disagreement_fails_closed(self) -> None:
        retriever = ConflictingRetriever(self.base.retriever.articles)
        decision = self.pipeline(retriever=retriever).process(
            self.ticket("E-DISAGREE", "Как изменить язык приложения?")
        )

        self.assertEqual(decision.action, "human_review")
        self.assertEqual(decision.candidate_action, "human_only")
        self.assertIn("CLASSIFIER_RETRIEVAL_DISAGREEMENT", decision.reason_codes)
        self.assertIsNone(decision.draft)

    def test_output_rejection_separates_candidate_from_effective_action(self) -> None:
        decision = self.pipeline(output_policy=RejectingOutputPolicy()).process(
            self.ticket("E-OUTPUT-DOWNGRADE", "Как изменить язык приложения?")
        )

        self.assertEqual(decision.candidate_action, "auto_template")
        self.assertEqual(decision.effective_action, "human_review")
        self.assertEqual(decision.delivery_state, "not_requested")
        self.assertIn("FORCED_OUTPUT_REJECTION", decision.reason_codes)

    def test_audit_and_outbox_preserve_lifecycle_fields(self) -> None:
        pipeline = self.pipeline()
        decision = pipeline.process(self.ticket("E-LIFECYCLE", "Как изменить язык приложения?"))
        audit = pipeline.store.audit_payload(decision.event_id)
        outbox = pipeline.store.outbox_payload(decision.event_id)

        for name in (
            "candidate_action",
            "effective_action",
            "delivery_state",
            "resolution_outcome",
        ):
            self.assertEqual(audit["decision"][name], decision.to_dict()[name])
            self.assertEqual(outbox[name], decision.to_dict()[name])


if __name__ == "__main__":
    unittest.main()
