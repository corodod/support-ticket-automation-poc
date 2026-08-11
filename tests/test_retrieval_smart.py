from __future__ import annotations

import unittest
from dataclasses import replace
from unittest.mock import patch

from sklearn.feature_extraction.text import TfidfVectorizer

from ticket_automation.models import KnowledgeArticle
from ticket_automation.retrieval import KnowledgeRetriever


def article(
    article_id: str,
    *,
    topic: str,
    intent: str,
    title: str,
    keywords: tuple[str, ...],
) -> KnowledgeArticle:
    return KnowledgeArticle(
        article_id=article_id,
        topic=topic,
        intent=intent,
        title=title,
        answer=f"Утвержденный ответ: {title}.",
        keywords=keywords,
        status="approved",
        auto_reply_allowed=True,
        version=1,
        valid_until="2027-12-31",
    )


class SmartRetrievalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.language = article(
            "KB-LANGUAGE",
            topic="settings",
            intent="change_language",
            title="Как изменить язык приложения",
            keywords=("сменить язык", "язык интерфейса"),
        )
        self.notifications = article(
            "KB-NOTIFICATIONS",
            topic="settings",
            intent="change_notifications",
            title="Как настроить уведомления",
            keywords=("push", "отключить уведомления"),
        )
        self.payment = article(
            "KB-PAYMENT",
            topic="payment",
            intent="duplicate_charge",
            title="Двойное списание по карте",
            keywords=("дважды списали", "двойное списание"),
        )
        self.articles = (self.language, self.notifications, self.payment)

    def test_retrieval_is_global_even_when_topic_hint_is_wrong(self) -> None:
        retriever = KnowledgeRetriever(self.articles)

        result = retriever.retrieve("Как сменить язык интерфейса?", topic="payment")

        self.assertEqual(result.article, self.language)
        self.assertEqual(result.ranked_article_ids[0], self.language.article_id)
        self.assertEqual(
            set(result.ranked_article_ids), {item.article_id for item in self.articles}
        )

    def test_query_uses_prefitted_index_without_refitting(self) -> None:
        retriever = KnowledgeRetriever(self.articles)
        vocabulary_before = dict(retriever._vectorizer.vocabulary_)

        with patch.object(
            TfidfVectorizer,
            "fit_transform",
            side_effect=AssertionError("query must not refit the KB index"),
        ):
            first = retriever.retrieve("не приходят push уведомления", topic="settings")
            second = retriever.retrieve("не приходят push уведомления", topic="unknown")

        self.assertEqual(first, second)
        self.assertEqual(first.article, self.notifications)
        self.assertEqual(retriever._vectorizer.vocabulary_, vocabulary_before)

    def test_index_version_is_content_based_and_order_independent(self) -> None:
        original = KnowledgeRetriever(self.articles)
        reordered = KnowledgeRetriever(tuple(reversed(self.articles)))
        changed = KnowledgeRetriever(
            (replace(self.language, version=2), self.notifications, self.payment)
        )

        self.assertEqual(original.version, reordered.version)
        self.assertNotEqual(original.version, changed.version)
        self.assertTrue(original.version.startswith("kb-tfidf-global-v2-"))

    def test_empty_knowledge_base_fails_closed(self) -> None:
        result = KnowledgeRetriever(()).retrieve("Как изменить язык?", topic="settings")

        self.assertIsNone(result.article)
        self.assertEqual(result.top_score, 0.0)
        self.assertEqual(result.ranked_article_ids, ())


if __name__ == "__main__":
    unittest.main()
