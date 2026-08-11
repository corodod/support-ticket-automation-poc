from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .models import KnowledgeArticle, RetrievalResult

_INDEX_SPEC = {
    "analyzer": "char_wb",
    "ngram_range": (3, 5),
    "sublinear_tf": True,
}


def _document(article: KnowledgeArticle) -> str:
    return " ".join((article.title, article.intent, *article.keywords, article.answer))


class KnowledgeRetriever:
    def __init__(self, articles: Iterable[KnowledgeArticle]) -> None:
        self.articles = tuple(articles)
        canonical_articles = sorted(
            (asdict(article) for article in self.articles),
            key=lambda article: article["article_id"],
        )
        signature = json.dumps(
            {"articles": canonical_articles, "index_spec": _INDEX_SPEC},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        self.version = f"kb-tfidf-global-v2-{hashlib.sha256(signature.encode()).hexdigest()[:10]}"

        self._vectorizer: TfidfVectorizer | None = None
        self._article_matrix = None
        if self.articles:
            self._vectorizer = TfidfVectorizer(**_INDEX_SPEC)
            self._article_matrix = self._vectorizer.fit_transform(
                [_document(article) for article in self.articles]
            )

    def retrieve(self, text: str, topic: str) -> RetrievalResult:
        """Rank the full KB; ``topic`` remains only for call-site compatibility.

        The classifier topic must not constrain retrieval: agreement between the
        independently produced intent and article intent is checked by policy.
        """
        if not self.articles or self._vectorizer is None or self._article_matrix is None:
            return RetrievalResult(None, 0.0, 0.0, 0.0, self.version, ())

        query_vector = self._vectorizer.transform([text])
        scores = cosine_similarity(query_vector, self._article_matrix)[0]
        ranked = sorted(
            zip(self.articles, scores, strict=True),
            key=lambda item: (-float(item[1]), item[0].article_id),
        )
        article, top_score = ranked[0]
        second_score = float(ranked[1][1]) if len(ranked) > 1 else 0.0
        top_score = float(top_score)
        return RetrievalResult(
            article=article,
            top_score=round(top_score, 4),
            second_score=round(second_score, 4),
            margin=round(top_score - second_score, 4),
            index_version=self.version,
            ranked_article_ids=tuple(item.article_id for item, _ in ranked),
        )
