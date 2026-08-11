from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .models import KnowledgeArticle, RetrievalResult


def _document(article: KnowledgeArticle) -> str:
    return " ".join((article.title, article.intent, *article.keywords, article.answer))


class KnowledgeRetriever:
    def __init__(self, articles: Iterable[KnowledgeArticle]) -> None:
        self.articles = tuple(articles)
        signature = json.dumps(
            [asdict(article) for article in self.articles],
            ensure_ascii=False,
            sort_keys=True,
        )
        self.version = f"kb-tfidf-v1-{hashlib.sha256(signature.encode()).hexdigest()[:10]}"

    def retrieve(self, text: str, topic: str) -> RetrievalResult:
        candidates = tuple(article for article in self.articles if article.topic == topic)
        if not candidates:
            return RetrievalResult(None, 0.0, 0.0, 0.0, self.version)
        vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True)
        matrix = vectorizer.fit_transform([_document(article) for article in candidates] + [text])
        scores = cosine_similarity(matrix[-1], matrix[:-1])[0]
        ranked = sorted(
            zip(candidates, scores, strict=True), key=lambda item: float(item[1]), reverse=True
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
        )
