from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import Any

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .models import Ticket
from .pii import redact_pii


@dataclass(frozen=True)
class IncidentCandidate:
    candidate_id: str
    event_ids: tuple[str, ...]
    size: int
    mean_similarity: float
    action: str = "incident_candidate"
    auto_close_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def find_incident_candidates(
    tickets: Iterable[Ticket],
    *,
    similarity_threshold: float = 0.52,
    min_cluster_size: int = 3,
) -> tuple[IncidentCandidate, ...]:
    """Group redacted near-duplicates; a human must confirm every candidate."""
    unique_by_event = {ticket.event_id: ticket for ticket in tickets}
    unique = tuple(unique_by_event.values())
    if len(unique) < min_cluster_size:
        return ()

    texts = [redact_pii(ticket.text) for ticket in unique]
    matrix = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5)).fit_transform(texts)
    similarities = cosine_similarity(matrix)
    parents = list(range(len(unique)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    for left in range(len(unique)):
        for right in range(left + 1, len(unique)):
            if float(similarities[left, right]) >= similarity_threshold:
                union(left, right)

    groups: dict[int, list[int]] = {}
    for index in range(len(unique)):
        groups.setdefault(find(index), []).append(index)

    candidates: list[IncidentCandidate] = []
    for members in groups.values():
        if len(members) < min_cluster_size:
            continue
        event_ids = tuple(sorted(unique[index].event_id for index in members))
        pair_scores = [
            float(similarities[left, right])
            for position, left in enumerate(members)
            for right in members[position + 1 :]
        ]
        digest = hashlib.sha256("|".join(event_ids).encode()).hexdigest()[:12]
        candidates.append(
            IncidentCandidate(
                candidate_id=f"incident-{digest}",
                event_ids=event_ids,
                size=len(event_ids),
                mean_similarity=round(sum(pair_scores) / len(pair_scores), 4),
            )
        )
    return tuple(
        sorted(candidates, key=lambda candidate: (-candidate.size, candidate.candidate_id))
    )
