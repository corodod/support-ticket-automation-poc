from __future__ import annotations

from pathlib import Path

from .classifier import RuleIntentClassifier, SklearnIntentClassifier
from .config import PolicyConfig
from .generation import MockDraftGenerator
from .pipeline import TicketPipeline, load_knowledge_base
from .policy import AutomationPolicy, OutputPolicyChecker
from .retrieval import KnowledgeRetriever
from .storage import SQLiteDecisionStore


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def build_pipeline(
    *,
    db_path: Path,
    classifier_mode: str = "ml",
    generator_available: bool = True,
) -> TicketPipeline:
    config = PolicyConfig.load(REPOSITORY_ROOT / "config" / "policy.json")
    if classifier_mode == "ml":
        classifier = SklearnIntentClassifier(
            REPOSITORY_ROOT / "data" / "ml" / "train.jsonl",
            abstain_confidence=config.classifier_abstain_confidence,
            abstain_margin=config.classifier_abstain_margin,
        )
    elif classifier_mode == "rules":
        classifier = RuleIntentClassifier()
    else:
        raise ValueError(f"Unsupported classifier mode: {classifier_mode}")
    articles = load_knowledge_base(REPOSITORY_ROOT / "data" / "knowledge_base.json")
    return TicketPipeline(
        classifier=classifier,
        retriever=KnowledgeRetriever(articles),
        generator=MockDraftGenerator(available=generator_available),
        automation_policy=AutomationPolicy(config),
        output_policy=OutputPolicyChecker(config),
        store=SQLiteDecisionStore(db_path),
    )
