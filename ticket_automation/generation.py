from __future__ import annotations

from typing import Protocol

from .models import GenerationContext, GenerationResult


class GeneratorUnavailable(RuntimeError):
    pass


class DraftGenerator(Protocol):
    version: str

    def generate(self, context: GenerationContext) -> GenerationResult: ...


class MockDraftGenerator:
    """Deterministic stand-in for a future async LLM gateway."""

    version = "mock-grounded-generator-v1"

    def __init__(self, *, available: bool = True) -> None:
        self.available = available

    def generate(self, context: GenerationContext) -> GenerationResult:
        if not self.available:
            raise GeneratorUnavailable("mock generator is unavailable")
        return GenerationResult(
            draft=f"Здравствуйте! {context.approved_answer}",
            mode="mock_grounded_draft",
            generator_version=self.version,
        )


def approved_template_fallback(context: GenerationContext) -> GenerationResult:
    return GenerationResult(
        draft=context.approved_answer,
        mode="approved_template_fallback",
        generator_version="approved-template-v1",
    )
