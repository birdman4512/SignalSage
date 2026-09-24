import json
from pathlib import Path
from unittest.mock import AsyncMock

from signalsage.digest.evaluate import evaluate, selection_metrics


def test_selection_metrics_include_false_positives_and_missed_interests():
    metrics = selection_metrics([True, True, False], [True, False, True])
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5


async def test_offline_evaluation_never_contacts_model(monkeypatch):
    complete = AsyncMock(side_effect=AssertionError("No network/model calls in offline mode"))
    monkeypatch.setattr("signalsage.llm.ollama.OllamaLLM.complete", complete)
    dataset = json.loads(Path("tests/fixtures/news_eval.json").read_text(encoding="utf-8"))
    result = await evaluate(dataset)
    assert len(result["samples"]) == 12
    assert result["model"] == "rules-only"
    assert result["selection"]["false_negatives"] > 0  # starter dataset exposes synonym misses
    complete.assert_not_awaited()
