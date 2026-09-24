"""Offline relevance evaluation and opt-in local-model comparison. Never posts messages.

python -m signalsage.digest.evaluate --dataset tests/fixtures/news_eval.json
python -m signalsage.digest.evaluate --models gemma2:2b qwen3.5:4b --output data/eval.json
"""

import argparse
import asyncio
import json
import statistics
import time
from pathlib import Path

import httpx

from signalsage.llm.ollama import OllamaLLM

from .ranking import score_article
from .summarizer import DigestSummarizer


def selection_metrics(labels: list[bool], predictions: list[bool]) -> dict:
    tp = sum(a and b for a, b in zip(labels, predictions))
    fp = sum(not a and b for a, b in zip(labels, predictions))
    fn = sum(a and not b for a, b in zip(labels, predictions))
    return {
        "precision": tp / (tp + fp) if tp + fp else 0,
        "recall": tp / (tp + fn) if tp + fn else 0,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
    }


async def evaluate(
    dataset: dict, model: str | None = None, base_url="http://localhost:11434", think=None
) -> dict:
    profile = dataset["profile"]
    threshold = float(profile.get("minimum_score", 2.5))
    llm = OllamaLLM(base_url=base_url, model=model or "unused", think=think)
    summarizer = DigestSummarizer(llm)
    samples, predictions, labels, durations = [], [], [], []
    peak_loaded = 0
    peak_vram = 0
    stop = asyncio.Event()

    async def sample_model_memory():
        nonlocal peak_loaded, peak_vram
        async with httpx.AsyncClient(timeout=3) as client:
            while not stop.is_set():
                try:
                    response = await client.get(base_url.rstrip("/") + "/api/ps")
                    response.raise_for_status()
                    for loaded in response.json().get("models", []):
                        if loaded.get("name") == model or loaded.get("model") == model:
                            peak_loaded = max(peak_loaded, int(loaded.get("size", 0)))
                            peak_vram = max(peak_vram, int(loaded.get("size_vram", 0)))
                except (httpx.HTTPError, ValueError, TypeError):
                    pass
                try:
                    await asyncio.wait_for(stop.wait(), timeout=1)
                except TimeoutError:
                    pass

    sampler = asyncio.create_task(sample_model_memory()) if model else None
    try:
        for index, item in enumerate(dataset["articles"]):
            started = time.monotonic()
            score, reasons, veto = score_article(item, profile, [], [])
            selected = score >= threshold and not veto
            sample = {
                "title": item["title"],
                "expected": bool(item["interesting"]),
                "score": score,
                "reasons": reasons,
            }
            try:
                if model and 0 < score < threshold and not veto:
                    selected, reason = await summarizer.judge_relevance(item, profile)
                    sample["model_reason"] = reason
                if model and selected:
                    result = await summarizer.summarize_article(
                        {**item, "id": str(index), "body": item["summary"]}
                    )
                    sample.update(result)
                    sample["generation"] = llm.last_metrics
                    # Heuristics aid human review; they are NOT factuality certification.
                    sample["expected_terms_missing"] = [
                        term
                        for term in item.get("expected_terms", [])
                        if term.lower() not in result["summary"].lower()
                    ]
                    sample["forbidden_terms_present"] = [
                        term
                        for term in item.get("forbidden_terms", [])
                        if term.lower() in result["summary"].lower()
                    ]
            except Exception as exc:
                sample["error"] = str(exc)
            elapsed = time.monotonic() - started
            sample.update(selected=selected, seconds=round(elapsed, 3))
            samples.append(sample)
            predictions.append(selected)
            labels.append(bool(item["interesting"]))
            durations.append(elapsed)
    finally:
        stop.set()
        if sampler:
            await sampler
    return {
        "model": model or "rules-only",
        "selection": selection_metrics(labels, predictions),
        "mean_seconds": statistics.mean(durations) if durations else 0,
        "max_seconds": max(durations, default=0),
        "errors": sum("error" in sample for sample in samples),
        "peak_ollama_reported_loaded_bytes": peak_loaded or None,
        "peak_ollama_reported_vram_bytes": peak_vram or None,
        "memory_note": "Sampled /api/ps allocation, not measured peak system RAM; use a host profiler for total RSS.",
        "samples": samples,
    }


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="tests/fixtures/news_eval.json")
    parser.add_argument("--models", nargs="*", default=[])
    parser.add_argument("--base-url", default="http://localhost:11434")
    parser.add_argument("--no-think", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()
    dataset = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
    results = [await evaluate(dataset)]
    for model in args.models:
        results.append(
            await evaluate(dataset, model, args.base_url, False if args.no_think else None)
        )
    report = json.dumps(results, indent=2, ensure_ascii=False)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report + "\n", encoding="utf-8")
    else:
        print(report)


if __name__ == "__main__":
    asyncio.run(main())
