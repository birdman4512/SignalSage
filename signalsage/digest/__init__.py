"""Daily digest fetching and summarization package."""

from .fetcher import fetch_source, fetch_topic
from .summarizer import DigestSummarizer

__all__ = ["fetch_source", "fetch_topic", "DigestSummarizer"]
