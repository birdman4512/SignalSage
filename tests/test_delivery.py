import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from signalsage.bots.formatter import format_digest_slack_message
from signalsage.bots.slack import SlackBot


def summary(count=6):
    return json.dumps(
        {
            "items": [
                {
                    "art_id": str(i).zfill(12),
                    "headline": f"Story {i}",
                    "summary": "A factual summary.",
                    "url": f"https://example.com/{i}",
                    "relevance_reason": "Matches your interests",
                    "content_kind": "article text",
                }
                for i in range(count)
            ]
        }
    )


def bot():
    value = SlackBot.__new__(SlackBot)
    value.cfg = {"digest_channel": "C123"}
    value.app = SimpleNamespace(client=SimpleNamespace(chat_postMessage=AsyncMock()))
    return value


async def test_partial_slack_delivery_acknowledges_only_success_and_resumes():
    slack = bot()
    slack.app.client.chat_postMessage.side_effect = [{"ts": "1"}, RuntimeError("429")]
    offsets = []
    meta = {"compact": True, "_delivery_id": "stable-id", "_ack": offsets.append}
    with pytest.raises(RuntimeError):
        await slack.send_digest("News", summary(), meta=meta)
    assert offsets == [1]
    failed_id = slack.app.client.chat_postMessage.call_args.kwargs["client_msg_id"]
    slack.app.client.chat_postMessage.reset_mock(side_effect=True)
    await slack.send_digest("News", summary(), meta={**meta, "_offset": 1})
    calls = slack.app.client.chat_postMessage.await_args_list
    assert len(calls) == 5  # stories 2-6, one message each; story 1 is not re-sent
    assert calls[0].kwargs["client_msg_id"] == failed_id
    assert offsets == [1, 2, 3, 4, 5, 6]


async def test_missing_slack_channel_is_failure():
    slack = bot()
    slack.cfg = {}
    with pytest.raises(ValueError):
        await slack.send_digest("News", summary())
    slack.app.client.chat_postMessage.assert_not_awaited()


def test_compact_payload_preserves_relevance_order_and_slack_limits():
    data = json.loads(summary(20))
    for item in data["items"]:
        item["summary"] = "<@everyone> " * 150
    payloads = format_digest_slack_message("News", json.dumps(data), meta={"compact": True})
    assert len(payloads) == 20  # one message per story, never batched
    for index, payload in enumerate(payloads):
        assert f"Story {index}" in payload["blocks"][1]["text"]["text"]
    for payload in payloads:
        assert len(payload["blocks"]) < 50
        for block in payload["blocks"]:
            if block["type"] == "section":
                assert len(block["text"]["text"]) <= 3000
                assert "<@everyone>" not in block["text"]["text"]


def test_digest_urls_are_validated_again_at_rendering():
    data = json.loads(summary(1))
    data["items"][0]["url"] = "https://example.com/|<@everyone>"
    payload = format_digest_slack_message("News", json.dumps(data), meta={"compact": True})
    assert "https://" not in payload[0]["blocks"][1]["text"]["text"]
