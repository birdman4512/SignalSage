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


async def test_slack_story_messages_are_mapped_and_seeded_with_votes():
    slack = bot()
    slack.app.client.chat_postMessage.side_effect = [
        {"channel": "C9", "ts": str(i)} for i in range(2)
    ]
    slack.app.client.reactions_add = AsyncMock(side_effect=[None, RuntimeError("no scope")] * 2)
    sent = []
    meta = {"compact": True, "articles": ["a0", "a1"], "_sent": lambda i, m: sent.append((i, m))}
    await slack.send_digest("News", summary(2), meta=meta)
    assert sent == [(0, "C9:0"), (1, "C9:1")]  # a reaction failure doesn't fail delivery
    names = [c.kwargs["name"] for c in slack.app.client.reactions_add.await_args_list]
    assert names == ["+1", "-1", "+1", "-1"]


async def test_vote_seeding_can_be_disabled_but_story_is_still_mapped():
    slack = bot()
    slack.app.client.chat_postMessage.return_value = {"channel": "C9", "ts": "0"}
    slack.app.client.reactions_add = AsyncMock()
    sent = []
    meta = {
        "compact": True,
        "articles": ["a0"],
        "seed_votes": False,
        "_sent": lambda i, m: sent.append((i, m)),
    }
    await slack.send_digest("News", summary(1), meta=meta)
    assert sent == [(0, "C9:0")]
    slack.app.client.reactions_add.assert_not_awaited()


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


def combined_meta(count, **extra):
    return {"combined": True, "articles": [f"a{i}" for i in range(count)], **extra}


def test_combined_payload_is_one_numbered_message_with_also_list():
    data = json.loads(summary(3))
    data["more"] = [{"headline": "Extra <@everyone>", "url": "https://example.com/x"}]
    payloads = format_digest_slack_message("News", json.dumps(data), meta=combined_meta(3))
    assert len(payloads) == 1
    blocks = payloads[0]["blocks"]
    assert blocks[0]["type"] == "header" and blocks[0]["text"]["text"].endswith("News")
    sections = [b["text"]["text"] for b in blocks if b["type"] == "section"]
    stories, also = sections[:-1], sections[-1]
    assert [s.split()[0] for s in stories] == [":one:", ":two:", ":three:"]
    assert "<https://example.com/0|Story 0>" in stories[0]
    assert "Why selected" not in stories[0]  # less text per story than the old cards
    assert also.startswith("*Also:*") and "<@everyone>" not in also
    assert "_example.com_" in also  # host is plain italic, not a second link
    context = " ".join(b["elements"][0]["text"] for b in blocks if b["type"] == "context")
    assert ":one:–:three:" in context
    assert "3 stories  ·  1 more headline at the end" in context
    assert [b["type"] for b in blocks].count("divider") == 4  # before each story and Also
    assert not any(b["type"] == "image" for b in blocks)
    assert len(blocks) < 50


def test_combined_notification_text_leads_with_top_headline():
    data = json.loads(summary(3))
    data["items"][0]["headline"] = "Patch now <!channel>"
    payload = format_digest_slack_message("News", json.dumps(data), meta=combined_meta(3))[0]
    assert payload["text"].endswith(": Patch now &lt;!channel&gt; (+2 more)")
    single = json.dumps({"items": data["items"][:1]})
    text = format_digest_slack_message("News", single, meta=combined_meta(1))[0]["text"]
    assert text.endswith(": Patch now &lt;!channel&gt;")


def test_combined_post_with_twenty_stories_stays_under_block_limit():
    data = json.loads(summary(20))
    data["more"] = [
        {"headline": f"Extra {i}", "url": f"https://example.com/x{i}"} for i in range(15)
    ]
    payload = format_digest_slack_message("News", json.dumps(data), meta=combined_meta(20))[0]
    assert len(payload["blocks"]) <= 50


async def test_combined_post_maps_every_story_and_seeds_numbers():
    slack = bot()
    slack.app.client.chat_postMessage.return_value = {"channel": "C9", "ts": "5"}
    slack.app.client.reactions_add = AsyncMock()
    sent = []
    meta = combined_meta(3, _sent=lambda i, m: sent.append((i, m)))
    await slack.send_digest("News", summary(3), meta=meta)
    slack.app.client.chat_postMessage.assert_awaited_once()
    assert sent == [(0, "C9:5")]
    names = [c.kwargs["name"] for c in slack.app.client.reactions_add.await_args_list]
    assert names == ["one", "two", "three"]


async def test_number_reaction_on_slack_is_story_feedback():
    slack = bot()
    store = SimpleNamespace(react_feedback=lambda *a, **k: calls.append((a, k)) or True)
    calls: list = []
    slack.scheduler = SimpleNamespace(store=store)
    slack.auth = SimpleNamespace(authorized_slack=lambda user: True)
    handlers = {}
    slack.app = SimpleNamespace(
        event=lambda name: lambda fn: handlers.setdefault(name, fn),
        action=lambda pattern: lambda fn: fn,
        error=lambda fn: fn,
    )
    slack._register()
    event = {
        "reaction": "two",
        "user": "U1",
        "item": {"type": "message", "channel": "C9", "ts": "5"},
    }
    await handlers["reaction_added"](event, {"bot_user_id": "B1"})
    assert calls == [(("slack", "C9:5", "U1", True), {"removed": False, "position": 2})]
