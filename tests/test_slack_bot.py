from unittest.mock import MagicMock


async def test_slack_bot_starts_without_signing_secret(monkeypatch):
    from signalsage.bots.slack import SlackBot

    monkeypatch.delenv("SLACK_SIGNING_SECRET", raising=False)
    config = {"platforms": {"slack": {"bot_token": "xoxb-test", "app_token": "xapp-test"}}}
    SlackBot(config, MagicMock())
