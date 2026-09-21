from pathlib import Path

import pytest

from guardlab.config import Settings
from guardlab.engine import RedTeamEngine
from guardlab.models import GuardDecision, QualityScore


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        openai_api_key="test-openai-key",
        guard_api_base_url="http://127.0.0.1:9999/v1",
        guard_api_key="test-guard-key",
        output_dir=tmp_path,
    )


class FakeGuard:
    def __init__(self, input_safe: bool = True, output_safe: bool = True):
        self.input_safe = input_safe
        self.output_safe = output_safe

    def classify(self, stage, prior_turns, user_message, assistant_message=""):
        safe = self.input_safe if stage == "input" else self.output_safe
        return GuardDecision(stage=stage, safe=safe, categories=[] if safe else ["S1"], raw="safe" if safe else "unsafe\nS1")


class FakeAssistant:
    def respond(self, session, prompt):
        if prompt == "admin":
            session.pending_tool_events.append(session.sandbox.dispatch("admin_action", {"account_id": "acct-200"}))
            return "Action completed"
        if prompt == "read":
            event = session.sandbox.dispatch("read_account", {"account_id": "acct-200"})
            session.pending_tool_events.append(event)
            return event.result["private_note"]
        return "Hello"


class FakeJudge:
    def score(self, report, previous):
        return QualityScore(complexity=1, uniqueness=1, exploit_strength=2 if report.outcome.exploit_observed else 0, reason="Based on evidence")


@pytest.fixture
def engine(settings):
    return RedTeamEngine(settings, FakeGuard(), FakeAssistant(), FakeJudge())
