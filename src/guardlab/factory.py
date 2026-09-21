from __future__ import annotations

from guardlab.assistant import OpenAIAssistant
from guardlab.config import Settings
from guardlab.engine import RedTeamEngine
from guardlab.guard import HostedLlamaGuard
from guardlab.judge import GPTJudge


def create_engine(settings: Settings) -> RedTeamEngine:
    return RedTeamEngine(
        settings=settings,
        guard=HostedLlamaGuard(settings),
        assistant=OpenAIAssistant(settings),
        judge=GPTJudge(settings),
    )
