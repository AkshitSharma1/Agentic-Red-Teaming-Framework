from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol
from uuid import uuid4

from guardlab.config import Settings, safe_error
from guardlab.guard import Guard
from guardlab.judge import ReportJudge
from guardlab.models import AttackReport, ToolEvent, Turn
from guardlab.sandbox import SyntheticSandbox


class Assistant(Protocol):
    def respond(self, session: AttackSession, prompt: str) -> str: ...


@dataclass
class AttackSession:
    objective: str
    source: str
    method: str
    id: str = field(default_factory=lambda: uuid4().hex)
    sandbox: SyntheticSandbox = field(default_factory=SyntheticSandbox)
    turns: list[Turn] = field(default_factory=list)
    pending_tool_events: list[ToolEvent] = field(default_factory=list)
    response_id: str | None = None
    submitted: bool = False


class RedTeamEngine:
    def __init__(
        self,
        settings: Settings,
        guard: Guard,
        assistant: Assistant,
        judge: ReportJudge | None = None,
    ) -> None:
        self.settings = settings
        self.guard = guard
        self.assistant = assistant
        self.judge = judge

    def new_session(self, objective: str, source: str, method: str) -> AttackSession:
        if objective not in {"unauthorized_tool", "privacy_disclosure"}:
            raise ValueError("Unknown attack objective")
        if source not in {"manual", "deepteam"}:
            raise ValueError("Unknown attack source")
        return AttackSession(objective=objective, source=source, method=method)

    def send(self, session: AttackSession, prompt: str) -> Turn:
        if session.submitted:
            raise ValueError("This attack report was already submitted")
        if len(session.turns) >= 8:
            raise ValueError("An attack session is limited to eight user turns")
        prompt = prompt.strip()
        if not prompt or len(prompt) > 4000:
            raise ValueError("Message must contain 1 to 4,000 characters")
        turn = Turn(user=prompt)
        try:
            turn.input_guard = self.guard.classify("input", session.turns, prompt)
            if not turn.input_guard.safe:
                turn.visible_assistant = "Blocked by Llama Guard 4 before reaching the assistant."
            else:
                turn.raw_assistant = self.assistant.respond(session, prompt)
                turn.tool_events = list(session.pending_tool_events)
                turn.output_guard = self.guard.classify(
                    "output", session.turns, prompt, turn.raw_assistant
                )
                turn.visible_assistant = (
                    turn.raw_assistant
                    if turn.output_guard.safe
                    else "Blocked by Llama Guard 4 before reaching the user."
                )
        except Exception as exc:
            turn.error = safe_error(exc, self.settings)
            turn.tool_events = list(session.pending_tool_events)
            session.pending_tool_events.clear()
            session.turns.append(turn)
            raise
        session.pending_tool_events.clear()
        session.turns.append(turn)
        return turn

    def submit(
        self,
        session: AttackSession,
        description: str,
        previous: list[AttackReport] | None = None,
    ) -> AttackReport:
        if session.submitted:
            raise ValueError("This attack report was already submitted")
        if not session.turns:
            raise ValueError("Send at least one message before submitting")
        description = description.strip()
        if not description or len(description) > 2000:
            raise ValueError("Report description must contain 1 to 2,000 characters")
        report = AttackReport(
            id=session.id,
            source=session.source,
            objective=session.objective,
            method=session.method,
            description=description,
            turns=list(session.turns),
            outcome=session.sandbox.outcome(session.turns),
            error=next((turn.error for turn in session.turns if turn.error), None),
            assistant_model=self.settings.assistant_model,
            guard_model=self.settings.guard_model,
            judge_model=self.settings.judge_model,
        )
        session.submitted = True
        if report.error is None and self.judge is not None:
            try:
                report.quality = self.judge.score(report, previous or [])
            except Exception as exc:
                report.judge_error = safe_error(exc, self.settings)
        return report
