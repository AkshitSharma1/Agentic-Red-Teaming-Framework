from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class GuardDecision(BaseModel):
    stage: Literal["input", "output"]
    safe: bool
    categories: list[str] = Field(default_factory=list)
    raw: str


class ToolEvent(BaseModel):
    name: str
    arguments: dict[str, str]
    authorized: bool
    simulated_executed: bool
    result: dict[str, str]


class Turn(BaseModel):
    user: str
    raw_assistant: str = ""
    visible_assistant: str = ""
    input_guard: GuardDecision | None = None
    output_guard: GuardDecision | None = None
    tool_events: list[ToolEvent] = Field(default_factory=list)
    error: str | None = None


class Outcome(BaseModel):
    input_blocked: bool = False
    output_blocked: bool = False
    unauthorized_admin_action: bool = False
    cross_account_read: bool = False
    visible_canary_disclosure: bool = False

    @property
    def exploit_observed(self) -> bool:
        return self.unauthorized_admin_action or self.visible_canary_disclosure


class QualityScore(BaseModel):
    complexity: int = Field(ge=0, le=2)
    uniqueness: int = Field(ge=0, le=1)
    exploit_strength: int = Field(ge=0, le=2)
    reason: str

    @property
    def total(self) -> int:
        return self.complexity + self.uniqueness + self.exploit_strength


class AttackReport(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    created_at: datetime = Field(default_factory=utc_now)
    source: Literal["manual", "deepteam"]
    objective: Literal["unauthorized_tool", "privacy_disclosure"]
    method: str
    description: str
    turns: list[Turn]
    outcome: Outcome
    quality: QualityScore | None = None
    judge_error: str | None = None
    error: str | None = None
    assistant_model: str
    guard_model: str
    judge_model: str


class RunReport(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    created_at: datetime = Field(default_factory=utc_now)
    status: Literal["complete", "partial", "failed"] = "complete"
    attacks: list[AttackReport] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    deepteam_version: str | None = None

    def summary(self) -> dict[str, int]:
        valid = [attack for attack in self.attacks if attack.error is None]
        return {
            "attempted": len(self.attacks),
            "completed": len(valid),
            "input_blocked": sum(a.outcome.input_blocked for a in valid),
            "output_blocked": sum(a.outcome.output_blocked for a in valid),
            "unauthorized_admin_actions": sum(a.outcome.unauthorized_admin_action for a in valid),
            "cross_account_reads": sum(a.outcome.cross_account_read for a in valid),
            "visible_canary_disclosures": sum(a.outcome.visible_canary_disclosure for a in valid),
            "observed_exploits": sum(a.outcome.exploit_observed for a in valid),
            "quality_points": sum(a.quality.total for a in valid if a.quality is not None),
            "quality_scored": sum(a.quality is not None for a in valid),
        }
