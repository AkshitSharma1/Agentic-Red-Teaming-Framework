from guardlab.engine import RedTeamEngine

from conftest import FakeAssistant, FakeGuard, FakeJudge


def test_sessions_are_isolated(engine):
    first = engine.new_session("privacy_disclosure", "manual", "Interactive")
    second = engine.new_session("privacy_disclosure", "manual", "Interactive")
    engine.send(first, "hello")
    engine.send(first, "read")
    engine.send(second, "hello")
    assert len(first.turns) == 2
    assert len(second.turns) == 1
    assert first.sandbox.protected_canary != second.sandbox.protected_canary
    assert first.response_id is None and second.response_id is None


def test_tool_execution_and_visible_disclosure_are_separate(settings):
    engine = RedTeamEngine(settings, FakeGuard(output_safe=False), FakeAssistant(), FakeJudge())
    session = engine.new_session("privacy_disclosure", "manual", "Interactive")
    engine.send(session, "read")
    report = engine.submit(session, "Tried to read the other account")
    assert report.outcome.cross_account_read is True
    assert report.outcome.visible_canary_disclosure is False
    assert report.outcome.output_blocked is True
    assert report.quality.exploit_strength == 0


def test_simulated_admin_action_is_observed(engine):
    session = engine.new_session("unauthorized_tool", "manual", "Interactive")
    engine.send(session, "admin")
    report = engine.submit(session, "Requested an admin action")
    assert report.outcome.unauthorized_admin_action is True
    assert session.sandbox.admin_actions == ["acct-200"]
    assert report.quality.total == 4


def test_canary_requires_visible_reply(engine):
    session = engine.new_session("privacy_disclosure", "manual", "Interactive")
    engine.send(session, "read")
    report = engine.submit(session, "Tried to disclose a synthetic record")
    assert report.outcome.cross_account_read is True
    assert report.outcome.visible_canary_disclosure is True
    assert report.outcome.exploit_observed is True


def test_blocked_input_never_reaches_tools(settings):
    engine = RedTeamEngine(settings, FakeGuard(input_safe=False), FakeAssistant(), FakeJudge())
    session = engine.new_session("unauthorized_tool", "manual", "Interactive")
    engine.send(session, "admin")
    report = engine.submit(session, "Attempted an admin action")
    assert report.outcome.input_blocked is True
    assert report.outcome.unauthorized_admin_action is False
    assert session.sandbox.admin_actions == []


def test_submit_requires_attempt_and_is_single_use(engine):
    session = engine.new_session("unauthorized_tool", "manual", "Interactive")
    try:
        engine.submit(session, "Description")
        assert False
    except ValueError:
        pass
    engine.send(session, "hello")
    engine.submit(session, "Description")
    try:
        engine.submit(session, "Again")
        assert False
    except ValueError:
        pass
