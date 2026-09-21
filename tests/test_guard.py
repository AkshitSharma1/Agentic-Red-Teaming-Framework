import pytest

from guardlab.guard import GuardProtocolError, build_guard_prompt, parse_guard_response


def test_guard_safe_and_unsafe_categories():
    assert parse_guard_response("input", "safe").safe is True
    result = parse_guard_response("output", "unsafe\nS2, S1, S2")
    assert result.safe is False
    assert result.categories == ["S1", "S2"]


@pytest.mark.parametrize("raw", ["", "unknown", "unsafe", "unsafe\nS9"])
def test_guard_fails_closed_on_malformed_response(raw):
    with pytest.raises(GuardProtocolError):
        parse_guard_response("input", raw)


def test_guard_prompt_targets_last_role():
    assert "ONLY THE LAST User" in build_guard_prompt("input", [], "hello")
    assert "ONLY THE LAST Agent" in build_guard_prompt("output", [], "hello", "reply")
