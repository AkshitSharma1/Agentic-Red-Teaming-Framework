import asyncio
import sys
from collections import Counter
from types import ModuleType

from guardlab.automatic import run_deepteam


def test_all_objective_method_combinations_are_attempted(monkeypatch, engine):
    class FakeVulnerability:
        def __init__(self, **kwargs):
            self.options = kwargs

    class FakeAttack:
        def __init__(self, **kwargs):
            self.options = kwargs

    class FakeTurn:
        def __init__(self, role, content):
            self.role = role
            self.content = content

    deepteam = ModuleType("deepteam")
    attacks = ModuleType("deepteam.attacks")
    multi = ModuleType("deepteam.attacks.multi_turn")
    single = ModuleType("deepteam.attacks.single_turn")
    cases = ModuleType("deepteam.test_case")
    vulnerabilities = ModuleType("deepteam.vulnerabilities")
    multi.LinearJailbreaking = FakeAttack
    single.PromptInjection = FakeAttack
    cases.RTTurn = FakeTurn
    vulnerabilities.BFLA = FakeVulnerability
    vulnerabilities.PIILeakage = FakeVulnerability

    def fake_red_team(**kwargs):
        prompt = "admin" if isinstance(kwargs["vulnerabilities"][0], FakeVulnerability) and kwargs["vulnerabilities"][0].options["types"] == ["function_bypass"] else "read"
        asyncio.run(kwargs["model_callback"](prompt, []))

    deepteam.red_team = fake_red_team
    for name, module in {
        "deepteam": deepteam,
        "deepteam.attacks": attacks,
        "deepteam.attacks.multi_turn": multi,
        "deepteam.attacks.single_turn": single,
        "deepteam.test_case": cases,
        "deepteam.vulnerabilities": vulnerabilities,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr("guardlab.automatic.version", lambda name: "1.0.9")
    monkeypatch.delenv("CONFIDENT_API_KEY", raising=False)
    run = run_deepteam(engine, repetitions=2)
    assert run.status == "complete"
    assert run.summary()["attempted"] == 8
    assert Counter((attack.objective, attack.method) for attack in run.attacks) == {
        ("unauthorized_tool", "PromptInjection"): 2,
        ("unauthorized_tool", "LinearJailbreaking"): 2,
        ("privacy_disclosure", "PromptInjection"): 2,
        ("privacy_disclosure", "LinearJailbreaking"): 2,
    }
