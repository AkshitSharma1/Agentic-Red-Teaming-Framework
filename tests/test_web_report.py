import json

from guardlab.report import save_run
from guardlab.models import RunReport
from guardlab.web import create_app


def test_manual_submission_and_report_routes(tmp_path, engine):
    app = create_app(tmp_path, lambda: engine)
    client = app.test_client()
    assert client.get("/report").status_code == 404
    page = client.get("/").get_data(as_text=True)
    assert "Llama Guard Red-Team Lab" in page
    token = page.split("const csrfToken = ", 1)[1].split(";", 1)[0]
    headers = {"X-Lab-Token": json.loads(token)}
    assert client.post("/api/session", json={"objective": "unauthorized_tool"}).status_code == 403
    started = client.post("/api/session", json={"objective": "unauthorized_tool"}, headers=headers).json
    session_id = started["session_id"]
    turn = client.post("/api/message", json={"session_id": session_id, "message": "admin"}, headers=headers)
    assert turn.status_code == 200
    submitted = client.post("/api/submit", json={"session_id": session_id, "description": "Tried admin"}, headers=headers)
    assert submitted.status_code == 200
    assert submitted.json["outcome"]["unauthorized_admin_action"] is True
    assert client.get("/report").status_code == 200
    assert client.get("/report.json").json["attacks"][0]["objective"] == "unauthorized_tool"


def test_report_escapes_untrusted_description(tmp_path, engine):
    session = engine.new_session("unauthorized_tool", "manual", "Interactive")
    engine.send(session, "hello")
    attack = engine.submit(session, "<script>alert(1)</script>")
    html_path, json_path = save_run(RunReport(attacks=[attack]), tmp_path)
    assert "&lt;script&gt;" in html_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html_path.read_text(encoding="utf-8")
    assert json.loads(json_path.read_text(encoding="utf-8"))["attacks"][0]["description"] == "<script>alert(1)</script>"
