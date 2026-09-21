from __future__ import annotations

from pathlib import Path
from secrets import token_urlsafe
from threading import RLock
from typing import Callable

from flask import Flask, jsonify, render_template, request, send_file

from guardlab.config import Settings, safe_error
from guardlab.engine import AttackSession, RedTeamEngine
from guardlab.factory import create_engine
from guardlab.models import RunReport
from guardlab.report import save_run


def create_app(
    output_dir: Path,
    engine_factory: Callable[[], RedTeamEngine] | None = None,
) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 128 * 1024
    token = token_urlsafe(32)
    lock = RLock()
    current_engine: RedTeamEngine | None = None
    current_session: AttackSession | None = None
    current_paths: tuple[Path, Path] | None = None

    def default_factory() -> RedTeamEngine:
        return create_engine(Settings.from_env(output_dir))

    build_engine = engine_factory or default_factory

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "connect-src 'self'; form-action 'self'"
        )
        return response

    @app.get("/")
    def index():
        return render_template("ui.html", csrf_token=token)

    @app.before_request
    def require_token():
        if request.path.startswith("/api/") and request.method == "POST":
            if request.headers.get("X-Lab-Token") != token:
                return jsonify(error="Invalid local session token"), 403
            if not request.is_json:
                return jsonify(error="Expected JSON request"), 415

    @app.post("/api/session")
    def start_session():
        nonlocal current_engine, current_session, current_paths
        payload = request.get_json(silent=True) or {}
        objective = payload.get("objective")
        if objective not in {"unauthorized_tool", "privacy_disclosure"}:
            return jsonify(error="Select a valid objective"), 400
        with lock:
            try:
                engine = build_engine()
                session = engine.new_session(objective, "manual", "Interactive")
            except Exception as exc:
                return jsonify(error=safe_error(exc)), 400
            current_engine = engine
            current_session = session
            current_paths = None
            return jsonify(session_id=session.id, objective=session.objective)

    @app.post("/api/message")
    def send_message():
        payload = request.get_json(silent=True) or {}
        prompt = payload.get("message")
        if not isinstance(prompt, str):
            return jsonify(error="Message must be text"), 400
        with lock:
            if current_engine is None or current_session is None:
                return jsonify(error="Start a session first"), 409
            if payload.get("session_id") != current_session.id:
                return jsonify(error="Session no longer active"), 409
            try:
                turn = current_engine.send(current_session, prompt)
            except ValueError as exc:
                return jsonify(error=str(exc)), 400
            except Exception as exc:
                last = current_session.turns[-1] if current_session.turns else None
                return jsonify(
                    error="Model request failed: " + safe_error(exc, current_engine.settings),
                    turn_count=len(current_session.turns),
                    turn=last.model_dump() if last else None,
                ), 502
            return jsonify(
                reply=turn.visible_assistant,
                input_guard=turn.input_guard.model_dump() if turn.input_guard else None,
                output_guard=turn.output_guard.model_dump() if turn.output_guard else None,
                turn_count=len(current_session.turns),
            )

    @app.post("/api/submit")
    def submit_report():
        nonlocal current_paths
        payload = request.get_json(silent=True) or {}
        description = payload.get("description")
        if not isinstance(description, str):
            return jsonify(error="Report description must be text"), 400
        with lock:
            if current_engine is None or current_session is None:
                return jsonify(error="Start a session first"), 409
            if payload.get("session_id") != current_session.id:
                return jsonify(error="Session no longer active"), 409
            try:
                attack = current_engine.submit(current_session, description)
                run = RunReport(
                    status="partial" if attack.error else "complete",
                    attacks=[attack],
                    errors=[attack.error] if attack.error else [],
                )
                current_paths = save_run(run, output_dir)
            except ValueError as exc:
                return jsonify(error=str(exc)), 400
            except Exception as exc:
                return jsonify(error="Could not save report: " + safe_error(exc, current_engine.settings)), 500
            return jsonify(
                run_id=run.id,
                outcome=attack.outcome.model_dump(),
                quality=attack.quality.model_dump() if attack.quality else None,
                quality_total=attack.quality.total if attack.quality else None,
                judge_error=attack.judge_error,
                report_url="/report",
                json_url="/report.json",
            )

    @app.get("/report")
    def html_report():
        with lock:
            if current_paths is None:
                return jsonify(error="No completed report"), 404
            return send_file(current_paths[0], mimetype="text/html")

    @app.get("/report.json")
    def json_report():
        with lock:
            if current_paths is None:
                return jsonify(error="No completed report"), 404
            return send_file(current_paths[1], mimetype="application/json", as_attachment=True)

    return app
