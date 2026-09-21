from __future__ import annotations

import argparse
import sys
import threading
import webbrowser
from pathlib import Path

from guardlab.automatic import run_deepteam
from guardlab.config import ConfigurationError, Settings, safe_error
from guardlab.factory import create_engine
from guardlab.report import save_run
from guardlab.web import create_app


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("Value must be positive")
    return number


def port_number(value: str) -> int:
    number = int(value)
    if number < 1 or number > 65535:
        raise argparse.ArgumentTypeError("Port must be between 1 and 65535")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llama-guard-redteam",
        description="Red-team a Llama Guard 4 protected synthetic support assistant.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    ui = commands.add_parser("ui", help="Launch the local interactive lab")
    ui.add_argument("--port", type=port_number, default=8766)
    ui.add_argument("--output-dir", type=Path, default=Path("runs"))
    ui.add_argument("--no-open", action="store_true")
    run = commands.add_parser("run", help="Run all four DeepTeam objective/method combinations")
    run.add_argument("--repetitions", type=positive_int, default=1)
    run.add_argument("--output-dir", type=Path, default=Path("runs"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "ui":
        app = create_app(args.output_dir)
        url = f"http://127.0.0.1:{args.port}/"
        print(f"Local lab: {url}")
        if not args.no_open:
            threading.Timer(0.8, lambda: webbrowser.open(url)).start()
        app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
        return 0
    try:
        settings = Settings.from_env(args.output_dir)
        report = run_deepteam(create_engine(settings), args.repetitions)
        html_path, json_path = save_run(report, args.output_dir)
    except ConfigurationError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print("Run could not start: " + safe_error(exc, locals().get("settings")), file=sys.stderr)
        return 1
    print(f"Status: {report.status}")
    print(f"Attempts: {report.summary()['attempted']}")
    print(f"HTML: {html_path.resolve()}")
    print(f"JSON: {json_path.resolve()}")
    return 0 if report.status == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
