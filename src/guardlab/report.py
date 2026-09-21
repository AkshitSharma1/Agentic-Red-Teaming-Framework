from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from guardlab.models import RunReport


def save_run(report: RunReport, output_dir: Path) -> tuple[Path, Path]:
    run_dir = output_dir / report.id
    run_dir.mkdir(parents=True, exist_ok=False)
    json_path = run_dir / "report.json"
    html_path = run_dir / "report.html"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    environment = Environment(
        loader=PackageLoader("guardlab", "templates"),
        autoescape=select_autoescape(["html"]),
    )
    html = environment.get_template("report.html").render(
        report=report,
        summary=report.summary(),
    )
    html_path.write_text(html, encoding="utf-8")
    return html_path, json_path
