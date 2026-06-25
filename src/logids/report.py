from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .detector import summarize
from .models import DetectionFinding, Incident, ParseStats


def write_reports(
    output_dir: str | Path,
    findings: list[DetectionFinding],
    stats: ParseStats,
    *,
    title: str = "Log IDS Detection Report",
    incidents: list[Incident] | None = None,
    investigation_graph: dict[str, object] | None = None,
) -> None:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    incidents = incidents or []
    (path / "detections.json").write_text(
        json.dumps([item.to_dict() for item in findings], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (path / "incidents.json").write_text(
        json.dumps([item.to_dict() for item in incidents], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if investigation_graph is not None:
        (path / "investigation_graph.json").write_text(
            json.dumps(investigation_graph, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    (path / "report.md").write_text(render_markdown(title, findings, stats, incidents), encoding="utf-8")
    (path / "summary.txt").write_text(render_summary(findings, stats), encoding="utf-8")


def render_summary(findings: list[DetectionFinding], stats: ParseStats) -> str:
    summary = summarize(findings)
    lines = [
        f"generated_at={datetime.now().isoformat(timespec='seconds')}",
        f"total_logs={stats.total}",
        f"valid_logs={stats.valid}",
        f"invalid_logs={stats.invalid}",
        f"duplicate_lines={stats.duplicates}",
        f"findings={summary.total_findings}",
        f"by_severity={summary.by_severity}",
        f"by_type={summary.by_type}",
        f"top_sources={summary.top_sources}",
    ]
    return "\n".join(lines) + "\n"


def render_markdown(
    title: str,
    findings: list[DetectionFinding],
    stats: ParseStats,
    incidents: list[Incident] | None = None,
) -> str:
    summary = summarize(findings)
    incidents = incidents or []
    lines = [
        f"# {title}",
        "",
        f"- Generated at: {datetime.now().isoformat(timespec='seconds')}",
        f"- Total logs: {stats.total}",
        f"- Valid logs: {stats.valid}",
        f"- Invalid logs: {stats.invalid}",
        f"- Duplicate lines: {stats.duplicates}",
        f"- Findings: {summary.total_findings}",
        f"- By severity: {summary.by_severity}",
        f"- By type: {summary.by_type}",
        f"- Incidents: {len(incidents)}",
        "",
        "## Top Source IPs",
        "",
        "| Source IP | Findings |",
        "| --- | ---: |",
    ]
    for src_ip, count in summary.top_sources:
        lines.append(f"| {src_ip} | {count} |")
    lines.extend(
        [
            "",
            "## Correlated Incidents",
            "",
            "| Incident | Severity | Score | Source | Time Range | Findings | Recommended Action |",
            "| --- | --- | ---: | --- | --- | --- | --- |",
        ]
    )
    for incident in incidents:
        lines.append(
            f"| {incident.incident_id} | {incident.severity} | {incident.score} | {incident.src_ip} | "
            f"{incident.start_time.isoformat()} - {incident.end_time.isoformat()} | "
            f"{', '.join(incident.finding_types)} | {incident.recommended_action} |"
        )
    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Time | Severity | Score | Type | Source | Tactic | Reason | Evidence |",
            "| --- | --- | ---: | --- | --- | --- | --- | --- |",
        ]
    )
    for item in findings:
        evidence = item.evidence.replace("|", "\\|")
        reason = item.reason.replace("|", "\\|")
        lines.append(
            f"| {item.timestamp.isoformat()} | {item.severity} | {item.score} | {item.finding_type} | "
            f"{item.src_ip} | {item.tactic} | {reason} | {evidence} |"
        )
    return "\n".join(lines) + "\n"
