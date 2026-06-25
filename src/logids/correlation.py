from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import timedelta

from .models import DetectionFinding, Incident, LogRecord


SEVERITY_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def correlate_findings(findings: list[DetectionFinding], *, gap_minutes: int = 10) -> list[Incident]:
    grouped: dict[str, list[DetectionFinding]] = defaultdict(list)
    for finding in sorted(findings, key=lambda item: item.timestamp):
        grouped[finding.src_ip].append(finding)

    incidents: list[Incident] = []
    for src_ip, items in grouped.items():
        current: list[DetectionFinding] = []
        previous = None
        for item in items:
            if previous is not None and item.timestamp - previous > timedelta(minutes=gap_minutes):
                incidents.append(_build_incident(src_ip, current))
                current = []
            current.append(item)
            previous = item.timestamp
        if current:
            incidents.append(_build_incident(src_ip, current))
    return sorted(incidents, key=lambda item: (-item.score, item.start_time, item.src_ip))


def build_investigation_graph(records: list[LogRecord], findings: list[DetectionFinding]) -> dict[str, object]:
    finding_lines = {item.line_no for item in findings if item.line_no is not None}
    nodes: dict[str, dict[str, object]] = {}
    edges: list[dict[str, object]] = []

    def add_node(node_id: str, node_type: str, label: str) -> None:
        nodes.setdefault(node_id, {"id": node_id, "type": node_type, "label": label})

    for record in records:
        if finding_lines and record.line_no not in finding_lines:
            continue
        src = f"ip:{record.src_ip}"
        add_node(src, "source_ip", record.src_ip)
        if record.uri:
            uri_node = f"uri:{_stable_id(record.uri)}"
            add_node(uri_node, "uri", record.uri[:80])
            edges.append({"source": src, "target": uri_node, "type": "requests", "line_no": record.line_no})
        if record.dest_port is not None:
            port_node = f"port:{record.dest_ip or 'unknown'}:{record.dest_port}"
            add_node(port_node, "service", f"{record.dest_ip or 'unknown'}:{record.dest_port}")
            edges.append({"source": src, "target": port_node, "type": "connects", "line_no": record.line_no})

    for finding in findings:
        src = f"ip:{finding.src_ip}"
        add_node(src, "source_ip", finding.src_ip)
        alert_node = f"alert:{finding.finding_type}:{finding.line_no or finding.timestamp.isoformat()}"
        add_node(alert_node, "alert", finding.finding_type)
        edges.append({"source": src, "target": alert_node, "type": "triggers", "line_no": finding.line_no})

    return {"nodes": list(nodes.values()), "edges": edges}


def _build_incident(src_ip: str, findings: list[DetectionFinding]) -> Incident:
    tactics = sorted({item.tactic for item in findings if item.tactic})
    finding_types = sorted({item.finding_type for item in findings})
    score = sum(max(item.score, 0) for item in findings)
    score += 20 * max(len(tactics) - 1, 0)
    severity = _incident_severity(score, findings)
    start_time = min(item.timestamp for item in findings)
    end_time = max(item.timestamp for item in findings)
    evidence_lines = sorted({item.line_no for item in findings if item.line_no is not None})
    incident_id = _stable_id(f"{src_ip}:{start_time.isoformat()}:{end_time.isoformat()}")[:12]
    narrative = _narrative(src_ip, finding_types, tactics, start_time, end_time)
    return Incident(
        incident_id=f"INC-{incident_id}",
        src_ip=src_ip,
        severity=severity,
        score=score,
        start_time=start_time,
        end_time=end_time,
        finding_count=len(findings),
        tactics=tactics,
        finding_types=finding_types,
        evidence_lines=evidence_lines,
        narrative=narrative,
        recommended_action=_recommended_action(severity, finding_types),
    )


def _incident_severity(score: int, findings: list[DetectionFinding]) -> str:
    if any(item.severity == "CRITICAL" for item in findings) or score >= 160:
        return "CRITICAL"
    if score >= 90 or any(item.severity == "HIGH" for item in findings):
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _narrative(src_ip: str, finding_types: list[str], tactics: list[str], start_time, end_time) -> str:
    return (
        f"Source {src_ip} produced {', '.join(finding_types)} between "
        f"{start_time.isoformat()} and {end_time.isoformat()}, covering tactics: "
        f"{', '.join(tactics) if tactics else 'unspecified'}."
    )


def _recommended_action(severity: str, finding_types: list[str]) -> str:
    if severity == "CRITICAL":
        return "Block the source, preserve raw logs, and perform host/application integrity checks."
    if "BRUTE_FORCE" in finding_types:
        return "Rate-limit the source and review affected accounts for successful login after failures."
    if "PORT_SCAN" in finding_types:
        return "Block or throttle scanning source and verify exposed service inventory."
    return "Review evidence, tune rule threshold if benign, and add confirmed attacker to denylist."


def _stable_id(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="ignore")).hexdigest()
