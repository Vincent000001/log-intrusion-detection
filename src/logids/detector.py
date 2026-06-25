from __future__ import annotations

import json
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .matchers import build_prefix_table, kmp_match, match_any
from .models import DetectionFinding, DetectionSummary, LogRecord


def load_config(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def detect(
    records: list[LogRecord],
    config: dict[str, Any],
    *,
    match_method: str = "kmp",
) -> list[DetectionFinding]:
    findings: list[DetectionFinding] = []
    allowlist = set(config.get("allowlist", []))
    denylist = set(config.get("denylist", []))
    findings.extend(_detect_denylist(records, denylist))

    filtered = [record for record in records if record.src_ip not in allowlist]
    findings.extend(_detect_signatures(filtered, config.get("signatures", []), match_method))
    findings.extend(_detect_evasion_indicators(filtered))
    findings.extend(_detect_windows(filtered, config.get("thresholds", {})))
    return sorted(findings, key=lambda item: (item.timestamp, _severity_rank(item.severity), item.src_ip))


def _detect_denylist(records: list[LogRecord], denylist: set[str]) -> list[DetectionFinding]:
    findings = []
    for record in records:
        if record.src_ip in denylist:
            findings.append(
                DetectionFinding(
                    finding_type="BLACKLIST",
                    severity="CRITICAL",
                    src_ip=record.src_ip,
                    timestamp=record.timestamp,
                    reason="Source IP is present in denylist",
                    evidence=_short(record.raw),
                    line_no=record.line_no,
                    dest_ip=record.dest_ip,
                    dest_port=record.dest_port,
                    rule_id="denylist",
                    score=_score("CRITICAL"),
                    tactic="Policy Violation",
                    technique="Known Bad Source",
                    confidence=1.0,
                )
            )
    return findings


def _detect_signatures(
    records: list[LogRecord],
    signatures: list[dict[str, Any]],
    match_method: str,
) -> list[DetectionFinding]:
    findings: list[DetectionFinding] = []
    prefix_cache: dict[str, list[int]] = {}
    for record in records:
        for rule in signatures:
            patterns = [str(pattern).lower() for pattern in rule.get("patterns", [])]
            matched_pattern: str | None = None
            if match_method == "kmp":
                for pattern in patterns:
                    prefix = prefix_cache.setdefault(pattern, build_prefix_table(pattern))
                    if kmp_match(record.normalized, pattern, prefix).matched:
                        matched_pattern = pattern
                        break
            else:
                matched_pattern, _ = match_any(record.normalized, patterns, method=match_method)
            if matched_pattern:
                findings.append(
                    DetectionFinding(
                        finding_type=rule.get("name", "signature"),
                        severity=rule.get("severity", "MEDIUM"),
                        src_ip=record.src_ip,
                        timestamp=record.timestamp,
                        reason=rule.get("description", "Signature pattern matched"),
                        evidence=f"pattern={matched_pattern}; raw={_short(record.raw)}",
                        line_no=record.line_no,
                        dest_ip=record.dest_ip,
                        dest_port=record.dest_port,
                        rule_id=rule.get("id", ""),
                        score=int(rule.get("score", _score(rule.get("severity", "MEDIUM")))),
                        tactic=rule.get("tactic", ""),
                        technique=rule.get("technique", ""),
                        confidence=float(rule.get("confidence", 0.9)),
                    )
                )
    return findings


def _detect_evasion_indicators(records: list[LogRecord]) -> list[DetectionFinding]:
    findings: list[DetectionFinding] = []
    attack_markers = (
        "union select",
        "or 1=1",
        "<script",
        "/etc/passwd",
        "../",
        "&&whoami",
        ";cat ",
        "cmd=whoami",
    )
    for record in records:
        raw_lower = record.raw.lower()
        percent_count = raw_lower.count("%")
        has_html_entity = "&#" in raw_lower or "&lt;" in raw_lower or "&gt;" in raw_lower
        has_double_encoding = "%25" in raw_lower or "%252f" in raw_lower or "%253c" in raw_lower
        decoded_attack = percent_count > 0 and any(marker in record.normalized for marker in attack_markers)
        if percent_count >= 5 or has_html_entity or has_double_encoding or decoded_attack:
            findings.append(
                DetectionFinding(
                    finding_type="OBFUSCATED_PAYLOAD",
                    severity="MEDIUM",
                    src_ip=record.src_ip,
                    timestamp=record.timestamp,
                    reason="Encoded or entity-obfuscated payload indicates possible filter evasion",
                    evidence=f"percent_count={percent_count}; raw={_short(record.raw)}",
                    line_no=record.line_no,
                    dest_ip=record.dest_ip,
                    dest_port=record.dest_port,
                    rule_id="heuristic.obfuscation",
                    score=_score("MEDIUM"),
                    tactic="Defense Evasion",
                    technique="Obfuscated Files or Information",
                    confidence=0.65,
                )
            )
    return findings


def _detect_windows(records: list[LogRecord], thresholds: dict[str, Any]) -> list[DetectionFinding]:
    records = sorted(records, key=lambda item: item.timestamp)
    findings: list[DetectionFinding] = []
    findings.extend(_detect_request_burst(records, thresholds))
    findings.extend(_detect_auth_failures(records, thresholds))
    findings.extend(_detect_port_scan(records, thresholds))
    return findings


def _detect_request_burst(records: list[LogRecord], thresholds: dict[str, Any]) -> list[DetectionFinding]:
    window_seconds = int(thresholds.get("request_window_seconds", 60))
    threshold = int(thresholds.get("request_count", 20))
    queues: dict[str, deque[LogRecord]] = defaultdict(deque)
    last_alert: dict[str, datetime] = {}
    findings: list[DetectionFinding] = []
    for record in records:
        if not record.method and record.dest_port is not None:
            continue
        queue = queues[record.src_ip]
        queue.append(record)
        cutoff = record.timestamp - timedelta(seconds=window_seconds)
        while queue and queue[0].timestamp < cutoff:
            queue.popleft()
        if len(queue) >= threshold and _can_alert(last_alert, record.src_ip, record.timestamp, window_seconds):
            findings.append(
                DetectionFinding(
                    finding_type="REQUEST_BURST",
                    severity="MEDIUM",
                    src_ip=record.src_ip,
                    timestamp=record.timestamp,
                    reason=f"Request count reached {len(queue)} within {window_seconds}s",
                    evidence=_short(record.raw),
                    line_no=record.line_no,
                    count=len(queue),
                    window_start=queue[0].timestamp,
                    window_end=record.timestamp,
                    rule_id="window.request_burst",
                    score=_score("MEDIUM") + min(len(queue) - threshold, 10),
                    tactic="Reconnaissance",
                    technique="Active Scanning or Resource Exhaustion",
                    confidence=0.7,
                )
            )
            last_alert[record.src_ip] = record.timestamp
    return findings


def _detect_auth_failures(records: list[LogRecord], thresholds: dict[str, Any]) -> list[DetectionFinding]:
    window_seconds = int(thresholds.get("auth_window_seconds", 120))
    threshold = int(thresholds.get("auth_failures", 5))
    queues: dict[str, deque[LogRecord]] = defaultdict(deque)
    last_alert: dict[str, datetime] = {}
    findings: list[DetectionFinding] = []
    for record in records:
        if not _is_auth_failure(record):
            continue
        queue = queues[record.src_ip]
        queue.append(record)
        cutoff = record.timestamp - timedelta(seconds=window_seconds)
        while queue and queue[0].timestamp < cutoff:
            queue.popleft()
        if len(queue) >= threshold and _can_alert(last_alert, record.src_ip, record.timestamp, window_seconds):
            findings.append(
                DetectionFinding(
                    finding_type="BRUTE_FORCE",
                    severity="HIGH",
                    src_ip=record.src_ip,
                    timestamp=record.timestamp,
                    reason=f"Authentication failures reached {len(queue)} within {window_seconds}s",
                    evidence=_short(record.raw),
                    line_no=record.line_no,
                    count=len(queue),
                    window_start=queue[0].timestamp,
                    window_end=record.timestamp,
                    dest_ip=record.dest_ip,
                    dest_port=record.dest_port,
                    rule_id="window.auth_failures",
                    score=_score("HIGH") + min(len(queue) - threshold, 10),
                    tactic="Credential Access",
                    technique="Brute Force",
                    confidence=0.85,
                )
            )
            last_alert[record.src_ip] = record.timestamp
    return findings


def _detect_port_scan(records: list[LogRecord], thresholds: dict[str, Any]) -> list[DetectionFinding]:
    window_seconds = int(thresholds.get("scan_window_seconds", 30))
    threshold = int(thresholds.get("distinct_ports", 6))
    queues: dict[str, deque[LogRecord]] = defaultdict(deque)
    last_alert: dict[str, datetime] = {}
    findings: list[DetectionFinding] = []
    for record in records:
        if record.dest_port is None:
            continue
        queue = queues[record.src_ip]
        queue.append(record)
        cutoff = record.timestamp - timedelta(seconds=window_seconds)
        while queue and queue[0].timestamp < cutoff:
            queue.popleft()
        ports = {item.dest_port for item in queue if item.dest_port is not None}
        if len(ports) >= threshold and _can_alert(last_alert, record.src_ip, record.timestamp, window_seconds):
            findings.append(
                DetectionFinding(
                    finding_type="PORT_SCAN",
                    severity="HIGH",
                    src_ip=record.src_ip,
                    timestamp=record.timestamp,
                    reason=f"Source touched {len(ports)} distinct destination ports within {window_seconds}s",
                    evidence=f"ports={sorted(ports)}; raw={_short(record.raw)}",
                    line_no=record.line_no,
                    count=len(ports),
                    window_start=queue[0].timestamp,
                    window_end=record.timestamp,
                    dest_ip=record.dest_ip,
                    dest_port=record.dest_port,
                    rule_id="window.port_scan",
                    score=_score("HIGH") + min(len(ports) - threshold, 10),
                    tactic="Reconnaissance",
                    technique="Network Service Discovery",
                    confidence=0.85,
                )
            )
            last_alert[record.src_ip] = record.timestamp
    return findings


def _is_auth_failure(record: LogRecord) -> bool:
    action = record.action.lower()
    text = record.normalized
    if record.status in {401, 403} and ("login" in text or "auth" in text or "admin" in text):
        return True
    return action in {"fail", "failed", "deny", "denied"} and (
        record.dest_port in {22, 3389, 3306} or "login" in text or "auth" in text or "ssh" in text
    )


def _can_alert(last_alert: dict[str, datetime], key: str, now: datetime, window_seconds: int) -> bool:
    previous = last_alert.get(key)
    return previous is None or now - previous >= timedelta(seconds=window_seconds)


def summarize(findings: list[DetectionFinding]) -> DetectionSummary:
    by_severity = Counter(item.severity for item in findings)
    by_type = Counter(item.finding_type for item in findings)
    by_source = Counter(item.src_ip for item in findings)
    return DetectionSummary(
        total_findings=len(findings),
        by_severity=dict(by_severity),
        by_type=dict(by_type),
        top_sources=by_source.most_common(10),
    )


def _severity_rank(value: str) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return order.get(value.upper(), 9)


def _score(severity: str) -> int:
    scores = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 40, "LOW": 20, "INFO": 5}
    return scores.get(severity.upper(), 30)


def _short(value: str, limit: int = 180) -> str:
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 3] + "..."
