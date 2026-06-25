from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class LogRecord:
    timestamp: datetime
    src_ip: str
    raw: str
    normalized: str
    line_no: int
    format_name: str
    method: str = ""
    uri: str = ""
    status: int | None = None
    dest_ip: str = ""
    dest_port: int | None = None
    action: str = ""
    user_agent: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParseStats:
    total: int = 0
    valid: int = 0
    invalid: int = 0
    duplicates: int = 0
    kept: int = 0
    by_format: dict[str, int] = field(default_factory=dict)
    invalid_examples: list[tuple[int, str]] = field(default_factory=list)

    def mark_format(self, name: str) -> None:
        self.by_format[name] = self.by_format.get(name, 0) + 1


@dataclass
class DetectionFinding:
    finding_type: str
    severity: str
    src_ip: str
    timestamp: datetime
    reason: str
    evidence: str
    line_no: int | None = None
    count: int | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    dest_ip: str = ""
    dest_port: int | None = None
    rule_id: str = ""
    score: int = 0
    tactic: str = ""
    technique: str = ""
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "timestamp": self.timestamp.isoformat(),
            "reason": self.reason,
            "evidence": self.evidence,
            "line_no": self.line_no,
            "count": self.count,
            "window_start": self.window_start.isoformat() if self.window_start else None,
            "window_end": self.window_end.isoformat() if self.window_end else None,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "rule_id": self.rule_id,
            "score": self.score,
            "tactic": self.tactic,
            "technique": self.technique,
            "confidence": self.confidence,
        }


@dataclass
class BenchmarkResult:
    matcher: str
    matched: bool
    comparisons: int
    elapsed_ms: float


@dataclass
class DetectionSummary:
    total_findings: int
    by_severity: dict[str, int]
    by_type: dict[str, int]
    top_sources: list[tuple[str, int]]


@dataclass
class Incident:
    incident_id: str
    src_ip: str
    severity: str
    score: int
    start_time: datetime
    end_time: datetime
    finding_count: int
    tactics: list[str]
    finding_types: list[str]
    evidence_lines: list[int]
    narrative: str
    recommended_action: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "src_ip": self.src_ip,
            "severity": self.severity,
            "score": self.score,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "finding_count": self.finding_count,
            "tactics": self.tactics,
            "finding_types": self.finding_types,
            "evidence_lines": self.evidence_lines,
            "narrative": self.narrative,
            "recommended_action": self.recommended_action,
        }


@dataclass
class EvaluationMetrics:
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    by_type: dict[str, dict[str, float]]
