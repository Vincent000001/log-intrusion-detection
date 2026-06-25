from __future__ import annotations

import ipaddress
import json
import re
import shlex
from html import unescape
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote_plus

from .models import LogRecord, ParseStats


ISO_ACCESS_RE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2}T[0-9:.+-]+Z?)\s+"
    r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+"
    r"(?P<status>\d{3})(?:\s+(?P<size>\S+))?"
    r"(?:\s+\"(?P<referer>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\")?"
)

COMMON_ACCESS_RE = re.compile(
    r"^(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r"\"(?P<method>[A-Z]+)\s+(?P<uri>[^\" ]+)(?:\s+HTTP/[0-9.]+)?\"\s+"
    r"(?P<status>\d{3})\s+(?P<size>\S+)"
    r"(?:\s+\"(?P<referer>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\")?"
)


def parse_log_file(path: str | Path, deduplicate: bool = False) -> tuple[list[LogRecord], ParseStats]:
    records: list[LogRecord] = []
    stats = ParseStats()
    seen: set[str] = set()
    with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, raw_line in enumerate(handle, start=1):
            stats.total += 1
            line = raw_line.strip()
            if not line:
                stats.invalid += 1
                continue
            if line in seen:
                stats.duplicates += 1
                if deduplicate:
                    continue
            seen.add(line)
            record = parse_line(line, line_no)
            if record is None:
                stats.invalid += 1
                if len(stats.invalid_examples) < 5:
                    stats.invalid_examples.append((line_no, line[:160]))
                continue
            records.append(record)
            stats.valid += 1
            stats.kept += 1
            stats.mark_format(record.format_name)
    return records, stats


def parse_line(line: str, line_no: int) -> LogRecord | None:
    for parser in (_parse_json_line, _parse_iso_access, _parse_common_access, _parse_key_value):
        record = parser(line, line_no)
        if record is not None:
            return record
    return None


def _parse_json_line(line: str, line_no: int) -> LogRecord | None:
    if not line.startswith("{"):
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    lowered = {str(key).lower(): value for key, value in data.items()}
    src_ip = str(lowered.get("src_ip") or lowered.get("src") or lowered.get("ip") or "")
    if not src_ip or not _valid_ip(src_ip):
        return None
    timestamp = _parse_time(str(lowered.get("time") or lowered.get("timestamp") or lowered.get("@timestamp") or ""))
    if timestamp is None:
        return None
    uri = str(lowered.get("uri") or lowered.get("url") or lowered.get("path") or "")
    extra = {key: str(value) for key, value in lowered.items()}
    return _make_record(
        timestamp=timestamp,
        src_ip=src_ip,
        raw=line,
        line_no=line_no,
        format_name="json",
        method=str(lowered.get("method") or ""),
        uri=uri,
        status=_to_int(str(lowered.get("status") or "")),
        dest_ip=str(lowered.get("dst_ip") or lowered.get("dst") or ""),
        dest_port=_to_int(str(lowered.get("dest_port") or lowered.get("dst_port") or lowered.get("dpt") or "")),
        action=str(lowered.get("action") or ""),
        user_agent=str(lowered.get("user_agent") or lowered.get("ua") or ""),
        extra=extra,
    )


def _parse_iso_access(line: str, line_no: int) -> LogRecord | None:
    match = ISO_ACCESS_RE.match(line)
    if not match:
        return None
    data = match.groupdict(default="")
    timestamp = _parse_time(data["time"])
    if timestamp is None or not _valid_ip(data["src_ip"]):
        return None
    return _make_record(
        timestamp=timestamp,
        src_ip=data["src_ip"],
        raw=line,
        line_no=line_no,
        format_name="iso_access",
        method=data["method"],
        uri=data["uri"],
        status=_to_int(data["status"]),
        user_agent=data.get("ua", ""),
        extra={"referer": data.get("referer", ""), "size": data.get("size", "")},
    )


def _parse_common_access(line: str, line_no: int) -> LogRecord | None:
    match = COMMON_ACCESS_RE.match(line)
    if not match:
        return None
    data = match.groupdict(default="")
    timestamp = _parse_time(data["time"])
    if timestamp is None or not _valid_ip(data["src_ip"]):
        return None
    return _make_record(
        timestamp=timestamp,
        src_ip=data["src_ip"],
        raw=line,
        line_no=line_no,
        format_name="common_access",
        method=data["method"],
        uri=data["uri"],
        status=_to_int(data["status"]),
        user_agent=data.get("ua", ""),
        extra={"referer": data.get("referer", ""), "size": data.get("size", "")},
    )


def _parse_key_value(line: str, line_no: int) -> LogRecord | None:
    try:
        parts = shlex.split(line)
    except ValueError:
        return None
    if not parts:
        return None
    fields: dict[str, str] = {}
    if "=" not in parts[0]:
        fields["time"] = parts[0]
        parts = parts[1:]
    for part in parts:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        fields[key.lower()] = value

    src_ip = fields.get("src") or fields.get("src_ip") or fields.get("ip") or ""
    if not src_ip or not _valid_ip(src_ip):
        return None
    timestamp = _parse_time(fields.get("time") or fields.get("ts") or "")
    if timestamp is None:
        return None
    uri = fields.get("uri") or fields.get("path") or fields.get("url") or ""
    action = fields.get("action", "")
    method = fields.get("method", "")
    status = _to_int(fields.get("status", ""))
    return _make_record(
        timestamp=timestamp,
        src_ip=src_ip,
        raw=line,
        line_no=line_no,
        format_name="key_value",
        method=method,
        uri=uri,
        status=status,
        dest_ip=fields.get("dst", "") or fields.get("dst_ip", ""),
        dest_port=_to_int(fields.get("dpt", "") or fields.get("port", "")),
        action=action,
        user_agent=fields.get("ua", ""),
        extra=fields,
    )


def _make_record(
    *,
    timestamp: datetime,
    src_ip: str,
    raw: str,
    line_no: int,
    format_name: str,
    method: str = "",
    uri: str = "",
    status: int | None = None,
    dest_ip: str = "",
    dest_port: int | None = None,
    action: str = "",
    user_agent: str = "",
    extra: dict[str, str] | None = None,
) -> LogRecord:
    normalized = normalize_text(" ".join([raw, method, uri, action, user_agent, " ".join((extra or {}).values())]))
    return LogRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        raw=raw,
        normalized=normalized,
        line_no=line_no,
        format_name=format_name,
        method=method,
        uri=uri,
        status=status,
        dest_ip=dest_ip,
        dest_port=dest_port,
        action=action,
        user_agent=user_agent,
        extra=dict(extra or {}),
    )


def normalize_text(value: str) -> str:
    text = value
    for _ in range(4):
        decoded = unescape(unquote_plus(text))
        if decoded == text:
            break
        text = decoded
    text = text.replace("\\/", "/").replace("\\x2f", "/").replace("\\x3c", "<").replace("\\x3e", ">")
    text = re.sub(r"(?i)/\./", "/", text)
    text = re.sub(r"\s+", " ", text)
    return text.lower()


def _parse_time(value: str) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    candidates = []
    if value.endswith("Z"):
        candidates.append(value[:-1] + "+00:00")
    candidates.append(value)
    for item in candidates:
        try:
            dt = datetime.fromisoformat(item)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _to_int(value: str | None) -> int | None:
    if value is None or value == "" or value == "-":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def iter_records(paths: Iterable[str | Path]) -> tuple[list[LogRecord], ParseStats]:
    merged: list[LogRecord] = []
    merged_stats = ParseStats()
    for path in paths:
        records, stats = parse_log_file(path)
        merged.extend(records)
        merged_stats.total += stats.total
        merged_stats.valid += stats.valid
        merged_stats.invalid += stats.invalid
        merged_stats.duplicates += stats.duplicates
        merged_stats.kept += stats.kept
        for key, value in stats.by_format.items():
            merged_stats.by_format[key] = merged_stats.by_format.get(key, 0) + value
        merged_stats.invalid_examples.extend(stats.invalid_examples)
    merged.sort(key=lambda item: item.timestamp)
    return merged, merged_stats
