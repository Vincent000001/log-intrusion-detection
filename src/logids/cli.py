from __future__ import annotations

import argparse
import json
from pathlib import Path

from .correlation import build_investigation_graph, correlate_findings
from .detector import detect, load_config
from .evaluation import evaluate_findings, load_labels
from .matchers import benchmark_matchers
from .parser import parse_log_file
from .report import write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Log-based intrusion detection system")
    parser.add_argument("log_file", help="input log file")
    parser.add_argument("-c", "--config", default="config/rules.json", help="rules JSON path")
    parser.add_argument("-o", "--output", default="report/runtime", help="output report directory")
    parser.add_argument("--match-method", choices=["kmp", "brute"], default="kmp", help="signature matcher")
    parser.add_argument("--deduplicate", action="store_true", help="drop exact duplicate lines during parsing")
    parser.add_argument("--benchmark", action="store_true", help="run matcher benchmark after detection")
    parser.add_argument("--benchmark-rounds", type=int, default=200, help="benchmark rounds")
    parser.add_argument("--labels", help="optional CSV labels for precision/recall/F1 evaluation")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    records, stats = parse_log_file(args.log_file, deduplicate=args.deduplicate)
    config = load_config(args.config)
    findings = detect(records, config, match_method=args.match_method)
    incidents = correlate_findings(findings, gap_minutes=int(config.get("correlation_gap_minutes", 10)))
    graph = build_investigation_graph(records, findings)
    write_reports(args.output, findings, stats, incidents=incidents, investigation_graph=graph)
    print(f"logs total={stats.total} valid={stats.valid} invalid={stats.invalid} duplicates={stats.duplicates}")
    print(f"findings={len(findings)} incidents={len(incidents)} output={Path(args.output).resolve()}")

    if args.labels:
        metrics = evaluate_findings(findings, load_labels(args.labels))
        metrics_path = Path(args.output) / "metrics.json"
        metrics_path.write_text(json.dumps(metrics.__dict__, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"metrics precision={metrics.precision:.3f} recall={metrics.recall:.3f} f1={metrics.f1:.3f}")

    if args.benchmark:
        text = ("a" * 8000) + "b"
        pattern = ("a" * 64) + "b"
        for result in benchmark_matchers(text, pattern, rounds=args.benchmark_rounds):
            print(
                f"benchmark matcher={result.matcher} matched={result.matched} "
                f"comparisons={result.comparisons} elapsed_ms={result.elapsed_ms:.3f}"
            )
    return 0
