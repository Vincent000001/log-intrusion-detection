# Log-IDS: Explainable Multi-Source Log Intrusion Detection & Attack Chain Correlation

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-5%2F5%20passed-brightgreen.svg)](tests/)

A **configuration-driven, explainable intrusion detection system** for multi-source security logs. Built entirely on Python's standard library for core detection — no heavy ML frameworks, no external services required.

**Why "explainable"?** Every alert carries the triggering rule, source IP, timestamp, raw evidence, ATT&CK tactic/technique, and confidence score. Discrete alerts are aggregated into scored security incidents with natural-language narratives and investigation graphs — not just "attack detected," but **what happened, when, who did it, how confident we are, and what to do about it**.

## Features

- **Multi-format log parsing** — ISO 8601 access logs, Apache/Nginx Common Log Format, key-value firewall/auth logs, and structured JSON logs. Tolerant: malformed lines are counted and skipped, not fatal.
- **Anti-evasion normalization** — Multi-round URL decoding, HTML entity decoding, case normalization, and slash/whitespace canonicalization to defeat encoding-based bypass attempts.
- **Dual-engine detection**:
  - *Signature engine* — JSON-configurable attack pattern library (SQL injection, XSS, path traversal, command injection, web scanners, webshell uploads) matched via KMP string search with prefix-table caching.
  - *Time-series engine* — Sliding-window detectors for request bursts, brute-force attacks, and port scans with per-source alert suppression.
- **Attack chain correlation** — Alerts grouped by source IP and time proximity into scored incidents. Multi-stage attacks (recon → exploit → persist → execute) receive cross-tactic weighting via a kill-chain-aware scoring formula.
- **Quantifiable evaluation** — Per-line multi-label ground truth with Precision/Recall/F1 computed by attack type. The labeled corpus deliberately includes false-positive traps (benign-but-suspicious requests) and false-negative cases (evasive/low-and-slow attacks).
- **Investigation graph export** — Source IP → URI → service → alert edges in JSON for manual triage and visualization.
- **Zero heavy dependencies for core detection** — `re`, `json`, `csv`, `collections`, `dataclasses`, `argparse`, `hashlib`, `ipaddress` only.

## Architecture

```
Multi-source Logs
       │
       ▼
┌──────────────────┐    ┌─────────────────┐    ┌──────────────┐
│  Multi-format    │───▶│  Normalization   │───▶│  Allow/Deny  │
│  Parser (4 types)│    │  & Anti-evasion  │    │  List Filter │
└──────────────────┘    └─────────────────┘    └──────────────┘
                                                       │
                              ┌─────────────────────────┤
                              ▼                         ▼
                    ┌──────────────────┐    ┌──────────────────┐
                    │  KMP Signature   │    │  Sliding Window   │
                    │  Matching        │    │  Detection        │
                    │  (6 attack types)│    │  (3 anomaly types)│
                    └──────────────────┘    └──────────────────┘
                              │                         │
                              └──────────┬──────────────┘
                                         ▼
                              ┌──────────────────┐
                              │  Risk Scoring &   │
                              │  Attack Chain     │
                              │  Correlation      │
                              └──────────────────┘
                                         │
                                         ▼
                              ┌──────────────────┐
                              │  Reports / Graph  │
                              │  / Metrics / Eval │
                              └──────────────────┘
```

*Configuration-driven: attack signatures, window thresholds, allow/deny lists, and risk weights all live in `config/rules.json` — no code changes needed to tune detection.*

## Quick Start

```bash
# 1) Generate a deterministic labeled corpus (fixed random seed, reproducible)
python3 scripts/build_corpus.py

# 2) Run detection, correlation, evaluation, and generate all figures
python3 scripts/run_demo.py

# 3) Or run the CLI directly on any log file
PYTHONPATH=src python3 -m logids data/corpus_access.log \
  -c config/rules.json -o report/runtime \
  --labels data/corpus_labels.csv --benchmark
```

**Output** (in `report/runtime/`):
- `detections.json` — all 159 raw alerts with full evidence
- `incidents.json` — 43 correlated security incidents with risk scores
- `investigation_graph.json` — nodes & edges for manual triage
- `metrics.json` — Precision/Recall/F1 overall and per attack type
- `report.md` — human-readable Markdown report
- `summary.txt` — one-line-per-stat text summary

**Figures** (in `assets/`):
- Attack type distribution bar chart
- Severity pie chart
- Incident risk score ranking
- Per-type P/R/F1 grouped bar chart
- KMP vs brute-force comparison (real logs + worst-case synthetic)

## CLI Reference

```
usage: python3 -m logids [-h] [-c CONFIG] [-o OUTPUT] [--match-method {kmp,brute}]
                         [--deduplicate] [--benchmark] [--benchmark-rounds N]
                         [--labels LABELS] log_file

Log-based intrusion detection system

positional arguments:
  log_file              input log file

optional arguments:
  -c, --config CONFIG   rules JSON path (default: config/rules.json)
  -o, --output OUTPUT   output report directory (default: report/runtime)
  --match-method METHOD signature matcher: kmp or brute (default: kmp)
  --deduplicate         drop exact duplicate lines during parsing
  --benchmark           run KMP vs brute-force benchmark
  --labels LABELS       CSV ground-truth labels for P/R/F1 evaluation
```

## API Overview

```python
from logids.parser import parse_log_file
from logids.detector import detect, load_config
from logids.correlation import correlate_findings, build_investigation_graph
from logids.evaluation import evaluate_findings, load_labels
from logids.report import write_reports

# Parse multi-format logs
records, stats = parse_log_file("access.log")

# Detect attacks (signatures + sliding windows + denylist)
config = load_config("config/rules.json")
findings = detect(records, config)

# Correlate into scored incidents
incidents = correlate_findings(findings, gap_minutes=10)

# Build investigation graph
graph = build_investigation_graph(records, findings)

# Evaluate against ground truth
labels = load_labels("labels.csv")
metrics = evaluate_findings(findings, labels)
print(f"P/R/F1 = {metrics.precision:.3f}/{metrics.recall:.3f}/{metrics.f1:.3f}")

# Export reports
write_reports("output/", findings, stats, incidents=incidents, investigation_graph=graph)
```

## KMP vs Brute-Force Matching

The project includes a clean implementation of both brute-force string matching and Knuth-Morris-Pratt (KMP) with prefix-function caching. Key finding: on real-world short log fields, both algorithms perform nearly identically (brute force exits early on first-character mismatches). On pathological inputs with long repeated prefixes (e.g., `aaaa...aab`), KMP's O(n+m) advantage becomes dramatic — up to 50× fewer character comparisons at 16,000-character text length.

## Evaluation Results (3399-record labeled corpus)

| Metric | Value |
|--------|-------|
| Total alerts | 159 |
| Correlated incidents | 43 |
| **Precision** | **0.937** |
| **Recall** | **0.937** |
| **F1** | **0.937** |
| True positives | 149 |
| False positives | 10 |
| False negatives | 10 |

The evaluation is intentionally honest: the corpus includes 23 benign-but-suspicious trap lines (e.g., search queries containing "union select", legitimate `../` paths, URL-encoded CJK text, high-frequency thumbnail loads) and 11 evasive attacks (comment-obfuscated SQLi, log4shell-style JNDI lookups, SSTI payloads, slow brute-force below the window threshold). The 0.937 F1 reflects real design boundaries, not overfitting.

## Project Structure

```
log-ids/
├── src/logids/              # Core library (stdlib only)
│   ├── __init__.py
│   ├── models.py            # LogRecord, DetectionFinding, Incident, metrics
│   ├── parser.py            # 4-format parser + anti-evasion normalization
│   ├── matchers.py          # Brute-force, KMP prefix table, KMP match, benchmark
│   ├── detector.py          # Denylist, signatures, evasion heuristics, sliding windows
│   ├── correlation.py       # Risk scoring, attack-chain aggregation, investigation graph
│   ├── evaluation.py        # Per-line multi-label P/R/F1 computation
│   ├── report.py            # JSON, Markdown, and text summary report writers
│   ├── cli.py               # argparse-based CLI entry point
│   └── __main__.py          # python3 -m logids entry
├── config/rules.json        # Signatures, thresholds, allow/deny lists, risk weights
├── data/                    # Sample + corpus data
│   ├── sample_access.log    # Small hand-crafted test log
│   ├── sample_labels.csv    # Ground truth for sample log
│   ├── corpus_access.log    # Large auto-generated multi-format corpus
│   ├── corpus_labels.csv    # Adjudicated per-line multi-label ground truth
│   └── corpus_meta.json     # Corpus generation metadata
├── scripts/
│   ├── build_corpus.py      # Deterministic labeled corpus generator
│   └── run_demo.py          # Full pipeline demo: detect → correlate → evaluate → plot
├── tests/
│   └── test_logids.py       # 5 unit tests
├── assets/                  # Generated figures
├── report/runtime/          # Runtime output (gitignored)
├── pyproject.toml
├── LICENSE
└── README.md
```

## Running Tests

```bash
PYTHONPATH=src python3 -m pytest tests/ -q
```

Five tests cover: KMP/brute-force consistency, multi-format parser correctness, detection of all 9 major attack classes, incident correlation scoring, and realistic corpus evaluation with honest FP/FN expectations.

## Dependencies

**Core detection** (running `logids` CLI or using the library): **Python 3.9+ standard library only.**

**Demo script** (`scripts/run_demo.py`) additionally requires:
- `matplotlib` — for figure generation
- `numpy` — for chart data handling

Install with: `pip install matplotlib numpy`

## License

MIT — see [LICENSE](LICENSE) for details.
