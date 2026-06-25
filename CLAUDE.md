# CLAUDE.md — Log-IDS

## Project overview

Log-IDS is a configuration-driven, explainable intrusion detection system for multi-source security logs. Core detection uses only Python stdlib. It parses 4 log formats, normalizes against encoding evasion, detects attacks via KMP signature matching + sliding-window anomaly detection, correlates alerts into scored incidents with ATT&CK tactics, and evaluates against labeled ground truth.

## Build & test commands

```bash
# Generate labeled corpus (deterministic, fixed seed)
python3 scripts/build_corpus.py

# Run full demo: detect → correlate → evaluate → generate all figures
python3 scripts/run_demo.py

# CLI detection on any log file
PYTHONPATH=src python3 -m logids data/corpus_access.log \
  -c config/rules.json -o report/runtime \
  --labels data/corpus_labels.csv --benchmark

# Run unit tests
PYTHONPATH=src python3 -m pytest tests/ -q
```

## Architecture (8 modules, ~1200 lines core)

```
src/logids/
├── models.py       # Dataclasses: LogRecord, DetectionFinding, Incident, EvaluationMetrics
├── parser.py       # 4-format parser (ISO/Common/KV/JSON) + anti-evasion normalization
├── matchers.py     # Brute-force + KMP (prefix table, match) + benchmark
├── detector.py     # Denylist → signatures (KMP) → evasion heuristics → 3 sliding windows
├── correlation.py  # Per-IP temporal grouping, risk scoring, investigation graph
├── evaluation.py   # Per-line multi-label P/R/F1 against CSV ground truth
├── report.py       # JSON + Markdown + text summary writers
├── cli.py          # argparse CLI entry
└── __main__.py     # python3 -m logids
```

## Key design decisions

- **Configuration-driven**: `config/rules.json` holds all signatures, thresholds, allow/deny lists, and risk weights. No code changes needed to tune detection.
- **Normalization pipeline**: `normalize_text()` in parser.py applies up to 4 rounds of URL decode + HTML entity decode + case folding. This is what makes `%3Cscript%3E` match `<script>`.
- **KMP prefix caching**: `_detect_signatures()` in detector.py caches prefix tables per pattern via `prefix_cache.setdefault()`.
- **Alert suppression**: `_can_alert()` in detector.py prevents duplicate window alerts from the same source within one window period.
- **Risk scoring formula**: `Score(e) = Σ score(f) + 20 × max(|tactics| - 1, 0)` — multi-stage attacks get cross-tactic weighting.
- **Honest evaluation**: The labeled corpus deliberately includes FP traps (benign-but-suspicious lines) and FN cases (evasive/slow attacks). The 0.937 F1 is intentionally not 1.0.

## Corpus generation

`scripts/build_corpus.py` generates a 3403-line multi-format log corpus deterministically (seed=20260623). Scenarios include:
- 520 benign sessions with 4-format mixing
- 6 SQLi attacker IPs with URL-encoded payloads
- 4 XSS, 4 path traversal, 4 command injection attackers
- 3 web scanner IPs (nikto/sqlmap/acunetix user-agents)
- 3 webshell upload scenarios
- 2 fast brute-force, 2 fast request-burst, 2 fast port-scan attackers
- 2 multi-stage kill-chain attackers (recon → sqli → webshell → rce)
- FP traps: benign "union select" searches, legitimate `../` paths, URL-encoded CJK, high-frequency thumbnail loads
- FN traps: comment-obfuscated SQLi (`/**/`), log4shell JNDI, SSTI `{{7*7}}`, slow brute-force (75s gaps), slow port scan (12s gaps)

Ground truth adjudication: the detector runs once; its hits on real attacks are confirmed TP; designed benign traps are marked benign (detector hits → FP); known evasive attacks are added as truth (detector misses → FN).
