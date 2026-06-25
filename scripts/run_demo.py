"""Run the full Log-IDS detection pipeline and produce figures + metrics.

Usage:
    python3 scripts/run_demo.py

Output:
    assets/fig_*.png        — 7 figures (architecture, distribution, severity,
                              incident ranking, per-type metrics, benchmark
                              comparisons)
    report/runtime/*.json   — detections, incidents, investigation graph, metrics
    report/runtime/report.md — human-readable Markdown report
    report/runtime/summary.txt — one-line text summary
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from time import perf_counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from logids.correlation import build_investigation_graph, correlate_findings  # noqa: E402
from logids.detector import detect, load_config                           # noqa: E402
from logids.evaluation import evaluate_findings, load_labels              # noqa: E402
from logids.matchers import (brute_force_match, build_prefix_table,       # noqa: E402
                             kmp_match)
from logids.parser import parse_log_file                                  # noqa: E402
from logids.report import write_reports                                   # noqa: E402

# ---------------------------------------------------------------------------
# Attack type & severity display labels
# ---------------------------------------------------------------------------
CN_TYPE = {
    "BLACKLIST": "Blacklist", "SQL_INJECTION": "SQL Injection",
    "WEB_SCANNER": "Web Scanner", "XSS": "Cross-Site Scripting",
    "PATH_TRAVERSAL": "Path Traversal", "COMMAND_INJECTION": "Command Injection",
    "WEBSHELL_UPLOAD": "WebShell Upload", "BRUTE_FORCE": "Brute Force",
    "REQUEST_BURST": "Request Burst", "PORT_SCAN": "Port Scan",
    "OBFUSCATED_PAYLOAD": "Obfuscated Payload",
}
CN_SEV = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
          "LOW": "Low", "INFO": "Info"}


# ===========================================================================
# Pipeline
# ===========================================================================
def run_pipeline():
    log_path = ROOT / "data" / "corpus_access.log"
    config = load_config(ROOT / "config" / "rules.json")
    records, stats = parse_log_file(log_path)
    findings = detect(records, config)
    incidents = correlate_findings(findings,
                                   gap_minutes=int(config.get("correlation_gap_minutes", 10)))
    graph = build_investigation_graph(records, findings)
    labels = load_labels(ROOT / "data" / "corpus_labels.csv")
    metrics = evaluate_findings(findings, labels)
    report_dir = ROOT / "report" / "runtime"
    write_reports(report_dir, findings, stats, title="Log-IDS Detection Report",
                  incidents=incidents, investigation_graph=graph)
    (report_dir / "metrics.json").write_text(
        json.dumps(metrics.__dict__, ensure_ascii=False, indent=2), encoding="utf-8")
    return records, stats, config, findings, incidents, graph, metrics


# ===========================================================================
# Benchmarks
# ===========================================================================
def bench_realistic(records, config, scales=(1, 2, 4)):
    patterns = [str(p).lower() for s in config.get("signatures", [])
                for p in s.get("patterns", [])]
    prefixes = {p: build_prefix_table(p) for p in patterns}
    texts = [r.normalized for r in records]
    rows = []
    for scale in scales:
        scaled = texts * scale
        for method in ("brute", "kmp"):
            comps = 0
            start = perf_counter()
            for t in scaled:
                for p in patterns:
                    if method == "brute":
                        comps += brute_force_match(t, p).comparisons
                    else:
                        comps += kmp_match(t, p, prefixes[p]).comparisons
            ms = (perf_counter() - start) * 1000
            rows.append({"lines": len(scaled), "method": method,
                         "ms": ms, "comparisons": comps})
    return rows, len(patterns)


def bench_worstcase(lengths=(2000, 4000, 8000, 16000), m=64):
    pattern = ("a" * m) + "b"
    prefix = build_prefix_table(pattern)
    rows = []
    for L in lengths:
        text = ("a" * L) + "b"
        s = perf_counter(); rb = brute_force_match(text, pattern)
        tb = (perf_counter() - s) * 1000
        s = perf_counter(); rk = kmp_match(text, pattern, prefix)
        tk = (perf_counter() - s) * 1000
        rows.append({"length": L, "brute_comp": rb.comparisons,
                     "kmp_comp": rk.comparisons,
                     "brute_ms": tb, "kmp_ms": tk})
    return rows, m


def bench_threshold(records, config, burst_attacker_ips):
    import copy
    attackers = set(burst_attacker_ips)
    rows = []
    for thr in (8, 10, 12, 16, 20):
        cfg = copy.deepcopy(config)
        cfg["thresholds"]["request_count"] = thr
        findings = detect(records, cfg)
        burst = [f for f in findings if f.finding_type == "REQUEST_BURST"]
        tp = sum(1 for f in burst if f.src_ip in attackers)
        rows.append({"threshold": thr, "alerts": len(burst),
                     "tp": tp, "fp": len(burst) - tp})
    return rows


# ===========================================================================
# Font setup for plots
# ===========================================================================
def configure_plot_font():
    for cand in ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
                 "/usr/share/fonts/truetype/arphic/uming.ttc"):
        if Path(cand).exists():
            font_manager.fontManager.addfont(cand)
            plt.rcParams["font.family"] = font_manager.FontProperties(fname=cand).get_name()
            break
    plt.rcParams["axes.unicode_minus"] = False


# ===========================================================================
# Figures
# ===========================================================================
def fig_architecture(path):
    configure_plot_font()
    fig, ax = plt.subplots(figsize=(9.6, 3.3)); ax.axis("off")
    boxes = [
        ("Multi-source\nLog Input", 0.02, 0.55),
        ("Multi-format\nParser", 0.155, 0.55),
        ("Normalization\n& Anti-evasion", 0.29, 0.55),
        ("Allow/Deny\nList Filter", 0.425, 0.55),
        ("KMP Signature\nMatching", 0.57, 0.74),
        ("Sliding Window\nDetection", 0.57, 0.36),
        ("Risk Scoring &\nAttack Chain", 0.72, 0.55),
        ("Reports / Graph\n/ Evaluation", 0.865, 0.55),
    ]
    for label, x, y in boxes:
        ax.add_patch(plt.Rectangle((x, y - 0.10), 0.115, 0.20,
                                   facecolor="#EAF2F8", edgecolor="#1F618D", linewidth=1.4))
        ax.text(x + 0.0575, y, label, ha="center", va="center", fontsize=9.5)
    arrows = [
        ((0.135, 0.55), (0.155, 0.55)), ((0.27, 0.55), (0.29, 0.55)),
        ((0.405, 0.55), (0.425, 0.55)), ((0.54, 0.55), (0.57, 0.74)),
        ((0.54, 0.55), (0.57, 0.36)), ((0.685, 0.74), (0.72, 0.58)),
        ((0.685, 0.36), (0.72, 0.52)), ((0.835, 0.55), (0.865, 0.55)),
    ]
    for a, b in arrows:
        ax.annotate("", xy=b, xytext=a,
                    arrowprops={"arrowstyle": "->", "lw": 1.3, "color": "#34495E"})
    ax.text(0.5, 0.10,
            "Configuration-driven: rules.json (signatures / thresholds / lists / weights)",
            ha="center", fontsize=9, color="#566573")
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    fig.savefig(path, dpi=220, bbox_inches="tight"); plt.close(fig)


def fig_attack_dist(path, findings):
    configure_plot_font()
    counts = Counter(f.finding_type for f in findings)
    items = counts.most_common()
    labels = [CN_TYPE.get(k, k) for k, _ in items]
    values = [v for _, v in items]
    fig, ax = plt.subplots(figsize=(8.6, 4.4))
    bars = ax.barh(labels, values, color="#2E86C1")
    ax.invert_yaxis(); ax.set_xlabel("Alert Count"); ax.set_title("Alert Distribution by Attack Type")
    ax.bar_label(bars, padding=3); ax.grid(axis="x", alpha=0.25)
    fig.savefig(path, dpi=220, bbox_inches="tight"); plt.close(fig)


def fig_severity(path, findings):
    configure_plot_font()
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    c = Counter(f.severity for f in findings)
    labels, values = [], []
    for s in order:
        if c.get(s):
            labels.append(CN_SEV[s]); values.append(c[s])
    colors = ["#C0392B", "#E67E22", "#F1C40F", "#7F8C8D"][:len(values)]
    fig, ax = plt.subplots(figsize=(5.2, 4.2))
    ax.pie(values, labels=[f"{l}\n{v}" for l, v in zip(labels, values)],
           colors=colors, autopct="%1.0f%%", startangle=90,
           wedgeprops={"edgecolor": "white"})
    ax.set_title("Alert Severity Distribution"); ax.axis("equal")
    fig.savefig(path, dpi=220, bbox_inches="tight"); plt.close(fig)


def fig_incident_rank(path, incidents):
    configure_plot_font()
    top = incidents[:8]
    labels = [f"{i.src_ip}" for i in top]
    values = [i.score for i in top]
    colors = ["#922B21" if i.severity == "CRITICAL" else "#B9770E" for i in top]
    fig, ax = plt.subplots(figsize=(8.6, 4.4))
    bars = ax.barh(labels, values, color=colors)
    ax.invert_yaxis(); ax.set_xlabel("Risk Score"); ax.set_title("Incident Risk Score Ranking (Top 8)")
    ax.bar_label(bars, padding=3); ax.grid(axis="x", alpha=0.25)
    fig.savefig(path, dpi=220, bbox_inches="tight"); plt.close(fig)


def fig_metrics(path, metrics):
    configure_plot_font()
    types = [t for t in metrics.by_type if t in CN_TYPE]
    types.sort(key=lambda t: CN_TYPE[t])
    labels = [CN_TYPE[t] for t in types]
    P = [metrics.by_type[t]["precision"] for t in types]
    R = [metrics.by_type[t]["recall"] for t in types]
    F = [metrics.by_type[t]["f1"] for t in types]
    x = np.arange(len(labels)); w = 0.26
    fig, ax = plt.subplots(figsize=(9.6, 4.3))
    ax.bar(x - w, P, w, label="Precision", color="#117A65")
    ax.bar(x, R, w, label="Recall", color="#2874A6")
    ax.bar(x + w, F, w, label="F1", color="#B9770E")
    ax.set_xticks(x); ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=9)
    ax.set_ylim(0, 1.12); ax.set_ylabel("Score"); ax.grid(axis="y", alpha=0.25)
    ax.axhline(metrics.f1, ls="--", lw=1, color="#7B241C",
               label=f"Overall F1 = {metrics.f1:.3f}")
    ax.set_title("Precision / Recall / F1 by Attack Type"); ax.legend(ncol=4, fontsize=9, loc="lower center")
    fig.savefig(path, dpi=220, bbox_inches="tight"); plt.close(fig)


def fig_bench_real(path, rows):
    configure_plot_font()
    sizes = sorted({r["lines"] for r in rows})
    bc = [next(r["comparisons"] for r in rows if r["lines"] == s and r["method"] == "brute") for s in sizes]
    kc = [next(r["comparisons"] for r in rows if r["lines"] == s and r["method"] == "kmp") for s in sizes]
    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    ax.plot(sizes, bc, "o-", color="#C0392B", label="Brute-force comparisons")
    ax.plot(sizes, kc, "s-", color="#1E8449", label="KMP comparisons")
    ax.set_xlabel("Log lines"); ax.set_ylabel("Character comparisons")
    ax.set_title("Real Logs: Brute-force vs KMP (nearly overlapping)")
    ax.grid(alpha=0.25); ax.legend()
    fig.savefig(path, dpi=220, bbox_inches="tight"); plt.close(fig)


def fig_bench_worst(path, rows):
    configure_plot_font()
    L = [r["length"] for r in rows]
    bc = [r["brute_comp"] for r in rows]
    kc = [r["kmp_comp"] for r in rows]
    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    ax.plot(L, bc, "o-", color="#C0392B", label="Brute-force comparisons")
    ax.plot(L, kc, "s-", color="#1E8449", label="KMP comparisons")
    ax.set_xlabel("Text length (repeated-prefix worst case)"); ax.set_ylabel("Character comparisons")
    ax.set_title("Worst Case: Comparison count vs text length"); ax.grid(alpha=0.25); ax.legend()
    fig.savefig(path, dpi=220, bbox_inches="tight"); plt.close(fig)


# ===========================================================================
# Extra report: clean Markdown with all key results
# ===========================================================================
def write_summary_report(path, C):
    lines = [
        "# Log-IDS Experiment Report",
        "",
        f"**Generated**: {C['generated_at']}",
        "",
        "## Corpus",
        f"- Total lines: {C['total']}, Valid: {C['valid']}, Invalid: {C['invalid']}, Duplicates: {C['dup']}",
        f"- Format distribution: {C['fmt_text']}",
        "",
        "## Detection Results",
        f"- **{C['n_find']}** alerts, correlated into **{C['n_inc']}** incidents",
        f"- Severity: {C['sev_text']}",
        f"- Type distribution: {C['type_text']}",
        "",
        "## Evaluation",
        f"- **Precision = {C['P']:.3f}**, **Recall = {C['R']:.3f}**, **F1 = {C['F1']:.3f}**",
        f"- TP = {C['TP']}, FP = {C['FP']}, FN = {C['FN']}",
        "",
        "### Per-Type Metrics",
        "",
        "| Attack Type | TP | FP | FN | Precision | Recall | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for t in C["metric_types"]:
        m = C["by_type"][t]
        lines.append(f"| {CN_TYPE.get(t, t)} | {int(m['tp'])} | {int(m['fp'])} | {int(m['fn'])} | "
                     f"{m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} |")
    lines.extend([
        "",
        "## Top Incidents",
        "",
        "| Incident | Source IP | Severity | Score | Alerts | Tactics | Types |",
        "| --- | --- | --- | ---: | ---: | ---: | --- |",
    ])
    for inc in C["top_incidents"]:
        lines.append(f"| {inc['id']} | {inc['ip']} | {CN_SEV.get(inc['sev'], inc['sev'])} | "
                     f"{inc['score']} | {inc['count']} | {inc['tactics']} | {inc['types']} |")
    lines.extend([
        "",
        "## KMP vs Brute-Force Benchmark (Real Logs)",
        "",
        "| Log Lines | Method | Comparisons | Time (ms) |",
        "| ---: | --- | ---: | ---: |",
    ])
    for r in C["bench_real"]:
        lines.append(f"| {r['lines']:,} | {r['method']} | {r['comparisons']:,} | {r['ms']:.2f} |")
    lines.extend([
        "",
        "## KMP vs Brute-Force Benchmark (Worst Case)",
        "",
        "| Text Length | Brute-force Comp. | KMP Comp. | Brute-force ms | KMP ms |",
        "| ---: | ---: | ---: | ---: | ---: |",
    ])
    for r in C["bench_worst"]:
        lines.append(f"| {r['length']:,} | {r['brute_comp']:,} | {r['kmp_comp']:,} | "
                     f"{r['brute_ms']:.3f} | {r['kmp_ms']:.3f} |")
    worst_last = C["bench_worst"][-1]
    ratio = worst_last["brute_comp"] / max(worst_last["kmp_comp"], 1)
    lines.extend([
        "",
        f"At text length {worst_last['length']:,}, brute-force makes {worst_last['brute_comp']:,} "
        f"comparisons vs KMP's {worst_last['kmp_comp']:,} — roughly 1/{ratio:.0f}×.",
        "",
        "## Figures",
        f"- ![Architecture](../assets/fig_architecture.png)",
        f"- ![Attack Distribution](../assets/fig_attack_dist.png)",
        f"- ![Severity](../assets/fig_severity.png)",
        f"- ![Incident Ranking](../assets/fig_incident_rank.png)",
        f"- ![Metrics](../assets/fig_metrics.png)",
        f"- ![Bench Real](../assets/fig_bench_real.png)",
        f"- ![Bench Worst](../assets/fig_bench_worst.png)",
    ])
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


# ===========================================================================
# Context builder (all data for report + console output)
# ===========================================================================
def build_context(records, stats, findings, incidents, graph, metrics,
                  bench_real, n_patterns, bench_worst, worst_m, bench_thr):
    from datetime import datetime
    by_type = Counter(f.finding_type for f in findings)
    by_sev = Counter(f.severity for f in findings)
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_text = ", ".join(f"{CN_SEV[s]} {by_sev[s]}" for s in sev_order if by_sev.get(s))
    type_text = ", ".join(f"{CN_TYPE.get(t, t)} {c}" for t, c in by_type.most_common())
    fmt_text = ", ".join(f"{k} {v}" for k, v in sorted(stats.by_format.items(), key=lambda x: -x[1]))

    top_inc = []
    for inc in incidents[:6]:
        top_inc.append({
            "id": inc.incident_id, "ip": inc.src_ip, "sev": inc.severity,
            "score": inc.score, "count": inc.finding_count,
            "tactics": len(inc.tactics),
            "types": ", ".join(CN_TYPE.get(t, t) for t in inc.finding_types),
        })

    metric_types = [t for t in metrics.by_type if t in CN_TYPE]
    metric_types.sort(key=lambda t: CN_TYPE[t])

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "total": stats.total, "valid": stats.valid, "invalid": stats.invalid,
        "dup": stats.duplicates, "fmt_text": fmt_text,
        "n_find": len(findings), "n_inc": len(incidents),
        "sev_text": sev_text, "type_text": type_text,
        "graph_nodes": len(graph["nodes"]), "graph_edges": len(graph["edges"]),
        "top_incidents": top_inc,
        "P": metrics.precision, "R": metrics.recall, "F1": metrics.f1,
        "TP": metrics.tp, "FP": metrics.fp, "FN": metrics.fn,
        "by_type": metrics.by_type, "metric_types": metric_types,
        "n_patterns": n_patterns, "bench_real": bench_real,
        "bench_worst": bench_worst, "bench_thr": bench_thr,
    }


# ===========================================================================
# Main
# ===========================================================================
def main():
    assets = ROOT / "assets"; assets.mkdir(exist_ok=True)

    # 1) Run pipeline
    records, stats, config, findings, incidents, graph, metrics = run_pipeline()

    # 2) Benchmarks
    bench_real, n_patterns = bench_realistic(records, config)
    bench_worst, worst_m = bench_worstcase()
    meta = json.loads((ROOT / "data" / "corpus_meta.json").read_text(encoding="utf-8"))
    burst_ips = meta.get("attack_ips", {}).get("REQUEST_BURST", [])
    bench_thr = bench_threshold(records, config, burst_ips)

    # 3) Generate figures
    figs = {
        "arch": assets / "fig_architecture.png",
        "dist": assets / "fig_attack_dist.png",
        "sev": assets / "fig_severity.png",
        "inc": assets / "fig_incident_rank.png",
        "metrics": assets / "fig_metrics.png",
        "bench_real": assets / "fig_bench_real.png",
        "bench_worst": assets / "fig_bench_worst.png",
    }
    fig_architecture(figs["arch"])
    fig_attack_dist(figs["dist"], findings)
    fig_severity(figs["sev"], findings)
    fig_incident_rank(figs["inc"], incidents)
    fig_metrics(figs["metrics"], metrics)
    fig_bench_real(figs["bench_real"], bench_real)
    fig_bench_worst(figs["bench_worst"], bench_worst)

    # 4) Build context & write extra summary report
    C = build_context(records, stats, findings, incidents, graph, metrics,
                      bench_real, n_patterns, bench_worst, worst_m, bench_thr)
    write_summary_report(ROOT / "report" / "runtime" / "experiment_report.md", C)

    # 5) Console summary
    print(f"=== Log-IDS Experiment Complete ===")
    print(f"corpus: {C['valid']} valid / {C['total']} total / {C['invalid']} invalid / {C['dup']} dup")
    print(f"findings: {C['n_find']}  incidents: {C['n_inc']}")
    print(f"P = {C['P']:.3f}  R = {C['R']:.3f}  F1 = {C['F1']:.3f}  (TP={C['TP']} FP={C['FP']} FN={C['FN']})")
    print(f"figures: {len(figs)} generated in {assets}")
    print(f"reports: {ROOT / 'report' / 'runtime'}")


if __name__ == "__main__":
    main()
