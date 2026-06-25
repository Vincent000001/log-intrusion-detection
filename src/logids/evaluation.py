from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

from .models import DetectionFinding, EvaluationMetrics


def load_labels(path: str | Path) -> dict[int, set[str]]:
    labels: dict[int, set[str]] = defaultdict(set)
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            line_no = int(row["line_no"])
            for label in row["labels"].split(";"):
                label = label.strip()
                if label and label != "BENIGN":
                    labels[line_no].add(label)
    return labels


def evaluate_findings(findings: list[DetectionFinding], labels: dict[int, set[str]]) -> EvaluationMetrics:
    predicted: set[tuple[int, str]] = set()
    for finding in findings:
        if finding.line_no is not None:
            predicted.add((finding.line_no, finding.finding_type))
    truth = {(line_no, label) for line_no, items in labels.items() for label in items}
    tp_set = predicted & truth
    fp_set = predicted - truth
    fn_set = truth - predicted
    by_type: dict[str, dict[str, float]] = {}
    all_types = sorted({item[1] for item in predicted | truth})
    for label in all_types:
        type_pred = {item for item in predicted if item[1] == label}
        type_truth = {item for item in truth if item[1] == label}
        type_tp = len(type_pred & type_truth)
        type_fp = len(type_pred - type_truth)
        type_fn = len(type_truth - type_pred)
        by_type[label] = _metric_dict(type_tp, type_fp, type_fn)
    overall = _metric_dict(len(tp_set), len(fp_set), len(fn_set))
    return EvaluationMetrics(
        tp=len(tp_set),
        fp=len(fp_set),
        fn=len(fn_set),
        precision=overall["precision"],
        recall=overall["recall"],
        f1=overall["f1"],
        by_type=by_type,
    )


def _metric_dict(tp: int, fp: int, fn: int) -> dict[str, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": float(tp),
        "fp": float(fp),
        "fn": float(fn),
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }
