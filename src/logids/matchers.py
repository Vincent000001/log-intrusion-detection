from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter

from .models import BenchmarkResult


@dataclass(frozen=True)
class MatchResult:
    matched: bool
    comparisons: int


def brute_force_match(text: str, pattern: str) -> MatchResult:
    if pattern == "":
        return MatchResult(True, 0)
    n = len(text)
    m = len(pattern)
    comparisons = 0
    if m > n:
        return MatchResult(False, 0)
    for i in range(n - m + 1):
        matched = True
        for j in range(m):
            comparisons += 1
            if text[i + j] != pattern[j]:
                matched = False
                break
        if matched:
            return MatchResult(True, comparisons)
    return MatchResult(False, comparisons)


def build_prefix_table(pattern: str) -> list[int]:
    prefix = [0] * len(pattern)
    j = 0
    for i in range(1, len(pattern)):
        while j > 0 and pattern[i] != pattern[j]:
            j = prefix[j - 1]
        if pattern[i] == pattern[j]:
            j += 1
            prefix[i] = j
    return prefix


def kmp_match(text: str, pattern: str, prefix: list[int] | None = None) -> MatchResult:
    if pattern == "":
        return MatchResult(True, 0)
    if prefix is None:
        prefix = build_prefix_table(pattern)
    j = 0
    comparisons = 0
    for char in text:
        while j > 0 and char != pattern[j]:
            comparisons += 1
            j = prefix[j - 1]
        comparisons += 1
        if char == pattern[j]:
            j += 1
            if j == len(pattern):
                return MatchResult(True, comparisons)
    return MatchResult(False, comparisons)


def match_any(text: str, patterns: list[str], method: str = "kmp") -> tuple[str | None, int]:
    total_comparisons = 0
    for pattern in patterns:
        if method == "brute":
            result = brute_force_match(text, pattern)
        elif method == "kmp":
            result = kmp_match(text, pattern)
        else:
            raise ValueError(f"unknown match method: {method}")
        total_comparisons += result.comparisons
        if result.matched:
            return pattern, total_comparisons
    return None, total_comparisons


def benchmark_matchers(text: str, pattern: str, rounds: int = 100) -> list[BenchmarkResult]:
    results: list[BenchmarkResult] = []
    for name, func in (("brute", brute_force_match), ("kmp", kmp_match)):
        comparisons = 0
        matched = False
        start = perf_counter()
        prefix = build_prefix_table(pattern) if name == "kmp" else None
        for _ in range(rounds):
            if name == "kmp":
                result = func(text, pattern, prefix)  # type: ignore[arg-type]
            else:
                result = func(text, pattern)
            comparisons += result.comparisons
            matched = result.matched
        elapsed_ms = (perf_counter() - start) * 1000
        results.append(BenchmarkResult(name, matched, comparisons, elapsed_ms))
    return results
