"""Paired statistics over an ``eval_results.jsonl`` produced by the A/B harness.

Two tests, matched to the two metric types the harness records:

* **McNemar** on the paired *binary* ``solved`` outcome — the right test for
  "did configuration B solve more challenges than A" on matched pairs. Only
  the discordant pairs (b = A-solved-only, c = B-solved-only) carry signal.
  Exact (binomial) for small b+c, chi-square with continuity correction
  otherwise.
* **Wilcoxon signed-rank** on a paired *continuous* metric (steps, cost, or
  duration) — a non-parametric paired test that doesn't assume normality.

Pairing is by ``(challenge, run_idx)``: the i-th run of a challenge under the
baseline label is matched to the i-th run under the treatment label.

The functions here are pure and importable; ``scripts/eval_stats.py`` is the
thin CLI over them.
"""

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Continuous metrics that can be Wilcoxon-tested.
CONTINUOUS_METRICS = ("steps", "est_cost_usd_v2", "est_cost_usd", "duration_seconds")


@dataclass
class Pair:
    """One matched (baseline, treatment) observation on a challenge/run."""

    challenge: str
    run_idx: int
    baseline_solved: bool
    treatment_solved: bool
    baseline_metric: Optional[float] = None
    treatment_metric: Optional[float] = None


@dataclass
class ABReport:
    baseline_label: str
    treatment_label: str
    metric: str
    n_pairs: int
    baseline_solves: int
    treatment_solves: int
    # McNemar discordant cells.
    b_baseline_only: int
    c_treatment_only: int
    mcnemar_statistic: float
    mcnemar_p: float
    mcnemar_method: str
    wilcoxon_statistic: float
    wilcoxon_p: float
    wilcoxon_n: int
    median_metric_delta: Optional[float] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        from dataclasses import asdict

        return asdict(self)


def load_records(path: Any) -> List[Dict[str, Any]]:
    """Read an ``eval_results.jsonl`` into a list of dicts (skips blank lines)."""
    records: List[Dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def pair_records(
    records: List[Dict[str, Any]],
    baseline_label: str,
    treatment_label: str,
    metric: str = "steps",
) -> List[Pair]:
    """Match baseline/treatment records by ``(challenge, run_idx)``.

    Only keys present for *both* labels become pairs. When a label has
    multiple records for the same key (shouldn't happen, but be safe), the
    last one wins.
    """
    by_key: Dict[Tuple[str, int], Dict[str, Dict[str, Any]]] = {}
    for rec in records:
        label = rec.get("config_label")
        if label not in (baseline_label, treatment_label):
            continue
        key = (str(rec.get("challenge")), int(rec.get("run_idx", 0) or 0))
        by_key.setdefault(key, {})[label] = rec

    pairs: List[Pair] = []
    for (challenge, run_idx), sides in sorted(
        by_key.items(), key=lambda kv: (str(kv[0][0]), kv[0][1])
    ):
        if baseline_label not in sides or treatment_label not in sides:
            continue
        b = sides[baseline_label]
        t = sides[treatment_label]
        pairs.append(
            Pair(
                challenge=str(challenge),
                run_idx=run_idx,
                baseline_solved=bool(b.get("solved")),
                treatment_solved=bool(t.get("solved")),
                baseline_metric=_num(b.get(metric)),
                treatment_metric=_num(t.get(metric)),
            )
        )
    return pairs


def _count_duplicate_keys(
    records: List[Dict[str, Any]], baseline_label: str, treatment_label: str
) -> int:
    """Count records that collide on (challenge, run_idx, config_label).

    Only the two analyzed arms are considered. Returns the number of records
    beyond the first for each colliding key (i.e. how many would be silently
    dropped by ``pair_records``' last-wins behavior).
    """
    seen: Dict[Tuple[str, int, str], int] = {}
    for rec in records:
        label = rec.get("config_label")
        if label not in (baseline_label, treatment_label):
            continue
        key = (str(rec.get("challenge")), int(rec.get("run_idx", 0) or 0), str(label))
        seen[key] = seen.get(key, 0) + 1
    return sum(count - 1 for count in seen.values() if count > 1)


def _num(value: Any) -> Optional[float]:
    """Coerce to float, mapping None and non-finite (NaN/Inf) to None.

    Non-finite values must become None so the downstream ``is not None``
    filters drop them — otherwise a single NaN (e.g. an errored run's cost)
    propagates through the diff and silently poisons the Wilcoxon p-value.
    """
    try:
        if value is None:
            return None
        v = float(value)
        return v if math.isfinite(v) else None
    except (TypeError, ValueError):
        return None


def mcnemar(
    b: int, c: int, *, exact: Optional[bool] = None
) -> Tuple[float, float, str]:
    """McNemar's test on discordant counts.

    ``b`` = baseline-solved & treatment-not; ``c`` = treatment-solved &
    baseline-not. Returns ``(statistic, p_value, method)``. ``exact=None``
    auto-selects: exact binomial when ``b+c < 25``, else chi-square with
    continuity correction. With no discordant pairs, p=1.0.
    """
    n = b + c
    if n == 0:
        return 0.0, 1.0, "no-discordant-pairs"
    use_exact = (n < 25) if exact is None else exact
    if use_exact:
        from scipy.stats import binomtest  # type: ignore[import-untyped]

        p = binomtest(min(b, c), n=n, p=0.5, alternative="two-sided").pvalue
        # Statistic reported for the exact path is the smaller discordant cell.
        return float(min(b, c)), float(p), "exact-binomial"
    # Chi-square with Edwards' continuity correction.
    stat = (abs(b - c) - 1.0) ** 2 / n
    from scipy.stats import chi2  # type: ignore[import-untyped]

    p = float(chi2.sf(stat, df=1))
    return float(stat), p, "chi2-continuity"


def wilcoxon_paired(
    baseline: List[Optional[float]], treatment: List[Optional[float]]
) -> Tuple[float, float, int]:
    """Wilcoxon signed-rank on paired continuous values.

    Differences are ``treatment - baseline`` (so the sign matches
    ``median_metric_delta`` and the report's "median Δ (treat-base)"). Pairs
    with a missing value are dropped. Returns ``(statistic, p_value, n_used)``
    where ``n_used`` is the EFFECTIVE sample size — the count of non-zero
    (untied) differences, since scipy's default ``zero_method="wilcox"`` drops
    tied pairs before ranking. Degenerate inputs (no usable pairs, or all
    differences zero) return ``(nan, 1.0, n_used)`` rather than raising.
    """
    diffs = [
        tt - bt
        for bt, tt in zip(baseline, treatment)
        if bt is not None and tt is not None
    ]
    # scipy drops zero-diff (tied) pairs before ranking, so the effective n the
    # test actually used is the count of non-zero diffs — report that, not the
    # raw pair count, or "n used" overstates the power of the result.
    n_eff = sum(1 for d in diffs if d != 0)
    if n_eff == 0:
        return float("nan"), 1.0, n_eff
    from scipy.stats import wilcoxon  # type: ignore[import-untyped]

    res = wilcoxon(diffs)
    return float(res.statistic), float(res.pvalue), n_eff


def analyze(
    records: List[Dict[str, Any]],
    baseline_label: str,
    treatment_label: str,
    metric: str = "steps",
) -> ABReport:
    """Full paired analysis of two config arms over the records."""
    notes: List[str] = []
    if metric not in CONTINUOUS_METRICS:
        notes.append(
            f"metric {metric!r} not in {CONTINUOUS_METRICS}; Wilcoxon may be "
            "meaningless"
        )
    # Surface silently-dropped duplicates: pair_records keeps only the last
    # record per (challenge, run_idx, label). Appending a sweep to an existing
    # eval_results.jsonl (run_ab_sweep's default) collides on these keys, so
    # earlier runs would vanish from the analysis without warning.
    dup = _count_duplicate_keys(records, baseline_label, treatment_label)
    if dup:
        notes.append(
            f"{dup} duplicate (challenge, run_idx, label) record(s) found — "
            "only the last per key is analyzed. Re-runs into one file need a "
            "distinct run_idx range or a separate file."
        )
    pairs = pair_records(records, baseline_label, treatment_label, metric)
    n_pairs = len(pairs)

    baseline_solves = sum(p.baseline_solved for p in pairs)
    treatment_solves = sum(p.treatment_solved for p in pairs)
    b = sum(1 for p in pairs if p.baseline_solved and not p.treatment_solved)
    c = sum(1 for p in pairs if p.treatment_solved and not p.baseline_solved)
    mc_stat, mc_p, mc_method = mcnemar(b, c)

    base_metric = [p.baseline_metric for p in pairs]
    treat_metric = [p.treatment_metric for p in pairs]
    w_stat, w_p, w_n = wilcoxon_paired(base_metric, treat_metric)

    deltas = [
        (p.treatment_metric - p.baseline_metric)
        for p in pairs
        if p.baseline_metric is not None and p.treatment_metric is not None
    ]
    median_delta = _median(deltas) if deltas else None

    if n_pairs == 0:
        notes.append(
            f"no matched pairs for ({baseline_label!r}, {treatment_label!r}) — "
            "check config_label values and that both arms ran the same "
            "(challenge, run_idx) keys"
        )

    return ABReport(
        baseline_label=baseline_label,
        treatment_label=treatment_label,
        metric=metric,
        n_pairs=n_pairs,
        baseline_solves=baseline_solves,
        treatment_solves=treatment_solves,
        b_baseline_only=b,
        c_treatment_only=c,
        mcnemar_statistic=mc_stat,
        mcnemar_p=mc_p,
        mcnemar_method=mc_method,
        wilcoxon_statistic=w_stat,
        wilcoxon_p=w_p,
        wilcoxon_n=w_n,
        median_metric_delta=median_delta,
        notes=notes,
    )


def _median(values: List[float]) -> float:
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2 == 1:
        return float(s[mid])
    return (s[mid - 1] + s[mid]) / 2.0


def format_report(report: ABReport) -> str:
    """Human-readable summary for the CLI."""
    lines = [
        "=" * 64,
        f"A/B paired analysis: {report.baseline_label!r} (baseline) vs "
        f"{report.treatment_label!r} (treatment)",
        "=" * 64,
        f"matched pairs:            {report.n_pairs}",
        f"baseline solves:          {report.baseline_solves}/{report.n_pairs}",
        f"treatment solves:         {report.treatment_solves}/{report.n_pairs}",
        "",
        "McNemar (paired solved/not):",
        f"  discordant b (base-only): {report.b_baseline_only}",
        f"  discordant c (treat-only):{report.c_treatment_only}",
        f"  method:                   {report.mcnemar_method}",
        f"  statistic:                {report.mcnemar_statistic:.4f}",
        f"  p-value:                  {report.mcnemar_p:.4f}",
        "",
        f"Wilcoxon signed-rank ({report.metric}):",
        f"  n used:                   {report.wilcoxon_n}",
        f"  statistic:                {_fmt(report.wilcoxon_statistic)}",
        f"  p-value:                  {report.wilcoxon_p:.4f}",
        f"  median Δ (treat-base):    {_fmt(report.median_metric_delta)}",
    ]
    if report.notes:
        lines.append("")
        lines.append("notes:")
        lines.extend(f"  - {note}" for note in report.notes)
    lines.append("=" * 64)
    return "\n".join(lines)


def _fmt(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float) and math.isnan(value):
        return "nan"
    return f"{value:.4f}"
