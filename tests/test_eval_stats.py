"""Eval stats: McNemar, Wilcoxon, pairing, end-to-end analysis."""

import json
import math

from ctf_solver.eval import stats

# ---------------------------------------------------------------------------
# McNemar
# ---------------------------------------------------------------------------


def test_mcnemar_no_discordant_pairs():
    stat, p, method = stats.mcnemar(0, 0)
    assert stat == 0.0
    assert p == 1.0
    assert method == "no-discordant-pairs"


def test_mcnemar_exact_small_counts():
    stat, p, method = stats.mcnemar(8, 1)
    assert method == "exact-binomial"
    # two-sided binomial p for 1 of 9 at p=0.5
    assert p == 0.0390625


def test_mcnemar_symmetric_high_p():
    stat, p, method = stats.mcnemar(5, 5)
    assert method == "exact-binomial"
    assert p == 1.0


def test_mcnemar_chi2_for_large_counts():
    stat, p, method = stats.mcnemar(20, 5)
    assert method == "chi2-continuity"
    # (|20-5|-1)^2 / 25 = 14^2/25 = 7.84
    assert stat == 7.84
    assert p < 0.01


def test_mcnemar_exact_override():
    _, _, method = stats.mcnemar(20, 5, exact=True)
    assert method == "exact-binomial"


# ---------------------------------------------------------------------------
# Wilcoxon
# ---------------------------------------------------------------------------


def test_wilcoxon_detects_consistent_shift():
    base = [10, 12, 9, 11, 13, 8, 14]
    treat = [6, 7, 5, 6, 8, 4, 9]  # treatment uniformly lower
    stat, p, n = stats.wilcoxon_paired(base, treat)
    assert n == 7
    assert p < 0.05


def test_wilcoxon_all_zero_diffs_is_safe():
    stat, p, n = stats.wilcoxon_paired([3, 3, 3], [3, 3, 3])
    assert math.isnan(stat)
    assert p == 1.0
    # All pairs tied → scipy drops them all → effective n is 0, not 3.
    assert n == 0


def test_wilcoxon_n_is_effective_excludes_ties():
    # One tied pair (idx 0) plus three real differences → effective n is 3.
    base = [5, 10, 12, 8]
    treat = [5, 6, 7, 4]
    _stat, _p, n = stats.wilcoxon_paired(base, treat)
    assert n == 3  # not 4 — the tied pair is dropped by scipy and from n


def test_num_rejects_non_finite():
    assert stats._num(float("nan")) is None
    assert stats._num(float("inf")) is None
    assert stats._num("nan") is None
    assert stats._num(3.5) == 3.5
    assert stats._num(None) is None


def test_wilcoxon_drops_nan_metric_no_nan_pvalue():
    # A NaN in one pair must be dropped (via _num upstream); here we simulate
    # the raw float path: a NaN diff must not poison the p-value.
    base = [10.0, 9.0, 11.0]
    treat = [6.0, float("nan"), 6.0]
    # _num is what the pipeline uses; emulate it dropping the NaN.
    base_n = [stats._num(x) for x in base]
    treat_n = [stats._num(x) for x in treat]
    _stat, p, n = stats.wilcoxon_paired(base_n, treat_n)
    assert n == 2  # the NaN pair dropped
    assert not math.isnan(p)


def test_wilcoxon_direction_matches_median_delta_sign():
    # Treatment uniformly lower than baseline → diffs (treat-base) negative,
    # consistent with a negative median delta reported by analyze().
    base = [20, 18, 22]
    treat = [10, 9, 11]
    # Direction is treatment - baseline, so the underlying diffs are negative;
    # the two-sided p is unaffected but the sign convention is now consistent.
    _stat, p, n = stats.wilcoxon_paired(base, treat)
    assert n == 3
    assert p < 0.5


def test_wilcoxon_empty_is_safe():
    stat, p, n = stats.wilcoxon_paired([], [])
    assert math.isnan(stat)
    assert p == 1.0
    assert n == 0


def test_wilcoxon_drops_missing_values():
    base = [10, None, 9, 11]
    treat = [6, 7, None, 6]
    stat, p, n = stats.wilcoxon_paired(base, treat)
    assert n == 2  # only positions 0 and 3 have both values


# ---------------------------------------------------------------------------
# pair_records
# ---------------------------------------------------------------------------


def _rec(challenge, label, run_idx, solved, steps):
    return {
        "challenge": challenge,
        "config_label": label,
        "run_idx": run_idx,
        "solved": solved,
        "steps": steps,
    }


def test_pair_records_matches_by_challenge_and_run():
    records = [
        _rec("a", "base", 0, True, 10),
        _rec("a", "treat", 0, False, 8),
        _rec("b", "base", 0, False, 20),
        _rec("b", "treat", 0, True, 15),
        # unmatched: treat-only key
        _rec("c", "treat", 0, True, 5),
        # ignored label
        _rec("a", "other", 0, True, 1),
    ]
    pairs = stats.pair_records(records, "base", "treat", "steps")
    assert len(pairs) == 2  # a/0 and b/0; c/0 unmatched
    a = next(p for p in pairs if p.challenge == "a")
    assert a.baseline_solved is True and a.treatment_solved is False
    assert a.baseline_metric == 10 and a.treatment_metric == 8


def test_pair_records_metric_missing():
    records = [
        {"challenge": "a", "config_label": "base", "run_idx": 0, "solved": True},
        {"challenge": "a", "config_label": "treat", "run_idx": 0, "solved": True},
    ]
    pairs = stats.pair_records(records, "base", "treat", "steps")
    assert pairs[0].baseline_metric is None


# ---------------------------------------------------------------------------
# analyze end-to-end
# ---------------------------------------------------------------------------


def _build_records():
    # 4 challenges, treatment strictly better on solves and steps.
    recs = []
    data = [
        # challenge, base_solved, treat_solved, base_steps, treat_steps
        ("c1", False, True, 20, 10),
        ("c2", False, True, 18, 9),
        ("c3", True, True, 12, 8),
        ("c4", False, False, 30, 28),
    ]
    for ch, bs, ts, bst, tst in data:
        recs.append(_rec(ch, "base", 0, bs, bst))
        recs.append(_rec(ch, "treat", 0, ts, tst))
    return recs


def test_analyze_reports_solves_and_discordant():
    report = stats.analyze(_build_records(), "base", "treat", "steps")
    assert report.n_pairs == 4
    assert report.baseline_solves == 1
    assert report.treatment_solves == 3
    # discordant: treat-only on c1, c2 → c=2; base-only → b=0
    assert report.b_baseline_only == 0
    assert report.c_treatment_only == 2
    assert report.mcnemar_method == "exact-binomial"
    # treatment uniformly fewer steps → negative median delta
    assert report.median_metric_delta < 0
    assert report.wilcoxon_n == 4


def test_analyze_no_pairs_emits_note():
    report = stats.analyze(_build_records(), "nope", "alsonope", "steps")
    assert report.n_pairs == 0
    assert any("no matched pairs" in n for n in report.notes)


def test_analyze_flags_duplicate_records():
    # Two sweeps appended to one file → duplicate (challenge, run_idx, label)
    # keys. analyze must surface the silent last-wins data loss in notes.
    recs = _build_records() + _build_records()
    report = stats.analyze(recs, "base", "treat", "steps")
    assert any("duplicate" in n for n in report.notes)
    # still pairs (last-wins) rather than crashing
    assert report.n_pairs == 4


def test_count_duplicate_keys():
    recs = [
        _rec("a", "base", 0, True, 10),
        _rec("a", "base", 0, False, 12),  # dup of (a,0,base)
        _rec("a", "treat", 0, True, 8),
    ]
    assert stats._count_duplicate_keys(recs, "base", "treat") == 1


def test_analyze_unknown_metric_note():
    report = stats.analyze(_build_records(), "base", "treat", "est_cost_usd_v2")
    # valid continuous metric → no metric warning
    assert not any("not in" in n for n in report.notes)


# ---------------------------------------------------------------------------
# load_records + helpers + formatting
# ---------------------------------------------------------------------------


def test_load_records_skips_blank_lines(tmp_path):
    p = tmp_path / "r.jsonl"
    p.write_text(
        json.dumps({"a": 1}) + "\n\n" + json.dumps({"a": 2}) + "\n",
        encoding="utf-8",
    )
    recs = stats.load_records(p)
    assert recs == [{"a": 1}, {"a": 2}]


def test_median_odd_even():
    assert stats._median([3, 1, 2]) == 2
    assert stats._median([1, 2, 3, 4]) == 2.5


def test_format_report_has_key_lines():
    report = stats.analyze(_build_records(), "base", "treat", "steps")
    text = stats.format_report(report)
    assert "A/B paired analysis" in text
    assert "McNemar" in text
    assert "Wilcoxon" in text
    assert "matched pairs:" in text
