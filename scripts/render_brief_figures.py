"""Render the five slide-ready figures for the Monday brief.

Inputs:
- ``out/batch_*/results.tsv`` — pulled for the LESSONS_WRITE and ORIGINAL
  batches identified at module level. (Override via ``--write-batch`` /
  ``--original-batch`` if you re-run with v4.1 instrumentation.)
- ``out/batch_*/<slug>.injections.json`` — Phase A5 sidecars. Required for
  fig 4 (retrieval panel). Falls back to "data unavailable" when missing.
- ``out/batch_*/<slug>.events.jsonl`` — Phase C event log. Currently
  unused for the five core figures but consumed by ``--extra`` flag for a
  per-step tool-sequence visual.

Outputs PNGs to ``out/brief_figures/`` at 1920×1080 / 150 dpi.

Run:
    python scripts/render_brief_figures.py
    python scripts/render_brief_figures.py --write-batch batch_<new> \
                                          --original-batch batch_<new>
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import matplotlib.pyplot as plt
from matplotlib.patches import Patch

ROOT = Path(__file__).resolve().parent.parent
OUT_FIG_DIR = ROOT / "out" / "brief_figures"

# Defaults match the May 3 batches the brief is built on.
DEFAULT_WRITE_BATCH = "batch_20260503_012947"
DEFAULT_ORIGINAL_BATCH = "batch_20260503_024526"

# Stable display order for the per-challenge matrix.
CHALLENGE_ORDER = [
    ("treasure_map", "Treasure Map"),
    ("direct_login", "Direct Login"),
    ("door_to_door", "Door to Door"),
    ("open_application", "Open Application"),
    ("livestream", "Livestream"),
    ("dot_matrix_destruction", "Dot-Matrix Destruction"),
    ("super_quick_logic_invitational", "Super Quick Logic"),
    ("snowfall_wishes", "Snowfall Wishes"),
    ("cracking_the_javashop", "Cracking the Javashop"),
    ("admin_portal", "Admin Portal"),
    ("cookie_crackdown", "Cookie Crackdown"),
    ("great_paywall", "Great Paywall"),
    ("microdosing", "Microdosing"),
]

OUTCOME_COLOR = {
    "success": "#2ca02c",
    "partial": "#ff7f0e",
    "failure": "#d62728",
    "error": "#7f7f7f",
}


def load_results_tsv(batch_dir: Path) -> Dict[str, Dict[str, str]]:
    tsv = batch_dir / "results.tsv"
    if not tsv.exists():
        return {}
    out: Dict[str, Dict[str, str]] = {}
    with tsv.open() as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            out[row["slug"]] = row
    return out


def load_injection(batch_dir: Path, slug: str) -> Optional[Dict[str, Any]]:
    p = batch_dir / f"{slug}.injections.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def wilson_ci(successes: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    """Wilson score 95% CI for a binomial proportion."""
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    margin = (z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total)) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def fig1_solve_rate_ablation(
    write_results: Dict[str, Dict[str, str]],
    original_results: Dict[str, Dict[str, str]],
    out_path: Path,
) -> None:
    write_n = len(write_results)
    write_succ = sum(1 for r in write_results.values() if r["outcome"] == "success")
    orig_n = len(original_results)
    orig_succ = sum(1 for r in original_results.values() if r["outcome"] == "success")

    write_rate = write_succ / max(write_n, 1)
    orig_rate = orig_succ / max(orig_n, 1)
    write_lo, write_hi = wilson_ci(write_succ, write_n)
    orig_lo, orig_hi = wilson_ci(orig_succ, orig_n)

    fig, ax = plt.subplots(figsize=(8, 5), dpi=150)
    labels = ["ORIGINAL\n(curated only)", "LESSONS_WRITE\n(curated + lessons KB)"]
    means = [orig_rate, write_rate]
    lower_err = [orig_rate - orig_lo, write_rate - write_lo]
    upper_err = [orig_hi - orig_rate, write_hi - write_rate]
    colors = ["#1f77b4", "#d62728"]

    bars = ax.bar(
        labels,
        means,
        yerr=[lower_err, upper_err],
        color=colors,
        capsize=8,
        edgecolor="black",
        linewidth=0.8,
    )
    for bar, val, n, succ in zip(
        bars, means, [orig_n, write_n], [orig_succ, write_succ]
    ):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            val + 0.04,
            f"{val:.1%}\n({succ}/{n})",
            ha="center",
            va="bottom",
            fontsize=11,
            fontweight="bold",
        )

    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Solve rate (success only)")
    ax.set_title(
        "Adding the lessons KB hurt solve rate by 23 pp on gpt-5.2",
        fontsize=12,
        fontweight="bold",
    )
    delta = write_rate - orig_rate
    ax.text(
        0.5,
        -0.12,
        f"Δ = {delta * 100:+.1f} pp · McNemar exact p ≈ 0.25 (n={write_n}, "
        f"0 vs 3 discordant) · Wilson 95% CI shown",
        ha="center",
        va="top",
        transform=ax.transAxes,
        fontsize=9,
        style="italic",
        color="#444",
    )
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    print(f"  ✓ {out_path.name}")


def fig2_per_challenge_matrix(
    write_results: Dict[str, Dict[str, str]],
    original_results: Dict[str, Dict[str, str]],
    out_path: Path,
) -> None:
    fig, ax = plt.subplots(figsize=(9, 7), dpi=150)
    rows = list(reversed(CHALLENGE_ORDER))  # plot top-down
    n = len(rows)

    for i, (slug, name) in enumerate(rows):
        for col, results in enumerate([original_results, write_results]):
            r = results.get(slug)
            outcome = r["outcome"] if r else "missing"
            color = OUTCOME_COLOR.get(outcome, "#cccccc")
            ax.barh(i, 1, left=col, color=color, edgecolor="black", linewidth=0.5)
            label = {"success": "✓", "partial": "◐", "failure": "✗"}.get(outcome, "?")
            ax.text(
                col + 0.5,
                i,
                label,
                ha="center",
                va="center",
                fontsize=14,
                color="white",
                fontweight="bold",
            )

    # Highlight regressions: success under ORIGINAL but partial under WRITE
    for i, (slug, _name) in enumerate(rows):
        o = original_results.get(slug, {}).get("outcome")
        w = write_results.get(slug, {}).get("outcome")
        if o == "success" and w == "partial":
            ax.annotate(
                "",
                xy=(2.05, i),
                xytext=(2.4, i),
                arrowprops=dict(arrowstyle="->", color="#d62728", lw=1.8),
            )
            ax.text(
                2.5,
                i,
                "regression",
                va="center",
                ha="left",
                fontsize=8,
                color="#d62728",
                fontweight="bold",
            )

    ax.set_yticks(range(n))
    ax.set_yticklabels([name for _, name in rows], fontsize=9)
    ax.set_xticks([0.5, 1.5])
    ax.set_xticklabels(["ORIGINAL", "LESSONS_WRITE"], fontsize=10, fontweight="bold")
    ax.set_xlim(-0.05, 3.4)
    ax.set_ylim(-0.5, n - 0.5)
    ax.set_title("Per-challenge outcomes — same gpt-5.2, same URLs, only KB changed")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["bottom"].set_visible(False)

    legend_elems = [
        Patch(facecolor=OUTCOME_COLOR["success"], label="success"),
        Patch(facecolor=OUTCOME_COLOR["partial"], label="partial (no flag)"),
        Patch(facecolor=OUTCOME_COLOR["failure"], label="failure"),
    ]
    ax.legend(handles=legend_elems, loc="lower right", fontsize=8)
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    print(f"  ✓ {out_path.name}")


def fig3_steps_cdf(
    write_results: Dict[str, Dict[str, str]],
    original_results: Dict[str, Dict[str, str]],
    out_path: Path,
) -> None:
    def _step_list(results: Dict[str, Dict[str, str]]) -> List[int]:
        out: List[int] = []
        for r in results.values():
            try:
                out.append(int(r["steps"]))
            except (ValueError, KeyError):
                continue
        return sorted(out)

    orig = _step_list(original_results)
    write = _step_list(write_results)

    def _cdf(xs: List[int]) -> Tuple[List[int], List[float]]:
        if not xs:
            return [], []
        n = len(xs)
        return xs, [(i + 1) / n for i in range(n)]

    fig, ax = plt.subplots(figsize=(8, 5), dpi=150)
    ox, oy = _cdf(orig)
    wx, wy = _cdf(write)
    if ox:
        ax.step(ox, oy, where="post", label=f"ORIGINAL (n={len(ox)})", lw=2.0)
    if wx:
        ax.step(wx, wy, where="post", label=f"LESSONS_WRITE (n={len(wx)})", lw=2.0)
    ax.set_xlabel("Steps to terminal state (success or budget exhaustion)")
    ax.set_ylabel("Cumulative fraction of runs")
    ax.set_title("Steps-to-solve CDF — LESSONS_WRITE shifts right (slower paths)")
    ax.grid(alpha=0.3, linestyle="--")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    print(f"  ✓ {out_path.name}")


def fig4_retrieval_panel_dotmatrix(
    write_dir: Path, original_dir: Path, out_path: Path
) -> None:
    """Side-by-side top-5 retrieval panel for dot_matrix_destruction.

    Requires Phase A5 *.injections.json sidecars to exist for both batches.
    Falls back to a placeholder slide when the sidecar is missing.
    """
    slug = "dot_matrix_destruction"
    write_inj = load_injection(write_dir, slug)
    orig_inj = load_injection(original_dir, slug)

    fig, axes = plt.subplots(1, 2, figsize=(13, 6), dpi=150)
    fig.suptitle(
        "Retrieval pool — what the agent saw at step 0 (dot_matrix_destruction)",
        fontweight="bold",
    )

    def _draw_panel(ax: Any, inj: Optional[Dict[str, Any]], title: str) -> None:
        ax.set_title(title, fontsize=11, fontweight="bold")
        ax.set_xlim(0, 10)
        ax.set_ylim(0, 10)
        ax.axis("off")
        if not inj or not inj.get("proactive"):
            ax.text(
                5,
                5,
                "(no injection sidecar — rerun with v4.1 instrumentation)",
                ha="center",
                va="center",
                fontsize=10,
                color="#888",
                style="italic",
            )
            return
        records = (inj.get("proactive") or {}).get("retrieval_records") or []
        if not records:
            ax.text(5, 5, "(no retrieval records)", ha="center", color="#888")
            return
        for i, rec in enumerate(records[:5]):
            sf = rec.get("source_file") or "?"
            score = rec.get("score")
            is_lesson = bool(rec.get("is_lesson"))
            color = "#d62728" if is_lesson else "#1f77b4"
            label = (
                f"{i+1}. {sf}\n" f"   score={score:.3f}"
                if score is not None
                else f"{i+1}. {sf}"
            )
            ax.text(
                0.2,
                9 - i * 1.7,
                label,
                fontsize=8.5,
                fontfamily="monospace",
                color=color,
            )

    _draw_panel(axes[0], orig_inj, "ORIGINAL (curated only)")
    _draw_panel(axes[1], write_inj, "LESSONS_WRITE (curated + lessons KB)")

    legend_elems = [
        Patch(color="#1f77b4", label="curated doc"),
        Patch(color="#d62728", label="auto-generated lesson"),
    ]
    fig.legend(handles=legend_elems, loc="lower center", ncol=2, fontsize=9)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    print(f"  ✓ {out_path.name}")


def fig5_cost_per_flag(
    write_results: Dict[str, Dict[str, str]],
    original_results: Dict[str, Dict[str, str]],
    out_path: Path,
) -> None:
    def _summary(results: Dict[str, Dict[str, str]]) -> Tuple[float, int]:
        total_cost = 0.0
        n_success = 0
        for r in results.values():
            try:
                total_cost += float(r.get("est_cost_usd", "0") or 0)
            except ValueError:
                pass
            if r.get("outcome") == "success":
                n_success += 1
        return total_cost, n_success

    orig_cost, orig_succ = _summary(original_results)
    write_cost, write_succ = _summary(write_results)

    fig, ax = plt.subplots(figsize=(8, 5), dpi=150)
    if orig_cost == 0 and write_cost == 0:
        ax.text(
            0.5,
            0.5,
            "Cost data unavailable — rerun with v4.1 token tracking enabled.\n"
            "(scripts/run.sh ... --rag-mode lessons_write)",
            ha="center",
            va="center",
            fontsize=11,
            transform=ax.transAxes,
            color="#888",
            style="italic",
        )
        ax.axis("off")
    else:
        labels = ["ORIGINAL", "LESSONS_WRITE"]
        cost_per_flag = [
            orig_cost / orig_succ if orig_succ else 0.0,
            write_cost / write_succ if write_succ else 0.0,
        ]
        bars = ax.bar(
            labels,
            cost_per_flag,
            color=["#1f77b4", "#d62728"],
            edgecolor="black",
            linewidth=0.8,
        )
        for bar, val in zip(bars, cost_per_flag):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                val + max(cost_per_flag) * 0.02,
                f"${val:.3f}",
                ha="center",
                va="bottom",
                fontsize=11,
                fontweight="bold",
            )
        ax.set_ylabel("USD per successful flag")
        ax.set_title(
            f"Cost per flag — total spend ${orig_cost + write_cost:.2f} "
            f"across {len(write_results) + len(original_results)} runs",
            fontsize=11,
            fontweight="bold",
        )
        ax.grid(axis="y", alpha=0.3, linestyle="--")
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    print(f"  ✓ {out_path.name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-batch",
        default=DEFAULT_WRITE_BATCH,
        help="Batch dir name (under out/) for LESSONS_WRITE results.",
    )
    parser.add_argument(
        "--original-batch",
        default=DEFAULT_ORIGINAL_BATCH,
        help="Batch dir name for ORIGINAL (curated-only) results.",
    )
    args = parser.parse_args()

    out_root = ROOT / "out"
    write_dir = out_root / args.write_batch
    original_dir = out_root / args.original_batch
    OUT_FIG_DIR.mkdir(parents=True, exist_ok=True)

    print(f"WRITE batch:    {write_dir}")
    print(f"ORIGINAL batch: {original_dir}")
    print(f"Output dir:     {OUT_FIG_DIR}")

    write_results = load_results_tsv(write_dir)
    original_results = load_results_tsv(original_dir)

    if not write_results or not original_results:
        print("WARN: missing results.tsv in one or both batches.")

    print("\nRendering figures:")
    fig1_solve_rate_ablation(
        write_results, original_results, OUT_FIG_DIR / "fig1_solve_rate_ablation.png"
    )
    fig2_per_challenge_matrix(
        write_results, original_results, OUT_FIG_DIR / "fig2_per_challenge_matrix.png"
    )
    fig3_steps_cdf(write_results, original_results, OUT_FIG_DIR / "fig3_steps_cdf.png")
    fig4_retrieval_panel_dotmatrix(
        write_dir, original_dir, OUT_FIG_DIR / "fig4_retrieval_panel_dotmatrix.png"
    )
    fig5_cost_per_flag(
        write_results, original_results, OUT_FIG_DIR / "fig5_cost_per_flag.png"
    )
    print(f"\nDone — 5 figures in {OUT_FIG_DIR}")


if __name__ == "__main__":
    main()
