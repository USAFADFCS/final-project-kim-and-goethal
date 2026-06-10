"""Evaluation harness for ``ctf_solver``.

Two thin benchmark adapters over one shared run-and-grade core, plus a
seeded paired A/B harness and a statistics layer. The point is to turn
"the agent feels better" into a signed, paired number.

Layout (see memory/comparative_eval_harnesses.md for the rationale):

    ctf_solver/eval/
    ├── _core.py          # RunResult + run_against_target() — wraps the agent
    ├── nyu_adapter.py    # NYU CTF Bench (nyuctf Python API) → RunResult
    ├── cybench_adapter.py# Cybench (metadata.json) → RunResult + TaskRunCompletion
    └── ab_harness.py     # seeded paired A/B runner → eval_results.jsonl

The statistics live in ``scripts/eval_stats.py`` (McNemar on paired
solved/not, Wilcoxon on paired continuous metrics).

Adapter dependencies (``nyuctf``, Docker) are imported lazily, so importing
this package — and unit-testing the grading/stats logic — never requires
them.
"""

from ctf_solver.eval._core import (
    RunResult,
    run_against_target,
    run_against_target_sync,
)

__all__ = [
    "RunResult",
    "run_against_target",
    "run_against_target_sync",
]
