"""Seeded paired A/B harness.

Runs every (challenge × config-cell) combination ``n_runs_per_cell`` times and
appends one flat record per run to ``eval_results.jsonl``. The records are the
input to ``scripts/eval_stats.py``, which pairs runs by ``(challenge,
run_idx)`` across two ``config_label``s and computes McNemar (paired
solved/not) + Wilcoxon (paired continuous metric).

**Pairing model.** Both cells run the same challenge the same number of times;
the i-th baseline run is matched with the i-th treatment run on each challenge.
A single ``run_seed`` is derived per ``run_idx`` and shared across cells, so
the pairing is reproducible. NOTE (carried from the plan): local providers
(Ollama/Nemotron) do not honour seeds deterministically, so this is
*paired-by-config*, not *paired-by-output* — the seed fixes the experimental
structure, not the model's sampling.

The actual run function is injectable (``run_fn``) so the orchestration is
unit-testable without standing up an agent.
"""

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ctf_solver.eval._core import RunResult, run_against_target_sync

# Frozen MetaCTF splits (slugs). report-12 is the full headline set; fast-8 is
# the quick-iteration subset that drops the slow / persistently-failing
# challenges (livestream, microdosing, super_quick_logic_invitational, and the
# slower open_application) so a dev loop is ~minutes not ~tens of minutes.
REPORT_12 = (
    "treasure_map",
    "direct_login",
    "door_to_door",
    "open_application",
    "livestream",
    "super_quick_logic_invitational",
    "snowfall_wishes",
    "cracking_the_javashop",
    "admin_portal",
    "cookie_crackdown",
    "great_paywall",
    "microdosing",
)
FAST_8 = (
    "treasure_map",
    "direct_login",
    "door_to_door",
    "snowfall_wishes",
    "cracking_the_javashop",
    "admin_portal",
    "cookie_crackdown",
    "great_paywall",
)


@dataclass
class Cell:
    """One arm of the A/B: a label + how to configure the agent for it."""

    label: str
    config: Optional[Any] = None  # SolverConfig treatment (prompt/model/etc.)
    model: Optional[str] = None
    provider: Any = None
    max_steps: Optional[int] = None
    inject_rag: bool = False


@dataclass
class EvalChallenge:
    """One target the sweep runs against, across all cells."""

    name: str
    kind: str = "url"  # "url" | "nyu" | "cybench"
    # url kind
    url: Optional[str] = None
    description: Optional[str] = None
    hints: Optional[str] = None
    expected_flag: Optional[str] = None
    files: Optional[Dict[str, str]] = None
    # nyu kind
    canonical_name: Optional[str] = None
    split: str = "test"
    # cybench kind
    task_dir: Optional[str] = None
    start_container: bool = True


def _slugify(name: str) -> str:
    """Mirror run_batch.sh: lowercase, non-alnum → '_', collapse, trim."""
    out = []
    for ch in name.lower():
        out.append(ch if ch.isalnum() else "_")
    slug = "".join(out)
    while "__" in slug:
        slug = slug.replace("__", "_")
    return slug.strip("_")


def derive_seed(base_seed: int, run_idx: int) -> int:
    """Per-run seed shared across cells so a (challenge, run_idx) pair lines up.

    Stable, no RNG — just a deterministic mix of the base seed and the run
    index. Recorded on every record for provenance.
    """
    return (base_seed * 100_003) + run_idx


def _apply_seed(config: Any, run_seed: int) -> Any:
    """Set a ``seed`` on the config if it has that field; else return as-is.

    SolverConfig may or may not expose a seed; we never invent one. This keeps
    the harness forward-compatible without coupling to a specific field.
    """
    if config is not None and hasattr(config, "seed"):
        from dataclasses import replace

        try:
            return replace(config, seed=run_seed)
        except (TypeError, ValueError):
            return config
    return config


def _run_cell(
    challenge: EvalChallenge, cell: Cell, run_seed: int, log_fn: Callable
) -> RunResult:
    """Default dispatcher: run one challenge under one cell's config."""
    cfg = _apply_seed(cell.config, run_seed)
    if challenge.kind == "url":
        return run_against_target_sync(
            url=challenge.url,
            description=challenge.description,
            hints=challenge.hints,
            expected_flag=challenge.expected_flag,
            files=challenge.files,
            model=cell.model,
            provider=cell.provider,
            max_steps=cell.max_steps,
            challenge_name=challenge.name,
            config=cfg,
            inject_rag=cell.inject_rag,
            log_callback=log_fn,
        )
    if challenge.kind == "nyu":
        from ctf_solver.eval.nyu_adapter import run_nyu_challenge

        if not challenge.canonical_name:
            raise ValueError(f"nyu challenge {challenge.name!r} has no canonical_name")
        return run_nyu_challenge(
            challenge.canonical_name,
            split=challenge.split,
            model=cell.model,
            provider=cell.provider,
            max_steps=cell.max_steps,
            inject_rag=cell.inject_rag,
            start_container=challenge.start_container,
            config=cfg,
            log_callback=log_fn,
        )
    if challenge.kind == "cybench":
        from ctf_solver.eval.cybench_adapter import run_cybench_task

        return run_cybench_task(
            challenge.task_dir,
            model=cell.model,
            provider=cell.provider,
            max_steps=cell.max_steps,
            inject_rag=cell.inject_rag,
            start_container=challenge.start_container,
            config=cfg,
            log_callback=log_fn,
        )
    raise ValueError(f"unknown challenge kind: {challenge.kind!r}")


def run_ab_sweep(
    challenges: List[EvalChallenge],
    cells: List[Cell],
    *,
    n_runs_per_cell: int = 1,
    seed: int = 0,
    out_path: Any = "out/eval/eval_results.jsonl",
    append: bool = True,
    run_fn: Optional[Callable[[EvalChallenge, Cell, int, Callable], RunResult]] = None,
    log_callback: Optional[Callable] = None,
) -> List[Dict[str, Any]]:
    """Run the full sweep and stream JSONL records to ``out_path``.

    Order is ``run_idx → challenge → cell`` so a paired (baseline, treatment)
    observation on one challenge lands close together. Each record carries the
    headline metrics plus ``config_label`` / ``run_idx`` / ``seed`` / ``kind``.
    A failing run is recorded with ``solved=False`` and its ``error`` (the core
    already swallows agent exceptions); the sweep never aborts midway.

    Returns the in-memory list of records (also written to disk).
    """
    log_fn = log_callback or (lambda *_a, **_k: None)
    runner = run_fn or _run_cell
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    records: List[Dict[str, Any]] = []

    mode = "a" if append else "w"
    with out.open(mode, encoding="utf-8") as fh:
        for run_idx in range(n_runs_per_cell):
            run_seed = derive_seed(seed, run_idx)
            for challenge in challenges:
                for cell in cells:
                    try:
                        result = runner(challenge, cell, run_seed, log_fn)
                    except Exception as exc:  # noqa: BLE001 — one bad cell ≠ abort
                        log_fn(
                            f"[ab] {challenge.name}/{cell.label} run {run_idx} "
                            f"raised {type(exc).__name__}: {exc}"
                        )
                        result = RunResult(
                            challenge=challenge.name,
                            solved=False,
                            error=f"{type(exc).__name__}: {exc}",
                        )
                    rec = result.to_record(
                        challenge=challenge.name,
                        kind=challenge.kind,
                        config_label=cell.label,
                        run_idx=run_idx,
                        seed=run_seed,
                    )
                    fh.write(json.dumps(rec) + "\n")
                    fh.flush()
                    records.append(rec)
                    log_fn(
                        f"[ab] {challenge.name}/{cell.label} run {run_idx}: "
                        f"solved={rec['solved']} steps={rec['steps']} "
                        f"cost_v2={rec['est_cost_usd_v2']}"
                    )
    return records


def load_metactf_challenges(
    tsv_path: Any = "out/batch_window_test/challenges.tsv",
    flags_tsv_path: Any = "out/batch_window_test/summary_obs7_v2.tsv",
    *,
    only: Optional[List[str]] = None,
) -> List[EvalChallenge]:
    """Build ``EvalChallenge`` specs from the MetaCTF batch TSVs.

    Joins ``challenges.tsv`` (name/url/description/hints) with a hand-verified
    flags TSV (slug → flag) so runs grade against the real flag. ``only`` is an
    optional slug allow-list (e.g. ``FAST_8``). Only flags carrying a known CTF
    prefix (``MetaCTF{``/``picoCTF{``) are attached — rows with no flag, ``-``,
    or a non-prefixed false positive (e.g. a JS literal) get
    ``expected_flag=None`` and fall back to strict-confirmed grading.
    """
    flags: Dict[str, str] = {}
    fpath = Path(flags_tsv_path)
    if fpath.is_file():
        with fpath.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh, delimiter="\t"):
                slug = (row.get("slug") or "").strip()
                flag = (row.get("flag") or "").strip()
                if (
                    slug
                    and flag
                    and flag != "-"
                    and flag.startswith(("MetaCTF{", "picoCTF{"))
                ):
                    flags[slug] = flag

    only_set = set(only) if only else None
    challenges: List[EvalChallenge] = []
    with Path(tsv_path).open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            name = (row.get("name") or "").strip()
            if not name:
                continue
            slug = _slugify(name)
            if only_set is not None and slug not in only_set:
                continue
            challenges.append(
                EvalChallenge(
                    name=slug,
                    kind="url",
                    url=(row.get("url") or "").strip() or None,
                    description=(row.get("description") or "").strip() or None,
                    hints=(row.get("hints") or "").strip() or None,
                    expected_flag=flags.get(slug),
                )
            )
    return challenges
