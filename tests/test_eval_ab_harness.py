"""A/B harness: seeding, sweep orchestration, JSONL output, MetaCTF loader."""

import json

import pytest

from ctf_solver.eval import ab_harness as ab
from ctf_solver.eval._core import RunResult

# ---------------------------------------------------------------------------
# Seeding + slug helpers
# ---------------------------------------------------------------------------


def test_derive_seed_deterministic_and_run_varying():
    assert ab.derive_seed(7, 0) == ab.derive_seed(7, 0)
    assert ab.derive_seed(7, 0) != ab.derive_seed(7, 1)
    # Same base+run is shared across cells (the pairing key).
    assert ab.derive_seed(0, 3) == ab.derive_seed(0, 3)


def test_slugify():
    assert (
        ab._slugify("Super Quick Logic Invitational")
        == "super_quick_logic_invitational"
    )
    assert ab._slugify("I Got Id!") == "i_got_id"
    assert ab._slugify("  Trim__Me  ") == "trim_me"


# ---------------------------------------------------------------------------
# run_ab_sweep with an injected run_fn (no real agent)
# ---------------------------------------------------------------------------


def _fake_runner(solved_for=None):
    solved_for = solved_for or set()
    calls = []

    def run_fn(challenge, cell, run_seed, log_fn):
        calls.append((challenge.name, cell.label, run_seed))
        solved = (challenge.name, cell.label) in solved_for
        return RunResult(
            challenge=challenge.name,
            solved=solved,
            steps=5 if cell.label == "baseline" else 3,
            est_cost_usd_v2=0.0,
        )

    run_fn.calls = calls
    return run_fn


def test_sweep_writes_one_record_per_run(tmp_path):
    out = tmp_path / "eval.jsonl"
    challenges = [
        ab.EvalChallenge(name="c1", url="http://1/"),
        ab.EvalChallenge(name="c2", url="http://2/"),
    ]
    cells = [ab.Cell(label="baseline"), ab.Cell(label="treatment")]
    run_fn = _fake_runner({("c1", "treatment")})

    records = ab.run_ab_sweep(
        challenges, cells, n_runs_per_cell=2, seed=1, out_path=out, run_fn=run_fn
    )
    # 2 challenges × 2 cells × 2 runs
    assert len(records) == 8
    assert len(run_fn.calls) == 8
    lines = out.read_text().strip().splitlines()
    assert len(lines) == 8
    rec0 = json.loads(lines[0])
    assert {"challenge", "config_label", "run_idx", "seed", "solved", "steps"} <= set(
        rec0
    )
    # c1/treatment solved on both runs
    c1t = [
        json.loads(x)
        for x in lines
        if json.loads(x)["challenge"] == "c1"
        and json.loads(x)["config_label"] == "treatment"
    ]
    assert all(r["solved"] for r in c1t)


def test_sweep_shared_seed_across_cells(tmp_path):
    out = tmp_path / "e.jsonl"
    challenges = [ab.EvalChallenge(name="c1", url="http://1/")]
    cells = [ab.Cell(label="a"), ab.Cell(label="b")]
    run_fn = _fake_runner()
    records = ab.run_ab_sweep(
        challenges, cells, n_runs_per_cell=1, seed=5, out_path=out, run_fn=run_fn
    )
    seeds = {r["config_label"]: r["seed"] for r in records}
    assert seeds["a"] == seeds["b"]  # paired cells share the run seed


def test_sweep_append_vs_overwrite(tmp_path):
    out = tmp_path / "e.jsonl"
    challenges = [ab.EvalChallenge(name="c1", url="http://1/")]
    cells = [ab.Cell(label="a")]
    run_fn = _fake_runner()
    ab.run_ab_sweep(challenges, cells, out_path=out, run_fn=run_fn, append=False)
    ab.run_ab_sweep(challenges, cells, out_path=out, run_fn=run_fn, append=True)
    assert len(out.read_text().strip().splitlines()) == 2
    ab.run_ab_sweep(challenges, cells, out_path=out, run_fn=run_fn, append=False)
    assert len(out.read_text().strip().splitlines()) == 1  # truncated


def test_sweep_records_runner_exception_and_continues(tmp_path):
    out = tmp_path / "e.jsonl"
    challenges = [
        ab.EvalChallenge(name="c1", url="http://1/"),
        ab.EvalChallenge(name="c2", url="http://2/"),
    ]
    cells = [ab.Cell(label="a")]

    def run_fn(challenge, cell, run_seed, log_fn):
        if challenge.name == "c1":
            raise RuntimeError("kaboom")
        return RunResult(challenge=challenge.name, solved=True)

    records = ab.run_ab_sweep(challenges, cells, out_path=out, run_fn=run_fn)
    assert len(records) == 2  # did not abort on c1
    c1 = next(r for r in records if r["challenge"] == "c1")
    assert c1["solved"] is False
    assert "kaboom" in (c1["error"] or "")
    c2 = next(r for r in records if r["challenge"] == "c2")
    assert c2["solved"] is True


# ---------------------------------------------------------------------------
# _run_cell dispatch
# ---------------------------------------------------------------------------


def test_run_cell_url_dispatch(monkeypatch):
    capture = {}

    def fake_run(**kwargs):
        capture.update(kwargs)
        return RunResult(challenge=kwargs.get("challenge_name", "?"), solved=True)

    monkeypatch.setattr(ab, "run_against_target_sync", fake_run)
    ch = ab.EvalChallenge(name="c1", url="http://1/", expected_flag="MetaCTF{x}")
    cell = ab.Cell(label="t", model="gpt-5.2")
    ab._run_cell(ch, cell, 42, lambda *_a, **_k: None)
    assert capture["url"] == "http://1/"
    assert capture["expected_flag"] == "MetaCTF{x}"
    assert capture["model"] == "gpt-5.2"


def test_run_cell_unknown_kind_raises():
    ch = ab.EvalChallenge(name="c1", kind="martian")
    with pytest.raises(ValueError, match="unknown challenge kind"):
        ab._run_cell(ch, ab.Cell(label="a"), 0, lambda *_a, **_k: None)


# ---------------------------------------------------------------------------
# MetaCTF loader against the real repo TSVs
# ---------------------------------------------------------------------------


def test_load_metactf_challenges_full():
    challenges = ab.load_metactf_challenges()
    assert len(challenges) == 12
    names = {c.name for c in challenges}
    assert "treasure_map" in names
    assert "microdosing" in names
    # Known solved challenge has a real MetaCTF flag attached.
    tm = next(c for c in challenges if c.name == "treasure_map")
    assert tm.expected_flag is not None
    assert tm.expected_flag.startswith("MetaCTF{")
    assert tm.url and tm.description


def test_load_metactf_challenges_fast8_subset():
    challenges = ab.load_metactf_challenges(only=list(ab.FAST_8))
    assert len(challenges) == 8
    assert {c.name for c in challenges} == set(ab.FAST_8)


def test_load_metactf_unsolved_has_no_expected_flag():
    challenges = ab.load_metactf_challenges()
    # microdosing was never solved → no verified flag in the v2 TSV.
    micro = next(c for c in challenges if c.name == "microdosing")
    assert micro.expected_flag is None
