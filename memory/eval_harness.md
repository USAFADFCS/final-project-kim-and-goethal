# Eval harness (`ctf_solver/eval/`)

The measurement keystone: turns "the agent feels better" into a signed, paired
number. Built 2026-06-05 from the `runner.py` eval-harness TODO + plan item #5
(`memory/parity_sprint_plan.md`). Design rationale:
`memory/comparative_eval_harnesses.md`, `memory/cybench_protocol.md`,
`memory/comparative_agent_loops.md`.

## Layout

| File | Role |
|---|---|
| `_core.py` | `RunResult` dataclass + `run_against_target()` (async) / `run_against_target_sync()`. Wraps `build_agent` → `agent.arun` → strict/broad flag grade, returns structured data. |
| `nyu_adapter.py` | `run_nyu_challenge()` via the `nyuctf` package; web-only filter; container lifecycle; `ImportError` guard; `list_web_challenges()`. |
| `cybench_adapter.py` | `parse_cybench_metadata()`, `build_task_run_completion()` (output-replay JSON), `run_cybench_task()`. Bypasses Cybench's destructive `setup_environment`; Docker guard. |
| `ab_harness.py` | `run_ab_sweep()` (seeded paired cells × challenges × runs → `eval_results.jsonl`); `Cell`/`EvalChallenge`; `load_metactf_challenges()`; `FAST_8`/`REPORT_12`. |
| `stats.py` | `mcnemar()` (paired binary), `wilcoxon_paired()` (paired continuous), `pair_records()`, `analyze()`, `format_report()`. |
| `scripts/eval_stats.py` | thin CLI over `stats.py`. |
| CLI | `runner.py` `--nyu-challenge` / `--nyu-split` / `--cybench-task-dir` → `_run_eval_adapter`. |

Tests: `tests/test_eval_*.py` (75 tests). Full suite 3004 pass, 1 skipped.

## Load-bearing design decisions

- **No measurement confound.** `_core` never writes lessons and (default)
  never injects RAG — forces `RAGMode.ORIGINAL` unless `inject_rag=True`. A/B
  cells must not read/write the experience DB or the comparison is poisoned.
- **Grading.** Benchmark mode (`expected_flag` set) → `solved` = substring
  match of the exact flag in response/tool outputs (what NYU + Cybench both
  do). Live mode → `solved` = any strict-regex-confirmed flag. Same
  `extract_flags_from_run` + `strict_flag_regex` split as `runner.run_agent`.
- **Honest cost.** `est_cost_usd_v2` (parity item #2): $0 for Ollama/MLX.
- **Pairing.** McNemar/Wilcoxon pair by `(challenge, run_idx)`; one `run_seed`
  is shared across cells per `run_idx`. Local models don't honour seeds →
  **paired-by-config, not paired-by-output** (seed fixes structure, not
  sampling).
- **Adapters are write-to-spec + mock-tested** because Docker and `nyuctf` are
  absent on the dev machine. The A/B + stats layer is fully runnable here and
  is the immediately useful part.

## Adversarial review (2026-06-05) — fixed

A 5-dimension workflow (37 agents) found 23 verified issues; the impactful
ones were fixed + regression-tested:

- **CLI crashed on nested `asyncio.run`** (high): `main()` runs in a loop but
  the sync adapters call `asyncio.run` internally → dispatch via
  `asyncio.to_thread(_run_eval_adapter, args)`.
- **Cybench `TaskRunCompletion` omitted `task.subtasks`** (high): the real
  `grade_benchmark.py` reads `challenge_task['subtasks'][0]['answer']` → emit a
  single synthetic unguided subtask whose answer = the FINAL flag (`or ""`).
- **Wilcoxon**: diffs now `treatment − baseline` (sign-consistent with median
  delta); `_num` rejects NaN/Inf (a NaN silently produced `p=nan`); reported
  `n` is the effective (non-tied) count scipy actually uses.
- **`analyze` flags duplicate `(challenge, run_idx, label)` records** — appending
  a re-run to one JSONL silently dropped earlier runs via last-wins pairing.
- **`_compose_up`** raises `RuntimeError` with docker stderr (was uncaught
  `CalledProcessError`). **`list_web_challenges`** derives canonical names via
  `nyuctf.utils.get_canonical_name` (filter yields bare dicts).

## Known limitation (scoped TODO in `nyu_adapter.run_nyu_challenge`)

NYU `_target_url` returns the `ctfnet`-network alias:internal_port, which a
**host-side in-process agent cannot reach** (services often publish no host
port). nyuctf's own harness runs the agent inside a `ctfnet` container. Until
host-reachability is wired (publish the port, or containerize the agent —
needs Docker to validate), a host-side NYU run connection-fails and records
`solved=False`. **Don't trust NYU numbers from this adapter yet.** Cybench
(published host ports) and live-URL/MetaCTF are unaffected.

## Live status — runs end-to-end locally (2026-06-09)

**Docker is now installed** (OrbStack, `~/.orbstack/bin/docker`; arm64 +
Rosetta amd64 emulation + compose v5). The "docker absent" caveats above are
historical — the adapters can now actually stand challenges up. **Proven:**
`nemotron-3-super:120b-a12b-q4_K_M` solved cybench **Flag Command** (Very Easy)
end-to-end locally — ~20 min, $0, correct flag, graded by the harness.

**Benchmarks on disk** (`agentic_systems_for_analysis/`, ~7 GB):
- **cybench** — ~7 web challenges WITH metadata, difficulty-labeled Very Easy→
  Hard (Flag Command=VeryEasy, Labyrinth Linguist=Easy/SSTI, LockTalk=Medium/
  JWT, frog-waf=Hard/WAF, chunky=Hard). Run: `docker network create shared_net`
  then `docker compose up -d` in the challenge dir.
- **NYU CTF Bench** — 29 usable web (10 development + 19 test); no difficulty
  labels; needs `docker network create ctfnet`.

**Host-reachability caveat (refined):** both adapters build the in-docker URL
(`web_flag:1337` / ctfnet alias). For a HOST-side agent, target
`localhost:<published_port>` instead. It's per-challenge: Flag Command publishes
`1337:1337` and NYU `cloudb` publishes `80:80` (reachable); some HTB web
challenges publish no host port (need an in-container agent or a compose
override). The `nyu_adapter` TODO covers wiring published-port discovery.

To run a live demo: container up → `ollama serve` (models on disk) → point the
agent at `http://localhost:<port>`, or use `run_against_target_sync(url=...,
expected_flag=...)` for a graded RunResult. Scratch driver: `/tmp/run_flagcmd.py`.

## Next

Follow-on #4 (confirmed-flag early-termination, [[auto-submit-flag]]) is SHIPPED
— its **A/B is the pending next step** (off vs on, McNemar + Wilcoxon, use the
30B prism model for speed). Related: [[parity-sprint-plan]], [[auto-submit-flag]].
