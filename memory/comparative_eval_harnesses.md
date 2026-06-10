# Comparative: evaluation harnesses

How each project exposes a runnable benchmark contract that an
external agent can plug into, vs. `ctf_solver`'s in-app batch mode.

## Dimensions to compare

1. **Challenge format**: what does one challenge look like on disk?
2. **Agent contract**: what does the agent receive (task text,
   working dir, container, files, network)?
3. **Agent output**: what does the agent return (flag string, list of
   attempts, subtask answers)?
4. **Grading**: pass/fail? subtask-graded? token cost?
5. **Adapter shape**: what would it take to plug our `AgentRunner`
   into this benchmark?

## Reference: `ctf_solver` baseline

- Batch runner in
  [`ctf_solver/ui/qt/batch_page.py`](../ctf_solver/ui/qt/batch_page.py)
  + Streamlit; reads CSV / TSV of challenges
- Per-run RunTracker stores tool calls, candidate flags, outcomes
- No external benchmark protocol — `ctf_solver` is self-contained

## Findings (fill in during Phase 1)

### Cybench (Phase 1.1 — done 2026-05-16)

Full protocol notes in [cybench_protocol.md](cybench_protocol.md).
Headline findings:

- **Invocation is in-process, not protocol-based.** `run_task.py`
  imports and instantiates `SimpleAgent` directly with a config +
  prompt + work_dir; iterates `agent.run()` as a generator of
  `SubtaskRun`.  No JSON-RPC.  This is an ABI lock-in, not a clean
  protocol.
- **The baseline agent is "an LM driving bash"** — `subprocess.run(
  ["bash", "-c", command_str])`, with regex-parsed `Command:` /
  `Answer:` blocks ending in `<END>`.  Fundamental shape mismatch
  with our FAIR-tool JSON-envelope agent.
- **Grading is *substring* on stdout, not strict equality.** Two
  grading paths exist; `grade_benchmark.py` (the reported metric)
  marks the challenge solved if the flag string appears in *any*
  iteration's stdout, even if the agent never formally submits
  `Answer:`.  Our `LoggingToolWrapper` already captures candidate
  flags from tool outputs — direct alignment.
- **Network access is via Docker network.** `target_host` looks like
  `web_flag:1337`; the challenge container is reachable by that
  hostname from inside Cybench's own container.  Agent is expected
  to use `curl` etc. against it.
- **Token budget is very tight by default.** `max_input_tokens=1000`,
  `responses_to_keep=3`, `observations_to_keep=3`.  README examples
  use 6000.  Our 16-message sliding window is luxurious by
  comparison.
- **`setup_environment` has destructive side effects on the host**
  (`rm -rf /app/benchmark`, `docker system prune -a -f`) — only safe
  inside Cybench's container.  Our adapter must bypass this on dev
  machines.

**Adapter strategy chosen (output-replay):** rather than subclass
`SimpleAgent`, run our agent independently against the challenge URL,
then synthesise a `TaskRunCompletion` JSON whose iterations carry the
agent's tool-output observations.  Cybench's substring grader picks
up the flag from our logged outputs.  Details in
[cybench_protocol.md](cybench_protocol.md#adapter-strategy-output-replay).

### NYU CTF Bench — done 2026-05-16

**Repository inventory:** 57 dev + 200 test challenges across 6 categories.
Web challenges: **10 dev + 19 test = 29 total**.  Category mix (test
split): crypto 52, rev 51, pwn 39, misc 24, web 19, forensics 15.

**On-disk layout:** `<split>/<year>/<event>/<category>/<name>/`,
e.g. `development/2016/CSAW-Quals/web/I Got Id/`.  Each challenge dir
contains:

| File | Role |
|---|---|
| `challenge.json` | the spec (8-field flat JSON, see below) |
| `Dockerfile` | challenge service image build |
| `docker-compose.yml` | service definition |
| `README` | sometimes — challenge brief for humans (not for the agent) |
| `src/`, setup scripts | challenge-specific |
| `solver.py` | reference solution — **must not be shown to agent** |

Pleasant surprise: the EnIGMA web demonstration trajectory
[`SWE-agent-v0.7/trajectories/demonstrations/ctf/web/i_got_id_demo.traj`](../agentic_systems_for_analysis/SWE-agent-v0.7/trajectories/demonstrations/ctf/web/i_got_id_demo.traj)
is a recorded solve of the *same* NYU challenge
`development/2016/CSAW-Quals/web/I Got Id`.  D-CIPHER, EnIGMA, and this
dataset are tightly coupled — three threads of the same NYU/CSAW
ecosystem.

**`challenge.json` schema** (verified against "I Got Id"):

```json
{
  "name": "I Got Id",
  "category": "web",
  "description": "Wtf... I literally just setup this website and it's already popped...",
  "box": "web.chal.csaw.io",      // target hostname (Docker network)
  "internal_port": 8000,            // target port
  "files": [],                       // agent-visible files (often [])
  "compose": true,                   // start via docker-compose
  "flag": "FLAG{p3rl_6_iz_EVEN_BETTER!!1}"
}
```

Optional fields seen elsewhere: `points` or `initial` (challenge
value), `proto: "nc"` (non-web socket protocol), `server_description`
(pre-baked text shown to agent).

**Dataset index files** (`development_dataset.json`,
`test_dataset.json`) map canonical names → bare metadata pointers:

```json
"2013f-web-historypeats": {
  "year": "2013",
  "event": "CSAW-Finals",
  "category": "web",
  "challenge": "historypeats",
  "path": "development/2013/CSAW-Finals/web/historypeats"
}
```

Canonical name format (see
[python/nyuctf/utils.py:38 — get_canonical_name](../agentic_systems_for_analysis/NYU_CTF_Bench/python/nyuctf/utils.py)):
`{year}{event_char}-{cat3}-{safe_name}` where `event_char` is
`q`/`f` for Quals/Finals and `cat3` is `web`/`pwn`/`cry`/etc.

**Python API** (`pip install nyuctf`):

```python
from nyuctf.dataset import CTFDataset
from nyuctf.challenge import CTFChallenge

ds = CTFDataset(split="test")            # auto-downloads if missing
chal = CTFChallenge(ds.get("2021q-web-no_pass_needed"), ds.basedir)

chal.start_challenge_container()         # docker-compose up -d
# target = f"http://{chal.server_name}:{chal.port}"
# expected_flag = chal.flag
# ... run our agent against the target ...
chal.stop_challenge_container()          # docker-compose down --volumes
```

`CTFDataset.filter(category="web", year=..., event=...)` returns a
generator — useful for subsetting.

**Server-type inference**
([challenge.py:104](../agentic_systems_for_analysis/NYU_CTF_Bench/python/nyuctf/challenge.py)):
`server_type` returns `"web"` if `category in {"web", "misc"}` and not
`proto=="nc"`; else `"nc"`.  Our agent should filter on
`server_type == "web"` for the pilot.

**Container behaviour is non-destructive.** `CTFChallenge.start_*`
runs `docker compose -f docker-compose.yml up -d --force-recreate`;
stop runs `down --volumes`.  No `docker system prune` like Cybench.
Safe to run on a dev machine.

## Format delta: NYU vs. Cybench

| Dimension | NYU CTF Bench | Cybench |
|---|---|---|
| Spec file | `challenge.json` (flat, 8 fields) | `metadata/metadata.json` (nested, subtasks) |
| Service start | `compose: true` → docker-compose | `start_docker.sh` shells out |
| Service stop | clean `down --volumes` | `stop_docker.sh` + host `docker system prune -a -f` |
| Target host | `{box}:{internal_port}` | `target_host` string |
| Subtasks | **none** — single flag only | yes — subtask-graded mode + unguided mode |
| Hints | none in challenge.json | per-subtask `hints[]` list |
| Reference solver | `solver.py` in challenge dir | `metadata/solution/` or `htb/solver.py` |
| Python API | `pip install nyuctf` — clean, filtered | none — clone repo + run scripts |
| Agent contract | caller-driven (load challenge, give URL to agent, check flag) | `SimpleAgent`-shaped class OR matching JSON log shape |
| Grading | substring `flag in response` in challenge.py:39 | substring `flag in stdout` across iterations (grade_benchmark.py:84) **OR** strict equality on `Answer:` (agent.py:643) |
| Dev split | 57 challenges | none (single benchmark) |
| Test split | 200 challenges | 40 challenges |
| Web subset | 29 challenges (10 dev + 19 test) | ~9+ across HTB / Sekai / HKCERT — needs counting |
| Categories | web, pwn, crypto, rev, forensics, misc | web, pwn, crypto, rev, forensics, misc + bug-bounty |

**Both projects converge on substring-grading.** That's load-bearing
for our adapter strategy: as long as the flag appears anywhere in our
agent's tool outputs, both benchmarks count it as solved.  Our
`LoggingToolWrapper` already captures flag-shaped tokens from
outputs.

## Unified adapter sketch

Don't unify into one adapter — the harnesses are too different.
Instead: **two thin adapters + one shared core**.

```
ctf_solver/eval/
├── __init__.py
├── _core.py           # shared: run_against_target(url, desc, files, flag) -> RunResult
├── cybench_adapter.py # reads metadata/metadata.json, emits Cybench TaskRunCompletion JSON
└── nyu_adapter.py     # uses nyuctf Python API, returns plain RunResult
```

The NYU adapter is dramatically simpler because:
1. `nyuctf` Python package handles Docker plumbing.
2. No `Answer:`-format requirement — substring match is the only grade.
3. No `setup_environment` destructive parts to bypass.
4. Caller controls the loop, no `SimpleAgent` shape to mimic.

**Shape sketch** (≈40 LOC for NYU adapter):

```python
# ctf_solver/eval/nyu_adapter.py
def run_nyu_challenge(canonical_name: str, *, split="test", model=None) -> RunResult:
    ds = CTFDataset(split=split)
    chal = CTFChallenge(ds.get(canonical_name), ds.basedir)
    if chal.server_type != "web":
        raise ValueError(f"Pilot is web-only; {canonical_name} is {chal.server_type}")
    chal.start_challenge_container()
    try:
        target_url = f"http://{chal.server_name}:{chal.port}"
        result = _core.run_against_target(
            url=target_url,
            description=chal.description,
            flag_format=chal.flag_format,
            expected_flag=chal.flag,
            files=[chal.challenge_dir / f for f in chal.files],
            model=model,
        )
    finally:
        chal.stop_challenge_container()
    return result  # solved: bool, flag_seen: str|None, tool_calls: int, cost: float
```

The Cybench adapter is heavier (~150 LOC) because it must emit the
TaskRunCompletion JSON shape and bypass `setup_environment`'s
destructive parts.  Both call `_core.run_against_target`.

## Phase 3 sequencing

1. **NYU adapter first.**  It's smaller, runs safely on the dev
   machine, and gives a clean second number to compare against.
2. Cybench adapter second — heavier but unlocks the published
   leaderboard comparison.
3. Both adapters available for the Phase 1.3 multi-agent decision
   experiment — run both pilot modes against both eval sets, pick the
   richer signal.

## Verdict (one line, end of Phase 2)

**Build two thin adapters sharing a core; pilot on NYU first.**

### SWE-agent benchmarking
*(Skip — SWE-bench is for code, not security.  EnIGMA's evaluation
runs on NYU CTF + Cybench, which are already covered above.)*

### D-CIPHER's evaluation runner
*(Read `run_dcipher.py`'s --split / --challenge flags to see how they
load NYU CTF challenges programmatically.  Useful reference for our
adapter.)*

## Verdict (one line, end of Phase 2)

*Expected: "Build a unified adapter; Cybench protocol first because
its grading is more granular."*

## Phase 3 deliverable

A working adapter at e.g. `ctf_solver/eval/cybench_adapter.py` that
exposes our `AgentRunner` to Cybench's `run_task.py` contract.  This
must exist *before* deciding which other patterns to port.
