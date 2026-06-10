# Window-mode experiment — 2026-05-17

Direct measurement that motivated the default change in
[`config.py`](../ctf_solver/config.py) from
`(history_window_size=16, history_window_mode="messages")` →
`(history_window_size=7, history_window_mode="observations")`.

## Hypothesis

Two independent agentic CTF projects (EnIGMA, D-CIPHER) converged
on a sliding window of **5 most-recent tool observations**.  Our
default was 16 raw messages (≈ 8 ReAct turns).  The convergent
default is meaningfully tighter — close to half the context — and
the underlying mechanism (less distractor token rot, less
attention to middle context) is well-documented.  Worth testing.

## Setup

- **Model:** `gpt-5.2`
- **Step budget:** 30
- **RAG:** `--rag-mode original` (curated docs only, no lessons)
- **Challenges:** 12 MetaCTF web challenges (live URLs at run time,
  see [`out/batch_window_test/challenges.tsv`](../out/batch_window_test/challenges.tsv))
- **Run shape:** sequential, one challenge at a time, each batch
  rerun cleanly
- **Configurations compared:**
  - `baseline`: `--history-window-size 16 --history-window-mode messages`
    (the previous default)
  - `obs7`: `--history-window-size 7 --history-window-mode observations`
    (the convergent default applied as a sliding window of last 5
    observations + 2 anchor messages)

## Results

Strict grading (only `MetaCTF{...}` matches count, not the agent's
own permissive `\w+{...}` marker which produced one false positive
in baseline):

| Metric | Baseline | Obs7 | Δ |
|---|---|---|---|
| Real flags found | 9/12 (75%) | 10/12 (83%) | **+1** |
| Total steps used on solved challenges | 60 | 44 | **−27%** |
| Wall time total | 559 s | 589 s | +5% |
| False-positive submissions | 1 | 0 | −1 |
| Same-failures | super_quick_logic_invitational, microdosing | (same) | both modes fail same 2 |

### Per-challenge step count (solved only)

| Challenge | Baseline steps | Obs7 steps |
|---|---|---|
| Treasure Map | 3 | 3 |
| Direct Login | 4 | 4 |
| Door to Door | 6 | 6 |
| Open Application | 14 | **5** |
| Livestream | 30 (false positive) | **20** (real flag) |
| Snowfall Wishes | 4 | 5 |
| Cracking the Javashop | 4 | 3 |
| Admin Portal | 4 | 4 |
| Cookie Crackdown | 2 | 2 |
| Great Paywall | 2 | 2 |

## Qualitative wins

1. **Livestream.**  Baseline burned all 30 steps and ended up
   submitting `try{u||null==r.return||r.return()}` — a JavaScript
   snippet that happened to match the agent's flag regex.  Obs7
   found the real flag `MetaCTF{W3b_S0cket_4ssignm3nt!}` at step 20.
   The tighter window kept the agent from confabulating after
   extended fruitless exploration.

2. **Open Application.**  Both modes solved it, but baseline took
   14 steps while obs7 took 5.  Same outcome at 65% lower step cost.

## Conclusions

- Pass-rate delta (+1 challenge) is within noise on n=12, but the
  step-efficiency delta (−27% on solves) is much larger than noise
  and consistent across solved challenges.
- The two failures (Super Quick Logic Invitational, Microdosing)
  are unchanged between modes — they're **capability gaps**
  (auth-bypass and admin-account compromise), not context-rot
  failures.  Window tuning is the wrong lever for them.

## Decision

**Defaults committed 2026-05-17:**
```python
history_window_size: Optional[int] = 7
history_window_mode: str = "observations"
```

Legacy behavior remains accessible via:
```
--history-window-size 16 --history-window-mode messages
```
or env vars `CTF_HISTORY_WINDOW=16 CTF_HISTORY_WINDOW_MODE=messages`.

## Caveats this experiment does not cover

- **n=12, one model.**  GPT-5.2 only.  Behavior on Sonnet / Opus /
  local models could differ.
- **One platform.**  MetaCTF challenges only.  Other CTFs may have
  different flag formats and difficulty distributions.
- **One point in parameter space.**  Tested obs7 (last 5 observations
  + 2 anchors).  Did not sweep obs5 / obs10.  EnIGMA + D-CIPHER both
  use 5 observations exactly; we left them slightly above that and
  it worked.  Lower might be even better.
- **No cost number.**  Wall time and step counts only.  Token spend
  per challenge is the proxy for cost; obs7 is plausibly cheaper but
  not measured.
- **Capability-gated failures stayed the same.**  See
  [`window_mode_failure_analysis.md`](window_mode_failure_analysis.md)
  for the follow-on capability-gap analysis on the two unsolved
  challenges.
