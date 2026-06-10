# Tier 1 implementation — 2026-05-18

Executes the recommendations in
[`window_mode_failure_analysis.md`](window_mode_failure_analysis.md)
Tier 1 (the three "bug-fix / tweak" items, not the larger ports).

## What changed

| # | Task | Files |
|---|---|---|
| 1 | strict_flag_regex tier | [`config.py`](../ctf_solver/config.py), [`run_tracker.py`](../ctf_solver/run_tracker.py), [`runner.py`](../ctf_solver/runner.py), [`tests/test_config.py`](../tests/test_config.py) |
| 2 | flask_session_forge zlib fix | [`tools/session_forgery_tools.py`](../ctf_solver/tools/session_forgery_tools.py), [`tests/test_session_forgery_tools.py`](../tests/test_session_forgery_tools.py) |
| 3 | cookie-persistence prompt note | [`prompts/templates.py`](../ctf_solver/prompts/templates.py) |

### Task 1 — strict_flag_regex tier (gap G7)

- New constant `DEFAULT_STRICT_FLAG_REGEX` in `config.py`: only matches known
  CTF prefixes `(picoCTF|MetaCTF|HTB|THM|CSAW|UTCTF|TJCTF|FLAG|flag|CTF)`.
- New `SolverConfig.strict_flag_regex` field, defaulting to that constant.
- Plumbed through `from_env()` (`CTF_STRICT_FLAG_REGEX`), `merge_with_args()`,
  and a new CLI flag `--strict-flag-regex`.
- `runner.py` now splits run-end candidates: strict matches print
  `[FLAG DETECTED]`, broad-but-not-strict print `[FLAG CANDIDATE]`.
  `tracker.confirmed_flags_found` carries the strict subset;
  `tracker.candidate_flags_found` keeps the full audit trail.
  `run_succeeded` / `outcome` are now keyed off the **strict** list.
- 11 new tests: 6 in `TestStrictFlagRegex` (extract_candidate_flags behaviour,
  including the JS / CSS false-positive cases from the prior run) and 5 in
  `TestStrictFlagRegexConfig` (default / env / merge wiring).

**Practical impact**: the `[FLAG DETECTED]` marker in agent logs and the
`run_succeeded` flag are now precise.  The Livestream-style false positive
(`try{u||null==r.return||r.return()}`) is still recorded as a candidate but
no longer counted as a solve.

### Task 2 — `flask_session_forge` zlib decode fix (gap G1)

Root cause: Flask compressed-session cookies start with a literal `.` to
signal zlib compression.  The old `_decode_payload` did `cookie.split(".")`
*first*, so the leading `.` yielded `parts[0] == ""` and the decoder
silently returned `None`.

Fix: detect leading `.` BEFORE splitting; treat as a compression flag; zlib
-decompress unconditionally.  Code is at
[`session_forgery_tools.py:656-689`](../ctf_solver/tools/session_forgery_tools.py).

**Verification**: re-running `_decode_payload` on the actual cookie captured
from the Super Quick Logic Invitational run now returns:

```python
{
    "csrf_token": "c3e7e7ab7bc39041647a6fc91e009c80bd5b4d3a3273f8c263c7fc57c05b5721",
    "current_difficulty": 4,
    "current_problem": 91,
    "current_problem_attempts": 0,
    "current_question": "What is the largest prime factor of 2197?",
    "game_attempts": [],
    "score": ...,
    "start_time": ...,
}
```

This is a real capability unlock: the agent can now decode the live trivia
question *from the session cookie itself* and bypass the multi-step game
loop entirely (read question → compute answer → submit → score the flag).

Two regression tests in `tests/test_session_forgery_tools.py`:
- `test_decode_zlib_compressed_real_cookie` — direct `_decode_payload` call
- `test_decode_zlib_via_use_operation` — via the public `use(...)` entry

### Task 3 — cookie-persistence prompt note (gap G3 / G6 perceptual)

Added a one-paragraph note under the `cookie_inspector` block in
[`prompts/templates.py`](../ctf_solver/prompts/templates.py) explaining that
the shared `requests.Session` jar persists cookies across all tool calls,
so the agent does **not** need to manually re-fetch to "get the new
cookie."  This addresses the agent's hallucinated "cookie rotation" theory
that burned ~5 steps in the SQL Invitational run.

Investigation found the shared session IS properly wired in
`build_agent` ([`agent.py:2240-2293`](../ctf_solver/agent.py)) — every
HTTP-using tool receives the same `shared_session`.  No code fix was
needed; only the prompt was misleading.

## Verification

- **ruff**: zero new errors.  10 pre-existing errors remain (4 E402 in
  `runner.py`, 6 F401 in `tests/test_*.py`) and are present on a clean
  HEAD — verified via `git stash`.
- **black**: clean on all 7 touched files.
- **pytest** on the relevant subset: **166/166 pass**
  (`tests/test_config.py` + `test_session_forgery_tools.py` +
  `test_v38_scaffold_quick_wins.py` + `test_ctf_agent.py`).

## Tier 1 re-run results (2026-05-18, task `b72uj451d`)

**Outcome: 10/12 strict-MetaCTF solves — same as obs7 baseline.**

| slug | tier1 | obs7 |
|---|---|---|
| treasure_map | ✓ | ✓ |
| direct_login | ✓ | ✓ |
| door_to_door | ✓ | ✓ |
| open_application | ✓ | ✓ |
| livestream | ✓ | ✓ |
| super_quick_logic_invitational | ✗ | ✗ |
| snowfall_wishes | ✓ | ✓ |
| cracking_the_javashop | ✓ | ✓ |
| admin_portal | ✓ | ✓ |
| cookie_crackdown | ✓ | ✓ |
| great_paywall | ✓ | ✓ |
| microdosing | ✗ | ✗ |

Total wall time: **821s** (obs7 was 589s).  The +232s is dominated by
super_quick_logic_invitational at 318s (vs ~120s typical failure budget)
because the agent now actually engages the session-decode path before
timing out.

### Tier 1 fixes — observed effects

- **Task 2 (zlib decode) confirmed live**: SQL Invitational log line
  1262–1276 shows `flask_session_forge analyze` successfully returning
  the decoded payload including `"current_question": "If you have a 3-bit
  key and a 3-bit plaintext, how many possible ciphertexts can you
  produce?"` (answer: 8). **Capability unlock works.**
- **Task 1 (strict regex)**: zero false-positive `[FLAG DETECTED]`
  markers; all 10 solves are real `MetaCTF{…}` flags.
- **Task 3 (cookie note)**: no cookie-rotation hallucinations in the
  microdosing log this run.

### Why the agent still loses SQL Invitational despite the decode unlock

The agent decodes the cookie, *sees* `current_question`, but does NOT
take the simple path (compute answer → POST `/submit`).  Instead it
fans out into:

1. SQLi probing of `/submit` (lines 917–1066)
2. `ctf_knowledge_query` on intermittent 403s (line 1140)
3. Flask `brute_secret` (line 1379) — wrong category
4. Repeated 403 responses until step budget exhausted

This is the **behavioral ceiling**: the tool capability exists, but the
agent's planner doesn't pick the trivia loop over the more "CTF-shaped"
SQLi path.  Tier 1 was always going to be insufficient here.

### Decision per the original tree

10/12 = same as obs7 ⇒ "Tier 1 helped grading precision and fixed real
bugs but did not change the agent's behavioural ceiling on these
challenges.  Move to Tier 2 (capability additions) or Tier 3
(multiagent pilot) — both target the step-budget bottleneck."

**Ship Tier 1.**  Next: scope Tier 2.

## Comparison baseline (do this on completion)

The 2026-05-17 obs7 run was the previous best:
- Strict MetaCTF solves: **10/12** (Livestream, Open Application, Cookie
  Crackdown, Treasure Map, Direct Login, Door to Door, Snowfall Wishes,
  Cracking the Javashop, Admin Portal, Great Paywall)
- Failures: super_quick_logic_invitational, microdosing
- Total wall time: 589 s

Tier 1 hypotheses for the re-run:

1. **Super Quick Logic Invitational** — now solvable in principle.
   Task 2 unlocked the session-decode path.  Whether the agent *uses*
   `flask_session_forge decode` to read `current_question` is a
   behavioural question; the tool capability is there.
2. **Microdosing** — modest improvement expected.  Task 3 reduces
   step-burning on cookie confusion; Task 2 also helps if the agent
   decodes that session.  But the agent's `/search` 500 problem was
   never about cookies, so this may stay a failure.
3. **The other 10** — should remain solves.  No behavioral change for
   trivially-solved challenges.
4. **Grading precision** — `[FLAG DETECTED]` will now exclude broad
   false positives.  Livestream's solve (real `MetaCTF{...}`) still
   counts; what used to slip through (JS object literals) no longer
   does.

## Analysis script for re-run

> **Superseded (parity-sprint item #1, 2026-06-02):** `run_batch.sh` now
> grades via `ctf_solver/log_grader` (the runner's own `[FLAG DETECTED]`
> marker), so fresh runs no longer need this manual re-grade. The pre-fix
> buggy-grader output was renamed to `summary_tier1_LEGACY_GRADER.tsv`. The
> recipe below is kept only to re-grade the *old* legacy logs if needed.

The legacy run's `summary_tier1_LEGACY_GRADER.tsv` has the buggy
case-sensitive grader (used `(metaCTF|MCTF|FLAG|flag)` + `{...}`).
Re-grade with the same approach used for the obs7 run:

```bash
cd <project_root>
printf "slug\tflag_seen\tflag\twall_seconds\n" > /tmp/summary_tier1_v2.tsv
tail -n +2 out/batch_window_test/summary_tier1_LEGACY_GRADER.tsv | while IFS=$'\t' read -r slug rc _flag_seen wall; do
  log="out/batch_window_test/logs_tier1/${slug}.log"
  flag=$(grep -oE '\[FLAG DETECTED\] [A-Za-z0-9_]+\{[^}]{1,200}\}' "$log" | head -1 | sed 's/^\[FLAG DETECTED\] //')
  seen="no"; [ -n "$flag" ] && seen="yes"
  printf "%s\t%s\t%s\t%s\n" "$slug" "$seen" "${flag:--}" "$wall" >> /tmp/summary_tier1_v2.tsv
done
column -t -s $'\t' /tmp/summary_tier1_v2.tsv
```

Strict count:
```bash
awk -F'\t' 'NR>1 && $3 ~ /^(MetaCTF|HTB|picoCTF|FLAG|flag)\{/' /tmp/summary_tier1_v2.tsv | wc -l
```

## Decision tree on results

| Outcome | Next move |
|---|---|
| ≥11/12 solved (any new solve over obs7's 10) | Commit Tier 1 as "shipped", document in `tier1_implementation.md`, decide whether to invest in Tier 2 (`submit_until_done` tool + per-category prompts) |
| 10/12 (same as obs7) | Tier 1 helped grading precision and fixed real bugs but did not change the agent's behavioural ceiling on these challenges.  Move to Tier 2 (capability additions) or Tier 3 (multiagent pilot) — both target the step-budget bottleneck. |
| <10/12 (regression) | Investigate which previously-solved challenge regressed.  Most likely culprit: Task 3 prompt note inadvertently changed agent behaviour on something unrelated.  Easy revert. |

## Files to re-read post-compaction if needed

- This file (durable summary of Tier 1)
- [`window_mode_experiment.md`](window_mode_experiment.md) — A/B
  experiment that set the new defaults
- [`window_mode_failure_analysis.md`](window_mode_failure_analysis.md)
  — gap analysis with Tier 1/2/3 ranking
- [`out/batch_window_test/summary_obs7_v2.tsv`](../out/batch_window_test/summary_obs7_v2.tsv)
  — the comparison baseline
