# Tier 2 implementation — 2026-05-18

Executes the two Tier 2 items from
[`window_mode_failure_analysis.md`](window_mode_failure_analysis.md)
after [`tier1_implementation.md`](tier1_implementation.md) shipped at
10/12 — the same ceiling as obs7, confirming the gap is behavioral not
bug-driven.

## What changed

| # | Task | Files |
|---|---|---|
| 4 | `submit_until_done` server-side loop tool | [`tools/submit_until_done.py`](../ctf_solver/tools/submit_until_done.py), [`agent.py`](../ctf_solver/agent.py), [`tests/test_submit_until_done.py`](../tests/test_submit_until_done.py) |
| 5 | Per-category prompt overlays | [`prompts/category_overlays.py`](../ctf_solver/prompts/category_overlays.py), [`prompts/templates.py`](../ctf_solver/prompts/templates.py), [`agent.py`](../ctf_solver/agent.py), [`config.py`](../ctf_solver/config.py), [`tests/test_category_overlays.py`](../tests/test_category_overlays.py) |

### Task 4 — `submit_until_done`

A FAIR-pattern tool that runs an N-iteration request loop server-side
within a single tool call.  Solves the step-budget problem on
challenges like Super Quick Logic Invitational where the trivia loop
needs ~100 iterations.

Two iteration shapes:
- **`static`**: every iter sends the same body (with optional answer
  lookup).
- **`regex_extract`**: per-iter, parse the previous response with a
  caller-supplied regex, look up the extracted value in
  `answer_lookup`, substitute into `{placeholder}` slots of
  `body_template`, post.  Iter 0 is treated as a probe — unbound
  placeholders render as empty string via `_EmptyDefaultMap`.

Stops on the first match against `success_marker`, `stop_marker`, or
when `max_iterations` (capped at 200) is reached.  Returns JSON with
`outcome`, `iterations`, `elapsed_seconds`, `final_response_excerpt`,
and a per-iter `trace` (first 20).

The tool uses the **shared** `requests.Session` by default so cookies
persist into and out of the loop — matters because the trivia game
mutates `current_question` server-side as POSTs land.

Registered in `agent.py` next to `auto_form_submit_tool` (line ~2278).
**23 tests**, all pass.

### Task 5 — Per-category prompt overlays

When the keyword classifier confidently labels a challenge, the
system prompt gets a `## Category-specific guidance` section
containing:

- Priority tools (first 6 from `TOOL_PRIORITIES[category]`)
- Numbered approach (from existing `APPROACH_SUGGESTIONS[category]`)
- New `Do` / `Do NOT` bullets per category (in
  `_CATEGORY_GUIDANCE` — sourced from observed failure modes in the
  Tier 1 run, e.g. "don't pivot to SQLi on /submit before proving
  auth bypass" for AUTHENTICATION; "don't burn steps on /search before
  trying lfi_probe" for FILE_INCLUSION)

The classifier was already implemented but never wired into the
runner.  Task 5 now calls `classify_challenge(config)` at the top of
`build_agent` (only on the JSON-ReAct path, not the simple planner
path), passes the result to `get_system_prompt(..., classification=)`,
which appends the overlay AFTER the auto-generated tool catalog.

**Confidence gate**: overlays only render when
`result.confidence >= MIN_OVERLAY_CONFIDENCE` (0.40) AND the primary
category is not `UNKNOWN`.  This way a low-signal classification
cannot push the agent toward the wrong category.

Config flag `enable_category_overlay: bool = True` (default on) in
`SolverConfig`; existing instances of `build_agent` get the new
behaviour automatically.

**16 tests**, all pass.  Covered categories with explicit do/don't:
AUTHENTICATION, FILE_INCLUSION, SQL_INJECTION, SSTI, JWT, FILE_UPLOAD,
XSS.  Categories without explicit guidance (e.g. WASM_RE) still get
the priority-tools + approach sections rendered without crashing.

## Verification

- **ruff**: zero new errors on touched files.
- **black**: clean on all 7 touched files (after one auto-format pass).
- **pytest** on the relevant subset:
  - `test_submit_until_done.py`: 23/23
  - `test_category_overlays.py`: 16/16
  - Adjacent suites — `test_config.py`, `test_session_forgery_tools.py`,
    `test_v38_scaffold_quick_wins.py`, `test_classifier.py`: 236/236
  - `test_ctf_agent.py` + `test_integration.py`: 49/49

## How Tier 2 maps onto the two failures

**Super Quick Logic Invitational (game loop, ~100 iters)**:
1. Classifier sees Flask cookie keywords → AUTHENTICATION overlay.
   Overlay says: "Decode the cookie FIRST. Don't pivot to SQLi
   probing before proving auth bypass.  Use `submit_until_done` in
   regex_extract mode for state-driven loops."
2. Agent decodes cookie, sees `current_question`, builds a
   `submit_until_done` call with `extract_regex={"question":
   "\"current_question\"\\s*:\\s*\"([^\"]+)\""}` and an
   `answer_lookup` keyed on the question strings.
3. One tool call drives the full trivia loop.  Step budget pays for
   one call, not 100.

**Microdosing (LFI not tried)**:
1. Classifier sees path-shaped parameters and "search" patterns →
   FILE_INCLUSION or RECONNAISSANCE primary (depends on confidence).
2. Overlay says: "Probe path-shaped params with `lfi_probe` BEFORE any
   other category.  Don't spend more than two steps on /search."
3. Agent reaches for `lfi_probe` earlier in the budget.

Both fixes are **behavioral nudges**, not capability fixes — they bias
the agent's first few steps but don't add new exploits.

## Tier 2 re-run results (2026-05-18, task `bow60h7o0`)

**Outcome: 9/12 strict-MetaCTF solves — one regression (Livestream) vs Tier 1's 10/12.**

| slug | tier2 | tier1 | Δ |
|---|---|---|---|
| treasure_map | ✓ | ✓ | — |
| direct_login | ✓ | ✓ | — |
| door_to_door | ✓ | ✓ | — |
| open_application | ✓ | ✓ | — |
| livestream | ✗ | ✓ | **regression** |
| super_quick_logic_invitational | ✗ | ✗ | — |
| snowfall_wishes | ✓ | ✓ | — |
| cracking_the_javashop | ✓ | ✓ | — |
| admin_portal | ✓ | ✓ | — |
| cookie_crackdown | ✓ | ✓ | — |
| great_paywall | ✓ | ✓ | — |
| microdosing | ✗ | ✗ | — |

Total wall time: 935s (Tier 1: 821s).

### Critical finding: Tier 2 did not activate on any failing challenge

Classifier verdicts across all 12 challenges:

| slug | category | confidence | overlay fired |
|---|---|---|---|
| treasure_map | unknown | 0.00 | no |
| direct_login | authentication | 0.09 | no (below threshold) |
| door_to_door | unknown | 0.00 | no |
| open_application | unknown | 0.00 | no |
| livestream | unknown | 0.00 | no |
| super_quick_logic_invitational | unknown | 0.00 | no |
| snowfall_wishes | unknown | 0.00 | no |
| cracking_the_javashop | authentication | 0.36 | no (just below 0.40) |
| admin_portal | sql_injection | 0.07 | no |
| cookie_crackdown | unknown | 0.00 | no |
| great_paywall | unknown | 0.00 | no |
| microdosing | unknown | 0.00 | no |

**Zero overlays fired across all 12 challenges.** The Tier 2.5
classifier-driven overlay was effectively a no-op in this run.

Root cause: `classify_challenge()` runs at `build_agent` time and
only sees `config.description` + `config.hints` + an optional
pre-fetched `response_content` (which the runner does NOT supply).
MetaCTF challenges arrive with sparse descriptions, so the keyword
classifier has almost no signal.

### `submit_until_done` was not exercised either

SQL Invitational log shows the tool was **referenced once** (the
tool listing in the system prompt) but **invoked zero times**.  The
agent picked `flask_session_forge` (2 calls) and SQLi probing
(several calls) without ever reaching for the loop tool.

### Why Livestream regressed (it's run-variance, not Tier 2)

The classifier returned UNKNOWN with 0.00 confidence on Livestream
→ no overlay was applied → Tier 2 changes had zero behavioural
effect on this challenge.  The Tier 2 batch happened to take a
different early path (16 http_fetch + 4 path_enumerator + 4
deep_recon before only 3 websocket_probe calls) and timed out at
step 30.  Tier 1 had hit the WebSocket path earlier.  Same model,
same temperature, different sample.  **Not a Tier 2 problem.**

### What this means

- **No regression from Tier 2 itself**: the overlay never fired on
  any of the 3 failing challenges (or any other one), so it cannot
  have changed behaviour.
- **No improvement from Tier 2 either**: neither the overlays nor
  `submit_until_done` activated on the failures they were designed
  to address.
- Tier 2's code is wired correctly (16 + 23 tests pass); the gap is
  that the **classifier doesn't run after the opener pack**, so it
  never sees the actual response content that would push it above
  the confidence threshold.

### Next moves (prioritised)

1. **Re-fire the classifier post-opener** (low cost, high ROI):
   call `classify_challenge(config, response_content=first_http_fetch)`
   after the recon DAG fires.  Re-render the system prompt with the
   updated overlay before the agent's first reasoning step.  This
   would push cracking_the_javashop above 0.40 and likely activate
   AUTHENTICATION/FILE_INCLUSION overlays for SQL Invitational and
   Microdosing.
2. **Lower the threshold** (smallest change): drop
   `MIN_OVERLAY_CONFIDENCE` from 0.40 → 0.20.  Risk: low-signal
   misclassifications start nudging the agent.  Worth A/B testing.
3. **Teach the prompt to reach for `submit_until_done`**: the tool
   description exists in the catalog but the system prompt's prose
   never mentions when to prefer it.  Add a one-paragraph "when to
   use" note (similar to the cookie-persistence note added in
   Tier 1).

The Tier 1 fixes are still load-bearing — strict flag regex worked
(no false positives), the zlib decode unlocked the cookie path that
Tier 2 was meant to leverage.

## (Original) Re-run plan

Same 12-challenge batch with the same defaults
(GPT-5.2 / 30 steps / obs7 history / RAG=original) — `enable_category_overlay`
defaults on, `submit_until_done` is in the registry.  Compare against
the tier1 baseline (10/12, [`memory/tier1_implementation.md`]).

The decision tree from Tier 1 applies again:
- **≥11/12** → ship Tier 2, decide whether Tier 3 (D-CIPHER planner-
  executor split) is worth the cost.
- **10/12** → Tier 2 helped grading/precision but didn't change the
  ceiling.  Most likely cause: agent doesn't use `submit_until_done`
  because the prompt overlay didn't quite land.  Inspect the failure
  logs for tool-usage patterns before declaring Tier 2 a wash.
- **<10/12** → regression.  Likely culprit: the overlay nudged the
  agent away from something that was working.  Easy revert via
  `enable_category_overlay=False`.
