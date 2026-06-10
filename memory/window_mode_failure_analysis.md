# Capability-gap analysis — the two challenges that failed in both window modes

Both `super_quick_logic_invitational` and `microdosing` burned all 30
steps in both `baseline` and `obs7` runs (see
[`window_mode_experiment.md`](window_mode_experiment.md)).  Window
tuning was *not* the lever — these are real capability gaps.  This
note walks the failure traces and identifies the gap precisely.

## Method

For each failure I read the full
[`out/batch_window_test/logs_baseline/<slug>.log`](../out/batch_window_test/logs_baseline/)
(both modes had near-identical failure patterns; baseline was a
sufficient trace).  I extracted the tool-call sequence, the LLM's
running theory ("Thought:" lines), and the body content the server
actually returned at each pivot point.

## Failure 1 — Super Quick Logic Invitational

**Challenge shape:**  Trivia game at `/game`.  Initial root `/`
returns 403, only `/game` is reachable (after providing a browser
User-Agent).  Each problem has an `id` and an `answer` parameter
posted to `/submit` along with a CSRF token from a Flask session
cookie.  The "impossible question" is *"What is the flag for this
CTF challenge?"* — the intended exploit bypasses the answer check
to advance through all problems and reveal a flag.

**What the agent did well:**

- Bypassed the 403 with a browser User-Agent (step 7)
- Found the `/submit` endpoint from inline JS (step 9)
- Probed SQLi on the `answer` parameter and got `vuln_signal partial`
  (step 11)
- Correctly identified the backend as SQLite from the error
  `"unrecognized token"` (step 14)
- Built a working `UNION SELECT 1,2,3,4 -- ` payload by incrementally
  testing column counts (steps 14–17)
- One submission returned `correct=true` (step 17)

**Where it broke down:**

1. After the first correct submission, the Flask session cookie
   rotated.  `/game` started returning 403, so the agent couldn't
   retrieve the next CSRF token to chain the next attack.
2. The agent tried `flask_session_forge` — and the *tool reported it
   couldn't decode* (step 24).  But the file
   [`session_forgery_tools.py:664-674`](../ctf_solver/tools/session_forgery_tools.py)
   shows `flask_session_forge` *does* handle zlib-compressed sessions
   in code; the decode failure was either a bug or a non-standard
   compression header on this specific cookie.
3. The agent fell back to manual `shell_execute` with
   `base64.urlsafe_b64decode + zlib.decompress` and *succeeded* at
   decoding (step 25).  But then ran out of steps to:
   - Brute-force the Flask SECRET_KEY (the tool's 262-entry CTF
     wordlist would have been tried in seconds, but the agent never
     reached that path)
   - Forge a session with the new state
4. Final 5 steps were burned on cookie-jar debugging.

**Capability gaps identified:**

- **G1 (real bug):** `flask_session_forge`'s zlib-decode path
  silently fails on certain Flask versions instead of returning a
  helpful error.  The agent reported "Flask tool couldn't decode"
  but the tool code *should* have handled this — needs reproduction
  + fix.
- **G2 (composition):** No tool composes "play this game to completion
  via SQLi" into one call.  Each turn through the trivia game costs
  one step, and the 30-step budget is exhausted long before reaching
  the score threshold.  A `game_loop` or `submit_until_done` tool
  that takes (URL, payload-template, success-marker) and loops server
  -side would fix this.
- **G3 (real bug):** The shared `requests.Session` appears to not
  cleanly carry cookies between tool calls in some cases.  Agent
  reported "cookie rotated" between successive tool calls — even
  when the same `requests.Session` should have been in use.  Needs
  diagnosis in
  [`tools/core.py`](../ctf_solver/tools/core.py) /
  [`tools/http_tools.py`](../ctf_solver/tools/http_tools.py).

## Failure 2 — Microdosing

**Challenge shape:**  A Flask app for "medical titration studies"
with a `/dashboard` containing a `/search` POST endpoint (15-char
limit on input from inline JS).  The flag is presumably in
admin-only records accessible via auth bypass or NoSQL injection.

**What the agent did well:**

- Recon → found `/dashboard`, `/login`, `/search`
- Identified the Flask session cookie format and tried to decode it
- Called `nosql_probe` and got `vuln_signal partial` on `/search`
  (step 14)
- Tried Flask session brute-force (step 21 — "Try brute_secret with
  common secrets quickly")
- Considered LFI ("LFI to read source/config for SECRET_KEY",
  step 22)
- Considered SSTI in search/report rendering
- Considered IDOR

**Where it broke down:**

1. The `/search` endpoint returned **HTTP 500 + JSON body
   `{"error":"Search failed"}`** for every payload tried — including
   the baseline `search=a`.  No useful error detail leaked.  The
   agent looped on this for ~10 steps trying form encoding, JSON
   bodies, NoSQL operator notation (`search[$ne]=1`), without ever
   getting a non-500 response.
2. The agent *thought about* LFI to read source for SECRET_KEY but
   never actually invoked `lfi_probe` — even though the tool is
   registered (verified in the run's full tool list, 76 tools
   total).
3. The agent tried `flask_session_forge` three times.  Same
   decode/brute-force failure pattern as Failure 1 — the 262-entry
   wordlist didn't crack this challenge's SECRET_KEY (which means
   either the key is non-default or the tool isn't trying the
   wordlist correctly).
4. A `flag_match` signal fired from `javascript_source` (step 17) —
   *but it was a false positive*: the flag-shaped string was a CSS
   color object in Tailwind's bundled JavaScript (`slate:{50:...}`
   etc.).  The agent correctly did not act on it.

**Capability gaps identified:**

- **G4 (composition):** Agent had three plausible attack hypotheses
  (NoSQLi via JSON body, LFI to extract SECRET_KEY, IDOR on admin
  records) but couldn't iterate through them in 30 steps because
  most of the budget was burned debugging `/search`'s opaque 500s.
- **G5 (real gap):** No "exhaust hypothesis-A then move to
  hypothesis-B" higher-level structure.  D-CIPHER's planner /
  executor split (memory note
  [`comparative_agent_loops.md`](comparative_agent_loops.md))
  addresses exactly this — the planner would have said "burned 10
  steps on NoSQLi, switch to LFI" much sooner.  This is the
  strongest data point in the analysis for porting the multiagent
  pattern.
- **G6 (tool-selection):** `lfi_probe` exists and is registered, but
  the agent didn't call it even when its own reasoning explicitly
  named LFI as the most plausible next move.  Possible causes:
  - The tool's description in the system prompt isn't compelling
    enough vs. competing tools.
  - The phase gate (`enable_phase_gate`) may be blocking it because
    no LFI-category signal has been confirmed yet — needs check.
  - The agent's tool-budget heuristic deprioritizes "probe" tools
    when it's already past mid-run.
- **G7 (false-positive flag detection):** The agent's flag regex
  `[A-Za-z0-9_]+\{[^\n\r{}]{1,200}\}` is too permissive — matches
  Tailwind color objects, JS short-circuit expressions, and CSS
  variable declarations.  Worth tightening to require the prefix
  to be a known CTF format (e.g. `(?:metaCTF|MCTF|HTB|FLAG|flag|
  picoCTF)\{...\}`) for the *strict* signal, while keeping the
  permissive regex as a *candidate* signal that the agent doesn't
  treat as final.

## Cross-cutting observations

Both failures share three structural patterns:

1. **The agent's hypothesis-formation is good.**  It identifies the
   correct attack class in both cases.  SQL Invitational: "this is
   a Flask SQLi + session-forging challenge."  Microdosing:
   "this is Flask + NoSQLi or LFI to read SECRET_KEY."  These are
   correct intuitions.

2. **The execution loop is the bottleneck, not the hypothesis.**
   30 steps × 1 tool/step = 30 atomic actions.  Multi-step exploits
   (loop a SQLi to win the game; iterate hypotheses to find the
   right vuln) need more than 30 atomic actions, even when the
   hypothesis is right.

3. **Tools that exist aren't always reached.**  `lfi_probe`,
   `flask_session_forge`'s brute-force path — both available, neither
   invoked in the failure cases.  This points at the agent's
   tool-selection heuristic rather than a missing capability.

## Concrete recommendations, ranked

Ordered by ratio of (expected impact on these two failures) /
(implementation cost).

### Tier 1 — high ROI, low cost

1. **Fix `flask_session_forge` zlib-decode failure mode.**  The code
   should handle the case; the tool reported failure anyway.  Add a
   regression test that decodes the cookie from the SQL Invitational
   log
   ([`logs_baseline/super_quick_logic_invitational.log` step 24]),
   verify error messaging gives the agent actionable next steps.
   Estimate: 1–2 hours.

2. **Tighten the flag-regex strict detection.**  Add a known-format
   prefix list to
   [`config.py`](../ctf_solver/config.py): default
   `(metaCTF|MCTF|HTB|FLAG|flag|picoCTF|CTF|UTCTF|MetaCTF)\{...\}`.
   Treat broad matches as *candidate* flags (kept in tracker for
   audit), strict matches as *confirmed* (eligible for Final
   Answer).  Would have prevented the Livestream false positive
   from baseline run and the Microdosing CSS noise.  Estimate: 1
   hour.

3. **Diagnose the session-cookie rotation issue (G3).**  Add a one-
   line print of `session.cookies.get_dict()` to a few key tools so
   the next run reveals whether cookies actually rotate or whether
   the agent is just wrong about why `/game` 403s.  Estimate: 30 min
   diagnostic + however long the fix takes.

### Tier 2 — medium ROI, medium cost

4. **Add a `game_loop` or `submit_until_done` tool.**  Signature:
   `submit_until_done(url, method, body_template, success_marker,
   max_iterations, share_session=True)`.  Runs server-side without
   consuming agent steps.  Would have solved SQL Invitational
   outright (one tool call replays the SQLi until the flag appears).
   Estimate: 4 hours including tests.

5. **Per-category prompt overlays
   ([`comparative_eval_harnesses.md`](comparative_eval_harnesses.md)).**
   Category-specific tool emphasis: when the classifier says "this
   is a Flask session forgery challenge," put `flask_session_forge`
   and `lfi_probe` higher in the system prompt's tool ordering.
   D-CIPHER convergence + EnIGMA convergence both support this.
   Would have nudged the agent to try `lfi_probe` in Microdosing.
   Estimate: half a day.

### Tier 3 — strategic, high cost

6. **Implement the D-CIPHER planner-executor pilot
   ([`comparative_agent_loops.md`](comparative_agent_loops.md)).**
   The Microdosing failure is the textbook case for this — the agent
   had three plausible hypotheses but couldn't iterate through them.
   A planner would have said "burned 10 steps on `/search`, pivot to
   LFI" much sooner.  But this is the highest-cost port (~200 LOC,
   2× API cost, requires running the planner and executor as separate
   conversations).  Don't do this *before* Tier 1 and 2 — they're
   cheaper diagnostics that may resolve the same failures.

## Decision

Implement **Tier 1 (items 1, 2, 3)** before any further architectural
work.  All three are bug fixes / regex tweaks, not refactors; each is
1–2 hours of focused work; each addresses an issue surfaced by
*both* failing challenges.

After Tier 1, re-run the same 12-challenge suite to see if either
failure flips.  Use the results to decide whether to invest in Tier 2
or jump straight to Tier 3.
