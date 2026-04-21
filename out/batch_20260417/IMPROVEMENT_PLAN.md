# Improvement Plan — MetaCTF Batch 2026-04-17

## 1. Batch Results (GPT-5.2, 30 steps, rag-mode=original)

| # | Challenge | Result | Steps | Technique | Official rate |
|---|-----------|:---:|:---:|---|---:|
| 1 | Treasure Map | ✅ | 3 | sitemap.xml recon | 86.6% |
| 2 | Direct Login | ✅ | 3 | direct `employee_portal.php` access | 62.4% |
| 3 | Door To Door | ✅ | 4 | IDOR `api/house.php?id=13` | 73.2% |
| 4 | **Open Application** | ❌ | 30 | file-upload RCE (looped) | 15.1% |
| 5 | Livestream | ✅ | 9 | websocket `session` + mass-assignment `isAdmin:true` | 27.7% |
| 6 | Dot-Matrix Destruction | ✅ | 5 | XXE `file:///flag.txt` | 13.9% |
| 7 | Super Quick Logic Invitational | ✅ | 14 | `/attempts` page shows correct-answer span | 14.8% |
| 8 | Snowfall Wishes | ✅ | 3 | client-side embedded flag | 90.3% |
| 9 | Cracking the Javashop | ✅ | 3 | JSON tamper `{"status":["open"×4]}` | 75.5% |
| 10 | Admin Portal | ✅ | 4 | cookie `role=admin` | 66.0% |
| 11 | Cookie Crackdown | ✅ | 2 | cookie inspector | 87.2% |
| 12 | Great Paywall | ✅ | 2 | DOM/CSS overlay removal | 83.0% |
| 13 | Trading Places | ✅ | 8 | HS256 JWT forge w/ leaked secret | 16.2% |
| 14 | **Microdosing** | ❌ | 30 | Flask session brute-force (looped) | 0.2% |

**12 / 14 solved = 85.7%.** Two failures, both by hitting max_steps while looping.

Also validated during batch: the prior-session v2.x fixes are live — WebSocket `session` operation (drove #5), stall detector (fires in both fails), moderation decoupling (no moderation hits this batch), opener pack default on. WASM oracle untested (no WASM challenges).

---

## 2. Gaps Identified (ranked)

### Gap A — **DEFAULT_FLAG_REGEX false positives** (HIGH)

**Symptom.** [ctf_solver/config.py:83](ctf_solver/config.py#L83): `r"(?:[A-Za-z0-9_]+)?\{[^\n\r{}]{1,200}\}"`. The `(?:...)?` makes the prefix **optional** — so `{...}` alone matches. Observed false-positive counts per run:

| Run | Real | False | Source of FP |
|---|---:|---:|---|
| 05 Livestream | 1 | 34 | JSON: `{"user":"…"}`, `{"sid":"…"}`, `{"msg":"…"}` |
| 10 Admin Portal | 1 | 6 | JSON responses |
| 07 Super Quick Logic | 1 | 5 | JSON |
| 13 Trading Places | 1 | 3 | JSON |
| 03 Door To Door | 1 | 2 | JSON |
| **04 Open Application** | **0** | **1** | agent's own PHP payload `{system($_GET['cmd']);}` |
| **14 Microdosing** | **0** | **2** | CSS `{opacity:0;…}`, `{"results":[]}` |

**Critical secondary bug.** [ctf_solver/runner.py:508](ctf_solver/runner.py#L508) sets `tracker.run_succeeded = bool(candidate_flags)` — so runs #4 and #14 record `outcome="success"` despite producing no real flag. In `LESSONS_WRITE` mode this would write **false-success atomic rules** to the experience DB, poisoning future retrieval. Our batch ran in `original` mode so nothing was written, but the flag logic itself is broken.

**Fix.** Two cheap complementary changes:
1. **Require ≥1 prefix char** in `DEFAULT_FLAG_REGEX`: drop the `?`. Platforms with bare-brace flags override via `--flag-regex` or `--flag-preset`. Change: 1 char in `config.py`.
2. **Content-shape filter** in `extract_candidate_flags`: reject candidates where inner content contains obvious JSON-key-value (`"[^"]+"\s*:`), CSS (`:\s*\d+\w*;?$`), or PHP (`\$_GET\b`, `\$_POST\b`, `system\(`, `echo\s+"`). Tightens the net without breaking custom regexes.

Effort: ~10 LOC + ~6 test cases. No behavior change for correctly-prefixed flags.

---

### Gap B — **One-shot stall nudge** (HIGH)

**Symptom.** [ctf_solver/agent.py:337](ctf_solver/agent.py#L337) guards with `if self._stall_nudge_sent: return`. Observed:

- Run #4: stall nudge fired at step 13 (last progress step 7). Agent ran ONE `ctf_knowledge_query` at step 14, then looped on file_upload/http_fetch for steps 15-30. **No second nudge.**
- Run #14: stall nudge fired at step 14 (last progress step 8). Same pattern — one RAG query at step 15, then looped on path_enumerator / sqli_probe / flask_session_forge for steps 16-30. **No second nudge.**

The nudge's own gate (`if rag_queries > 0: return` at [agent.py:345](ctf_solver/agent.py#L345)) means once the agent has queried RAG even once, the nudge is permanently disarmed — so subsequent stalls can't re-trigger it.

**Fix.** Convert to tiered re-fire:
- **Tier 1** (current): after 5 stall steps, nudge "issue one ctf_knowledge_query".
- **Tier 2** (new): after another 5 stall steps post-tier-1, nudge "abandon this vulnerability class — list 3 alternatives and try the one you haven't tried".
- **Tier 3** (new): after another 5, nudge "emit FINAL ANSWER with current best guess and stop — you are spinning".

Tracks `_stall_nudge_tier: int` instead of boolean; `rag_queries > 0` gate stays on tier 1 only. Also: reset `_last_progress_step = current_step` at each firing so the threshold applies relative to the last nudge, not the start.

Effort: ~25 LOC in `_maybe_inject_stall_nudge` + 4 tests (tier 1 fires, tier 2 fires after another stall, tier 3 fires, RunTracker records tier count).

---

### Gap C — **Progress signal counts redundant new URLs** (MEDIUM)

**Symptom.** `_observation_shows_progress` marks progress if the observation text contains *any* URL whose path is not yet in `_seen_paths` ([agent.py:310-317](ctf_solver/agent.py#L310-L317)). Failure modes:

- Run #4: every new upload (`shell_1.php7`, `shell_4.php7`, `shell.jpg`, `../shell.php7`, `/var/www/html/shell.php7`) creates a new URL path → fake progress.
- HTML observations contain CSS links, favicon URLs, API refs — any new HTML page triggers "progress".

This is why the stall detector's `_last_progress_step` kept advancing in runs #4 and #14, delaying nudges and masking real spin.

**Fix.** Complement URL-path progress with **tool-invocation repetition** tracking: record `(tool_name, normalized_target)` for each executed step; if a tuple repeats 3+ times, treat that step as *anti-progress* (do NOT advance `_last_progress_step`). `normalized_target` = primary URL param for HTTP tools, operation name for dispatching tools (file_upload, websocket_probe).

Effort: ~20 LOC, 3 tests.

---

### Gap D — **file_upload .htaccess workflow can't verify** (MEDIUM, Run #4 blocker)

**Symptom.** Run #4 called `file_upload operation=upload_htaccess target_ext=.php7`, got an opaque result, then kept trying adjacent tricks. The `upload_htaccess` operation exists but there's no self-verification step showing "the .htaccess is now live — upload a test file with ext=X and fetch it to confirm PHP execution". Agent at step 19-21 did try `.htaccess → .jpg → shell.jpg` manually, but the fetch returned raw content instead of execution, meaning the .htaccess either didn't upload or wasn't applied.

**Fix.** Enhance `file_upload.upload_htaccess`:
1. Upload `.htaccess` with `AddType application/x-httpd-php .XYZ` (XYZ chosen randomly to avoid collisions).
2. Immediately upload a tiny PHP probe with ext=XYZ containing `<?= "HTACCESS_OK_" . time(); ?>`.
3. Fetch probe URL; search for `HTACCESS_OK_` in body.
4. Return structured result: `{"htaccess_uploaded": bool, "probe_url": str, "execution_confirmed": bool, "next_ext": str}`.

Agent then knows immediately whether to move on or escalate. Effort: ~50 LOC in `upload_tools.py` + 3 tests (happy path, htaccess rejected, probe not executed).

---

### Gap E — **flask_session_forge brute wordlist is tiny** (LOW, Run #14 specific)

**Symptom.** Run #14 called `brute_secret` twice with the agent's own ~24-word lists. Real Flask secret brute needs thousands of entries. Flask-unsign ships with a ~10k common-secrets list that handles most CTF cases.

**Fix.** Ship `ctf_solver/data/flask_secrets.txt` (top 2000 entries from flask-unsign's default list — ~20 KB). `flask_session_forge` `brute_secret` uses this if no `wordlist` arg is passed. Agent gets useful coverage without guessing.

Effort: ~15 LOC + data file + 1 test (loads the file, finds a secret in a known cookie).

**Also probe Flask debug endpoints** — run #14 never hit `/console` (Werkzeug), `/debug`, `/_debug_toolbar`, `/?__debugger__=yes`. Add `flask_endpoint_probe` op to `flask_session_forge`: parallel-fetches 8 known Flask debug paths, reports anything non-404. ~25 LOC.

---

### Gap F — **verbose mode dumps full system prompt per step** (COSMETIC)

**Symptom.** [Run #7 log](07_super_quick_logic.log) with `--verbose` = 122 KB; non-verbose runs are 300-500 lines. The DEBUG dump includes the full `json_data` prompt each LLM call — 90% duplicate bytes.

**Fix.** In the LLM adapter's DEBUG logging, log only the *new* user/system message delta per turn, not the full message list. ~5 LOC.

---

## 3. Recommended Implementation Order

One commit per fix, TDD style, ordered by value/effort ratio:

1. **Gap A** — flag regex prefix + content filter. Biggest scientific-validity win, smallest change. **First.**
2. **Gap B** — tiered stall nudge. Addresses both real failures in this batch.
3. **Gap C** — tool-repetition anti-progress. Cleanly composes with B.
4. **Gap D** — htaccess self-verification. Unblocks run #4 class of challenges.
5. **Gap E** — flask secrets wordlist + debug endpoint probe. Narrow win.
6. **Gap F** — verbose log trimming. Operational cleanup, do last or skip.

Projected outcome if A–D land: #4 and #14 both solvable in ≤20 steps on re-run. Future lesson DB writes won't be poisoned by JSON/CSS false positives.

## 4. Non-goals

- No new tool classes. The existing tools cover all 14 challenges; failures were agentic (looping), not tool-absent.
- No model change. GPT-5.2 worked — the issues are in the loop harness.
- No RAG-mode changes. Batch used `original` deliberately; WRITE-mode poisoning is prevented by Gap A.
- Not rerunning the batch until A–D are shipped.
