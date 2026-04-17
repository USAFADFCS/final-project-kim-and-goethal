DEPARTMENT OF THE AIR FORCE
CADET SQUADRON 23
UNITED STATES AIR FORCE ACADEMY

07 April 2026

MEMORANDUM FOR DS CAPSTONE DIRECTOR

FROM: Cadet First Class Andrew Kim

SUBJECT: Week Nine Progress Report

1. **Purpose:** To provide the Data Science capstone director with a bi-weekly report on work completed, problems encountered, and future plans.

2. **Work Completed:**

a. Analyzed six real CTF challenge run logs against published writeups to identify systemic failures. Findings drove the remaining work items in this report:

   (1) The WASM analyzer's `scan_flags` function produced 50+ garbage "flag" matches from binary data, bloating the LLM context. Fixed by adding quality filters (`_is_plausible_flag`) and capping output to 10 matches with truncation limits.

   (2) The agent lacked an admin-bot XSS exploitation workflow. Created a comprehensive 12-payload RAG reference document (`docs/42_xss_admin_bot_exploitation.md`) covering cookie theft, localStorage exfiltration, webhook setup, and delivery mechanisms.

   (3) The challenge classifier missed admin-bot XSS patterns. Added recognition keywords (`admin bot`, `report.*url`, `bot.*visit`, `steal.*cookie`) and updated the XSS approach text with admin-bot workflow steps.

   (4) False-positive flag detection (e.g., `picoCTF{test_flag}`) was wasting steps. Implemented a placeholder flag blocklist in `config.py` with content-based quality filtering.

b. Built a robust source code analyzer (`source_analyzer.py`, ~750 lines, stdlib-only) for automated challenge source code analysis, incorporating:

   (1) Source-to-sink flow tracking inspired by Pysa/Semgrep taint analysis, organized by vulnerability class (RCE, Deserialization, SSTI, SQLi, XSS, PathTraversal) with per-class sinks, sanitizers, and severity levels.

   (2) Smart code extraction using Python AST walking to reduce large files to only security-relevant functions, cutting ~95% of tokens for files over 200 lines while preserving route handlers and dangerous patterns.

   (3) Dependency version analysis against a CVE-sourced database of ~30 vulnerable package versions across Python, Node.js, PHP, and Ruby ecosystems (e.g., Flask <2.3.0 debug PIN, PyJWT <2.4.0 algorithm confusion, node-serialize any version).

   (4) Optional Semgrep integration with 65 pre-downloaded local YAML rules across `semgrep_rules/python/` (18 rules), `semgrep_rules/javascript/` (24 rules), and `semgrep_rules/php/` (23 rules) for fully offline static analysis.

c. Added `.tar` archive support for challenge source code uploads in both the Streamlit UI (`_extract_tar()` function) and CLI runner (`_load_source_files()` rewrite), complementing existing ZIP support.

d. Implemented challenge run logging to `challenge_logs/` folder with codebase version numbers, timestamps, and full execution traces for post-run failure analysis via a new `_save_challenge_log()` function in the Streamlit app.

e. Migrated the CTF Solver's default LLM from OpenAI GPT-5.2 to Anthropic Claude Sonnet 4.6 due to persistent content policy rejections from OpenAI when generating exploitation payloads. Updated the Streamlit UI model dropdown to include `claude-sonnet-4-6`, `claude-opus-4-6`, `claude-haiku-4-5`, `gpt-4o`, and `gpt-5.2`, with Claude Sonnet 4.6 as the default.

f. Conducted a comprehensive Anthropic API compatibility audit and resolved five critical bugs:

   (1) System message handling: The FAIR framework sends tool observations as `role="system"` messages. OpenAI handles these inline, but Anthropic's adapter was extracting ALL system messages into the `system` parameter, destroying conversation flow. After multiple steps, Claude could not see any tool results—just `user→assistant→user→assistant` with observations buried in an ever-growing system prompt. Fixed by mapping only the first system message to the `system` parameter and converting subsequent ones to inline `"user"` role messages.

   (2) Factory function defaults: `create_adapter_from_config()` was not passing `max_tokens` or `timeout` kwargs to the adapter factory. The factory's hardcoded defaults (4096 tokens, 60s timeout) overrode the adapter's intended values (2048 tokens, 120s timeout), causing frequent "Request timed out" errors. Fixed by threading config values through the factory chain.

   (3) Conflicting format instructions: The system prompt contained three conflicting format specifications: the CTF prompt's format rules, the FAIR library's default format instructions (expecting `{"thought": "...", "action": {...}}`), and the CTF few-shot examples (showing `Thought: text\nAction: {"tool_name": ...}` flat text format). Resolved by clearing FAIR defaults and converting all six few-shot examples to the nested JSON format the parser expects.

   (4) Missing system prompt content: `build_agent()` was using `get_role_definition()` (a 32-line short summary with no JSON format rules) instead of `get_system_prompt()` (the full 165-line prompt with format rules, exploitation protocols, flag regex, recon priorities, and self-reflection instructions). The detailed format rules were never reaching the LLM.

   (5) Silent error handling: API exceptions were logged via `logger.error()` which was invisible in the Streamlit terminal, and errors were returned as bare `"Error: ..."` strings that triggered format recovery loops. Fixed by adding `print()` for terminal visibility and returning valid JSON fallback responses.

g. Implemented Anthropic API structured output enforcement using `output_config` with a JSON schema (`_REACT_SCHEMA`) to guarantee valid JSON responses from Claude at the API level, eliminating format error death spirals. Added graceful handling of edge cases:

   (1) `stop_reason` checking after every API call—only `end_turn` guarantees valid JSON; `refusal` and `max_tokens` produce non-conforming responses per Anthropic documentation.

   (2) JSON fallback responses for refusals and truncations that redirect the agent to `attack_planner` instead of entering format error loops.

   (3) Default `max_tokens` increased to 4096 and default `temperature` set to 0.2 for consistent structured output.

h. Implemented a consecutive format error counter with force-stop after 3 consecutive failures, preventing death spirals where format errors and premature FinalAnswer guards consumed the entire 30-step budget.

i. Expanded the test suite from 1,978 tests to 2,052 tests (74 new tests) covering all Anthropic adapter functionality, structured output handling, stop_reason edge cases, and factory defaults.

3. **Problems Encountered:**

a. OpenAI's GPT-5.2 consistently rejected the agent's system prompt due to content policy restrictions on generating exploitation payloads (XSS, SQL injection, cookie theft). This was the primary motivation for switching to Anthropic Claude Sonnet 4.6, which handles authorized CTF/security-education contexts without refusal.

b. Anthropic's Claude Sonnet 4.6 does not support assistant message prefill (`{"role": "assistant", "content": "{"}`), which was initially used to force JSON output. The API returns: "This model does not support assistant message prefill." Resolved by removing prefill entirely and using `output_config` with JSON schema enforcement.

c. Anthropic's structured output (`output_config`) does not guarantee valid JSON when `stop_reason` is `refusal` or `max_tokens`. Per Anthropic documentation: "If Claude refuses for safety reasons, the output may not match your schema." This caused intermittent format errors when the agent processed exploitation source code. Resolved with JSON fallback responses.

d. The `output_config` JSON schema initially used an empty schema `{}` for the `tool_input` field, which Anthropic rejected: "Empty schema ({}) that accepts any JSON value is not supported." Resolved by specifying `{"type": "string"}`.

e. The FAIR framework's architectural assumption that system messages work inline (as they do with OpenAI) was the single most impactful compatibility issue. Diagnosing this required tracing the full message flow from `PromptBuilder.build_message_list()` through `_prepare_messages()` to the Anthropic API call.

f. Streamlit's module caching caused the agent to use stale bytecode even after source code changes. Required clearing `__pycache__` directories and full Streamlit restarts.

4. **Analysis: Why Secure-Email-Service Cannot Be Solved by an Autonomous AI Agent**

The PicoCTF 2025 challenge "secure-email-service" (500 points, solved by only 9 of 10,000 teams) was tested against the CTF Solver agent. Despite the agent correctly identifying several components of the vulnerability (admin bot localStorage flag storage, `shadow.innerHTML` XSS sink, S/MIME signature requirement, MIME structure analysis), it was unable to solve the challenge. Analysis of the published writeup reveals the following fundamental limitations:

a. **Computational infeasibility within step budget.** The exploit requires sending ~800 emails to collect MIME boundary values, then using a z3-based Mersenne Twister state recovery solver to predict future boundary strings. The agent's 30-step budget cannot accommodate 800+ sequential API calls for data collection alone, let alone the subsequent exploitation steps.

b. **External tooling dependency.** The solve script requires `z3_crack` (a symbolic Mersenne Twister solver), `tqdm`, and an external webhook listener (requestcatcher.com) for data exfiltration. The agent has no mechanism to install Python packages, run arbitrary scripts, or set up external listening infrastructure.

c. **Multi-phase exploit coordination.** The attack requires triggering the admin bot twice in sequence: once to make the admin send a signed reply containing the XSS payload to itself, and again to make the admin open that reply and execute the XSS. The agent's single-pass ReAct-loop execution model does not support this kind of stateful multi-phase orchestration.

d. **Deep protocol knowledge requirements.** The exploit chain requires specialized knowledge across multiple domains simultaneously:

   (1) RFC 2047 Encoded-Word format (`=?ISO-8859-1?B?...?=`) to preserve newlines through the admin bot's reply pipeline.

   (2) UTF-7 character encoding (`+ADw-` for `<`) to bypass Jinja2's autoescape HTML entity encoding in the signed email template.

   (3) CPython email library internals: the `_embedded_header` regex (`\n[^ \t]+:`) can be bypassed by adding a space before the colon (`From :` instead of `From:`).

   (4) CPython `_make_boundary()` regex uses `^` and `$` anchors with `re.MULTILINE`, which can be bypassed by adding leading whitespace to injected boundary markers.

   (5) Python's `random` module uses the Mersenne Twister PRNG, which is cryptographically insecure and fully recoverable from approximately 624 32-bit outputs.

e. **Absence of creative reasoning.** The key insight—that the admin bot uses the original email's subject line in its reply, meaning the attacker can trick the admin into performing header injection on the attacker's behalf, with the result being cryptographically signed by the admin's certificate—requires a creative leap that current LLM-based agents cannot reliably make. The agent correctly identified the `shadow.innerHTML` sink and the S/MIME signing requirement, but could not bridge the gap to the reply-chain injection attack.

f. **Conclusion.** This challenge represents a class of problems that require human-level creative reasoning, deep multi-domain expertise, external computational tools, and multi-phase coordination that exceed the architectural capabilities of current ReAct-loop agents. The agent is optimized for single-vulnerability-class challenges solvable within 30 HTTP interactions—not multi-step exploit chains requiring cryptographic attacks, PRNG state recovery, and custom scripting. This finding suggests that future work on multi-agent orchestration and scripted exploit capabilities (see Future Plans) would be necessary to approach challenges of this complexity.

5. **Future Plans:**

a. Benchmark Claude Sonnet 4.6 solve rates against GPT-5.2 on the existing challenge suite to determine whether the LLM switch provides a net improvement despite the API integration complexity.

b. Investigate whether Anthropic's structured output `refusal` edge cases persist across different challenge types, or are specific to challenges with large source code uploads containing exploitation-adjacent content.

c. Explore multi-agent orchestration for challenges that require parallel reconnaissance and exploitation, as identified in the previous progress report.

d. Consider adding a "scripted exploit" capability where the agent can generate and execute Python solve scripts for challenges requiring computational steps (PRNG cracking, brute forcing, custom crypto) beyond simple HTTP interactions.

e. Evaluate whether the source code analyzer's flow tracking and dependency analysis measurably improve solve rates on source-code-provided challenges.


ANDREW J. KIM, Cadet, USAF
CS-23 Chief of Staff

Documentation Statement:
- Claude helped me draft this progress report based on work completed across multiple development sessions since the Week Seven report. The analysis of secure-email-service limitations is based on the published writeup at corgi.rip/posts/secure-email-service and comparison with the agent's observed behavior during testing.
