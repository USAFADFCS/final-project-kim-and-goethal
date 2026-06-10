# Phase 2 synthesis — what the four projects together say

Consolidated decision input for Phase 3.  Each row below distils the
verdict from one of the five comparison files.  Treat this as the
single page that determines what gets ported.

## The five verdicts

| Dimension | File | Verdict |
|---|---|---|
| Agent loop | [comparative_agent_loops.md](comparative_agent_loops.md) | **PILOT** planner+executor; ship if it wins ≥2 more challenges on Cybench HTB-web and cost ≤2.5× solo |
| Tool interfaces | [comparative_tool_interfaces.md](comparative_tool_interfaces.md) | **PORT** the `# @yaml` self-describing tool pattern; keep our Python `.use()` runtime |
| Memory / cross-run | [comparative_memory_systems.md](comparative_memory_systems.md) | **WE WIN** — keep our lessons-learned RAG, port nothing cross-run |
| Long-output handling | [comparative_long_output_handling.md](comparative_long_output_handling.md) | **PORT** EnIGMA's LMSummarizer tier with raw-output addressability; **PORT** space-preserving history placeholders |
| Eval harnesses | [comparative_eval_harnesses.md](comparative_eval_harnesses.md) | **BUILD** two thin adapters sharing one core; pilot on NYU first |

## Convergent patterns — independent teams that agreed

These are the strongest signals from the analysis: when two or three
independent teams converge on the same number/choice without coordination,
that's a best-practice signal worth weighting.

1. **`len_observations = 5` sliding window for executors.**  Both
   EnIGMA (default `Last5Observations` history processor) and D-CIPHER
   (executor config `len_observations: 5`) settled on this value.
   Two independent teams, same answer.  Our current default is 16
   messages (2 anchors + 14 recent) — worth A/B testing 5 against 16
   on web challenges.  Cheap experiment, potentially meaningful win.

2. **Substring-anywhere grading on tool output.**  Both Cybench
   ([grade_benchmark.py:84](../agentic_systems_for_analysis/cybench/grade_benchmark.py))
   and NYU CTF Bench
   ([challenge.py:39](../agentic_systems_for_analysis/NYU_CTF_Bench/python/nyuctf/challenge.py))
   mark a challenge solved if the flag appears anywhere in observed
   output, not just in a formal answer.  Means **our adapter does not
   need to mimic anyone's response format** — flag appearance in tool
   output is sufficient, and our `LoggingToolWrapper` already captures
   flag-shaped tokens.

3. **Per-category prompt specialization in configs.**  D-CIPHER ships
   6 category-specific planner + executor prompt pairs (web, pwn,
   crypto, rev, forensics, misc).  EnIGMA ships 6 categories × 4
   ablation variants in its `config/ctf/` dir.  Both independently
   decided category-tailored prompts beat one-size-fits-all.  Our
   `ChallengeClassifier` produces categories but
   [prompts/templates.py](../ctf_solver/prompts/templates.py) is
   one global system prompt.  Worth piloting per-category prompt
   overlays.

4. **Docker-compose for challenge service isolation.**  Cybench, NYU
   CTF Bench, and D-CIPHER's CTFEnvironment all use docker-compose
   for the challenge service container.  Our eval adapters should
   follow suit.

## Divergent patterns — where projects disagree

When teams disagree, the right answer depends on workload, not best
practice.

1. **Single-agent vs. multi-agent loop.**  D-CIPHER alone goes
   multi-agent; EnIGMA, Cybench, and our system are single-agent.
   The ablation lift (+5 pp Sonnet / +1.5 pp GPT-4o on NYU) is real
   but modest.  Decision: pilot, gate on numbers (see
   [comparative_agent_loops.md](comparative_agent_loops.md)).

2. **Tool implementation model.**  EnIGMA: shell/python scripts with
   `# @yaml` docstrings, autoparsed.  D-CIPHER: Python classes with
   `NAME / DESCRIPTION / PARAMETERS / REQUIRED_PARAMETERS` plus
   function-call schemas.  Cybench: no tool library at all; LM drives
   raw bash.  We use FAIR Python classes with `.use(json_str) -> str`.
   Our model is closest to D-CIPHER, but EnIGMA's `# @yaml` *docstring*
   pattern is orthogonal to execution model and worth borrowing
   regardless.

3. **Summarization sophistication.**  EnIGMA: 3-tier (Identity /
   SimpleSummarizer / LMSummarizer) with skip-list, fallback ladder,
   addressable raw outputs.  D-CIPHER: simple truncate-to-25K-chars.
   Cybench: brutal tokenizer-based "keep first half + last half".
   Our `summarize_for_llm` is closer to D-CIPHER's heuristic but with
   semantic awareness (strips scripts, preserves flags).  EnIGMA's
   LM tier is the clear winner here for long outputs.

4. **Cost-cap model.**  D-CIPHER caps in dollars (per-attempt cost
   tracked by backend).  Cybench caps in iterations + tokens.  Ours
   caps in steps.  All three are defensible; the dollar cap is most
   honest about real spend but harder to make portable across
   local-model and hosted-model configs.

## Where `ctf_solver` is *uniquely strong*

These are areas where we lead all four projects — guard them; don't
regress while porting other patterns.

1. **Cross-run learning (lessons-learned RAG).**  Confirmed by Phase
   2 grep sweep: nobody else has anything comparable.
2. **Tool specialization breadth** — 55 web-exploit Python classes
   vs. D-CIPHER's ~5, EnIGMA's ~10, Cybench's 0.  Different game.
3. **Multi-provider LLM support** — OpenAI / Anthropic / Ollama / MLX
   with provider-specific tuning.  All comparators are
   OpenAI/Anthropic-only.
4. **Production UI affordances** — Qt + Streamlit, run history,
   batch processing, source-file upload.  All comparators are
   CLI-only.

## Where `ctf_solver` is *uniquely weak*

These are areas where every comparator does something we don't.

1. **Tool docstring duplication.**  Hand-curated tool descriptions in
   [`prompts/templates.py`](../ctf_solver/prompts/templates.py) (45.6 KB)
   duplicate what's already in the Python tool classes.  EnIGMA's
   `# @yaml` block solves this.
2. **No LM-tier summarization.**  Our `summarize_for_llm` is purely
   heuristic; long outputs that survive it consume context unchecked.
3. **No raw-output addressability.**  Once `summarize_for_llm` runs,
   the original is in the trace log but not retrievable by the agent
   mid-run.
4. **No subtask decomposition / planner.**  When the agent tunnels
   into a dead-end, our stuck detection is *reactive* (3× → reflect,
   5× → hard stop); D-CIPHER's planner spawning fresh executors is
   *structural* prevention.
5. **No published benchmark number.**  Cybench / NYU CTF Bench /
   HackTheBox results are all on public leaderboards.  Until we run
   an adapter, our project lacks comparable evidence.

## Ranked Phase 3 candidates

Ordered by **expected-value-per-effort** for our web-CTF use case.
Effort in LOC is a working estimate.

| # | Pattern | Source | Effort | Risk | Expected lift |
|---|---|---|---|---|---|
| 1 | **NYU CTF eval adapter** | NYU_CTF_Bench | ~40 LOC + tests | Low | Unblocks every comparison; first real benchmark number |
| 2 | **EnIGMA `# @yaml` tool-docstring pattern** | EnIGMA v0.7 | ~60 LOC parser + 3 pilot tools | Low | Eliminates ~45 KB of doc duplication; cleaner prompt |
| 3 | **LMSummarizer tier + raw-output addressability** | EnIGMA v0.7 | ~120 LOC | Medium | Plausibly highest-impact single fix for long-output failures |
| 4 | **Cybench eval adapter** | Cybench | ~150 LOC + Docker handling | Medium | Second benchmark number; published-leaderboard comparison |
| 5 | **Planner-Executor pilot (multiagent mode)** | D-CIPHER | ~200 LOC + new prompts | Medium-High | +5 pp on NYU per their ablation; 2× cost overhead |
| 6 | **Per-category prompt overlays** | D-CIPHER + EnIGMA convergence | ~60 LOC + 6 prompt files | Low-Medium | Modest; complements existing classifier |
| 7 | **A/B `len_observations` = 5 vs. 16** | D-CIPHER + EnIGMA convergence | trivial config change | Trivial | Unknown but cheap to find out |
| 8 | **Space-preserving history placeholders** | EnIGMA | ~30 LOC | Low | Marginal vs. our current drop-the-oldest |
| 9 | Demonstration trajectory replay | EnIGMA | ~80 LOC | Medium | Speculative; only valuable if it outperforms our atomic-rule RAG |
| 10 | Interactive Agent Tools (gdb / connect) | EnIGMA | ~150 LOC | Medium | Off-mission for web CTF; defer until we expand into pwn |

## Phase 3 sequencing recommendation

Per the original roadmap, **pick top 3, no more**.  My recommendation:

- **Pick #1 (NYU adapter), #2 (`# @yaml`), #3 (LMSummarizer).**
  Total budget ~220 LOC.  All three are low-risk, complement each
  other (LMSummarizer needs the eval to measure), and don't preclude
  later adopting #4 or #5.

- **Defer #5 (multiagent).**  Higher cost, gated on Cybench numbers
  per the [comparative_agent_loops.md](comparative_agent_loops.md)
  decision.  We can't run that gate until the Cybench adapter (#4)
  exists.  So the natural ordering is: NYU adapter → ship → measure
  baseline → Cybench adapter → measure baseline on Cybench →
  multiagent pilot → measure delta → ship/revert.

- **Defer #6–#10.**  Each is plausibly worth doing eventually but
  the Phase 3 discipline is "top 3, then stop and measure."

Phase 3 will convert items 1–3 into specific `# TODO:` comments at
the exact files where the work goes (which they already partially
are, from Phase 1.x), then delete the lower-priority candidates
from this synthesis.  Items 4 and 5 stay as named pointers because
they're load-bearing for the decision gate; 6–10 get cut.
