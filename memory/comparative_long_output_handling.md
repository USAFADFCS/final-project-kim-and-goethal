# Comparative: long tool-output handling

How each project keeps long tool outputs from eating the LM's context
window, vs. `ctf_solver`'s current pre-summarisation.

## Why this dimension matters

Local-model contexts (Ollama 16k, MLX) are constantly under pressure
in our system.  A single `http_fetch` of a JS-heavy page can chew
through several thousand tokens.  Bad output handling shows up as:
trace-log bloat, stuck-loop recovery failures (the relevant history
falls out of the window), and degraded ReAct decisions late in a run.

EnIGMA explicitly cites the Summarizer as a major contributor to its
SOTA results — this is the section most likely to surface a concrete,
low-effort, high-impact port.

## Reference: `ctf_solver` baseline

- [`tools/core.py::summarize_for_llm`](../ctf_solver/tools/core.py)
  — strips `<script>` / `<style>`, collapses boilerplate, preserves
  flag-shaped strings via the configured flag regex, appends
  hash-pattern hints
- Sliding 16-message history window in
  [`agent.py`](../ctf_solver/agent.py) (2 anchors + 14 recent)
- `LoggingToolWrapper` prepends a structured header like
  `[ToolName] result=success; signal=flag_match;` before the raw
  observation
- No LM-driven summarisation of tool output — all heuristic

## Findings (fill in during Phase 1)

### EnIGMA Summarizer — done 2026-05-16

EnIGMA ships **three** registered summariser functions
([`sweagent/agent/summarizer.py`](../agentic_systems_for_analysis/SWE-agent-v0.7/sweagent/agent/summarizer.py)):

1. **`Identity`** — pass-through; no summarisation.  Used by
   `ctf_*_no_summarizer.yaml` ablation variants.
2. **`SimpleSummarizer`** (heuristic, *no LM call*) — when the
   observation exceeds `window_length` lines, the raw output is
   uploaded to `/output/<slugified_command>` inside the container and
   the response becomes `open <file>` (showing just the first
   WINDOW=100 lines).  The agent gets a manageable view + the path to
   the full raw output.
3. **`LMSummarizer`** — calls the LM with its own (system, instance)
   prompts, returns a tight summary, *also* uploads the raw to a
   file as a fallback view.

**Trigger condition** (LMSummarizer + SimpleSummarizer):
```python
if (
    any(input.startswith(s) for s in self.block_list_input)
    or len(observation.splitlines()) <= self._window_length
):
    return observation, APIStats()
```
- `block_list_input` =
  `["create", "open", "edit", "scroll_up", "scroll_down", "goto",
  "search_file", "search_dir"]` — these commands are NEVER
  summarised because they already produce window-sized output.
- Default `window_length = 105` lines.

**LMSummarizer fallback ladder:**
- If observation > 200 000 chars → falls back to `SimpleSummarizer`
- If input starts with `xxd / hexdump / strings` → falls back to
  `SimpleSummarizer` (binary-ish outputs the LM can't usefully
  summarise)
- If `ContextWindowExceededError` from the LM call → drops the
  summary, just shows the file path

**Raw output is always addressable.**  Even when summarising, the raw
observation is uploaded to `/output/<command_slug>` inside the
container.  The agent can always `open <file>` to view raw.  This is
a real win over our current heuristic-only `summarize_for_llm`,
which is lossy with no recovery path.

**Model independence.**  The summariser can use a *different* model
than the main agent ([agents.py:270](../agentic_systems_for_analysis/SWE-agent-v0.7/sweagent/agent/agents.py)):
```python
self.summarizer_model = get_model(
    args.config.summarizer_config.model
    if args.config.summarizer_config.model is not None
    else args.model
)
```
Costs are tracked separately in `self.info["summarizer"]` (model
stats + call count) so you can A/B summariser model independently of
agent model.

**Two-layer compaction.**  The summariser handles the *current*
observation; a separate `HistoryProcessor` compacts *older*
observations.  CTF configs default to `Last5Observations`:
```python
# history_processors.py:49 — last_n_history
new_history.append({
    ...entry,
    "content": f'Old output omitted ({len(entry["content"].splitlines())} lines)'
})
```
Older user messages stay in the history list as *space-preserving
placeholders* with their line count.  Demonstrations
(`is_demo: True`) and assistant messages are exempt.
`ClosedWindowHistoryProcessor` is a smarter variant that keeps only
the latest file-window view per file.

This is meaningfully better than our current 16-message sliding
window in [`ctf_solver/agent.py`](../ctf_solver/agent.py), which
simply *drops* older messages.  Their placeholder strategy preserves
sequence and gives the LM a "here was something, $N lines, now
forgotten" cue.

**Ablation grid (recovered from the YAMLs in the repo):**
- `ctf_web_no_summarizer.yaml` — drops the entire
  `summarizer_config:` block → `Identity` by default.
- `ctf_web_simple_summarizer.yaml` — replaces it with just
  `function: SimpleSummarizer; window_length: 105` (two lines).
- `ctf_web.yaml` — full LMSummarizer with custom system + instance
  templates.
- Same triple repeats for `crypto`, `pwn`, `rev`, `forensics`,
  `misc`.
- Plus a cross-cut `ctf_lm_summarizer.yaml` that combines LM
  summariser with IAT-disabled prompt text.

Reading the YAML diffs alone gives the experimental design.

## Verdict

**PORT THE LM-SUMMARIZER PATTERN, gated behind line threshold.**
This is plausibly the single highest-ROI borrow in the entire
analysis.  Our current `summarize_for_llm` is heuristic-only and
lossy; adding an LM-driven tier above ~N lines (with the raw output
saved and addressable) plugs a known pain point without disturbing
the cheap path.

**PORT THE SPACE-PRESERVING HISTORY PLACEHOLDER** at the same time.
Our 16-message sliding window drops messages outright; EnIGMA's
"Old output omitted (N lines)" preserves sequence at minimal token
cost.

**SKIP THE FILE-UPLOAD MECHANISM** verbatim — EnIGMA uploads raw to
`/output/<slug>` inside a Docker container.  We don't run in
containers; we can store the raw observation in our existing
per-run `RunTracker` instead and make it addressable via a new
`show_raw <step_id>` tool.

## Phase 3 pilot scope

**Goal:** Add an LM-summariser tier to
[`ctf_solver/tools/logging_wrapper.py`](../ctf_solver/tools/logging_wrapper.py)
that fires above a configurable line threshold, after the heuristic
`summarize_for_llm` already pre-trims.

**Minimal slice:**
1. New config knob in
   [`ctf_solver/config.py`](../ctf_solver/config.py):
   `lm_summarizer_threshold: int = 150` (lines),
   `lm_summarizer_model: str = "gpt-4o-mini"`,
   `use_lm_summarizer: bool = False`.
2. In `LoggingToolWrapper._wrap_observation` (or wherever
   `summarize_for_llm` is currently invoked): if the heuristic
   result still exceeds the threshold, route through a new
   `LMSummarizer.summarize(command, raw_output, challenge_ctx)`.
3. Store the *raw* output keyed by step-id in `RunTracker.raw_outputs`.
4. Expose a `show_raw_output(step_id)` tool the agent can call when
   it wants to see the original.
5. Track summariser cost separately in tracker metrics.

**Skip-list** (mirror EnIGMA's `block_list_input`): never summarise
output from inspection-style tools we already control the format of
(e.g. `summarize_for_llm`-formatted HTML, structured probe results).

### Cybench / D-CIPHER / NYU baseline
*(Sanity check — likely simpler truncation strategies; document what's
there but don't expect novelty.)*

## Verdict (one line, end of Phase 2)

*Expected: "Port EnIGMA's Summarizer pattern; gate it behind a token
threshold so we only pay the LM cost when our heuristic
`summarize_for_llm` isn't enough.  This is plausibly the single
highest-ROI borrow."*
