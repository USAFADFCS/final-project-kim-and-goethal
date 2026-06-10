# Comparative: agent control loops

How each project structures the LM-agent decision loop, vs.
`ctf_solver/agent.py`.  Populated during Phase 1.

## Dimensions to compare

For each project, capture:

1. **Roles**: how many distinct agent roles, and what state does each
   one own that the others don't?
2. **Message protocol**: what flows between roles (JSON? free text?
   structured tool calls?), and how many tokens per exchange?
3. **Step budget & termination**: how is "give up" decided?
4. **Failure recovery**: what happens when a tool fails or the LM
   produces unparseable output?
5. **Reflection / planning revision**: any explicit "rethink"
   mechanism, or just next-step ReAct?

## Reference: `ctf_solver` baseline

- Single-role custom `CTFAgent` extending fairlib's ReAct base
  ([`ctf_solver/agent.py`](../ctf_solver/agent.py))
- JSON envelope `{"thought": ..., "action": {"tool_name", "tool_input"}}`
- Sliding 16-message history window
- Stuck-loop detection in
  [`ctf_solver/tools/logging_wrapper.py`](../ctf_solver/tools/logging_wrapper.py)
  (3× → reflection, 5× → hard stop)
- Reflexion injection at challenge start from prior lessons docs

## Findings (fill in during Phase 1)

### Cybench's baseline agent — done 2026-05-16

Single-role `SimpleAgent`
([cybench/agent/agent.py:65](../agentic_systems_for_analysis/cybench/agent/agent.py))
running an "LM drives bash" loop with regex-parsed `Command:` /
`Answer:` blocks.  Sliding `(responses_to_keep=3, observations_to_keep=3)`
window.  No reflection, no replanning.  This is the architecture our
agent already beats on paper.  Full notes in
[cybench_protocol.md](cybench_protocol.md).

### EnIGMA agent loop — done 2026-05-16

Also single-role.  The novel surface is *below* the agent loop
(Summarizer, Interactive Agent Tools, declarative tool YAML), not in
the loop itself.  Pinned in
[comparative_long_output_handling.md](comparative_long_output_handling.md)
and [comparative_tool_interfaces.md](comparative_tool_interfaces.md).

### D-CIPHER Planner + Executor split — done 2026-05-16

This is the entire reason Phase 1.3 exists.  The architecture is
*remarkably simple*: a single `BaseAgent` class
([nyuctf_multiagent/agent.py:13](../agentic_systems_for_analysis/nyuctf_agents/nyuctf_multiagent/agent.py))
with three role-specific subclasses, distinguished primarily by which
*special tool* each one owns.

**Roles and special tools:**

| Role | Special tool | What it does |
|---|---|---|
| `AutoPromptAgent` | `GenAutoPromptTool` | Explores the challenge for a few rounds, then emits a tuned initial prompt for the Planner.  Optional (gated by `enable_autoprompt`). |
| `PlannerAgent` | `DelegateTool` (+ `SubmitFlagTool` + `GiveupTool`) | High-level reasoning; delegates concrete sub-tasks to executors. Owns the only path to flag submission. |
| `ExecutorAgent` | `FinishTaskTool` | Executes ONE delegated sub-task, then calls `finish_task(summary=...)`. The summary is the *only* thing returned to the planner. |

**Cross-agent message protocol:** literally just the executor's
`finish_summary: str`.  The planner sees that string as an
`Observation` from its `DelegateTool` call.  No structured handoff,
no state transfer, no shared memory.

**Executor lifecycle:** spawned *fresh per delegated task* via
`executor.new()` (agent.py:339) which creates an empty-conversation
ExecutorAgent.  Each delegation = new executor.  Old executors live
on only as log dumps in `all_executors[]`.  **This is the load-bearing
mechanism** — it gives every sub-task a clean context window with no
prior dead-ends polluting it.

**Toolset asymmetry (per
[configs/dcipher/web_planner_executor.yaml](../agentic_systems_for_analysis/nyuctf_agents/configs/dcipher/web_planner_executor.yaml)):**

```yaml
planner.toolset:  [run_command, submit_flag, giveup, delegate]
executor.toolset: [run_command, finish_task, disassemble, decompile, create_file]
```

The planner has fewer/simpler tools because it's a meta-reasoner; the
executor gets the tactical tools.  Only the planner can `submit_flag`
or `giveup` — the executor cannot accidentally end the challenge.

**Round budgets** (web variant): `planner.max_rounds=30`,
`executor.max_rounds=100`.  Planner is cheap meta-reasoning; executor
does heavy lifting.

**History compaction:** executor has `len_observations=5` (same
sliding-observation pattern EnIGMA settled on as `Last5Observations`
— **two independent projects converged on this default**).  Planner
sees its entire history un-truncated (its rounds are cheap and its
context needs to span the whole challenge).

**The autoprompter** ([agent.py:216](../agentic_systems_for_analysis/nyuctf_agents/nyuctf_multiagent/agent.py)):
a 4th agent role that exists *to generate the initial prompt*.
Runs first, explores the challenge for ≤5 rounds via `run_command`,
then emits a challenge-tuned initial prompt via `generate_prompt`
tool.  Outputs *replace* the planner's hardcoded `initial:` prompt.
Optional via `--enable-autoprompt` flag.  Modest piece, but a clean
abstraction: prompt-engineering as a first-class step.

**What the planner is told** (
[web_planner_prompt.yaml](../agentic_systems_for_analysis/nyuctf_agents/configs/dcipher/prompts/web_planner_prompt.yaml)):

> "Your job as the Planner is to devise a step-by-step plan to solve
> the given CTF challenge.  You may initially explore the CTF
> challenge for a few turns. After exploring, if you have found the
> flag you must submit it.  Else, you must generate your step-by-step
> plan. You must then delegate each step to the executor, providing a
> detailed task description to perform the step.  The Executor will
> return a summary of task completion after it is finished. You may
> alter the plan after every step."

**What the executor is told:**

> "The Planner will delegate ONE task to you. Your job is to solve
> that task, using any tools that are available to you.  At the end,
> you MUST generate a summary of your task and call the `finish_task`
> tool with the summary.  This summary will be returned to the
> Planner to evaluate and plan further tasks."

Two short paragraphs each.  No 9-tip behavior list.  Roles are tight.

**Ablation numbers (from Table III, [arXiv:2502.10931v2](https://arxiv.org/html/2502.10931v2)):**

| Model | D-CIPHER (full) | D-CIPHER w/o planner | Absolute Δ | $ per solved |
|---|---|---|---|---|
| Claude 3.5 Sonnet | 19.0% | 14.0% | **+5.0 pp** | $0.52 vs $0.36 (+44%) |
| GPT-4o | 10.5% | 9.0% | +1.5 pp | not separated |

Per-attempt cost is ~2× the single-executor cost.  The paper does
*not* break this down by category, so we don't have web-specific
deltas — only "overall CTF" deltas.  The paper's stated mechanism is:
"Each Executor starts with a fresh conversation history to focus on
the delegated task, while the Planner maintains overall context."

## Verdict

**PILOT, decision gated on Cybench numbers.**  Not "yes" (too costly
to commit without evidence on our agent's failure modes), not "no"
(the +5 pp Sonnet lift is real and the mechanism plausibly addresses
something our current architecture handles only reactively).

### Architectural rationale

D-CIPHER's planner-executor split addresses a specific failure mode:
the agent tunnels into a dead-end approach and burns its remaining
context window failing to recover.  Our system already has
*reactive* defences against this:

- Stuck-loop detection in
  [`tools/logging_wrapper.py`](../ctf_solver/tools/logging_wrapper.py)
  (3× repeat → reflection, 5× → hard stop)
- ReflectionEngine that suggests untried attack categories on stuck
- 16-message sliding window
- Reflexion injection from prior lessons

D-CIPHER's split is *structural* prevention of the same failure
mode: each delegated task starts in a clean context, so previous
dead-ends *cannot* contaminate the next attempt.  This is a different
fix from our reactive one, and the architecture suggests it's likely
*additive* rather than redundant.

### Why pilot, not commit

- **Cost overhead is real** — ~2× per attempt.  Acceptable for
  research/eval; harder for operational budget.
- **Per-category numbers don't exist** in the paper — we don't know
  whether the +5 pp generalises to web challenges (our scope) vs.
  binary/crypto where the planner may matter more.
- **Our agent has 55 specialised tools**; the D-CIPHER baseline has
  ~5 (`run_command` + 4 misc).  The "executor alone" baseline they
  beat is much weaker than our agent's solo mode.  The marginal lift
  on top of a strong solo agent could be smaller.
- **Implementation cost is bounded** — a pilot is one new file with
  a config toggle, not a refactor.  Budget: ≤200 LOC + tests.

### Pilot design (Phase 3)

New module `ctf_solver/multiagent.py` (≤200 LOC) that wraps the
existing agent build path.  Reuses the existing `CTFAgent` class as
*both* the planner-shell (with a `delegate(sub_task: str)` tool added
to its toolset, replacing `FinalAnswer` while the planner is
active) *and* the executor (spawned fresh per delegation, exits via
`finish_task(summary: str)`).

The pilot does NOT need to be a faithful D-CIPHER port.  The
minimal viable shape:

1. Add `multiagent_mode: bool = False` to
   [SolverConfig](../ctf_solver/config.py).
2. Add `multiagent_max_planner_rounds: int = 15`,
   `multiagent_max_executor_rounds: int = 30`, and
   `multiagent_planner_model`, `multiagent_executor_model` (defaults
   = primary `model_name`).
3. New file `ctf_solver/multiagent.py` exporting
   `run_multiagent(config: SolverConfig) -> RunResult`:
   - Build a "planner" agent with the existing toolset *minus*
     specialised attack tools, *plus* a new `DelegateTool` and
     `SubmitFlagTool`.
   - Loop the planner; when it calls `delegate(task=...)`, spin up a
     fresh executor (the existing `CTFAgent` build, but with system
     prompt overridden to the executor template, and with
     `delegate`/`submit_flag` removed from its toolset).
   - Run executor to completion; capture its `finish_task` summary
     (or last-N observations if it didn't call finish_task).
   - Feed summary back as an observation to the planner.
4. Wire `--multiagent` flag in `runner.py`'s `main`.

### Decision gate

Run pilot against the Cybench adapter
([cybench_protocol.md](cybench_protocol.md)) on the HTB
cyber-apocalypse-2024 web subset (9 challenges, span Very Easy →
Insane).  Compare to single-agent baseline on the same 9 challenges.
**Ship if** the multi-agent mode wins on ≥2 more challenges than the
solo baseline, *and* cost-per-success is ≤2.5× solo.  Otherwise
revert; the architecture is sound but not worth the maintenance burden
on our specific workload.
