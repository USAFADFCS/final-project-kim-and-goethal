# Comparative: memory & state across runs

How each project persists information between agent invocations, and
how it avoids contamination, vs. `ctf_solver`'s lessons-learned RAG.

## Prior expectation

Based on prior research, this is the dimension where `ctf_solver`
likely *wins*.  None of these four projects ship a sophisticated
cross-run learning loop; most are stateless between runs.  Phase 1
should *confirm* this, then move on — we should not regress our
strengths.

## Reference: `ctf_solver` baseline

- FAISS-backed knowledge base in
  [`ctf_solver/rag/`](../ctf_solver/rag/), with BM25 + vector hybrid
  retrieval, query expansion, and reranking
- Atomic-rule lessons-learned pipeline in
  [`ctf_solver/failure_analyzer.py`](../ctf_solver/failure_analyzer.py),
  ExpeL-style: causal explanations, Reflexion summaries, do / do_not
  rules, cross-run confidence merging via Jaccard similarity on
  triggering conditions
- Contamination filter: docs from the same challenge are excluded from
  retrieval (slug + content fingerprint)
- Flag scrubbing: extracted flags replaced with `[FLAG_REDACTED]`
  before docs are written to the KB
- Optional `gpt-4o-mini` enrichment for causal explanations
- See `memory/MEMORY.md` (auto-memory index) v2.3–v2.6 entries for the
  full design history

## Findings — done 2026-05-16

Verified via `grep` sweep across all three agent projects for
`faiss / chromadb / qdrant / sentence_transformers / sqlite /
embeddings / vector_store / knowledge_base / rag / atomic_rule /
lessons_learned / experience_db / prior_runs`.  Zero hits in agent
code.  The expectation from Phase 0 holds.

### Cybench
**No cross-run state.**  `SimpleAgent` runs each task cold; no
database, no embedding store, no cached prior runs.  Caching layer
in [grading/](../agentic_systems_for_analysis/cybench/grading/) is
only for *aggregating result JSONs after the fact*, not for the
agent's own use.  Sliding-window context (`responses_to_keep=3`,
`observations_to_keep=3`) is purely intra-run.

### EnIGMA (v0.7)
**No cross-run state.**  Each invocation reads its YAML config +
optional demonstration trajectory file and runs cold.  *Intra-run*
state is more interesting than ours:

- **Raw observations are addressable via files** — when the
  Summarizer fires, the raw tool output is uploaded to
  `/output/<slugified_command>` inside the container, and the agent
  can `open <file>` later to retrieve it.  We have no equivalent —
  raw output lives in our trace log but the agent can't pull it
  back mid-run.
- **Interactive sessions (gdb, connect) are persistent subprocesses**
  within a run — state survives across agent turns.  Our tools are
  stateless per `.use()` call.
- **Demonstration trajectories** (`.traj` files) are static few-shot
  exemplars loaded at start, not learned memory.

### D-CIPHER (nyuctf_agents)
**No cross-run state.**  The autoprompter explores the challenge in
real-time before each run; it does not consult any prior-run store.
*Intra-run* state:

- **Planner's conversation persists** across many executor
  delegations — the planner accumulates "I delegated X, got summary
  Y" history.  Closest equivalent in our system would be the agent's
  own ReAct chat history, but ours doesn't have the planner's
  meta-level summarisation cycles.
- **Executors are stateless across delegations** — `executor.new()`
  spins a fresh empty-conversation ExecutorAgent each time.
- **No persistent KB** — logs are dumped per-run as JSON, never read
  back.

### NYU_CTF_Bench
N/A — dataset, not an agent.  Challenges have an immutable `flag`
field, no memory.

## Reference state-of-the-art: `ctf_solver`

We are the only project in this comparison with a real cross-run
learning system:

- **FAISS vector store** + sentence-transformers embeddings in
  [`rag/knowledge_base.py`](../ctf_solver/rag/knowledge_base.py)
- **Atomic-rule extraction** (ExpeL pattern) in
  [`failure_analyzer.py`](../ctf_solver/failure_analyzer.py): causal
  explanations, Reflexion summaries, do / do_not rules
- **Cross-run confidence merging** via Jaccard similarity on
  triggering conditions
- **Content-fingerprint contamination filter** prevents same-site
  lessons from polluting same-site runs
- **Flag scrubbing** before KB write
- **Optional gpt-4o-mini causal-explanation enrichment**
- **4 RAG modes** (none / lessons_readonly / lessons_write /
  lessons_buildonly) gating write-side behavior

This is plausibly the most sophisticated experience-DB in any
open-source CTF agent on inspection — none of EnIGMA, D-CIPHER,
PentestGPT, HexStrike, or AWE (per Phase-0 survey) have anything
comparable.

## Verdict

**No cross-run port — we are state-of-the-art here.  Keep our
lessons-learned RAG.**

There are however **two intra-run patterns worth considering as
Phase-3 candidates**, both already noted in their respective files
but flagged here so the decision input is complete:

1. **Raw-output addressability** ([comparative_long_output_handling.md](comparative_long_output_handling.md))
   — port from EnIGMA: store raw observations keyed by step-id in
   `RunTracker.raw_outputs`, expose a `show_raw_output(step_id)`
   tool.
2. **Stateful tool sessions** ([comparative_tool_interfaces.md](comparative_tool_interfaces.md))
   — defer; EnIGMA's gdb / netcat sessions are not relevant to web
   CTF, and our shared `requests.Session` already gives us
   cookie-stateful HTTP.
