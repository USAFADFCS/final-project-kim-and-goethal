# Agentic systems under study

Four open-source agentic-cybersecurity projects cloned into
[`agentic_systems_for_analysis/`](../agentic_systems_for_analysis/) for
architectural comparison against `ctf_solver`.  Scope: pull *patterns*,
not code.  Don't copy implementations wholesale — most of these projects
are general pentest agents; ours is a specialised web-CTF solver and the
borrowable surface is narrower than it looks.

## The four projects

### Cybench — Stanford
- Path: [`agentic_systems_for_analysis/cybench/`](../agentic_systems_for_analysis/cybench/)
- Pinned commit: `88d68932` (2026-04-22, `main`)
- Paper: Zhang et al., "Cybench: A Framework for Evaluating
  Cybersecurity Capabilities and Risks of Language Models",
  [arXiv:2408.08926](https://arxiv.org/abs/2408.08926)
- License: Apache-2.0
- **One-line value:** an evaluation harness over 40 CTF tasks from 4
  competitions, with both unguided and subtask-graded modes, and a
  standardised agent contract any external agent can plug into.
- **Why it's here:** primary external benchmark.  Not architecturally
  novel for us; it's the *yardstick*.
- **Caveats:** Stanford's own follow-up evaluation
  ([BountyBench](https://bountybench.github.io/)) is now their focus.
  Cybench is feature-complete but no longer actively extended.

### SWE-agent / EnIGMA — Princeton + Stanford (+ NYU/TAU for EnIGMA)
- Path: [`agentic_systems_for_analysis/SWE-agent/`](../agentic_systems_for_analysis/SWE-agent/)
- Pinned commit: `0f4f3bba` (2026-03-24, `main`, `v1.1.0-153`)
- Papers:
  - Yang et al., "SWE-agent: Agent-Computer Interfaces Enable Automated
    Software Engineering", NeurIPS 2024
    ([arXiv:2405.15793](https://arxiv.org/abs/2405.15793))
  - Abramovich et al., "EnIGMA: Interactive Tools Substantially Assist
    LM Agents in Finding Security Vulnerabilities",
    [arXiv:2409.16165](https://arxiv.org/abs/2409.16165)
- License: MIT
- **One-line value:** a general LM-agent framework configured entirely
  by a single YAML file (the Agent-Computer Interface), whose EnIGMA
  mode adds *interactive stateful tools* (debugger, server connection)
  plus an output Summarizer to push CTF performance to SOTA on three
  benchmarks.
- **Why it's here:** smallest concrete borrowable units (tool YAML
  contract, Summarizer, interactive-tool pattern).  Highest expected
  ROI per hour of reading.
- **Worktree layout:** EnIGMA lives on the v0.7 line, not on `main`.
  We have *two* worktrees sharing the same `.git`:
  - [`SWE-agent/`](../agentic_systems_for_analysis/SWE-agent/) at
    `main` (`0f4f3bba`, v1.1.0+153) — the framework as it exists now
  - [`SWE-agent-v0.7/`](../agentic_systems_for_analysis/SWE-agent-v0.7/)
    at tag `v0.7.0` (`dc18a740`, detached HEAD) — the EnIGMA-era
    source.  This is what Phase 1.2 reads.
  Confirm at any time with `git worktree list` from either dir.
- The repo also warns that *all current dev effort* has moved to
  [mini-swe-agent](https://github.com/SWE-agent/mini-swe-agent/),
  which is "simpler and matches performance" — worth a glance, but
  not in scope for this analysis.

### D-CIPHER (nyuctf_agents) — NYU
- Path: [`agentic_systems_for_analysis/nyuctf_agents/`](../agentic_systems_for_analysis/nyuctf_agents/)
- Pinned commit: `6bb4d2b4` (2025-10-26, `main`)
- Paper: Udeshi et al., "D-CIPHER: Dynamic Collaborative Intelligent
  Multi-Agent System with Planner and Heterogeneous Executors for
  Offensive Security",
  [arXiv:2502.10931](https://arxiv.org/abs/2502.10931)
- License: MIT
- **One-line value:** a multi-agent CTF solver that splits a Planner
  agent from heterogeneous Executor agents and adds an optional
  Auto-prompter, reporting 22.0% / 22.5% / 44.0% on NYU CTF / Cybench
  / HackTheBox — a 2.5–8.5% absolute lift over prior single-agent
  baselines and 65% more MITRE ATT&CK techniques covered.
- **Why it's here:** the deepest architectural question — should our
  single ReAct loop become a planner+executor pair?  The repo ships
  both `run_dcipher.py` *and* a `run_single_executor.py` ablation, so
  the experiment is reproducible.
- **Caveats:** lift over baselines is meaningful but not transformative;
  the planner adds real token cost we'd need to weigh.

### NYU CTF Bench — NYU
- Path: [`agentic_systems_for_analysis/NYU_CTF_Bench/`](../agentic_systems_for_analysis/NYU_CTF_Bench/)
- Pinned commit: `4c5744f5` (2025-09-22, `main`, `v20250206-7`)
- Paper: associated with the same CSAW group; the dataset is the
  benchmark that D-CIPHER and EnIGMA are tested against
  ([nyu-llm-ctf.github.io](https://nyu-llm-ctf.github.io))
- License: see repo (CSAW challenge IP)
- **One-line value:** 200 dockerized CSAW CTF challenges (with a
  55-challenge dev split) across 6 categories — web, pwn, forensics,
  rev, crypto, misc — exposed as a Python package (`pip install
  nyuctf`) with programmatic challenge loading.
- **Why it's here:** secondary external benchmark, complementary to
  Cybench.  Strong web-challenge representation.  Likely a unified
  eval adapter handles both.
- **Caveats:** dataset only, no agent.  Phase 1.4 is short.

## Scope discipline

The roadmap explicitly excludes mini-swe-agent, BountyBench, AWE,
HackingBuddyGPT, CAI, and PentestGPT from this analysis.  All four
projects above are *enough* to identify the patterns worth porting.
Adding more would just dilute attention.

## Phase 0 outputs

- This file — the four projects, version-pinned, with caveats.
- Five comparative scaffold files for Phase 1 to populate:
  - [comparative_agent_loops.md](comparative_agent_loops.md)
  - [comparative_tool_interfaces.md](comparative_tool_interfaces.md)
  - [comparative_memory_systems.md](comparative_memory_systems.md)
  - [comparative_eval_harnesses.md](comparative_eval_harnesses.md)
  - [comparative_long_output_handling.md](comparative_long_output_handling.md)
