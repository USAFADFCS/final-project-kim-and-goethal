---
title: "Path to A — DATA 422 Final Capstone Plan"
subtitle: "Automated CTF Program (Cadet-Initiated)"
author: "C1C Andrew Kim · USAFA/DFMA"
date: "29 April 2026"
geometry: margin=1in
fontsize: 11pt
linkcolor: blue
toc: true
toc-depth: 2
---

# 0. Document Purpose

This is your day-by-day execution plan from **today (Wed 29 Apr 2026)** through the
**Final Paper deadline (COB Fri 8 May 2026)**. Every step is tagged with the rubric
criterion it earns and the artifact it produces. Code blocks are ready to paste —
modify paths only.

The plan assumes:

- You brief on the **earliest** Final Outbrief slot (Mon 4 May, T38). If you brief
  later (T39 = Wed 6 May or T40 = Fri 8 May) the buffer days at the end grow.
- You will use a **hybrid backend**: OpenAI API for the bulk benchmark sweep,
  Ollama (gemma4:26b) for a smaller subset that anchors the local-model thread.
- This is a **cadet-initiated, individual capstone** with Lt Col Todd as mentor
  (no external sponsor). The "decision-quality recommendations" rubric line maps
  to recommendations for (a) Lt Col Todd's research interests, (b) future cadet
  researchers continuing this work, and (c) an explicit "what would a master's
  thesis follow-on look like" section.

# 1. How a Cadet-Initiated Capstone Changes the Rubric Mapping

The Course Letter and the rubrics use the word "sponsor" frequently. For your
project there is no operational sponsor — Lt Col Todd is your mentor. Three
mappings to make explicit so the panel doesn't penalize for missing what isn't
there:

| Rubric line | What "sponsor" maps to in your case |
|---|---|
| "Decision-quality information that directly solves sponsor needs" | (a) Recommendations *to Lt Col Todd* on follow-on research directions; (b) deployment envelope for a hypothetical operational user; (c) explicit master's thesis problem statements derived from your gaps |
| "Open, transparent, timely communication with sponsor" | Documented mentor meetings (cite dates in the paper acknowledgements) |
| "Sponsor approval" for cloud APIs (Course Letter §9) | Mentor approval — you still owe Lt Col Todd a heads-up on the OpenAI-API decision before you spend |
| "Has answered the questions your sponsor was asking" | Has answered your **own** three research questions; restate them verbatim in §6 of the paper and on the conclusions slide |

In the Final Brief and Paper, **state once, near the top, that this is a
cadet-initiated individual capstone** so the panel scores recommendations
against the right reference. Suggested wording: *"This capstone is a
cadet-initiated individual research project mentored by Lt Col Todd (DFCS).
Research recommendations are scoped to follow-on work and future cadet
researchers in this domain rather than an external operational sponsor."*

# 2. Strategic Reframe (Read This First)

Your mid-semester brief asked: *"Can a 26B local model + lessons-learned KB
match capability?"* and reported the honest negative result that KB hurt
overall solve rate (3 regressed, 2 improved, 9 efficient).

For an **A**, that finding alone is insufficient — the rubric explicitly
penalizes narratives that dwell on the journey/failures over the final
solution. **Reframe the project around three claims that the data can
support:**

**Claim 1 — Scaffolding-tier hypothesis.**  Scaffolding investment scales
inversely with model capability. At 26B local, scaffolding moves the needle
materially. At frontier (GPT-4o), scaffolding marginal value approaches zero.
Lessons-DB is one component of scaffolding and behaves accordingly.

**Claim 2 — Regression diagnosis.**  Where lessons-DB hurt, the cause was
mechanical (context bloat, stale rule cross-talk, narrow IDOR enumeration
default). v3.10 P0–P5 patches address each mechanism; post-fix benchmark
quantifies the remediation.

**Claim 3 — Capability envelope.**  Across N challenges in M categories, the
solver reliably solves categories X/Y/Z; categories P/Q remain open. This
becomes the deployment recommendation table.

These three claims map cleanly to the three research questions on slide 8 of
your mid-semester deck and convert the "did RAG work?" framing into a "where
does scaffolding pay off, and how do we diagnose its failures?" framing —
which is exactly what the rubric A-line ("explored novel methodologies,
integrated them, comprehensive discussion") rewards.

# 3. Calendar — Day-by-Day

| Day | Date | Focus | Hrs | Deliverable |
|---|---|---|----|---|
| Wed | 29 Apr | Bench setup; mentor email; lit review pull | 6 | `bench/challenges.tsv`, `scripts/benchmark.sh`, batch 1 kicked off |
| Thu | 30 Apr | Lit review synthesis; methods inventory; bench batch 2 | 4+idle | `refs/synthesis.md`, `methods_inventory.md`, partial CSV |
| Fri | 1 May | Mentor sync; figures; regression diagnosis | 6 | `out/figures/fig{1..5}.png`, `results/regression_diagnoses.md`, `sponsor_notes.md` |
| Sat | 2 May | Paper draft §1–4 (Abstract, Intro, Lit, Methods) | 6 | `final_paper/main.tex` partial |
| Sun | 3 May | Paper draft §5–6 (Results, Conclusions); citations | 6 | `final_paper/main.tex` complete first draft, `references.bib` |
| Mon | 4 May | Slide deck (21 slides) | 5 | `presentation/final_brief.pptx` |
| Tue | 5 May | Q&A prep; solo run-through | 4 | `qa_prep.md`, timed solo |
| Wed | 6 May | Mock run-through; README handoff; paper edit pass 1 | 4 | `README_HANDOFF.md`, paper rev 2 |
| Thu | 7 May | Paper edit pass 2; AI-usage statement; final slide polish | 3 | paper rev 3, slides final |
| Fri | 8 May | Submit by 0900 | 1 | Email to Maj Merrick |

**Total: ~45 hours.** Tight but doable. Lighter days near the brief give buffer.

# 4. Phase 1 — Generate Evidence (Wed 29 Apr → Fri 1 May)

## 4.1 Build the benchmark spec (Wed AM, 1 hr)

Create `bench/challenges.tsv` (tab-separated, columns: name url category preset notes):

```
# Name<TAB>URL<TAB>category<TAB>preset<TAB>notes
crystal-peak<TAB>http://crystal-peak.picoctf.net:<port><TAB>idor<TAB>picoctf<TAB>md5(uid) IDOR
# ... continue with the 18 mid-sem challenges + 5–7 fresh picoCTF retired
```

**Sourcing the 18:** `ls out/lessons_knowledge/lessons_*.md | sed 's/.*lessons_[0-9]*_//' | sed 's/_r[0-9]*_.*//' | sort -u` — each file name is a challenge slug.

**Adding new ones:** pick from picoCTF retired challenges
(<https://play.picoctf.org/practice>) plus any leftover from your batch_*
directories. Stratify so each category has ≥2 entries.

**Document scope/exclusions** in `bench/README.md` — the rubric A-line wants
"data source, scope, and limitations clearly described."

## 4.2 The benchmark harness (Wed AM, 1.5 hr)

Three new files. **All three are designed to be paste-ready.**

### 4.2.1 `scripts/benchmark.sh`

```bash
#!/usr/bin/env bash
# Hybrid CTF benchmark — runs every challenge under three rag-mode configs
# on each backend tier. Tier 1: OpenAI (frontier). Tier 2: Ollama (26B local).
# Outputs runs/benchmark_<ts>/<tier>/<config>/<name>.log + metrics.csv.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TS=$(date +%Y%m%d_%H%M%S)
BENCH_ROOT="${HERE}/runs/benchmark_${TS}"
TSV="${HERE}/bench/challenges.tsv"
CONFIGS=("none" "lessons_readonly" "lessons_write")

# --- Tier toggles ---------------------------------------------------------
RUN_OPENAI="${RUN_OPENAI:-1}"        # set to 0 to skip
RUN_OLLAMA="${RUN_OLLAMA:-1}"        # set to 0 to skip
OPENAI_MODEL="${OPENAI_MODEL:-gpt-4o-mini}"   # cheap default
OLLAMA_MODEL="${OLLAMA_MODEL:-gemma4:26b}"
MAX_STEPS="${MAX_STEPS:-15}"
# Limit Ollama to a 6-challenge subset (rotate via OLLAMA_SUBSET env).
OLLAMA_SUBSET="${OLLAMA_SUBSET:-crystal-peak,verbal-stack,login-token,jwt-mate,cookie-monster,ssti-warmup}"

run_one() {
    local tier="$1"; local provider="$2"; local model="$3"; local cfg="$4"
    local name="$5"; local url="$6"; local preset="$7"
    local out="${BENCH_ROOT}/${tier}/${cfg}/${name}.log"
    mkdir -p "$(dirname "$out")"
    "${HERE}/scripts/run.sh" \
        --challenge-url "$url" \
        --challenge-name "$name" \
        --description "Benchmark: $name" \
        --flag-preset "$preset" \
        --llm-provider "$provider" \
        --model "$model" \
        --max-steps "$MAX_STEPS" \
        --rag-mode "$cfg" \
        --history-window-size 16 \
        > "$out" 2>&1 || echo "[WARN] $tier/$cfg/$name exit non-zero"
}

while IFS=$'\t' read -r name url category preset notes; do
    [[ "$name" =~ ^# ]] && continue
    [[ -z "$name" ]] && continue

    if [[ "$RUN_OPENAI" == "1" ]]; then
        for cfg in "${CONFIGS[@]}"; do
            run_one "openai" "openai" "$OPENAI_MODEL" "$cfg" "$name" "$url" "$preset"
        done
    fi

    if [[ "$RUN_OLLAMA" == "1" && ",${OLLAMA_SUBSET}," == *",${name},"* ]]; then
        for cfg in "${CONFIGS[@]}"; do
            run_one "ollama" "ollama" "$OLLAMA_MODEL" "$cfg" "$name" "$url" "$preset"
        done
    fi
done < "$TSV"

# Extract metrics
"${HERE}/.venv/bin/python" "${HERE}/scripts/extract_metrics.py" "$BENCH_ROOT" \
    > "${BENCH_ROOT}/metrics.csv"
echo "Benchmark complete. Results: ${BENCH_ROOT}/"
```

`chmod +x scripts/benchmark.sh`.

### 4.2.2 `scripts/extract_metrics.py`

```python
"""Walk a benchmark output tree and emit a CSV with one row per
(tier, config, challenge). Captures solve outcome, steps, validity,
repeated-call rate, and wall-clock estimate from each run.log."""
from __future__ import annotations
import csv
import re
import sys
from pathlib import Path

FLAG_RE = re.compile(r"\[FLAG DETECTED\] (.+)")
STEP_RE = re.compile(r"^--- Step (\d+)/\d+ ---")
ACTION_RE = re.compile(r"^Action: Using tool '([^']+)'")
ERROR_OBS_RE = re.compile(r"^Observation:.*result=error")
PARSE_FAIL_RE = re.compile(r"Could not parse simplified ReAct response")


def parse_one(path: Path) -> dict:
    text = path.read_text(errors="replace")
    flag = FLAG_RE.search(text)
    steps = [int(m.group(1)) for m in STEP_RE.finditer(text)]
    actions = ACTION_RE.findall(text)
    error_obs = len(ERROR_OBS_RE.findall(text))
    parse_fails = len(PARSE_FAIL_RE.findall(text))
    repeated = 0
    if actions:
        seen = {}
        for a in actions:
            seen[a] = seen.get(a, 0) + 1
        repeated = sum(c - 1 for c in seen.values() if c > 1)
    return {
        "max_step_seen": max(steps) if steps else 0,
        "total_actions": len(actions),
        "unique_actions": len(set(actions)),
        "error_observations": error_obs,
        "parse_failures": parse_fails,
        "repeated_call_count": repeated,
        "outcome": "success" if flag else "failure",
        "flag": flag.group(1) if flag else "",
    }


def main(root: str) -> None:
    rows = []
    for log in Path(root).rglob("*.log"):
        rel = log.relative_to(root)
        parts = rel.parts
        if len(parts) < 3:
            continue
        tier, cfg, name = parts[0], parts[1], parts[2].removesuffix(".log")
        m = parse_one(log)
        rows.append({"tier": tier, "config": cfg, "challenge": name, **m})
    cols = [
        "tier", "config", "challenge", "outcome", "max_step_seen",
        "total_actions", "unique_actions", "repeated_call_count",
        "error_observations", "parse_failures", "flag",
    ]
    w = csv.DictWriter(sys.stdout, fieldnames=cols)
    w.writeheader()
    w.writerows(sorted(rows, key=lambda r: (r["tier"], r["config"], r["challenge"])))


if __name__ == "__main__":
    main(sys.argv[1])
```

### 4.2.3 First dry-run on one challenge

```bash
echo -e "crystal-peak\thttp://crystal-peak.picoctf.net:<port>\tidor\tpicoctf\ttest" > bench/challenges.tsv
RUN_OLLAMA=0 OPENAI_MODEL=gpt-4o-mini MAX_STEPS=10 ./scripts/benchmark.sh
cat runs/benchmark_*/metrics.csv | tail -5
```

If the CSV has a row with `outcome=success` you are good. Then expand the TSV
to all 25 and run for real.

## 4.3 Run protocol

- **Wed PM, before bed:** kick off batch 1 with `RUN_OLLAMA=0` (OpenAI only,
  ~25 challenges × 3 configs = 75 runs, ~2 hrs at $5–10).
- **Thu AM:** check `metrics.csv`. If clean, kick off the Ollama subset
  (`RUN_OPENAI=0 OLLAMA_SUBSET=...`) — runs through Thu/Thu-night.
- **Fri AM:** combined CSV ready for analysis.

**Cost guard.** Set `OPENAI_MODEL=gpt-4o-mini` for the first pass. If you have
budget left after results, re-run a subset on `gpt-4o` for an extra
"frontier-tier" data point.

## 4.4 Mentor sync (Wed AM, 15 min email)

Send Lt Col Todd:

```
Subject: [CAPSTONE] 30-min vector check before final brief — Thu/Fri?

Sir,

Final brief is the week of 4 May. I've made significant changes to the
codebase since the 4 March update brief — most importantly:
  - Patched the FAISS+OpenMP segfault that was preventing RAG runs
  - Added 5 scaffolding fixes (v3.10) targeting failure modes I observed
    on a recent gemma4:26b live run
  - Adding a hybrid OpenAI-API arm to the benchmark to let me make
    cross-tier capability claims

I'd like 30 minutes this Thu or Fri to (a) walk you through the v3.10
results, (b) get your read on the reframed thesis, and (c) confirm the
recommendations slide hits what you want to see.

Times that work for me: [list 3].

V/R,
Andrew
```

**At the meeting, ask three questions:**

1. *"For the recommendations slide, what's the most useful thing this
   project could leave behind for follow-on cadet research?"*
2. *"Are you OK with me using OpenAI API for one arm of the benchmark? The
   data is all public picoCTF, but I want to flag it."*
3. *"What's the one thing you'd push back on if you saw this brief from
   another team?"*

Capture answers verbatim into `sponsor_notes.md` (keep the filename even
though there's no sponsor — your code already references it).

## 4.5 Lit-review additions (Thu, 3 hrs)

For each paper, write a 3-sentence synthesis paragraph in
`refs/synthesis.md`:

1. **Shinn et al., "Reflexion: Language Agents with Verbal Reinforcement Learning," NeurIPS 2023.** Justifies your compressed verbal lesson summaries.
2. **Zhao et al., "ExpeL: LLM Agents Are Experiential Learners," AAAI 2024.** Justifies atomic rule docs vs. monolithic logs.
3. **Wang et al., "VOYAGER: An Open-Ended Embodied Agent with Large Language Models," 2023.** Justifies the lessons-as-skills framing.
4. **Schick et al., "Toolformer: Language Models Can Teach Themselves to Use Tools," NeurIPS 2023.** Anchors tool-use scaffolding broadly.
5. **Yang et al., "EnIGMA: Enhanced Interactive Generative Model Agent for CTF Challenges," 2024.** Direct comparison point — what they did with GPT-4 vs. what your local-tier scaffolding does.
6. **Zhang et al., "Cybench: A Framework for Evaluating Cybersecurity Capabilities and Risks of Language Models," 2024.** Frames your benchmark methodology.
7. **Wei et al., "Emergent Abilities of Large Language Models," TMLR 2022.** Anchors your scaffolding-tier hypothesis (capability emerges at scale; sub-frontier models need help).
8. **Tann et al., "Using Large Language Models for Cybersecurity CTF Challenges," 2023.** (Already in mid-sem — deepen the synthesis.)

**Synthesis template per paper (3 sentences, no more):**

> **[Authors, year, short title].** [One sentence: what they claim.] [One sentence: how this informs your design choice.] [One sentence: what your work does differently or adds.]

Example:

> **Zhao et al., 2024, ExpeL.** They show that LLM agents extract higher-quality task heuristics when experiences are stored as atomic rule fragments rather than full trajectories, with retrieval gated by similarity to the current state. We adopt this atomic-rule structure in `failure_analyzer.py:generate_atomic_rule_doc` and add Jaccard-based deduplication on triggering conditions to prevent rule-set bloat across runs. Unlike ExpeL, our domain (web CTF) requires preserving exact attack inputs (e.g., template-injection payloads), so our extraction pipeline includes a post-scrub append of `winning_inputs` that bypasses the broad flag-regex redaction.

## 4.6 Novel-methods inventory (Wed PM, 30 min)

Create `methods_inventory.md` (this becomes one slide and one paper
sub-section). For each item annotate which model tier it applies to:

| Method | File | Local-tier | Frontier-tier |
|---|---|---|---|
| Hybrid BM25+vector retrieval (0.4/0.6, query-expand, rerank) | `rag/knowledge_base.py` | Y | Y |
| Outlines FSM grammar-constrained JSON (per-tool flat-enum) | `llm/adapters.py:MLXAdapter` | Y | n/a |
| ExpeL-style atomic rule docs with confidence-ladder dedup | `failure_analyzer.py` | Y | Y |
| Reflexion compressed prior-lesson injection | `runner.py:530-552` | Y | Marginal |
| Jaccard site-fingerprint contamination filter | `rag/knowledge_base.py` | Y | Y |
| Function-calling via per-tool `parameters_schema` (Draft-07) | `tools/schema.py` | Y | Y |
| Tool family collapse (5 SQLi → 1 dispatcher) | `tools/collapsed_*.py` | Y | Marginal |
| Hash-pattern hint surface (v3.10 P1+P5a) | `tools/core.py:_detect_hash_hints` | Y | Marginal |
| StuckDetector with canonicalized JSON hashing (v3.10 P2) | `tools/logging_wrapper.py` | Y | Marginal |
| DYLD-preload Apple-Silicon FAISS+OpenMP fix | `scripts/run.sh` | Y | Y (env) |

The "Local-tier vs. Frontier-tier" split is what makes Claim 1 (scaffolding
scales inversely with capability) defensible — you're showing exactly which
methods stop mattering as the model gets stronger.

# 5. Phase 2 — Analysis & Writing (Sat 2 May → Sun 3 May)

## 5.1 Five figures (Fri PM, 3 hrs)

Save all to `out/figures/` at 300 dpi. Caption each with the *finding*, not
the contents.

```python
# bench/analyze.py
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

df = pd.read_csv("runs/benchmark_LATEST/metrics.csv")  # symlink or paste actual path
df["solved"] = (df["outcome"] == "success").astype(int)

# Fig 1 — Solve rate by tier × config × category
# (need to merge in category from bench/challenges.tsv)
ch = pd.read_csv("bench/challenges.tsv", sep="\t",
                  names=["challenge", "url", "category", "preset", "notes"],
                  comment="#")
df = df.merge(ch[["challenge", "category"]], on="challenge", how="left")
fig, ax = plt.subplots(figsize=(10, 5))
pivot = (df.groupby(["category", "tier", "config"])["solved"]
            .mean().unstack(["tier", "config"]) * 100)
pivot.plot.bar(ax=ax)
ax.set_ylabel("Solve rate (%)")
ax.set_xlabel("Vulnerability category")
ax.set_title("Figure 1 — Scaffolding lift by category and model tier")
ax.legend(loc="upper right", fontsize=8)
plt.tight_layout()
plt.savefig("out/figures/fig1_solverate.png", dpi=300)

# Fig 2 — Per-challenge improvement matrix (heatmap)
import numpy as np
wide = df.pivot_table(index="challenge", columns=["tier", "config"], values="solved")
fig, ax = plt.subplots(figsize=(8, max(4, len(wide)*0.25)))
ax.imshow(wide.values, aspect="auto", cmap="RdYlGn", vmin=0, vmax=1)
ax.set_yticks(range(len(wide))); ax.set_yticklabels(wide.index, fontsize=8)
ax.set_xticks(range(len(wide.columns))); ax.set_xticklabels(["/".join(c) for c in wide.columns], rotation=45, ha="right", fontsize=8)
ax.set_title("Figure 2 — Per-challenge solve outcomes")
plt.tight_layout()
plt.savefig("out/figures/fig2_matrix.png", dpi=300)

# Fig 3 — Steps-to-flag CDF
solved = df[df["outcome"] == "success"]
fig, ax = plt.subplots(figsize=(7, 4))
for (tier, cfg), grp in solved.groupby(["tier", "config"]):
    s = sorted(grp["max_step_seen"])
    cdf = np.arange(1, len(s)+1) / len(s)
    ax.plot(s, cdf, label=f"{tier}/{cfg}", drawstyle="steps-post")
ax.set_xlabel("Steps to flag"); ax.set_ylabel("Cumulative solve fraction")
ax.set_title("Figure 3 — Efficiency: steps-to-flag CDF by config")
ax.legend(fontsize=8); plt.tight_layout()
plt.savefig("out/figures/fig3_cdf.png", dpi=300)

# Fig 4 — Tool-call validity rate (parse_failures vs. total_actions)
df["validity"] = 1 - (df["parse_failures"] / df["total_actions"].clip(lower=1))
fig, ax = plt.subplots(figsize=(8, 4))
df.groupby(["tier", "config"])["validity"].mean().mul(100).plot.bar(ax=ax)
ax.set_ylabel("Tool-call validity (%)")
ax.set_title("Figure 4 — Tool-call validity rate by tier × config")
plt.tight_layout()
plt.savefig("out/figures/fig4_validity.png", dpi=300)

# Fig 5 — Repeated-call rate (proxy for stuck loops)
fig, ax = plt.subplots(figsize=(8, 4))
df.groupby(["tier", "config"])["repeated_call_count"].mean().plot.bar(ax=ax)
ax.set_ylabel("Mean repeated-call count per run")
ax.set_title("Figure 5 — Stuck-loop incidence by tier × config")
plt.tight_layout()
plt.savefig("out/figures/fig5_stuck.png", dpi=300)
```

Run with `.venv/bin/python bench/analyze.py`. Eyeball each figure — if any
is degenerate (e.g. all categories tied), you have either a data problem or
a finding worth investigating.

## 5.2 Causal regression analysis (Sat AM, 3 hrs)

For every challenge where lessons_write *worsened* outcome vs. baseline, write
a `results/regression_diagnoses.md` entry:

```markdown
### <challenge_slug>

**Observation.** Baseline (rag-mode=none) solved in N steps; lessons_write
solver did <not solve / solved in M>N steps>.

**Mechanism.** Diff of the trajectories at line ___ shows [stale lesson
cited / context bloat truncated key observation / off-task RAG result
distracted from immediate signal].

**v3.10 fix that addresses this.** [P3a 1500-char proactive RAG cap / P5a
universal hash hint / P5b IDOR range_end=100 / etc.]

**Re-run result.** Post-fix benchmark on <date> shows <recovered / still
fails / improved by N steps>.
```

Aim for 3–5 entries (one per significant regression). This is **the
difference between a B-grade "honest negative result" and an A-grade
"diagnosed and partially remedied negative result."**

## 5.3 Final paper (Sat PM → Sun, 6 hrs)

Use IEEE conference template (`IEEEtran.cls`, two-column). Skeleton:

```
final_paper/
├── main.tex
├── references.bib
├── figures/   (symlink to ../out/figures)
├── IEEEtran.cls
└── IEEEtran.bst
```

Or use the Word IEEE template if LaTeX is too much to spin up. Either way,
the **section content** below is what matters.

### §1 Abstract (200 words, last thing you write)

Template:
> CTF challenges are increasingly being used to evaluate the offensive-cyber
> capability of LLM agents. This paper investigates the relative contribution
> of *scaffolding* (prompt engineering, tool schemas, observation processing,
> retrieval augmentation, and an experiential lessons-learned database)
> versus raw model capability on web CTF tasks. We benchmark a unified agent
> framework against N challenges across M vulnerability categories at two
> capability tiers: gemma4:26b (local) and gpt-4o-mini (frontier-API).
> Scaffolding lifts solve rate by X percentage points at the local tier and
> Y percentage points at the frontier tier. We diagnose three mechanisms
> (context bloat, stale-lesson contamination, narrow enumeration defaults)
> by which a lessons-learned database can *worsen* solve rate, and we show
> that targeted patches recover ~Z% of regressed cases. Code, benchmark, and
> raw run logs are released for reproducibility. Our results suggest
> scaffolding investment scales inversely with model capability — a finding
> with practical implications for sub-frontier deployments.

Fill in the numbers from your CSV.

### §2 Introduction (~1 page)

- Paragraph 1: Motivation (Volt Typhoon, NSA-MSS manpower asymmetry,
  AI-orchestrated cyber). Cite mid-sem references.
- Paragraph 2: Problem statement. State that this is a cadet-initiated
  individual capstone (per §1 of this plan).
- Paragraph 3: Three research questions, verbatim from mid-sem slide 8.
- Paragraph 4: Contributions, three bullets matching Claims 1/2/3 from §2
  of this plan.
- Paragraph 5: Roadmap sentence.

### §3 Theory & Literature Review (~1.5 pages)

Three threads (subsections), each ending in a *gap* sentence:

- §3.1 LLM CTF Agents — Tann 2023, EnIGMA 2024, Cybench 2024 → "no prior
  work evaluates a sub-frontier (26B) model with a structured experiential
  database on web-CTF tasks."
- §3.2 Experiential Learning — Reflexion, ExpeL, VOYAGER → "prior work
  focuses on simulated environments and dense feedback; web CTF feedback
  is sparse and observation-rich, motivating the atomic-rule
  representation we use."
- §3.3 Tool Use & Scaffolding at Tier — Toolformer, ReAct, Wei 2022
  emergence → "the scaffolding-vs-capability tradeoff has not been
  empirically characterized at the 26B/frontier boundary; this paper does."

### §4 Methodology (~2 pages)

Subsections matching `methods_inventory.md`. Each subsection: 2–3 sentences
of theory, one figure or code-snippet for the integration, one sentence of
why that choice. **Cite the prior coursework** (e.g. DATA 350 / DATA 410
content if those covered RAG, vector search, agentic systems) — the rubric
explicitly grades "integration of coursework tools with novel data science
methodologies."

### §5 Results & Discussion (~2 pages)

Lead with Figure 1 + the headline number. Then Figures 2/3/4/5 in turn.
End with the regression-diagnosis subsection. **Embrace the failed-model
discussion** — the rubric A-line for the Update Brief was "fully embraces
failed models and results"; the Final-Paper rubric implicitly inherits
this via "comprehensive discussion of outputs and models."

### §6 Conclusions & Recommendations (~1 page)

Three subsections:

- §6.1 Answers to RQ1/RQ2/RQ3 — 2–3 sentences each, citing your figures.
- §6.2 Recommendations for Follow-on Research (your "sponsor" stand-in):
  five numbered items including a master's-thesis problem statement
  derived from your gaps (e.g., "RL on top of SFT-LoRA over scaffold-aligned
  trajectories" from the audit).
- §6.3 Capability envelope — what this codebase reliably solves, deployment
  prerequisites, cost envelope.

### §7 References

IEEE-numeric, every paper in `refs/synthesis.md` must appear, plus your
mid-sem set.

### §8 AI Usage Statement (Course Letter §9, mandatory)

Three-part:
1. **What:** Tools used (Claude Opus, GPT-4o, etc.) for code authorship,
   debugging, paper drafting.
2. **How:** Whether output was reviewed/edited/used verbatim.
3. **Where:** Link to representative transcript (your existing OneDrive
   transcript link works).

# 6. Phase 3 — Polish, Brief, and Ship (Mon 4 May → Fri 8 May)

## 6.1 21-slide deck structure (Mon, 5 hrs)

Use exactly this structure. ~70 sec/slide → 25 min total.

| # | Slide | Rubric tie |
|---|---|---|
| 1 | Title (you, mentor, date, "cadet-initiated individual capstone") | bookkeeping |
| 2 | Team (you + Lt Col Todd as mentor; thank Wilson, Goethal) | bookkeeping |
| 3 | Overview / agenda | bookkeeping |
| 4 | Motivation (Volt Typhoon, NSA-MSS gap, AI-cyber rise) | §1 Intro |
| 5 | Purpose statement + 3 research questions verbatim | §1 Intro |
| 6 | Lit Thread 1 — LLM CTF agents (gap statement bold) | §2 Lit |
| 7 | Lit Thread 2 — Experiential learning (gap) | §2 Lit |
| 8 | Lit Thread 3 — Tool use / capability tier (gap) | §2 Lit |
| 9 | Data — 25 challenges, stratification table, KB sources | §3 RQ&Data |
| 10 | Methodology — scaffolding architecture diagram | §4 Methods |
| 11 | Methodology — lessons-DB pipeline (atomic rules, Reflexion, fingerprint) | §4 Methods |
| 12 | Methodology — v3.10 fixes table (audit→implementation chain) | §4 Methods |
| 13 | **Headline result** — Fig 1 + one-sentence finding | §5 Results |
| 14 | Fig 2 — per-challenge matrix | §5 Results |
| 15 | Fig 3 — efficiency CDF | §5 Results |
| 16 | Failure analysis — 3 short cases from `regression_diagnoses.md` | §5 Results |
| 17 | Answers to RQ1 / RQ2 / RQ3 (one bullet each, cite figure number) | §6 Conclusions |
| 18 | **Recommendations** — (cadet-initiated reframing) follow-on directions, master's thesis problem statements, deployment envelope | §6 Conclusions |
| 19 | Limitations & future work (single-seed, 25-challenge scope, no LoRA) | §6 Conclusions |
| 20 | References (IEEE-formatted) + AI Usage 3-part statement | §7 §8 |
| 21 | Questions | — |

## 6.2 Q&A prep (Tue, 2 hrs)

Write `qa_prep.md` with rehearsed ≤30-sec answers:

| Q | Crisp answer |
|---|---|
| Why local model not just GPT-4? | Cost, sovereignty (military deploy), reproducibility — and as a hypothesis test about scaffolding's marginal value at sub-frontier capability |
| Why no LoRA? | Audit showed scaffolding dominates LoRA at this stage; LoRA is the explicit next phase, listed as a master's-thesis problem in §6.2 |
| Why these 25 challenges? | Stratified across web vuln categories from picoCTF + MetaCTF; bounded by free-tier rotation. Document exclusions on slide 9 |
| How does this compare to EnIGMA / Cybench? | EnIGMA uses GPT-4 + Docker exec; we use a 26B local agent + structured lessons. Cybench is a benchmark, not an agent. We're closest to EnIGMA's *methodology*, with a scaffolding-first variant at smaller scale |
| Why did KB hurt some challenges? | Three diagnosed mechanisms: context bloat (P3a), stale-lesson cross-talk (v3.4 site-fingerprint), narrow IDOR range default (P5b). See slide 16 |
| Reproducibility? | `./scripts/run.sh` wraps env (DYLD libomp fix on Apple Silicon), pinned `pyproject.toml`, public benchmark TSV, raw logs published |
| Cadet-initiated — why no sponsor? | Personal interest informed by CTF competition experience; mentor (Lt Col Todd) shaped scope. "Recommendations" section is for follow-on research, not operational deployment |
| What's the deploy bar? | Slide 18 — categories with solve rate ≥ X% are deploy-ready for human-in-loop CTF triage; lower-rate categories need a human-in-loop |
| Honor / AI use? | Level-5 attributed Generative AI per DF policy; transcript link on slide 20 |

Practice each answer aloud once.

## 6.3 Solo run-through (Tue PM, 30 min)

Set a 25-min timer. If you go over, the cut order is:
- First cut: one lit-review thread slide (merge two)
- Second cut: one methodology slide (collapse 11+12)
- **Never cut Results, Recommendations, or Limitations** — those are
  graded directly.

## 6.4 Mock with classmate (Wed AM, 30 min)

Have one classmate (Wilson) ask you 5 questions from `qa_prep.md`. Time
each answer. Refine.

## 6.5 Reproducibility README (Wed PM, 1 hr)

`README_HANDOFF.md` at the repo root:

```markdown
# CTF Solver — Reproducibility & Handoff

**Status:** v3.10 (8 May 2026). Cadet-initiated individual capstone.
**Mentor:** Lt Col Todd, DFCS.
**Author:** C1C Andrew Kim, andrew.kim@afacademy.af.edu

## What this is
A web-CTF-solving agent that combines a unified scaffolding layer
(structured tool schemas, RAG-augmented prompts, lessons-learned
experiential database) with multi-backend LLM support (OpenAI,
Anthropic, Ollama, MLX). Released as a basis for follow-on cadet
research and as a working tool for picoCTF triage.

## Quickstart
./scripts/run.sh \
    --challenge-url <URL> \
    --challenge-name <NAME> \
    --description "<one-sentence brief>" \
    --flag-preset picoctf \
    --llm-provider ollama --model gemma4:26b \
    --rag-mode lessons_readonly \
    --max-steps 15 --history-window-size 16

## Apple Silicon — required env (segfault prevention)
See `memory/faiss_libomp_crash.md`. The wrapper sets
DYLD_INSERT_LIBRARIES so faiss/torch/sklearn share one libomp.

## Run the benchmark
./scripts/benchmark.sh
# Override defaults via env: RUN_OPENAI, RUN_OLLAMA, MAX_STEPS, OPENAI_MODEL.

## What it solves reliably (May 2026 benchmark)
[Categories-with-rates table from results/metrics.csv]

## Known gaps & follow-on work
1. [Category X] — model misidentifies pattern, needs hint Y
2. [Category Y] — observation truncation drops critical signal
3. [Category Z] — schema friction on tool W

## Master's-thesis-scope follow-ons
1. RL on top of SFT-LoRA trained on scaffold-aligned trajectories
2. Multi-agent decomposition (recon-agent + exploit-agent + extract-agent)
3. Cross-challenge transfer evaluation for the lessons-DB

## Key dependencies
- Python 3.13, faiss-cpu, sentence-transformers, torch
- Ollama (gemma4:26b for local) and/or OpenAI API key
- See pyproject.toml for pinned versions.

## Reproducing the benchmark
1. cp bench/challenges.tsv.template bench/challenges.tsv  # edit URLs
2. export OPENAI_API_KEY=...
3. ./scripts/benchmark.sh
4. python bench/analyze.py  # produces out/figures/*.png

## Tests
pytest tests/  # currently 2662 passing

## Contact
C1C Andrew Kim — andrew.kim@afacademy.af.edu
Mentor: Lt Col Todd, DFCS
```

## 6.6 Submission checklist (Thu PM)

```
[ ] Final paper PDF — all 6 sections present, 5–8 pages
[ ] Abstract ≤ 250 words
[ ] All figures captioned, referenced in text by number
[ ] All in-text citations resolve in references list
[ ] No "TODO" / "[FILL IN]" / placeholder text (grep)
[ ] AI Usage 3-part statement present
[ ] PDF rendering verified on a second machine
[ ] Slide deck PDF exported
[ ] README_HANDOFF.md committed
[ ] All run logs preserved under runs/benchmark_*
[ ] Repo tagged: git tag v3.10-final
[ ] qa_prep.md committed
[ ] Team Assessment email drafted (solo cadet — short)
```

## 6.7 Submit (Fri 8 May, before 0900)

```
Subject: [CAPSTONE] DATA 422 Final Report — C1C Andrew Kim
To: justin.merrick@afacademy.af.edu
CC: lt.col.todd@afacademy.af.edu

Sir,

Attached is my final report for DATA 422. Section 8 (AI Usage Statement)
includes the transcript link. The repository tag v3.10-final captures the
exact codebase state.

Final brief is on T___ at ____.

V/R,
C1C Andrew Kim
```

# 7. Code Changes Required (Summary)

| File | New / Modify | Purpose |
|---|---|---|
| `bench/challenges.tsv` | New | Benchmark spec |
| `bench/README.md` | New | Scope, exclusions, limitations |
| `scripts/benchmark.sh` | New | Hybrid OpenAI + Ollama harness |
| `scripts/extract_metrics.py` | New | CSV from run logs |
| `bench/analyze.py` | New | 5 figures from CSV |
| `refs/synthesis.md` | New | Lit-review synthesis paragraphs |
| `methods_inventory.md` | New | Novel-methods table by tier |
| `results/regression_diagnoses.md` | New | Causal analysis of failed runs |
| `sponsor_notes.md` | New | Mentor meeting notes (filename kept for code compat) |
| `final_paper/main.tex` + `references.bib` | New | Paper |
| `presentation/final_brief.pptx` | New | Deck |
| `qa_prep.md` | New | Q&A defense |
| `README_HANDOFF.md` | New | Reproducibility / handoff |
| Possibly `ctf_solver/runner.py` | Modify | Add `--save-metrics` JSON output to make extract_metrics.py simpler |

No existing test will break.

# 8. Rubric Coverage Map

Final Paper Rubric (DS422_EOC_Paper_Rubric.pdf):

| A-line | Where you earn it |
|---|---|
| "Concise summary of problem, methods, and results" | §1 Abstract + §2 Intro |
| "Synthesizes high-quality research on 'new topics'" | §3 Lit Review (refs/synthesis.md) |
| "Effectively integrates coursework with novel methodologies" | §4 Methodology + methods_inventory.md |
| "Focuses on primary solution; high-quality visuals" | §5 Results (Figures 1–5) |
| "Data-driven conclusions; decision-quality recommendations" | §6 (with cadet-initiated reframe) |
| "All sources cited professionally (IEEE/APA). Conference standard" | §7 + §8 |

Final Presentation Rubric (Final_Presentation_Rubric.pdf): 1:1 by slide, see §6.1.

Course Letter §6 holistic A: covered by mentor sync (§4.4), polished brief
(§6.1–6.4), professional submission (§6.6–6.7), and the codebase artifacts
themselves.

# 9. Risk Register

| Risk | Mitigation |
|---|---|
| OpenAI benchmark fails / rate-limits | Already using gpt-4o-mini (cheap, high quota); fall back to Ollama-only with a note in §5 limitations |
| FAISS+OpenMP segfault returns | Already patched via DYLD wrapper + memory note |
| Lt Col Todd unavailable for sync | Send written summary; capture his preferences async via email |
| Run-time on benchmark exceeds calendar | gpt-4o-mini takes ~2 hr for 75 runs; well within Thu morning |
| LaTeX template trouble | Fallback to Word IEEE template — content is what's graded |
| Brief runs over 25 min | Cut order documented in §6.3 |
| Fresh segfault on a tool I haven't touched | Check `~/Library/Logs/DiagnosticReports/Python-*.ips`, apply DYLD env, log it as known-issue |

---

## Appendix A — Quick reference: files you'll create

```
bench/
├── README.md
├── challenges.tsv
└── analyze.py
scripts/
├── benchmark.sh
├── extract_metrics.py
└── run.sh                   (already exists)
refs/
├── synthesis.md
└── *.pdf                    (the 7 papers)
results/
└── regression_diagnoses.md
out/figures/
├── fig1_solverate.png
├── fig2_matrix.png
├── fig3_cdf.png
├── fig4_validity.png
└── fig5_stuck.png
final_paper/
├── main.tex
├── references.bib
└── figures/                 (symlink → ../out/figures)
presentation/
└── final_brief.pptx
methods_inventory.md
qa_prep.md
sponsor_notes.md
README_HANDOFF.md
```

## Appendix B — Today's 60-minute starter sequence

```bash
cd "/Users/andrewkim/Documents/School Files/1 Dig Spring Semester/DATA422/new_final_project/kim_data_project"
mkdir -p bench refs results out/figures presentation final_paper

# 1. Email Lt Col Todd (2 min)
# Use the template in §4.4

# 2. Pull the 7 papers as PDFs into refs/ (15 min)
# Use Google Scholar; accept the arXiv PDFs

# 3. Build challenges.tsv from your existing lessons docs
ls out/lessons_knowledge/lessons_*.md | sed -E 's|.*lessons_[0-9]+_||' | sed -E 's|_r[0-9]+.*||' | sort -u
# Edit bench/challenges.tsv with these names + URLs

# 4. Paste scripts/benchmark.sh + scripts/extract_metrics.py from §4.2
chmod +x scripts/benchmark.sh

# 5. Dry-run on one challenge with OpenAI gpt-4o-mini
RUN_OLLAMA=0 OPENAI_MODEL=gpt-4o-mini MAX_STEPS=10 ./scripts/benchmark.sh
cat runs/benchmark_*/metrics.csv

# 6. If clean: full sweep before bed
./scripts/benchmark.sh
```

You're set up to wake up Thursday with the full benchmark CSV in hand.
