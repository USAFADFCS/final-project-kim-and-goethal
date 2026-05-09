# Final Report Outline — DATA 422 Capstone

**Title:** Experience-Augmented LLM Agents for Web CTF Exploitation
**Author:** C1C Andrew Kim, USAFA/DFMA
**Mentor:** Lt Col Michael Todd (DFCS)
**Course:** DATA 422 (Maj Justin Merrick)
**Due:** COB 8 May 2026 (T40)

---

## Argument arc (one paragraph)

The paper poses three research questions about whether giving an LLM agent access to its own prior actions and outcomes improves its ability to solve web CTF challenges. Across a 14-challenge paired benchmark (`May03_1720_MetaCTF_Run`), the experience-augmented agent solved exactly the same number of challenges as the baseline (12/14, zero new wins, zero regressions), so the lessons-learned database does not raise *capability*. On the same dataset it cut aggregate token use by 12.5%, wall-clock time by 21.9%, and step count by 22.5%, so it does raise *efficiency*. Disaggregating the gain reveals that those reductions are almost entirely driven by 3 of the 14 challenges where prior-reflection injection fired *and* the recalled experience was applicable; on the other 11 the experience DB had no measurable effect. This concentration matches the deck's diagnostic finding that the keyword-based challenge classifier retrieves the wrong document on roughly four out of every five lookups (21.4% retrieval rate). The paper argues that experience augmentation is therefore a *latent* efficiency lever, gated almost entirely by retrieval quality, and that the cleanest follow-on lever is to replace the keyword classifier with LLM-driven retrieval.

---

## §1 — Abstract (200–250 words)

- Single paragraph. Last thing to write so it can quote the final numbers.
- Structure: problem (CTF as offensive-cyber benchmark; manpower gap motivation) → method (FAIR-based ReAct agent, 60-tool executor, hybrid BM25+FAISS retrieval, atomic-rule lessons DB with Reflexion-style injection) → headline result (12/14 → 12/14 capability; -12.5% tokens, -21.9% time, -22.5% steps; concentration in 3/14 runs; 21.4% retrieval rate as bottleneck) → implication (latent efficiency lever, gated by retrieval; replace keyword classifier with LLM-driven retrieval).
- Sources: deck slide 18–19; `CTF_Run_Tracking.xlsx` sheet `May03_1720_MetaCTF_Run`.

## §2 — Introduction (~1 page)

- ¶1: Strategic motivation. NSA workforce / China-MSS asymmetry; Volt Typhoon prepositioning; Anthropic's 2025 disruption report on AI-orchestrated campaigns. Frame why an LLM offensive-cyber capability evaluation matters now.
- ¶2: Problem statement. State that this is a cadet-initiated individual capstone mentored by Lt Col Todd, scoped to follow-on research rather than an external operational sponsor (borrowed verbatim from `A_GRADE_PLAN.md` §1 to keep rubric "sponsor" language honest).
- ¶3: Three research questions, verbatim from deck slide 10:
  1. Can injecting facts from previous runs help an LLM increase its capability to solve CTF challenges?
  2. What are the best ways to summarize and store lessons learned from each challenge?
  3. If the knowledge base is comprised of previously successful tool use chains (not the specific vulnerability of the target), how will that impact solve times, token usage, and overall efficiency?
- ¶4: Contributions, three short bullets:
  - A reusable FAIR-based CTF-solving agent with a 60-tool web-exploitation executor and hybrid BM25+FAISS retrieval (BM25 weight 0.4 / FAISS 0.6).
  - An atomic-rule lessons-learned schema with site-fingerprint contamination filtering, deterministic dedup, and optional gpt-4o-mini causal enrichment.
  - An empirical capability/efficiency separation result on a 14-challenge paired benchmark that locates the bottleneck at retrieval, not extraction or storage.
- ¶5: Roadmap sentence.
- Sources: deck slides 5, 7, 10; `A_GRADE_PLAN.md` §1.

## §3 — Literature Review (~1.5 pages)

Three threads, each ending in an explicit gap sentence. Synthesize, don't enumerate.

- §3.1 *LLMs for CTF and offensive cyber.* Tann et al. (2023) on LLMs for CTF recon and tool-output interpretation; Fang et al. (2024) on LLM agents autonomously exploiting one-day vulnerabilities (this is the load-bearing citation for the capability-vs-efficiency framing); Anthropic 2025 disruption report on real-world AI-orchestrated campaigns. Gap: prior work establishes that LLM agents *can* exploit known vulnerabilities and that knowledge bases lift efficiency on CVE-shaped tasks; the capability-vs-efficiency question for *experiential* (agent-generated) augmentation in adversarial CTF settings is open.
- §3.2 *ReAct and experiential agents.* Yao et al. (2023) on ReAct's Thought–Act–Observe loop; Shinn et al. (2023) on Reflexion's verbal self-reflection for episodic learning; brief gesture at ExpeL/VOYAGER for cross-episode rule extraction in non-CTF settings. Gap: prior work focuses on simulated environments with dense feedback; web CTF feedback is sparse, observation-heavy, and adversarial, motivating atomic-rule and site-fingerprint design choices we adopt.
- §3.3 *Retrieval-augmented generation for agents.* Hybrid sparse+dense retrieval as a coursework-derived technique (BM25 + dense embeddings via Sentence-BERT); brief mention of Lewis et al. (2020) on RAG. Gap: most RAG evaluations target factual QA; the role of the *retrieval classifier* in adversarial agent loops is under-studied — and is exactly where the bottleneck appears in our results.
- Sources: deck slides 8–10 reference list; `failure_analyzer.py` design comments referencing Reflexion and ExpeL.

## §4 — Methodology (~2–3 pages)

Explain *why* each design choice, not just the code. Use tables for inventories so prose stays dense.

- §4.1 *System overview.* Custom FAIR-based `SimpleAgent` (`ctf_solver/agent.py:2017`), JSON ReAct loop with optional Anthropic native tool batching for parallel tool calls (`_arun_native_tools` line 774), `WorkingMemory`, ReActPlanner, ToolExecutor, RAG knowledge tool. Diagram from deck slide 15 reused.
- §4.2 *Tool library (Table 1).* 60 distinct tool classes across 12 vulnerability categories (HTTP/web, recon, SQLi, XSS, SSTI, XXE, file ops, auth/crypto, injection/encoding, race/smuggling/SSRF, misc, advanced). The deck's "75" figure is the `__all__` re-export count including `LoggingToolWrapper` variants; the class count is the truer methodological figure. All tools share a `requests.Session`, accept JSON input, and are wrapped by `LoggingToolWrapper` for telemetry.
- §4.3 *Retrieval pipeline (Table 2: RAG modes).* Hybrid BM25 + FAISS over Sentence-BERT (`all-MiniLM-L6-v2`, CPU-pinned for Apple Silicon stability), 1200-char chunks with 200-char overlap, query expansion, simple reranker. Five RAG modes (`NONE`, `ORIGINAL`, `LESSONS_WRITE`, `LESSONS_READONLY`, `LESSONS_BUILDONLY`); the May03_1720 benchmark uses `ORIGINAL` for the no-lessons arm and `LESSONS_WRITE` for the with-lessons arm. The hybrid weighting (0.6 vector / 0.4 BM25) is taken directly from deck slide 16.
- §4.4 *Lessons-learned generation.* `run_lessons_learned_pipeline` (`failure_analyzer.py:1381`) emits one atomic rule doc per extracted rule (300–400 words), each containing a triggering condition, agent takeaway, rule type (`do`/`do_not`), tool context, confidence, and causal explanation. Reflexion-style 100–200 word verbal summary injected into the next matching challenge's prompt. Optional gpt-4o-mini enrichment at ~$0.0003/run rewrites the three weakest deterministic fields.
- §4.5 *Contamination and provenance controls.* Flag scrubbing (`_scrub_flags`); site-fingerprint Jaccard ≥ 0.60 exclusion to keep the KB from leaking the current target's prior runs back into itself; tool-sequence hashing for approach-aware dedup; cross-run confidence merging via Jaccard on triggering conditions.
- §4.6 *Challenge classifier and matcher.* Keyword-and-regex `ChallengeClassifier` (`ctf_solver/classifier/challenge_classifier.py`) maps a challenge description to a primary `ChallengeCategory` plus secondary categories. This is the component the Results section identifies as the bottleneck.
- §4.7 *Telemetry and reproducibility.* `RunTracker` (`run_tracker.py:64`) records start/end times, token counts via `TokenTrackingAdapter`, per-step events, RAG-query counts, and a boolean `prior_reflection_injected` — the last of which makes the §5 concentration analysis reproducible.
- §4.8 *Coursework integration.* RAG, vector search, embeddings, and evaluation methodology drawn from prior data-science coursework; specific novel methods are atomic-rule extraction, fingerprint-based contamination filtering, and the cross-run confidence-merging dedup.

## §5 — Results (~2–3 pages)

Lead with the working solution. The Results rubric A-bar is "alternatives mentioned only for brief context"; alternatives and abandoned variants get at most one short paragraph in §5.5.

- §5.1 *Benchmark protocol.* 14 web CTF challenges (MetaCTF), each run twice — once without the lessons DB and once with `LESSONS_WRITE`. Identical agent, identical tool library, identical model, identical RAG mode for the curated docs. Difference is the lessons-DB read+write. Source: `CTF_Run_Tracking.xlsx` sheet `May03_1720_MetaCTF_Run`, 28 rows.
- §5.2 *RQ1 — Capability is unchanged.* 12/14 successes in both modes; identical failures (Super Quick Logic, Microdosing). Zero regressions, zero new captures. Figure 1 (solve-rate ablation) and the right panel of Figure 2 (per-challenge outcome matrix) anchor the claim.
- §5.3 *RQ3 — Aggregate efficiency improves.* Pooled over all 14 paired runs: tokens 3,644,114 → 3,185,806 (-12.58%); time 1228.2s → 958.6s (-21.95%); steps 168 → 130 (-22.62%). These reproduce the deck's headline 12.5/21.9/22.5%. Figure 3 (steps-to-solve CDF) shows the with-lessons distribution shifting left.
- §5.4 *Concentration and the bottleneck claim.* The aggregate gain is driven almost entirely by 3 of 14 runs in which `prior_reflection_injected = True` and the matched lesson was applicable: **Open Application** (231,646 → 78,577 tokens, 13 → 5 steps), **Livestream** (591,415 → 142,333 tokens, 28 → 8 steps), **Trading Places** (585,456 → 208,096 tokens, 27 → 10 steps). The other 11 runs are flat; Microdosing's tokens nearly double (763,245 → 1,280,143) while the outcome remains a failure — a tool-bounded result independent of the lessons DB. The 11/14 silence is direct evidence for the deck's 21.4% retrieval rate: most lookups don't surface an applicable rule, and the keyword classifier is the cause. Table 3 (per-challenge paired outcomes), Figure 4 (retrieval panel for Dot-Matrix Destruction) anchor this.
- §5.5 *RQ2 — Storage and extraction work; retrieval does not.* Atomic-rule extraction yields well-formed, dedup-clean rules (review of `out/lessons_knowledge/` confirms the schema holds and the site-fingerprint filter keeps cross-run contamination out). The failure mode is at the retrieval/matching stage. One short paragraph here for context — no journey narrative.
- §5.6 *Cost and operational footprint.* Figure 5 (cost-per-flag) summarizes USD-per-success for each arm. Useful for the deployment-envelope discussion in §6.
- Sources: `CTF_Run_Tracking.xlsx` sheet `May03_1720_MetaCTF_Run`; `out/brief_figures/fig{1..5}_*.png`.

## §6 — Conclusions and Recommendations (~1 page)

- §6.1 *Answers to research questions* (each 2–3 sentences, citing figure/table):
  - **RQ1.** No. Capability did not improve; 12/14 in both arms (Figure 1, Table 3). Capability appears bounded by the model's reasoning and the agent's tool library — both fixed across arms.
  - **RQ2.** Deterministic atomic-rule extraction with optional LLM enrichment produces well-formed, contamination-filtered lessons. The bottleneck is *retrieval*: the keyword-based `ChallengeClassifier` matches only ~21.4% of relevant prior lessons (deck slide 20), which is why most runs see no benefit.
  - **RQ3.** Yes — when retrieval succeeds. Aggregate -12.5/-21.9/-22.5% on tokens/time/steps (Figure 3), but with the gain concentrated in 3 of 14 paired runs (§5.4). The efficiency value of experiential augmentation is real but *latent*; closing the retrieval gap is what would unlock it across the rest of the benchmark.
- §6.2 *Recommendations for follow-on research* (the cadet-initiated reframe of "sponsor recommendations"):
  1. Replace the keyword `ChallengeClassifier` with an LLM-driven retrieval head that conditions on the full challenge description and prior tool-call traces.
  2. Close measured tooling gaps that bound capability (e.g., the multi-phase exploit chain Microdosing requires).
  3. Re-run the benchmark on a local LLM to remove API-driven variance and refusal artifacts (matches deck slide 19's "way forward").
  4. Expand the experience DB to cross-platform lessons (PicoCTF + MetaCTF + HackTheBox web tracks) and re-measure retrieval rate.
  5. Master's-thesis problem statement: learned retrieval over agent trajectories — does fine-tuning a small embedding model on (challenge_description, applicable_lesson) pairs beat keyword classification?
- §6.3 *Capability envelope.* Brief table or list: which CTF categories the system reliably solves (cookie/header tampering, simple SSTI, basic SQLi, IDOR enumeration, JWT manipulation), which it solves intermittently (multi-step XSS, partial logic flaws), which remain open (multi-phase exploit chains, novel cryptographic constructions). Useful for any future operational scoping.

## §7 — References

IEEE numeric. Minimum set:

1. Tann et al., 2023 — LLMs for cybersecurity CTF challenges and certification questions.
2. Yao et al., 2023 — ReAct: synergizing reasoning and acting in language models.
3. Shinn et al., 2023 — Reflexion: language agents with verbal reinforcement learning (NeurIPS).
4. Fang et al., 2024 — LLM agents can autonomously exploit one-day vulnerabilities.
5. Lewis et al., 2020 — Retrieval-augmented generation for knowledge-intensive NLP tasks.
6. Anthropic, 2025 — Disruption report on AI-orchestrated cyber campaigns.
7. (Optional) Zhao et al., 2024 — ExpeL: LLM agents are experiential learners.
8. (Optional) Wang et al., 2023 — VOYAGER: an open-ended embodied agent with LLMs.

Plus the four deck-cited threat-environment sources (CBS News on Chinese spies, Nextgov on NSA workforce, War on the Rocks on Volt Typhoon, etc.) used in §2.

## §8 — AI Usage Statement (per Course Letter §9)

Three-part disclosure:
1. **What:** Tools used (Claude Opus, GPT-4o-mini, gpt-4o, Anthropic Sonnet 4.6) — for code authorship, debugging, lesson-doc enrichment, and report drafting.
2. **How:** All output reviewed and edited by the author; final wording, structure, and claims are the author's. No AI-generated text accepted verbatim without review.
3. **Where:** `[transcript link: TBD]` — to be filled in before submission.

---

## Figures and tables

| ID | Title | Source | Section |
|---|---|---|---|
| Table 1 | Tool inventory by vulnerability category | `ctf_solver/tools/__init__.py` | §4.2 |
| Table 2 | RAG mode matrix | `ctf_solver/config.py:28-41` | §4.3 |
| Table 3 | Per-challenge paired outcomes (n=14) | `CTF_Run_Tracking.xlsx` sheet `May03_1720_MetaCTF_Run` | §5.2, §5.4 |
| Figure 1 | Solve-rate ablation (12/14 vs 12/14) | `out/brief_figures/fig1_solve_rate_ablation.png` | §5.2 |
| Figure 2 | Per-challenge outcome matrix | `out/brief_figures/fig2_per_challenge_matrix.png` | §5.2 |
| Figure 3 | Steps-to-solve CDF | `out/brief_figures/fig3_steps_cdf.png` | §5.3 |
| Figure 4 | Retrieval panel (Dot-Matrix Destruction) | `out/brief_figures/fig4_retrieval_panel_dotmatrix.png` | §5.4 |
| Figure 5 | Cost per flag | `out/brief_figures/fig5_cost_per_flag.png` | §5.6 |

---

## Open questions / decisions to confirm before drafting

1. **Figure regeneration.** The 5 figures in `out/brief_figures/` were rendered by `scripts/render_brief_figures.py`. They were generated against an earlier dataset; recommend regenerating against `May03_1720_MetaCTF_Run` so the figures match the numbers in the prose. **Decision needed:** regenerate, or use existing figures as-is and note any minor mismatches in REVIEW.md?
2. **Citation depth.** Recommend including Shinn 2023 (Reflexion) and Lewis 2020 (RAG) since both are load-bearing for design choices. ExpeL (Zhao 2024) and VOYAGER (Wang 2023) are nice-to-have for §3.2 depth — include or skip?
3. **Author voice.** Single-author paper; spec allows first-person "I" or passive voice. Recommend passive/active voice throughout for conference-paper register, with "I" only in the AI Usage Statement.
4. **Threat-motivation citations.** The deck cites CBS News, Nextgov, War on the Rocks. These are journalistic, not academic — fine to cite in IEEE format but they sit alongside the academic refs. Confirm acceptable.
5. **Length.** Target 8–12 pages; Methodology and Results may extend slightly. Confirm OK to push to ~14 if the architecture detail and figure spacing demand it.
6. **Tool count reconciliation.** The deck says 75; the actual class count is 60. Recommend stating 60 with a footnote that 75 is the `__all__` re-export count including logging wrappers — accurate and avoids a discrepancy with the codebase.
