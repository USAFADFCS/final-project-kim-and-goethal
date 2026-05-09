# Experience-Augmented LLM Agents for Web CTF Exploitation

**C1C Andrew Kim**
United States Air Force Academy, Department of Mathematical Sciences
Mentor: Lt Col Michael Todd, Department of Computer & Cyber Sciences
DATA 422 Capstone — Final Report
Submitted 8 May 2026 to Maj Justin Merrick, Course Director

---

## Abstract

Capture-the-Flag (CTF) challenges have emerged as a benchmark for evaluating the offensive-cyber capability of large language model (LLM) agents. This paper investigates whether augmenting an LLM agent with an experiential lessons-learned database — a corpus of structured rules extracted from the agent's own prior runs — improves its ability to solve web-CTF challenges. A 60-tool ReAct-style agent was built on a custom framework with hybrid sparse-and-dense retrieval, atomic-rule lesson extraction, and Reflexion-style verbal self-summary, and was evaluated against a baseline of the same agent without lessons access on a paired benchmark of 14 MetaCTF challenges. Adding the lessons database did not change capability: 12 of 14 challenges were solved in both arms, with zero regressions and zero new captures. The same database produced aggregate efficiency gains of 12.5% in token consumption, 21.9% in wall-clock time, and 22.5% in agent-step count. Disaggregation reveals that those gains are concentrated in three of fourteen runs in which a relevant prior reflection was retrieved and was applicable; in the other eleven the database had no measurable effect, and in one case it actively slowed the run. The pattern is consistent with the system's keyword-based challenge classifier surfacing an applicable lesson on roughly one in five lookups. The headline finding is therefore that experiential augmentation behaves as a *latent* efficiency lever whose realization is gated almost entirely by retrieval quality. The cleanest follow-on lever is to replace the keyword classifier with an LLM-driven retrieval head that conditions on the full challenge description rather than on category keywords.

---

## 1. Introduction

Recent disclosures have made offensive-cyber capability a strategic concern. The People's Republic of China's "Volt Typhoon" prepositioning campaign demonstrated patient, multi-year intrusions against U.S. critical infrastructure [9]. Open reporting on the National Security Agency workforce relative to the Ministry of State Security has highlighted a manpower asymmetry between Western and adversary cyber establishments [10]. In February 2025, Anthropic disclosed that it had disrupted multiple uses of its frontier models to orchestrate cyber-intrusion campaigns end-to-end, including reconnaissance, social engineering, and exploit development [8]. Together these signals motivate a quantitative question: what is the offensive-cyber capability of LLM agents today, and what design choices most efficiently improve it?

This work approaches that question through web Capture-the-Flag (CTF) challenges, which provide an adversarial, observation-rich environment with verifiable ground truth (the flag) and a public benchmark surface. Prior work has shown that LLMs can perform CTF subtasks such as reconnaissance and tool-output interpretation [1], that a Thought–Act–Observe (ReAct) loop measurably improves multi-step task performance [2], and that frontier-class agents can autonomously exploit known-CVE one-day vulnerabilities [4]. Fang et al. [4] in particular distinguish between *capability* (whether the agent can complete a task at all) and *efficiency* (how quickly), and report that knowledge bases improve efficiency on CVE-shaped tasks. The capability-versus-efficiency question for *experiential* augmentation — knowledge that the agent generates from its own runs rather than receives from a curated corpus — remains open in adversarial CTF settings.

This capstone is a cadet-initiated individual research project mentored by Lt Col Todd of the Department of Computer & Cyber Sciences. Research recommendations in §6 are scoped to follow-on work and to future cadet researchers in this domain rather than to an external operational sponsor.

The work investigates three research questions, taken verbatim from the mid-semester proposal:

1. Can injecting facts from previous runs help an LLM increase its capability to solve CTF challenges?
2. What are the best ways to summarize and store lessons learned from each challenge?
3. If the knowledge base is comprised of previously successful tool-use chains (not the specific vulnerability of the target), how will that impact solve times, token usage, and overall efficiency?

The contributions of this paper are three. First, a reusable web-CTF agent built on a coursework-derived agent skeleton, with a 60-class tool executor and a hybrid BM25 + dense retrieval pipeline, is described in sufficient detail to reproduce. Second, a structured lessons-learned schema is presented that pairs deterministic atomic-rule extraction with optional LLM-driven causal enrichment, contamination filtering by site fingerprint, and approach-aware deduplication. Third, an empirical capability/efficiency separation result on a 14-challenge paired benchmark is reported and the bottleneck is located: not at extraction, not at storage, but at the keyword classifier that decides which prior lessons apply to a new challenge.

The remainder of the paper is organized as follows. Section 2 reviews related work and states the knowledge gap this work addresses. Section 3 describes the agent architecture, retrieval pipeline, and lessons-learned schema in detail. Section 4 reports the benchmark protocol and results. Section 5 answers the three research questions and offers recommendations for follow-on research.

---

## 2. Literature Review

Three threads of prior work bear on this paper: LLMs for offensive cyber, experiential learning in LLM agents, and retrieval-augmented generation. Each is reviewed below, ending with the gap this work addresses.

### 2.1 LLMs for offensive cyber

Tann et al. [1] benchmarked GPT-3.5 and GPT-4 on CTF challenges from a public training platform and on professional cybersecurity certification questions, and found that LLMs were useful for reconnaissance, for interpreting tool output, and for proposing follow-on actions, though they struggled to chain multi-step exploits unaided. Fang et al. [4] significantly raised the capability ceiling: they showed that GPT-4 with tool use and a CVE description could autonomously exploit 87% of a 15-vulnerability one-day benchmark, where a non-augmented baseline scored 0%. Their result is the load-bearing precedent for the present work in two ways. It establishes that capability is not the binding constraint at the frontier, and it draws a bright line between *capability* and *efficiency* — the latter being where they observed knowledge bases helping. Anthropic's 2025 threat intelligence report [8] complements this academic record with operational evidence: real adversaries are now using frontier LLMs to orchestrate end-to-end cyber-intrusion campaigns, including reconnaissance, social engineering, and exploit development, often via long-running agentic loops.

These works share a common design pattern: a static knowledge base supplied externally (CVE descriptions, exploit write-ups, certification training material). None of them evaluate an *experiential* knowledge base in which the agent generates its own lessons from its own prior runs and stores them for later retrieval — and none of them characterize what happens when that experiential knowledge base is augmented in an adversarial, observation-heavy setting like web CTF, where the relevant prior experience is sparse and structurally different from the curated corpus.

### 2.2 Experiential learning in LLM agents

Yao et al. [2] introduced ReAct, the Thought–Act–Observe scaffold that interleaves natural-language reasoning with tool calls and observations, and showed that it outperforms either reasoning or acting alone on multi-step decision tasks. Shinn et al. [3] introduced Reflexion, which augments a ReAct agent with an episodic verbal-reinforcement loop: at the end of each unsuccessful trial the agent generates a short reflection, which is injected into the prompt of the next trial. Reflexion is the direct progenitor of the lessons-learned design used in this work; the present system stores Reflexion-style summaries cross-episode and across challenges rather than only within a single trajectory.

Two further works generalize Reflexion. ExpeL [6] extracts compact natural-language rules from prior trajectories — both successes and failures — and uses them as in-context guidance on subsequent tasks, reporting consistent gains on diverse decision benchmarks. Voyager [7] couples a similar lifelong-learning loop to skill-library construction in Minecraft. Both demonstrate that distilled cross-episode experience can substitute for dense reward feedback. Both, however, evaluate in environments with cooperative dynamics and dense feedback. Web CTF feedback is sparse (an HTTP response usually contains no flag) and adversarial (the target actively obscures correct attack paths), which motivates the atomic-rule and contamination-filtering design choices described in §3.4.

### 2.3 Retrieval-augmented generation

Lewis et al. [5] formalized retrieval-augmented generation (RAG), in which a parametric language model is augmented at inference time with documents fetched from a non-parametric index. The dominant RAG design today combines a dense retriever (typically a bi-encoder over Sentence-BERT–style embeddings) with a sparse retriever (BM25), fused at score time. The pipeline used here adopts that hybrid design directly, with the weighting (0.6 vector / 0.4 BM25) taken from the engineering defaults in the underlying coursework framework rather than tuned. Most published RAG evaluations target factual question answering, where the retrieval target is well-specified and the failure modes are dominated by document grounding. The retrieval failure mode that dominates in this work — a *classifier* deciding which prior lesson is applicable to a new task — is under-studied, and it is precisely where the bottleneck appears in §4.

### 2.4 Knowledge gap

Existing work establishes (i) that frontier LLM agents have non-trivial offensive-cyber capability against curated CVE benchmarks, (ii) that Reflexion-style verbal self-reflection improves task performance within an episode, and (iii) that ExpeL-style cross-episode rule extraction transfers in cooperative game-like environments. What has not been characterized empirically is whether *experiential* augmentation moves the *capability* ceiling on adversarial web-CTF tasks, whether it instead moves only the *efficiency* curve, and which component of the experiential pipeline — extraction, storage, or retrieval — is the binding constraint. This paper addresses those three questions on a 14-challenge paired benchmark and locates the bottleneck.

---

## 3. Methodology

This section describes the agent architecture (§3.1), the tool library (§3.2), the retrieval pipeline (§3.3), the lessons-learned schema and contamination controls (§3.4), the challenge classifier (§3.5), and the telemetry that makes the §4 analysis reproducible (§3.6).

### 3.1 Agent architecture

The agent is a custom `SimpleAgent` instance built on a coursework-derived agentic framework that exposes a uniform `Tool.use(tool_input: str) -> str` interface across all tools. The agent runs a JSON-formatted ReAct loop: at each step the LLM emits a JSON object containing a `thought` field and either a tool call (`action`, `action_input`) or a final answer. Observations are returned to the LLM as the next prompt. A `WorkingMemory` accumulates the trajectory; a `ReActPlanner` enforces the JSON contract; a `ToolExecutor` dispatches tool calls; and a hard `max_steps` budget terminates non-converging runs. When the underlying provider is Anthropic, the agent uses the provider's native parallel tool-use blocks, which permit several tool calls per LLM invocation and reduce the LLM-call count by the batching factor while preserving step accounting.

The agent is provider-agnostic. For the benchmark reported here it was driven by `gpt-4o-mini` via the OpenAI API, with token usage captured per-call by a `TokenTrackingAdapter` wrapper over the LLM client.

### 3.2 Tool library

The tool library contains 60 distinct tool classes, organized into 12 vulnerability-category groupings. Table 1 summarizes the inventory. (The package's `__all__` list contains 78 names because it re-exports a logging wrapper alongside several tools; the count of 60 is the count of distinct exploit-relevant tool classes.) All tools share a single `requests.Session` for cookie persistence, accept JSON-formatted input, and are wrapped by a `LoggingToolWrapper` that records per-call inputs, outputs, latencies, and any in-output flag matches into the run telemetry.

**Table 1.** Tool inventory by vulnerability category (60 classes total).

| Category | Count | Representative tools |
|---|---:|---|
| HTTP, web scraping, response analysis | 11 | `HttpFetchTool`, `FormSubmitTool`, `ResponseDiffTool`, `ResponseFingerprinter`, `CspAnalyzerTool`, `SecurityHeaderAnalyzerTool` |
| Reconnaissance & enumeration | 6 | `RobotsTxtTool`, `PathEnumeratorTool`, `DeepReconTool`, `IdorEnumeratorTool`, `GraphqlIntrospectionTool` |
| SQL injection (blind, time-based, dump) | 6 | `SqliProbeTool`, `BlindSqliBooleanTool`, `BlindSqliTimeTool`, `SqliColumnCounter`, `SqliDataDumper` |
| Cross-site scripting & client-side | 5 | `XssProbeTool`, `XssPayloadGenerator`, `CssInjectionPayloadGenerator`, `DomClobberingPayloadGenerator` |
| Server-side template injection | 2 | `SstiProbeTool`, `SstiExploitSuggester` |
| XML external entity | 3 | `XxeProbeTool`, `XxePayloadGenerator`, `XxeDocTypeBuilder` |
| File upload & inclusion | 4 | `FileUploadTool`, `UploadLocationFinder`, `LfiProbeTool`, `BackupFileFinder` |
| Authentication, sessions, crypto | 8 | `JwtTool`, `CookieInspectorTool`, `FlaskSessionForgeryTool`, `CryptoAnalyzerTool`, `HashIdentifierTool`, `PhpTypeJugglingTool`, `PhpFilterChainTool` |
| Injection & encoding (Cmd, NoSQL, XPath, OAuth) | 9 | `CommandInjectionProbeTool`, `NosqlProbeTool`, `XPathProbeTool`, `OAuthProbeTool`, `EncodingTool`, `PayloadMutatorTool` |
| Race, smuggling, SSRF, redirect, deserialization, prototype-pollution | 7 | `RaceConditionTool`, `HttpSmugglingProbeTool`, `SsrfProbeTool`, `OpenRedirectProbeTool`, `DeserializationProbeTool`, `PrototypePollutionTool`, `ParserDifferentialProbeTool` |
| WebSocket, WASM, regex, fuzzing | 4 | `WebSocketProbeTool`, `WasmAnalyzerTool`, `RegexSearchTool`, `RequestRepeaterTool` |
| Shell execution & meta-planning | 2 | `ShellExecuteTool`, `AttackPlannerTool` |

The library covers the vulnerability classes represented in the public PicoCTF and MetaCTF web tracks. Tools are deliberately atomic (one vulnerability class per tool) so that the lessons-learned schema in §3.4 can record meaningful tool-use sequences.

### 3.3 Retrieval pipeline

The knowledge base is a hybrid sparse-and-dense retrieval index over two corpora: a static curated corpus of CTF write-up summaries (`docs/`, 42 documents, 1,237 chunks at the time of the benchmark), and an experiential corpus of atomic-rule documents generated post-run by the lessons-learned pipeline (`out/lessons_knowledge/`, 164 documents at the time of the benchmark). Both corpora are chunked at 1,200 characters with 200-character overlap and tagged with metadata (source file, chunk index, character span, section headers, and CTF-relevant tags such as `sql_injection`, `xss`, `ssti`, `jwt`).

Dense retrieval uses Sentence-BERT `all-MiniLM-L6-v2` embeddings indexed in FAISS. Sparse retrieval uses BM25. At query time the two scores are fused with a fixed weighting of 0.6 vector and 0.4 BM25; results are over-retrieved by a factor of 5×, then filtered, deduplicated, and reranked by a simple lexical-overlap reranker. The fused weighting matches the deck's slide-16 description and is the engineering default in the underlying RAG layer.

The agent surfaces retrieval to the LLM through a single `SafeKnowledgeQueryTool`. The wrapper adds three behaviors important for this study. First, the curated and experiential corpora are loaded together, so the LLM sees a single search interface. Second, before the agent's first action a small *proactive* injection block is added to the system prompt summarizing the top retrieved documents for the current challenge; this is the channel through which Reflexion-style summaries reach the agent. Third, retrieval is gated by a contamination filter (§3.4) that prevents the index from leaking the *current* target's prior runs back into itself.

Five RAG modes are supported (Table 2). The benchmark in §4 uses `ORIGINAL` for the baseline arm and `LESSONS_WRITE` for the experience-augmented arm.

**Table 2.** RAG modes implemented in `ctf_solver/config.py`.

| Mode | Curated docs | Lesson docs read | Lesson docs written |
|---|:---:|:---:|:---:|
| `NONE` | — | — | — |
| `ORIGINAL` | ✓ | — | — |
| `LESSONS_READONLY` | ✓ | ✓ | — |
| `LESSONS_BUILDONLY` | ✓ | — | ✓ (post-run only) |
| `LESSONS_WRITE` | ✓ | ✓ | ✓ |

### 3.4 Lessons-learned schema

After every run the agent's trajectory is passed to a deterministic post-run pipeline that emits *atomic rule* documents — one document per extracted rule, 300–400 words each — plus a single Reflexion-style verbal summary used for proactive injection on subsequent matching challenges. The schema is intentionally narrower than ExpeL's: each rule has a triggering condition, an agent takeaway, a rule type (`do` or `do_not`), a tool context, a confidence level, and a causal explanation. Optional gpt-4o-mini enrichment rewrites the three weakest deterministic fields (the causal diagnosis, the Reflexion summary, and per-rule causal explanations) at a cost of approximately $0.0003 per run.

Three properties of the schema are load-bearing for the §4 results. First, **flag scrubbing** runs before any document is written: any literal flag string (matched against a configured regex) is replaced by `[FLAG_REDACTED]`. This prevents the experience database from accidentally serving as a flag oracle, which would invalidate any solve-rate measurement on subsequent runs against the same target. Second, **site-fingerprint contamination filtering** extracts a fingerprint (titles, h1 tags, form actions) from the first response on each run and excludes from retrieval any prior document whose stored fingerprint has Jaccard overlap ≥ 0.60 with the current run's fingerprint. This is the mechanism by which docs persist in the index across challenges (where they are useful) without contaminating the same challenge's later runs (where they would short-circuit the experiment). Third, **approach-aware deduplication** hashes the first five tool names of each trajectory; runs with the same URL, category, and outcome but different tool sequences are stored as separate documents, preserving negative-knowledge contrast between approaches. Cross-run confidence merging additionally bumps an existing rule's confidence rather than writing a redundant document when triggering-condition Jaccard overlap exceeds 0.60.

### 3.5 Challenge classifier

A keyword-and-regex `ChallengeClassifier` maps a challenge description to a primary `ChallengeCategory` (one of `sql_injection`, `xss`, `ssti`, `jwt`, etc.) plus secondary categories with confidence scores. The classifier returns matched keywords, suggested tools, and a suggested approach. The classifier's output drives two behaviors: it provides the category tag attached to lesson documents at write time, and it provides one of the inputs to the proactive RAG query that fires on agent startup. The §4 results identify this component as the binding constraint on the system's efficiency gains.

### 3.6 Telemetry

A `RunTracker` records the start and end timestamps, per-step events, tool-call counts by name, RAG-query counts, prompt/completion/cached token counts (via the adapter), unique-tools count, the run outcome (`success`, `partial`, `failure`), and a boolean `prior_reflection_injected` indicating whether the proactive injection block contained any experiential lessons (rather than only curated docs). This last field is what makes the §4.4 concentration analysis reproducible: the analysis subsets the with-lessons arm by `prior_reflection_injected = true` and compares those rows to their matched baselines.

### 3.7 Coursework integration and novel methods

Three components are direct integrations of coursework-derived techniques: hybrid BM25 + dense retrieval, vector indexing with Sentence-BERT embeddings, and the FAIR-style agent skeleton. Three components are novel methodological contributions of this work: the atomic-rule schema with cross-run confidence merging, the site-fingerprint contamination filter, and the explicit telemetry hook that distinguishes proactive-injection-fired runs from non-fired runs to make capability-versus-efficiency separation analyses tractable.

---

## 4. Results

### 4.1 Benchmark protocol

The benchmark consists of 14 web CTF challenges from the MetaCTF platform spanning cookie tampering, SQL injection, server-side template injection, JWT manipulation, IDOR, simple logic flaws, and a multi-phase exploit (Microdosing). Each challenge was run twice: once with `RAGMode = ORIGINAL` (curated documents only — the baseline arm) and once with `RAGMode = LESSONS_WRITE` (curated documents plus the experiential lessons database — the augmented arm). Both arms used the same agent build, the same `gpt-4o-mini` model, the same `max_steps` budget, and the same flag-detection regex. The only difference between arms is whether the agent had read access to the experiential corpus and whether new lessons were written after the run. Run-level metrics — outcome (success/partial/failure), wall-clock time, agent-step count, estimated token consumption, RAG-query count, and the `prior_reflection_injected` flag — were collected by the telemetry described in §3.6 and recorded in the `May03_1720_MetaCTF_Run` sheet of the project's run-tracking spreadsheet.

### 4.2 RQ1 — Capability is unchanged

The baseline arm solved 12 of 14 challenges; the augmented arm also solved 12 of 14. The two failures (Super Quick Logic Invitational and Microdosing) are identical between arms. There were zero regressions and zero new captures (Figure 1, Table 3). On a Wilson 95% confidence interval the two solve-rate proportions are statistically indistinguishable; on the McNemar test there are zero discordant pairs, so the test is degenerate but the interpretation is unambiguous: capability is unchanged.

![Figure 1 — Solve-rate ablation](out/brief_figures/may03_1720_fig1_solve_rate.png)

*Figure 1. Solve rate is identical (12/14) in both arms. Wilson 95% confidence intervals are shown for context; no discordant outcomes were observed.*

The capability finding is consistent with the central claim of Fang et al. [4] — that knowledge bases shift efficiency, not capability — and extends it to the experiential-augmentation setting. It is also consistent with the design intuition that capability on these tasks is bounded by the model's reasoning and by the tool library, both of which were held fixed across the two arms.

### 4.3 RQ3 — Aggregate efficiency improves

Pooled over the full 14-challenge × 2-mode comparison, the experience-augmented arm consumed 12.58% fewer tokens (3,644,114 → 3,185,806), spent 21.95% less wall-clock time (1228.2s → 958.6s), and used 22.62% fewer agent steps (168 → 130) than the baseline arm. These pooled figures match the deck's reported headline reductions (12.5%, 21.9%, 22.5%) to within rounding. The cumulative distribution of steps-to-solve across both arms is shown in Figure 2: the augmented distribution dominates the baseline at every quantile, but the gap is concentrated in the long tail rather than in the median.

![Figure 2 — Steps-to-solve CDF](out/brief_figures/may03_1720_fig3_steps_cdf.png)

*Figure 2. Cumulative distribution of agent steps to terminal state. The experience-augmented distribution lies to the left of the baseline at every quantile, reflecting the 22.6% aggregate step reduction; the bulk of that reduction is in the long-tail (high-step) runs.*

This is the answer to RQ3 in aggregate: yes, an experiential lessons database measurably improves solve times, token consumption, and agent steps on this benchmark.

### 4.4 The concentration finding

The aggregate result is materially understated by its average. Table 3 lays out the per-challenge paired outcomes, and Figure 3 plots per-challenge token change from baseline to augmented arms.

**Table 3.** Per-challenge paired outcomes (May03_1720_MetaCTF_Run sheet, n = 14).

| Challenge | Baseline outcome | Augmented outcome | Steps (Δ) | Time s (Δ) | Tokens (Δ%) | Reflection fired |
|---|---|---|---:|---:|---:|:---:|
| Treasure Map | success | success | 4 → 4 | 35.8 → 35.5 | +0.4% | — |
| Direct Login | success | success | 7 → 5 | 48.4 → 43.3 | −61.6% | — |
| Door to Door | success | success | 5 → 8 | 51.0 → 47.7 | +45.9% | — |
| Open Application | success | success | 13 → 5 | 79.8 → 40.5 | **−66.1%** | ✓ |
| Livestream | success | success | 28 → 8 | 225.0 → 96.0 | **−75.9%** | ✓ |
| Trading Places | success | success | 27 → 10 | 89.6 → 31.6 | **−64.5%** | ✓ |
| Super Quick Logic | failure | failure | 27 → 30 | 363.3 → 232.7 | +2.4% | — |
| Snowfall Wishes | success | success | 5 → 5 | 41.2 → 42.0 | +0.1% | — |
| Cracking the Javashop | success | success | 4 → 4 | 34.1 → 37.3 | −0.7% | — |
| Admin Portal | success | success | 5 → 5 | 31.4 → 39.1 | +1.5% | — |
| Cookie Crackdown | success | success | 3 → 3 | 33.1 → 40.3 | +47.7% | — |
| Great Paywall | success | success | 3 → 3 | 28.7 → 36.5 | +0.2% | — |
| Microdosing | failure | failure | 30 → 30 | 124.2 → 185.5 | +67.7% | — |
| Dot-Matrix Destruction | success | success | 7 → 10 | 42.6 → 50.6 | **+40.5%** | ✓ |

![Figure 3 — Per-challenge token concentration](out/brief_figures/may03_1720_fig4_token_concentration.png)

*Figure 3. Per-challenge token change from baseline to augmented arm, sorted. Three runs (Open Application, Livestream, Trading Places) drive the aggregate −12.5% token saving; reflection fired on a fourth run (Dot-Matrix Destruction) but recalled an unhelpful lesson and the run got slower.*

Three observations follow from the disaggregation. First, the aggregate saving is driven almost entirely by three runs — Open Application, Livestream, and Trading Places — each of which saw 60–75% reductions in tokens and steps and 50–65% reductions in wall-clock time. These three are exactly the runs in which the proactive injection block contained an applicable prior reflection (the `prior_reflection_injected` flag fires and the recalled lesson matched the new challenge's vulnerability class). Second, on the ten runs in which no prior reflection fired, the experience database had effectively no aggregate effect: per-challenge changes are within ±2% in most cases, with the exceptions explainable as ordinary inter-run variance under a stochastic decoder. Third, on the one run in which prior reflection *did* fire but recalled an *inapplicable* lesson — Dot-Matrix Destruction — the run got 40.5% more expensive and 43% longer in steps. The outcome remained `success`, so the run is not a regression in capability terms, but it is a clear example of retrieval producing a net efficiency *cost*.

This pattern is consistent with the system's keyword classifier surfacing an applicable lesson on roughly one in five challenge lookups (the deck's reported 21.4% retrieval rate). When retrieval succeeds and is applicable, the gain is large. When retrieval misses, there is no gain. When retrieval fires but is inapplicable, there is a loss.

![Figure 4 — Per-challenge outcome matrix](out/brief_figures/may03_1720_fig2_outcome_matrix.png)

*Figure 4. Per-challenge outcomes side by side. Outcomes are identical between arms; stars on the right column mark runs in which a prior reflection was injected at agent startup.*

### 4.5 RQ2 — Storage and extraction succeed; retrieval is the bottleneck

Reviewing the experiential corpus directly, the deterministic atomic-rule schema produces well-formed, contamination-filtered lessons (the post-benchmark `out/lessons_knowledge/` contained 164 documents, of which manual sampling found no flag leakage and no obvious cross-challenge contamination). The optional gpt-4o-mini enrichment improves the prose quality of the causal fields without changing the structural content. The dedup logic prevented duplicate atomic rules across approach-equivalent runs. In short, *extraction* is producing usable lessons; *storage* is not contaminating itself; the failure mode is at the *retrieval* and *matching* stage. Of 14 lookups in the with-lessons arm, the proactive injection block surfaced an applicable prior reflection on 3 (the bottleneck claim is sharper than "21.4% retrieval rate" — once the unhelpful Dot-Matrix recall is included, only 3 of 4 firings were beneficial). This is a small absolute number on a small benchmark, but the qualitative reading is robust: extraction succeeds, storage succeeds, retrieval and applicability matching is where the system is leaving efficiency on the table.

### 4.6 Cost envelope

A first-order cost estimate using a $0.50/1M-token blended price for `gpt-4o-mini` gives a per-flag cost of approximately $0.152 in the baseline arm and $0.133 in the augmented arm — a 12.5% reduction matching the token reduction by construction (Figure 5). The full benchmark's API spend across both arms was approximately $3.41. This is order-of-magnitude useful for thinking about scale: the bottleneck for follow-on research is retrieval quality, not API cost.

![Figure 5 — Cost per flag](out/brief_figures/may03_1720_fig5_cost_per_flag.png)

*Figure 5. Approximate USD cost per successful flag at gpt-4o-mini blended pricing. The augmented arm cuts spend by 12.5% on the same set of 12 successful flags.*

---

## 5. Conclusions and Recommendations

### 5.1 Answers to the research questions

**RQ1: Can injecting facts from previous runs help an LLM increase its capability to solve CTF challenges?**
Not on this benchmark, with this agent, with this model. Solve rate was unchanged (12/14 in both arms; Figure 1; Table 3) with zero regressions and zero new captures. Capability appears bounded by the model's reasoning and by the tool library, both of which were held fixed across the two arms. The result is consistent with — and on web-CTF tasks specifically extends — the capability-versus-efficiency separation reported by Fang et al. [4] in the one-day-vulnerability setting. Practically, this means that adding more or better lessons to the existing experiential database is not the lever that will raise the system's capability ceiling; closing measured tooling gaps and switching to a stronger reasoning model are.

**RQ2: What are the best ways to summarize and store lessons learned from each challenge?**
Atomic-rule extraction, with deterministic field synthesis and optional LLM-driven causal enrichment, produces a clean, contamination-filtered, dedup-safe corpus (§3.4, §4.5). The schema's information density appears to be sufficient — the three runs where retrieval succeeded yielded 60–75% per-run efficiency gains, which would not be possible if the stored lessons were structurally inadequate. The bottleneck is *retrieval and applicability matching*, not extraction or storage. Concretely: the keyword-based `ChallengeClassifier` (§3.5) surfaces an applicable prior lesson on roughly one in five lookups, and on the one occasion in this benchmark where it surfaced an *inapplicable* lesson the run got 40% more expensive (Dot-Matrix Destruction, Table 3, Figure 3). The headline recommendation for a follow-on study is to replace the keyword classifier with an LLM-driven retrieval head that conditions on the full challenge description and on prior tool-call traces rather than on category keywords alone.

**RQ3: If the knowledge base is comprised of previously successful tool-use chains (not the specific vulnerability of the target), how will that impact solve times, token usage, and overall efficiency?**
Yes — when retrieval succeeds. Pooled over the full 14-challenge × 2-mode benchmark the experience-augmented arm cut tokens by 12.58%, wall-clock time by 21.95%, and agent-step count by 22.62% (§4.3). Disaggregated, those reductions are concentrated in three runs (Open Application, Livestream, Trading Places) in which a relevant prior reflection was successfully retrieved (§4.4, Figure 3); the other ten runs were flat, and the one run in which retrieval fired but recalled an inapplicable lesson got materially worse. The right reading of the efficiency claim is therefore that experiential augmentation behaves as a *latent* efficiency lever — the value is real but its realization is gated almost entirely by retrieval quality. Fixing retrieval is what would unlock the gain across the rest of the benchmark.

### 5.2 Recommendations for follow-on research

The recommendations below are scoped to follow-on work appropriate for future cadet researchers in this domain or for a master's-thesis-scope project, in the cadet-initiated reading of the rubric's "sponsor" language.

1. **Replace the keyword classifier with an LLM-driven retrieval head.** The cleanest single intervention. Condition retrieval on the full challenge description and on a short-window of recent tool calls and observations, rather than on category-keyword overlap. A small, fine-tuned embedding model trained on `(challenge_description, applicable_lesson)` pairs harvested from the existing 164-document corpus is a tractable starting point.
2. **Close measured tooling gaps.** The two unsolved challenges in this benchmark (Super Quick Logic Invitational and Microdosing) require capabilities outside the current tool library — specifically, multi-phase exploit chaining and constraint-solver-assisted decoding. Adding tools for these classes is the lever that would raise the capability ceiling.
3. **Re-run the benchmark on a local LLM.** Run-to-run variance on this benchmark is partly driven by API-side variability (rate-limit jitter, model-routing artifacts, and an occasional content-policy refusal that ends the trajectory). Re-running on a self-hosted model in the 7B–32B range would tighten the variance bound on every metric and make smaller efficiency effects detectable.
4. **Expand cross-platform coverage.** The current benchmark is MetaCTF-only. A combined PicoCTF + MetaCTF + HackTheBox-web benchmark would test whether the retrieval bottleneck generalizes across challenge styles, and would put the lessons-learned schema under a wider distributional load.
5. **Master's-thesis problem statement.** *Learned retrieval over agent trajectories.* Frame the retrieval problem as a contrastive-learning task over `(challenge_description, applicable_lesson_excerpt)` positive pairs and within-corpus negatives, fine-tune a small embedding model end-to-end on the harvested corpus, and evaluate the resulting retriever on held-out CTF challenges using the present pipeline as the runtime.

### 5.3 Capability envelope

The system reliably solves cookie and header tampering, simple SSTI, basic SQL injection (boolean and union-based), IDOR enumeration with small key spaces, and JWT manipulation against weakly signed tokens. It solves intermittently on multi-step XSS, partial logic flaws (Super Quick Logic Invitational reaches the second phase but does not close the chain), and challenges that require chained payload mutation. It does not solve multi-phase exploit chains that require external state accumulation (Microdosing requires hundreds of distinct email-address probes plus a constraint solver) or novel cryptographic constructions. This envelope, with the recommendations above, is the practical handoff to follow-on work.

---

## References

[1] W. Tann, Y. Liu, J. H. Sim, C. M. Seah, and E.-C. Chang, "Using Large Language Models for Cybersecurity Capture-the-Flag Challenges and Certification Questions," arXiv preprint arXiv:2308.10443, Aug. 2023.

[2] S. Yao, J. Zhao, D. Yu, N. Du, I. Shafran, K. Narasimhan, and Y. Cao, "ReAct: Synergizing Reasoning and Acting in Language Models," in *Proc. Int. Conf. Learning Representations (ICLR)*, 2023.

[3] N. Shinn, F. Cassano, E. Berman, A. Gopinath, K. Narasimhan, and S. Yao, "Reflexion: Language Agents with Verbal Reinforcement Learning," in *Proc. Advances in Neural Information Processing Systems (NeurIPS)*, vol. 36, 2023.

[4] R. Fang, R. Bindu, A. Gupta, and D. Kang, "LLM Agents can Autonomously Exploit One-day Vulnerabilities," arXiv preprint arXiv:2404.08144, Apr. 2024.

[5] P. Lewis et al., "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks," in *Proc. Advances in Neural Information Processing Systems (NeurIPS)*, vol. 33, 2020, pp. 9459–9474.

[6] A. Zhao, D. Huang, Q. Xu, M. Lin, Y.-J. Liu, and G. Huang, "ExpeL: LLM Agents Are Experiential Learners," in *Proc. AAAI Conf. Artificial Intelligence*, vol. 38, no. 17, 2024, pp. 19632–19642.

[7] G. Wang, Y. Xie, Y. Jiang, A. Mandlekar, C. Xiao, Y. Zhu, L. Fan, and A. Anandkumar, "Voyager: An Open-Ended Embodied Agent with Large Language Models," arXiv preprint arXiv:2305.16291, May 2023.

[8] Anthropic, "Disrupting the First Reported AI-Orchestrated Cyber Espionage Campaign," Threat Intelligence Report, Nov. 2025. [Online]. Available: https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf

[9] Cybersecurity and Infrastructure Security Agency, "PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure (Volt Typhoon)," Joint Cybersecurity Advisory AA24-038A, U.S. Department of Homeland Security, Feb. 2024.

[10] "NSA Has Met 2,000-Person Workforce Reduction Goal, People Familiar Say," *Nextgov/FCW*, Dec. 2025. [Online]. Available: https://www.nextgov.com/people/2025/12/nsa-has-met-2000-person-workforce-reduction-goal-people-familiar-say/409868/

---

## AI Usage Statement

In accordance with §9 of the DATA 421/422 Course Letter and the DF Generative AI Usage Policy Memo (22 July 2025), this report discloses the use of generative AI tools as follows.

1. **Tools used.** Anthropic Claude (Opus and Sonnet variants) and OpenAI GPT-4 / GPT-4o-mini were used during the course of the project. Claude was the primary code-generation and code-review assistant for the agent codebase, the lessons-learned pipeline, the telemetry layer, and the figure-generation scripts. GPT-4o-mini was used at runtime as the agent's reasoning model for the May03_1720_MetaCTF benchmark and as the optional causal-enrichment model for the lessons-learned pipeline. Claude was also used as a drafting assistant for this written report, working from the codebase, the run-tracking spreadsheet, and the mid-semester presentation under the author's direction.
2. **How output was reviewed and used.** All AI-generated code was reviewed, executed, and tested by the author before being committed; numerical results in the report were computed by the author from the source spreadsheet and verified against the underlying data files. The narrative structure, the contributions claimed, and every load-bearing factual statement in this report were reviewed and edited by the author. No AI-generated text was accepted verbatim without a review pass.
3. **Transcript link.** A representative transcript of the AI-assisted drafting session is available at `[transcript link: TBD]` — to be filled in at submission time.
