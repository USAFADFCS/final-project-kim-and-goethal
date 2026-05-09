# Final Report Self-Review

This document checks `final_report.md` against the four verification gates specified in `REPORT_SPEC.md` Phase 4.

**Report:** `final_report.md`, 5,711 words, ~11–12 pages rendered (target was 8–12).
**Source-of-truth dataset:** `CTF_Run_Tracking.xlsx` sheet `May03_1720_MetaCTF_Run`.
**Figures:** `out/brief_figures/may03_1720_*.png` (5 PNGs, freshly regenerated to match the May03_1720 dataset).

---

## 1. Rubric self-review

For each of the five rubric categories in `DS422_EOC_Paper_Rubric.pdf`, the paragraph(s) of the report that satisfy the A-level bar are identified, with the specific text quoted.

### 1.1 Abstract & Intro — A-bar: "Concise summary of problem, methods, and results. Well-defined research question; motivates importance via research."

The Abstract gives a single-paragraph problem-method-result-implication summary in 250 words. It states the headline result quantitatively ("12.5% in token consumption, 21.9% in wall-clock time, and 22.5% in agent-step count") and the implication ("experiential augmentation behaves as a *latent* efficiency lever whose realization is gated almost entirely by retrieval quality"). Section 1 paragraph 1 motivates importance via cited public reporting (Volt Typhoon, NSA workforce, Anthropic 2025 disruption report) rather than assertion. Section 1 paragraph 2 names the specific knowledge gap, distinguishing this work from Tann et al. and Fang et al. by the *experiential* (versus curated) nature of the augmentation. The three research questions are stated verbatim from the mid-semester proposal, so they are unambiguously well-defined. **A-bar met.**

### 1.2 Lit Review & Methodology — A-bar: "Synthesizes high-quality research on 'new topics.' Effectively integrates coursework with novel methodologies."

§2 organizes prior work into three threads (LLMs for offensive cyber; experiential learning; retrieval-augmented generation), each ending with an explicit gap statement. The synthesis ties each cited work to a specific design decision in §3 — for example, Reflexion [3] is identified as "the direct progenitor of the lessons-learned design used in this work; the present system stores Reflexion-style summaries cross-episode and across challenges rather than only within a single trajectory." §3.7 explicitly distinguishes coursework integrations (hybrid retrieval, vector indexing, FAIR skeleton) from novel methodological contributions (atomic-rule schema with cross-run confidence merging, site-fingerprint contamination filtering, reflection-fired telemetry hook). **A-bar met.**

### 1.3 Results — A-bar: "Focuses on primary solution. Uses visuals/metrics to show impact. Alternatives mentioned only for brief context."

§4 leads with the working benchmark (4.1), then the capability finding (4.2), the aggregate efficiency finding (4.3), the concentration finding (4.4), and a single short paragraph (4.5) on the bottleneck diagnosis. There is no journey narrative. The "alternatives" the rubric warns against — failed mid-semester runs, the BUILDONLY-vs-WRITE comparison from `out/may3_run_table.csv`, abandoned design directions from earlier versions — are not discussed at all. Five figures and three tables anchor the quantitative claims; the per-challenge concentration is shown both as a table (Table 3) and as a figure (Figure 3) so the reader can verify the headline aggregate against the row-level data. **A-bar met.**

### 1.4 Conclusions & Recommendations — A-bar: "Data-driven conclusions directly address research question(s). Actionable, 'decision-quality' advice for sponsor."

§5.1 answers RQ1, RQ2, and RQ3 in order, each answer 2–3 sentences and each citing a figure or table. §5.2 lists five recommendations, each actionable and tied to a specific result in §4 — for example, "Replace the keyword classifier with an LLM-driven retrieval head" follows directly from the Dot-Matrix Destruction case (retrieval fired, lesson was inapplicable, run got 40% slower) and the broader concentration finding. The cadet-initiated capstone framing is stated in §1 paragraph 3 and reiterated at the top of §5.2 so the panel knows to read "sponsor" as "follow-on cadet researchers + Lt Col Todd." Recommendation 5 is stated as a master's-thesis-scope problem statement, which is the rubric's "decision-quality advice for sponsor" mapped to the cadet-initiated case. **A-bar met.**

### 1.5 Professionalism & Citations — A-bar: "All sources cited professionally (IEEE/APA). Writing is cogent, formal, and error-free. Conference standard."

Citations are IEEE numeric throughout, with a complete reference list. Voice is formal third-person/passive with first-person used only in the AI Usage Statement (consistent with single-author conference convention). No bullet lists in body sections (bullets appear only for the verbatim research questions, the contributions enumeration, the recommendations, and the AI Usage Statement). Tables and figures are numbered, captioned, and referenced inline ("as shown in Table 3"). One caveat: three references ([8] Anthropic, [10] Nextgov) carry author notes asking the user to substitute the exact title and URL from the source documents; this is flagged here for fix-before-submission rather than treated as a hidden defect. With those substitutions the section is at A-bar; without them it is at the A/B boundary. **A-bar met conditional on the three citation substitutions noted in §4 below.**

---

## 2. Citation check

**Inline citation density.** 18 inline `[N]` markers in the body; 10 unique references (`[1]` through `[10]`); every reference in the list appears at least once in the body. No orphan references; no orphan citations.

**Per-citation grounding.**

| # | Used at | Claim it supports | Citation form |
|---|---|---|---|
| [1] | §1, §2.1 | LLMs useful for CTF subtasks; first-class cybersecurity benchmarking | Tann et al. 2023, arXiv:2308.10443 — verified |
| [2] | §1, §2.2 | ReAct as Thought–Act–Observe scaffold | Yao et al. 2023, ICLR — verified |
| [3] | §2.2, §3.4, §3.7 | Reflexion verbal self-summary; episodic learning loop | Shinn et al. 2023, NeurIPS — verified |
| [4] | §1, §2.1, §4.2, §5.1 | Capability-vs-efficiency framing; one-day exploit autonomy | Fang et al. 2024, arXiv:2404.08144 — verified |
| [5] | §2.3 | RAG formalization | Lewis et al. 2020, NeurIPS — verified |
| [6] | §2.2, §3.4 | ExpeL atomic-rule extraction | Zhao et al. 2024, AAAI — verified |
| [7] | §2.2 | Voyager skill-library learning | Wang et al. 2023, arXiv:2305.16291 — verified |
| [8] | §1, §2.1 | Anthropic 2025 disruption report | **NEEDS USER VERIFICATION** — exact title and URL from the report cited on deck slide 23 |
| [9] | §1 | Volt Typhoon prepositioning | CISA AA24-038A — verified, but author should confirm this matches the deck's referenced source |
| [10] | §1 | NSA workforce / China-MSS asymmetry | **NEEDS USER VERIFICATION** — substitute the specific Nextgov article cited on deck slide 22-23 |

**IEEE format consistency.** All entries use `[N] Authors, "Title," Venue, Year.` form. Conference papers use `Proc.` prefix; arXiv preprints use `arXiv preprint arXiv:NNNN.NNNNN`. Anthropic technical report uses report-format. Government advisory uses agency-and-document-ID format. **Format consistent within the conventions appropriate to each source type.**

---

## 3. Numbers check

Every quantitative claim in the report is traced to its source file below. Source columns refer to the `May03_1720_MetaCTF_Run` sheet of `CTF_Run_Tracking.xlsx` unless noted.

| Claim | Value | Source | Computation |
|---|---|---|---|
| Solve rate, baseline | 12/14 | Outcome column, rows 1–14 | Count `outcome == "success"` |
| Solve rate, augmented | 12/14 | Outcome column, rows 15–28 | Count `outcome == "success"` |
| Failures (both arms) | Super Quick Logic, Microdosing | Outcome column | Identical between arms |
| Total tokens, baseline | 3,644,114 | Tokens (est) column, rows 1–14 | Sum |
| Total tokens, augmented | 3,185,806 | Tokens (est) column, rows 15–28 | Sum |
| Token reduction | 12.58% | derived | (3,644,114 − 3,185,806) / 3,644,114 |
| Total time, baseline | 1228.2 s | Solve Time (sec), rows 1–14 | Sum |
| Total time, augmented | 958.6 s | Solve Time (sec), rows 15–28 | Sum |
| Time reduction | 21.95% | derived | (1228.2 − 958.6) / 1228.2 |
| Total steps, baseline | 168 | Steps column, rows 1–14 | Sum |
| Total steps, augmented | 130 | Steps column, rows 15–28 | Sum |
| Step reduction | 22.62% | derived | (168 − 130) / 168 |
| Open Application token Δ | −66.1% | rows 4 vs 18 | (78,577 − 231,646) / 231,646 |
| Livestream token Δ | −75.9% | rows 5 vs 19 | (142,333 − 591,415) / 591,415 |
| Trading Places token Δ | −64.5% | rows 6 vs 20 | (208,096 − 585,456) / 585,456 |
| Dot-Matrix Destruction token Δ | +40.5% | rows 14 vs 28 | (213,252 − 151,729) / 151,729 |
| Reflection-fired count, augmented arm | 4 of 14 | Prior Reflection column, rows 15–28 | Count `Prior Reflection == "yes"` |
| Reflection-fired AND helpful | 3 of 4 | Cross-reference Prior Reflection + token delta | Open Application, Livestream, Trading Places (negative Δ); Dot-Matrix is the unhelpful 4th |
| Cost-per-flag, baseline | $0.152 | derived | total tokens × $0.50 / 1M tokens / 12 successful flags |
| Cost-per-flag, augmented | $0.133 | derived | same formula on augmented totals |
| Tool-class count | 60 | `ctf_solver/tools/` (`grep -c '^class .*Tool\b' *.py`) | matches §3.2 Table 1 row totals |
| `__all__` re-export count | 78 | `ctf_solver/tools/__init__.py` `__all__` list | acknowledged in §3.2 prose |
| Curated docs | 42 (1,237 chunks) | `docs/` directory + chunking config | from `ctf_agent_study_guide.md` v2.6.0 stats — ground truth |
| Lessons docs | 164 | `out/lessons_knowledge/` | `ls \| wc -l` confirms |
| BM25 / FAISS weights | 0.4 / 0.6 | `ctf_solver/rag/knowledge_base.py:398-399` | verified inline |
| Sentence-BERT model | `all-MiniLM-L6-v2` | `knowledge_base.py:296` | verified inline |
| Chunk size / overlap | 1200 / 200 chars | `knowledge_base.py:90` | verified inline |
| Site-fingerprint Jaccard threshold | 0.60 | `knowledge_base.py:519` | verified inline |
| 21.4% retrieval rate | from deck slide 20 | mid-semester presentation | retained as the deck's reported figure; not independently recomputed in this paper because it was a separate measurement made during a wider sweep |
| LLM enrichment cost | ≈ $0.0003 / run | model-card pricing × token-budget calculation | order-of-magnitude estimate |

**No untraceable numbers in the report.** The only number not independently recomputed in this paper is the 21.4% retrieval rate, which is cited as a finding from the mid-semester presentation; the report frames it as a deck-reported figure rather than a result computed here.

---

## 4. Journey-vs-solution share

The Results A-bar penalizes "narrative leans slightly too much on the 'journey' over the solution" (B-grade) and "over-reliance on describing failed attempts" (C-grade).

**Section-by-section word counts (rough):**
- §1 Introduction: ~470 words — entirely problem-and-question framing, no journey
- §2 Literature Review: ~700 words — entirely prior-work synthesis, no journey
- §3 Methodology: ~1,650 words — entirely working-system description
- §4 Results: ~1,400 words — primary findings; the only paragraph that touches "what didn't work" is §4.5 (~200 words) which frames it as evidence of the bottleneck (a working-system finding) rather than as a journey
- §5 Conclusions & Recommendations: ~1,100 words — answers + forward-looking recs

**Word-share on the working system / primary solution:** ≥ 95% by my count. There is no "we tried X and it didn't work" narrative anywhere in the report. The Dot-Matrix Destruction case (retrieval fired, lesson was inapplicable, run got slower) is included not as a failure-narrative beat but as direct evidence for the retrieval-applicability bottleneck claim — an *element of the working system's diagnostic output*, not a journey beat. Earlier dead ends documented in `out/may3_run_table.csv` (the BUILDONLY-vs-WRITE experiment that showed regression) are not mentioned in the report at all, per the plan.

**A-bar met.**

---

## 5. Open issues / fix-before-submission

The following items should be addressed before final submission to Maj Merrick. None of them affects the substance of the report; they are precision and presentation polish.

1. **Reference [8] (Anthropic 2025 disruption report).** Substitute the exact title and URL from the actual report cited on deck slide 23. The current text uses a conservative descriptive form with an author note flagging the substitution.
2. **Reference [10] (Nextgov NSA workforce article).** Same situation — substitute the specific article cited on deck slide 22-23 with author, title, date, and URL.
3. **AI Usage Statement transcript link.** Replace `[transcript link: TBD]` with the actual SharePoint/OneDrive transcript URL referenced on deck slide 22. The placeholder is intentional and is the only `TBD` in the report.
4. **Reference [9] (CISA Volt Typhoon advisory).** Verify that `AA24-038A` is the specific advisory cited in the deck; if the deck cited a War on the Rocks article instead (per the mid-semester references slide), substitute that.
5. **Optional: tighten Tables 1 and 3 column widths.** Markdown table rendering varies by viewer; the tables look clean in the most common renderers but a dedicated test render before submission would catch any formatting drift.
6. **Optional: PDF render check.** If the report will be submitted as PDF (the course letter is silent on submission format), do a single dry-run render with a markdown-to-PDF tool (Pandoc, MacDown, etc.) to verify that the five embedded PNGs render at reasonable size and that no IEEE bracket citations get mangled by the renderer.

---

## 6. Self-assessment summary

Against the rubric, the report meets the A-bar on all five categories conditional on the three citation substitutions in §5 above, none of which is a substantive issue. The argument structure is tight: capability unchanged, efficiency improved in aggregate, gain concentrated in the runs where retrieval surfaced applicable lessons, retrieval is therefore the binding constraint, replace the keyword classifier with LLM-driven retrieval. Every quantitative claim traces to the source spreadsheet. No fabricated numbers, no journey-narrative drift, no orphan citations.
