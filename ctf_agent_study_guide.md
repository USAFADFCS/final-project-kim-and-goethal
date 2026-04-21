# CTF SOLVER AGENT — CONFERENCE STUDY GUIDE
*Flashcard-Style Review | Architecture, Tools, Learning Pipeline | MORS AI Conference Prep*

## HOW TO USE THIS GUIDE
Cover the green answer row (`A:`). Say your answer aloud, then reveal. Focus on **exact class names, file paths, and research citations** — conference audiences will ask precise questions. If you can't articulate *why* a design choice was made, re-read the section.

**Project root:** `kim_data_project/` | **Version:** v2.6.0 | **Tools:** 55 classes | **RAG docs:** 42 (1,237 chunks) | **Tests:** 1,978

---

## SECTION 1 — SYSTEM OVERVIEW & AGENT LOOP

### Top-Level Architecture

**Q:** The CTF Solver is built on top of the _________ framework (imported as `fairlib`), an in-house _________ Lab / USAFA toolkit. The acronym stands for _________, _________, _________, _________. It provides `SimpleAgent`, `ReActPlanner`, `ToolRegistry`, `ToolExecutor`, and `WorkingMemory` primitives. The agent uses the _________ prompting pattern — a loop of Thought → Action → Observation.

**A:** FAIR; FAIR (USAFA); Flexible; Agnostic; Interoperable; Reasoning; ReAct

**Q:** The FAIR "anatomy metaphor" maps each module to a body part. Fill in the blanks:
- Brain: _________
- Mouth & Ears: _________ (the MAL — Model Abstraction Layer — adapters for OpenAI/Anthropic/Ollama)
- Hands: _________ + _________
- Short-term Memory: _________ | Long-term Memory: _________ (RAG)
- Senses: _________ module | Immune System: _________ module

**A:** Planner; LLM adapters; ToolRegistry; ToolExecutor; WorkingMemory; LongTermMemory; Perception; Security

**Q:** The agent supports four LLM providers via an adapter pattern: (1) _________, (2) _________, (3) _________ (local inference), and (4) _________ (routing between providers).

**A:** OpenAI; Anthropic; Ollama; Hybrid

**Q:** Every tool in the system conforms to the FAIR interface: a class with attributes `name`, `description`, and a method `.use(tool_input: _________) -> _________`. Tool inputs are parsed as _________ by convention.

**A:** str; str; JSON

**Q:** FAIR ships TWO planner variants, and your `agent.py` imports both. Choose the right one for the model:
- `ReActPlanner` — requires LLM output as a strict _________ object; best for GPT-4 / Claude Opus-class models
- `SimpleReActPlanner` — uses a simpler _________ format (`Thought:` / `Action:` / `tool_name:` / `tool_input:`); best for smaller or local _________ models that struggle with strict JSON

**A:** JSON; key-value; Ollama (open-source)

**Q:** The system prompt is NOT a single string — it is assembled by `PromptBuilder` from four discrete `PromptItem` types: (1) _________ (highest-level "who you are"), (2) _________ (auto-generated per registered tool), (3) _________ (rigid "your response MUST be JSON"), (4) _________ (few-shot exemplars). This is the main customization seam; e.g., `planner.prompt_builder.role_definition = RoleDefinition("You are a CTF solver...")`.

**A:** RoleDefinition; ToolInstruction; FormatInstruction; Example

**Q:** The prompt-code coupling is deliberate: the `SimpleReActPlanner` default prompt literally says "look at the most recent _________ message," and `SimpleAgent` wraps every tool output as `Message(role="_________", content=f"Observation: {result}")`. This tight alignment is what makes the parser reliable.

**A:** 'system'; system

**Q:** The core agent file is [ctf_solver/agent.py](ctf_solver/agent.py). The entry-point CLI is [ctf_solver/runner.py](ctf_solver/runner.py), which is invoked via `python -m ctf_solver` — the module delegates to _________.

**A:** runner.main()

### The Agent Loop — Reasoning Pattern

**Q:** On each turn the LLM produces JSON of the form `{"thought": "...", "action": {"tool_name": "...", "tool_input": "..."}}`. The executor invokes the named tool with the string input and returns an _________, which is appended to memory. The loop terminates when the LLM emits _________ AND a candidate flag matches the configured regex.

**A:** observation; FinalAnswer

**Q:** The custom subclass `CTFAgent` extends `SimpleAgent` with four defensive enhancements: (1) strips _________ code fences (```` ```json ````) before parsing; (2) blocks _________ (FinalAnswer returned before any flag was found); (3) applies _________ windowing to cap per-turn context; (4) fires a 3-tier _________ detection nudge system when progress stalls.

**A:** markdown; premature FinalAnswer; history; stall

**Q:** The 3-tier stall nudge fires when 5+ tool calls show no new URL, no new HTTP status, and no flag. Tier 1 forces a call to the _________ tool (RAG). Tier 2 pushes the agent to pivot to a different _________ (vulnerability class). Tier 3 emits a forced _________ with best-guess output.

**A:** ctf_knowledge_query; attack category; FinalAnswer

**Q:** A `StuckDetector` inside `LoggingToolWrapper` flags the 3rd+ identical `(tool_name, normalized_input)` invocation as _________ — tool repetition is treated as an anti-progress signal in addition to output stagnation.

**A:** redundant

### Opener Pack (Pre-LLM Reconnaissance)

**Q:** When `enable_opener_pack=True` (default) and `challenge_url` is set, the agent runs _________ zero-reasoning tool calls BEFORE the LLM loop begins: (1) _________, and (2) _________ with max 20 paths. Results are logged to the tracker and injected as initial _________ into the first LLM prompt — saving 2-3 LLM turns.

**A:** two; robots_txt; path_enumerator; observations

### Parallel Tool Use (Opt-In)

**Q:** When `enable_parallel_tools=True` and the adapter is _________, the agent routes LLM calls through native `tool_use` blocks (Claude's native tool format) and executes ALL tool calls from one assistant response in a _________ agent step. Other providers fall back to JSON-ReAct with a warning.

**A:** Anthropic; single

---

## SECTION 2 — CONFIGURATION (`ctf_solver/config.py`)

**Q:** The `SolverConfig` dataclass is the single source of truth for runtime behavior. The default flag regex is approximately `[A-Za-z0-9_]+{[^}]{1,200}}`, with noise filtering that rejects _________ placeholders, _________ shapes, _________ rules, and PHP arrays.

**A:** JSON; CSS; (accept either: JSON/CSS noise; or "placeholder text")

**Q:** The `max_steps` default is _________, the `max_tokens` default is _________, and the LLM timeout default is _________ seconds.

**A:** 20; 4096; 120.0

**Q:** The `RAGMode` enum has five values: `NONE`, _________, `LESSONS_WRITE`, `LESSONS_READONLY`, `LESSONS_BUILDONLY`. The two frozensets `RAG_WRITE_MODES` and `RAG_EXPERIENCE_MODES` are used throughout the codebase for mode checks.

**A:** ORIGINAL

**Q:** Explain the five RAG modes: (1) `NONE` — _________; (2) `ORIGINAL` — only curated docs in `docs/`; (3) `LESSONS_WRITE` — reads experience DB AND writes atomic rules after every run; (4) `LESSONS_READONLY` — reads experience DB, never _________; (5) `LESSONS_BUILDONLY` — curated docs only during run, writes atomic rules after every run (useful for _________ bootstrapping).

**A:** no knowledge base; writes; building the lessons DB from scratch

**Q:** `use_llm_for_lessons` defaults to _________. When set to True, the post-run analysis calls _________ to replace three deterministic fields: `causal_diagnosis`, `reflexion_summary`, and per-rule `causal_explanation`. Estimated cost per run is ~$_________.

**A:** False; gpt-4o-mini; 0.0003

**Q:** Config can be populated from three sources with the following precedence (highest to lowest): _________ arguments → _________ variables → dataclass defaults. The `from_env()` method reads `CTF_LLM_LESSONS` and `CTF_LESSONS_MODEL`.

**A:** CLI; environment

---

## SECTION 3 — TOOL INVENTORY (55 CLASSES, 14 CATEGORIES)

### Category Counts (Orient Yourself)

**Q:** Match each category to the number of tools:
- HTTP / Recon / Meta: _________
- SQL Injection family: _________
- XPath Injection: _________
- SSTI: _________
- XSS / Client-side (incl. CSS, DOM clobbering): _________
- File Upload + File Inclusion: _________
- Crypto: _________
- Encoding/Hash: _________

**A:** 8; 6; 3; 2; 5; 4; 3; 2

### HTTP, Reconnaissance & Search

**Q:** The two most-used tools in the entire system are _________ (GET/POST with cookies/headers/auth) and _________ (HTML form submission with redirect following). Both share a single `requests.Session` for cookie persistence.

**A:** HttpFetchTool (http_fetch); FormSubmitTool (form_submit)

**Q:** Reconnaissance tool roster: `RobotsTxtTool`, `PathEnumeratorTool`, `BackupFileFinder` (probes .bak, .swp, .old), `SecurityHeaderAnalyzerTool` (CSP/CORS/HSTS), _________ (combined probe: server type + WAF + framework), and `AttackPlannerTool` (LLM-free strategy suggestion).

**A:** DeepReconTool

**Q:** The three search/diff tools in [ctf_solver/tools/search_tools.py](ctf_solver/tools/search_tools.py) and [diff_tools.py](ctf_solver/tools/diff_tools.py) are: `RegexSearchTool`, `ResponseSearchTool`, `SqlPatternHintTool` (search) and `ResponseDiffTool`, `TimingCompareTool`, `ResponseFingerprinter` (diff). The _________ tool is used for blind-SQLi timing-side-channel detection.

**A:** TimingCompareTool

### Injection Tool Families

**Q:** The SQL injection family contains six tools. Name them (hint: 2 probe/hint, 2 blind, 1 utility, 1 dumper):

**A:** SqliProbeTool, SqliColumnCounter, SqlPatternHintTool, BlindSqliBooleanTool, BlindSqliTimeTool, SqliDataDumper

**Q:** SSTI has two tools: `SstiProbeTool` (injects arithmetic like `{{7*7}}`, `${7*7}`) and _________ (suggests RCE payloads once the template engine is known — Jinja2, Mako, FreeMarker, etc.).

**A:** SstiExploitSuggester

**Q:** XPath injection tools: `XPathProbeTool`, `XPathBlindBooleanTool`, `XPathPayloadGenerator`. NoSQL tools: `NosqlProbeTool`, `NosqlPayloadGenerator` (generates `$ne`, `$gt`, `$regex` operator injections). Command injection tools: `CommandInjectionProbeTool`, `CommandInjectionPayloadGenerator`. XXE tools are _________ in count: `XxeProbeTool`, `XxePayloadGenerator`, and `XxeDocTypeBuilder`.

**A:** three

### Client-Side Tools

**Q:** The XSS toolkit has: `XssProbeTool`, `XssPayloadGenerator` (polyglot generator, bypasses WAFs via event handlers/encoding), and `CspAnalyzerTool`. The DOM clobbering payload generator lives in [session_forgery_tools.py](ctf_solver/tools/session_forgery_tools.py) — class name _________.

**A:** DomClobberingPayloadGenerator

**Q:** The CSS injection tools are `CssInjectionPayloadGenerator` (builds `@import`, attribute selectors) and _________ (builds CSS-based data exfiltration via response timing and external requests).

**A:** CssExfiltrationBuilder

### File Handling

**Q:** File upload tools: `FileUploadTool` (manipulates content-type, magic bytes, extension) and _________ (probes common web-accessible directories to locate uploaded files after upload). LFI tools: `LfiProbeTool`, `LfiPayloadGenerator` (null bytes, `php://filter`, `zip://`, `phar://` wrappers).

**A:** UploadLocationFinder

### Specialized Attack Tools

**Q:** Auth/session forgery tool: _________ (forges Flask session cookies when the secret is known or guessed via the 400+-word secret wordlist). JWT utility: `JwtTool` (decode, verify, forge HS256 with known secret).

**A:** FlaskSessionForgeryTool

**Q:** Three crypto tools: `CryptoProbeTool` (weak ciphers: RC4, DES, ECB), `CryptoAnalyzerTool` (hashes, padding oracles), `CryptoPayloadGenerator` (hash collisions, padding oracle attacks). Two encoding tools: _________ (URL/Base64/HTML/Unicode/hex/morse), `HashIdentifierTool`.

**A:** EncodingTool

**Q:** The six specialized attack probes you should be able to name on demand:
- Open redirect: _________
- SSRF: _________ + _________
- HTTP request smuggling: _________
- CRLF injection: _________
- Parser differential: _________

**A:** OpenRedirectProbeTool; SsrfProbeTool; SsrfPayloadGenerator; HttpSmugglingProbeTool; CrlfProbeTool; ParserDifferentialProbeTool

**Q:** PHP-specific tools: `PhpTypeJugglingTool` (exploits `==` vs `===`) and `PhpFilterChainTool` (builds `php://filter/convert.base64-encode/...` chains). GraphQL tools: `GraphqlIntrospectionTool` (dumps `__schema`) and _________.

**A:** GraphqlQueryTool

**Q:** Logic/business tools: `RaceConditionTool` (concurrent requests), `IdorEnumeratorTool` (sequence guessing of object IDs), and _________ (mutates payloads — encode/obfuscate/concatenate — to bypass WAFs).

**A:** PayloadMutatorTool (filter_bypass_tools.py)

**Q:** The WebSocket tool is _________. The WASM reverse-engineering tool is _________ (disassembles `.wasm`, analyzes functions and data sections). The OAuth tools are `OAuthProbeTool` and `OAuthPayloadGenerator`.

**A:** WebSocketProbeTool; WasmAnalyzerTool

**Q:** Misc: `ShellExecuteTool` (local shell — for encoding/decoding/processing, NOT RCE on target), `PrototypePollutionTool`, `RequestRepeaterTool` (HTTP fuzzer — repeats requests with param/header/payload variations), `FilterEnumeratorTool` (enumerates WAF filters via encoding variations), and the single RAG tool _________.

**A:** SafeKnowledgeQueryTool (ctf_knowledge_query)

### Taxonomy (Tool → Category Mapping)

**Q:** [ctf_solver/taxonomy.py](ctf_solver/taxonomy.py) is the single source of truth for `TOOL_TO_CATEGORY`, which failure_analyzer uses for _________ naming, dedup, and lessons-learned output labels. A drift-protection test in _________ verifies every tool in `logging_wrapper._TOOL_CATEGORIES` is either in `TOOL_TO_CATEGORY` or explicitly listed as display-only.

**A:** slug; tests/test_taxonomy.py

---

## SECTION 4 — LOGGING WRAPPER & RUN TRACKER

### LoggingToolWrapper

**Q:** Every instantiated tool is wrapped by _________ inside `build_agent()`. The wrapper provides: (1) truncated tool-call logging (inputs to _________ chars, outputs to _________ chars); (2) flag scanning via regex against every output; (3) `StuckDetector` for repeated calls; (4) `ReflectionEngine` for category-pivot suggestions.

**A:** LoggingToolWrapper; 120; 150

**Q:** The wrapper records structured entries to `tracker.tool_call_log`: `{tool, input[:2000], output[:2000], timestamp}`. When a flag is detected, it is added to _________ and also preserved on the tracker for the final outcome determination.

**A:** tracker.candidate_flags_found

### RunTracker (`ctf_solver/run_tracker.py`)

**Q:** The `RunTracker` dataclass holds metrics used both at runtime (for decision-making) and post-run (for lessons analysis). Name the six v2.4-era learning metrics: (1) _________ (bool — was prior Reflexion injected?); (2) _________ (int — count of RAG queries); (3) _________ (str — "success"/"partial"/"failure"); (4) _________ (property — distinct tool names used); (5) _________ (str — content-based site identity); (6) _________ (List[int] — steps at which stall nudges fired).

**A:** prior_reflection_injected; rag_queries_made; outcome; unique_tools_used; site_fingerprint; stall_nudges_fired

**Q:** The `site_fingerprint` is extracted from the FIRST `http_fetch` or `form_submit` output. Its format is approximately `"title:<value>|h1:<value>|form:<value>"` and it is used for _________ filtering in the RAG system (v2.4) — replacing the earlier, more fragile _________-based filtering.

**A:** contamination; URL

**Q:** `TokenTrackingAdapter` is a transparent proxy that wraps any FAIR `AbstractChatModel`. It delegates all methods to the inner adapter while estimating token counts from message character length using the heuristic _________ characters per token.

**A:** ~4

---

## SECTION 5 — RAG / KNOWLEDGE BASE (`ctf_solver/rag/`)

### Vector Store Pipeline

**Q:** The embedding model is _________ (384 dimensions). The vector store backend is _________ with disk persistence. The default chunk size is _________ characters with _________ characters of overlap.

**A:** sentence-transformers/all-MiniLM-L6-v2; FAISS; 1000; 150

**Q:** The retrieval pipeline has four stages: (1) _________ — rephrases query into 2-3 semantic variations; (2) _________ — combines BM25 (40%) + vector similarity (60%); (3) filter exclusions (contamination + seen-docs); (4) _________ — re-ranks top-k with similarity threshold (~0.1) and doc-type boosting.

**A:** QueryExpander; HybridSearcher; SimpleReranker

**Q:** Doc-type boosting order during reranking: _________ > `experience_success` > `experience_failure`. This ensures distilled wisdom outranks raw episodic docs.

**A:** consolidated

### SafeKnowledgeQueryTool

**Q:** The tool exposed to the agent is `SafeKnowledgeQueryTool` (tool name `ctf_knowledge_query`). The "Safe" prefix refers to _________ — docs from the current challenge are filtered out of retrieval results but remain in the index for cross-challenge generalization.

**A:** contamination filtering

**Q:** The filter uses content fingerprint (title/h1/form) with a _________ similarity threshold of _________ for exclusion. The per-run `_seen_source_files` set is _________ every run to prevent the same doc from appearing in every query (VOYAGER pattern).

**A:** Jaccard; 0.60; reset

**Q:** After a lessons-writing run, the module-level registry function _________ is called to rebuild the vector index mid-session so newly written docs are queryable by subsequent runs in the same batch.

**A:** refresh_index() (via get/set_active_knowledge_tool)

---

## SECTION 6 — CHALLENGE CLASSIFIER (`ctf_solver/classifier/`)

**Q:** The classifier is _________-based (keyword + pattern matching); there is _________ ML model. It returns a `ClassificationResult` with `primary_category`, `confidence` (0.0-1.0), `secondary_categories`, `matched_keywords`, `suggested_tools`, and `suggested_approach`.

**A:** rule; no

**Q:** The classifier supports 20 categories via a `ChallengeCategory` enum (SQL_INJECTION, XSS, SSTI, XXE, FILE_UPLOAD, etc.). Its output `suggested_tools` is derived from `TOOL_PRIORITIES` — a dict mapping _________ → _________ tool list. This is intentionally NOT folded into `taxonomy.TOOL_TO_CATEGORY` because the shape and purpose differ.

**A:** category; ordered (ranked)

---

## SECTION 7 — LESSONS-LEARNED PIPELINE (`ctf_solver/failure_analyzer.py`)

### Research Lineage

**Q:** The lessons-learned pipeline is research-backed. Name the four cited works: (1) _________ (Zhao et al. — per-rule atomic experience distillation); (2) _________ (Shinn et al. NeurIPS 2023 — verbal reinforcement via reflection injection); (3) _________ (Wang et al. — skill-library accumulation for Minecraft agents, seen-doc pattern); (4) _________ (retrieval-augmented fine-tuning — cited for context selection).

**A:** ExpeL; Reflexion; VOYAGER; RAFT

### Core Data Structures

**Q:** The unified post-run result type is `LessonsLearnedDoc` (dataclass). Its key fields:
- `challenge_name`, `outcome`, `category`, `timestamp`, `total_steps`
- `tool_sequence: List[str]` — ordered unique tools
- `tool_frequency: Dict[str, int]`
- `causal_diagnosis: str` — WHY it succeeded/failed
- `atomic_rules: List[_________]` — 2-5 transferable rules per run
- `reflexion_summary: str` — _________ word narrative for future injection
- `winning_inputs: List[str]` — exact tool inputs (flag-scrubbed) that found the flag
- `failed_approaches: List[str]`
- `template_engine: str`

**A:** AtomicRule; 100-200

**Q:** An `AtomicRule` has six fields: `triggering_condition` (when you see X), `agent_takeaway` (imperative: "Do Y because Z"), `rule_type` (_________ or _________), `tool_context` (which tools), `confidence` (_________/_________/_________), and `causal_explanation`.

**A:** "do"; "do_not"; low; medium; high

### Pipeline Stages

**Q:** `run_lessons_learned_pipeline()` is the top-level entry. It calls `analyze_run()` which performs deterministic signal extraction:
1. `_detect_partial_successes()` — scans outputs for SSTI/SQLi/auth/schema signals
2. `_detect_missed_signals()` — identifies incomplete exploration
3. `_extract_winning_inputs()` — tool calls whose outputs contained the flag
4. `_detect_failed_approaches()` — specialized tools that failed BEFORE the win
5. _________ — 3-tier SSTI engine detection (arithmetic confirmation, scrubbed winning_inputs, output markers)
6. `_apply_causal_patterns()` — regex match against WAF/auth/rate-limit patterns

**A:** `_detect_template_engine()`

**Q:** Category inference uses tool frequency as the baseline heuristic, but `_PARTIAL_SUCCESS_CATEGORY_OVERRIDE` promotes specialist-tool signals. For example: SSTI challenges solved via `http_fetch` + `form_submit` (which dominate the frequency count) are still correctly categorized as _________ when the partial-success signal `ssti_confirmed` is present.

**A:** ssti

**Q:** Atomic rule generation produces _________ rules per run. Each is tightly focused for high-precision RAG retrieval. Example trigger: "When WAF blocks special characters in SQLi." Example takeaway: "Use filter_enumerator to detect filter, then PayloadMutator with hex/unicode encoding."

**A:** 2-5

### v2.6.0 LLM Enhancement

**Q:** When `use_llm_for_lessons=True`, `_llm_enhance_doc()` calls _________ to replace three deterministic fields with richer causal text: _________, _________, and per-rule _________. All text is pre-scrubbed before sending AND post-scrubbed before storing (to prevent flag leakage into the knowledge base). Silent fallback to deterministic text on any error.

**A:** gpt-4o-mini; causal_diagnosis; reflexion_summary; causal_explanation

**Q:** What stays deterministic even with LLM enhancement? Four fields that are structurally required by downstream consumers: (1) _________ (feeds Jaccard dedup in `_find_similar_rule_doc`); (2) `agent_takeaway` structure (RAG optimization); (3) `tool_sequence`; (4) `winning_inputs`. **Why?** These are load-bearing for dedup, retrieval, and analytics — LLM variance would break them.

**A:** triggering_condition

### Scrubbing & Dedup

**Q:** Flag scrubbing uses three different patterns depending on the field:
- **Broad regex (full flag_regex)**: applied to outputs, `causal_explanation`, `triggering_condition`, `agent_takeaway`
- **Exact-match only** (literal flag string replacement): applied to _________ to preserve template syntax like `{{config.items()}}` which would otherwise be destroyed by broad regex
- **Post-scrub append**: applied in `_compress_to_reflexion_summary` — strategy text and `winning_inputs` are appended AFTER `_scrub_flags()` to prevent broad regex destruction

**A:** winning_inputs (inside `_extract_winning_inputs`)

**Q:** Cross-run confidence merging: `_find_similar_rule_doc()` uses Jaccard similarity ≥ _________ on `triggering_condition`. If a similar rule exists, `_bump_confidence()` escalates low → medium → high instead of writing a redundant doc. The first-5-tools `_tool_sequence_hash` ensures that same URL+category+outcome with _________ tools is NOT treated as a duplicate.

**A:** 0.60; different

### Consolidation (`consolidate_knowledge.py`)

**Q:** `consolidate_lessons_knowledge()` groups `lessons_*.md` docs by category. When _________ or more docs exist in a category, it distills them into a single `consolidated_lessons_<category>.md` file containing a "Quick Exploitation Path" + ranked takeaways + negative knowledge.

**A:** 2 (threshold=2)

**Q:** Consolidated docs are tagged `consolidated, {category}, wisdom, high-priority` — these tags drive the reranker boost so distilled wisdom outranks raw episodic docs during retrieval.

### Reflexion Injection (Episodic Reuse)

**Q:** At agent startup, if `rag_mode in RAG_EXPERIENCE_MODES` and `challenge_name` is provided, the function _________ searches `lessons_docs_dir` for prior docs matching the challenge_name, collects ALL matching docs (not just the most recent), and injects a success/failure distribution + most recent success details as a "Prior Attempt Analysis" section into the initial prompt. This is the core Shinn et al. pattern: _________ reinforcement via verbal self-reflection.

**A:** find_and_compress_prior_lesson(); verbal

---

## SECTION 8 — SOURCE ANALYZER (`ctf_solver/source_analyzer.py`)

**Q:** For challenges that ship source code (uploaded via CLI `--source-file` or Streamlit upload), the source analyzer performs _________-flow analysis inspired by _________ taint-mode — source → sink analysis with sanitizer detection. Zero required dependencies (stdlib only); opportunistically uses bandit/semgrep when installed.

**A:** taint; Semgrep

**Q:** Six vulnerability classes, each with precompiled sink + sanitizer patterns: **RCE** (sinks: `eval`, `exec`, `system`, `subprocess`; sanitizer: `shlex.quote`); **Deserialization** (sinks: `pickle.loads`, `yaml.load`; sanitizer: `yaml.safe_load`); **SSTI** (sinks: `render_template_string`, `jinja2.from_string`; sanitizer: `Markup.escape`); **SQLi** (sinks: string-concatenated `execute`, `query`; sanitizer: _________); **XSS** (sinks: `.innerHTML=`, `document.write`); **PathTraversal** (sinks: `open(...request)`; sanitizer: `secure_filename`).

**A:** parameterize / placeholder (parameterized queries)

**Q:** Source patterns — user-controlled input detection spans four languages: Python (`request.args/form/cookies/headers/json`), JavaScript (`req.body/query/params`), PHP (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`), and _________ (`params[...]`, `request.env`).

**A:** Ruby

---

## SECTION 9 — LLM ADAPTER LAYER (`ctf_solver/llm/`)

**Q:** The adapter layer implements FAIR's `AbstractChatModel` interface (`.invoke`, `.ainvoke`, `.stream`, `.astream`). Each provider has a subclass: `OpenAIAdapter` (FAIR built-in), _________ (custom — supports native `tool_use` blocks for parallel tools), `OllamaAdapter` (custom — local inference, no API key), and `HybridAdapter` (custom — round-robin/fallback).

**A:** AnthropicAdapter

**Q:** Retry logic: `_retry_with_backoff()` uses _________ backoff (1s → 2s → 4s) for transient errors — `RateLimitError`, `APIConnectionError`, `APITimeoutError`, `InternalServerError`. Non-transient errors (`AuthenticationError`, `BadRequestError`) fail immediately. Max retries default is _________.

**A:** exponential; 3

**Q:** `create_adapter_from_config()` is the factory function that inspects `config.llm_provider` and instantiates the appropriate adapter. The factory supports custom `llm_base_url` for routing to alternative OpenAI-compatible endpoints (e.g., _________ for government/military deployments).

**A:** api.genai.mil

---

## SECTION 10 — STREAMLIT UI (`ctf_solver/ui/streamlit_app.py`)

**Q:** The Streamlit app exposes three runtime modes: (1) _________ entry — type challenge URL + description; (2) _________ upload — upload source code (ZIP/TAR/single file); (3) _________ dispatch — consolidate lessons / refresh knowledge base buttons.

**A:** manual; file; batch (or: offline tools)

**Q:** At startup the app calls `_find_and_load_dotenv()` to load `.env` from CWD or project root, then sets `TOKENIZERS_PARALLELISM=false` and `OMP_NUM_THREADS=1` to prevent _________ crashes on Apple Silicon.

**A:** multiprocessing

**Q:** The "Enrich lessons with gpt-4o-mini" checkbox in the Streamlit UI is visible ONLY when `rag_mode` is in `RAG_WRITE_MODES` — i.e., one of _________ or _________. It binds to `session_state.use_llm_for_lessons`.

**A:** LESSONS_WRITE; LESSONS_BUILDONLY

---

## SECTION 11 — END-TO-END RUN TIMELINE

**Q:** Walk through a canonical run in order. Fill in the blanks:

1. CLI parses args → builds `SolverConfig` → creates `RunTracker`.
2. `build_agent()`: creates LLM adapter → wraps with _________ → instantiates ~55 tools → wraps each with `LoggingToolWrapper` → registers in `ToolRegistry`.
3. If RAG mode ≠ NONE: initialize vector store → build `SafeKnowledgeQueryTool` with _________ filter active.
4. Create `ReActPlanner` with 6 few-shot examples: ROBOTS_EXAMPLE, DEEP_RECON_EXAMPLE, JSON_API_EXAMPLE, JS_ANALYSIS_EXAMPLE, COOKIE_BYPASS_EXAMPLE, _________.
5. Opener Pack (if enabled): run `robots_txt` and `path_enumerator` → inject results as observations.
6. Reflexion injection (if RAG_EXPERIENCE_MODES + challenge_name): call _________ → inject as "Prior Attempt Analysis."
7. Agent loop (max_steps = 20): Thought → Action → Observation, with stall detection and premature-FinalAnswer guard.
8. Post-run: extract flags → run `analyze_run()` → [optional LLM enhancement] → generate _________ → dedup check → write markdown doc.
9. [Async] `consolidate_lessons_knowledge()` + `refresh_index()`.

**A:** TokenTrackingAdapter; contamination; SELF_REFLECTION_EXAMPLE; find_and_compress_prior_lesson(); atomic rules

---

## SECTION 12 — KEY DESIGN DECISIONS (WHY QUESTIONS)

**Q: Why ReAct instead of a pure function-calling loop?**
**A:** ReAct produces an explicit `thought` field before each action, which is (1) interpretable for debugging and evaluation, (2) logged for lessons-learned extraction, and (3) keeps the pattern model-agnostic (works for OpenAI / Anthropic / Ollama alike without requiring native function calling).

**Q: Why atomic rule docs (300-400 words each) instead of monolithic failure/success docs?**
**A:** Atomic docs → better RAG retrieval _________. One transferable rule per doc means fewer irrelevant bytes in each retrieved chunk. Consolidation (≥2 docs → wisdom doc) then moves episodic memory → semantic memory offline, mirroring the ExpeL pattern.

**A:** precision

**Q: Why content-based (fingerprint) contamination filtering instead of URL-based?**
**A:** URL-based filtering is _________ — CTF platforms rotate URLs, randomize subdomains, and serve identical challenges at different paths. Fingerprint (title/h1/form) captures _________ identity and survives these changes.

**A:** fragile; content

**Q: Why keep `use_llm_for_lessons` OFF by default?**
**A:** Three reasons: (1) _________ — deterministic pipeline works without any API calls beyond the main agent; (2) _________ — ~$0.0003/run is small but compounds over batch runs; (3) _________ — deterministic fields are load-bearing for dedup and retrieval; LLM variance would break those invariants. LLM enhancement is optional enrichment, not baseline.

**A:** reliability (no network dependency); cost; determinism

**Q: Why tiered stall detection (3 tiers) instead of a single nudge?**
**A:** A one-shot nudge is either too weak (agent ignores it) or too aggressive (forces a premature FinalAnswer). The 3-tier escalation matches the severity of the stall: RAG retrieval first (cheapest, most informative), then category pivot (medium cost), then forced termination (last resort). Tool-call repetition is treated as an independent anti-progress signal parallel to output stagnation.

**Q: Why ReAct and not Plan-and-Execute (the alternative FAIR planner pattern)?**
**A:** CTF solving is fundamentally _________ — you cannot plan the whole exploit up front because you don't know what's on the server until you probe it. ReAct's step-at-a-time adaptation is a structural fit. Plan-and-Execute (FAIR Ch. 7) would be a better fit for _________, deterministic workflows where the steps are known in advance (e.g., a compliance-check agent). You explicitly picked reactivity over up-front planning because the problem domain demands it.

**A:** reactive (adaptive); fixed (scripted)

**Q: Why single-agent instead of the FAIR multi-agent committee pattern (`HierarchicalAgentRunner` + `ManagerPlanner`)?**
**A:** Three reasons. (1) _________ — CTF reasoning is tightly coupled: the "what to try next" decision depends on every prior observation, and splitting that across a manager/worker boundary would force every observation to be summarized and re-delegated, losing fidelity. (2) _________ — 55 specialized tools in one registry is simpler than 5 worker agents each with a narrow toolset, especially since category boundaries blur (XSS chained with CSRF, SSRF pivoting to LFI). (3) _________ cost — each delegation adds a Manager planning call AND a Worker planning call; single-agent is one LLM call per step.

**A:** context coherence; tool-category overlap; latency (or: token)

**Q: Why a `TokenTrackingAdapter` transparent proxy instead of inline instrumentation?**
**A:** The FAIR framework is _________ — adapting its internals would create an upgrade burden. A proxy delegates all methods to the inner adapter while adding telemetry; future FAIR updates are absorbed for free.

**A:** external (or: third-party / a dependency)

---

## SECTION 13 — STATS YOU MIGHT BE ASKED

**Q:** Version | Tool count | Doc count | Chunks | Tests
**A:** v2.6.0 | 55 tool classes (78 `__all__` entries including re-exports/wrappers) | 42 RAG docs | 1,237 chunks | 1,978 tests

**Q:** Rule-doc-to-wisdom-doc consolidation threshold, Jaccard dedup threshold, default max steps, default max tokens.
**A:** ≥2 docs per category triggers consolidation | Jaccard ≥ 0.60 | max_steps=20 | max_tokens=4096

**Q:** Average cost of LLM-enhanced lessons per run.
**A:** ~$0.0003 (gpt-4o-mini, 800 tokens in + 300 out)

**Q:** Chunk size and overlap for the vector store.
**A:** 1000 chars chunk, 150 chars overlap

---

## SECTION 14 — SELECT-ALL-THAT-APPLY PRACTICE

**Q:** Which of the following are RAG modes? (Select all)
- (a) NONE  (b) ORIGINAL  (c) AUGMENTED  (d) LESSONS_WRITE  (e) LESSONS_READONLY  (f) LESSONS_BUILDONLY  (g) LESSONS_HYBRID

**A:** (a), (b), (d), (e), (f). AUGMENTED/AUGMENTED_READONLY were **removed** when the monolithic pipeline was retired in v2.3. LESSONS_HYBRID does not exist.

**Q:** Which of the following are fields on `RunTracker` (v2.4 or later)?
- (a) `prior_reflection_injected`  (b) `rag_queries_made`  (c) `unique_tools_used`  (d) `site_fingerprint`  (e) `stall_nudges_fired`  (f) `llm_cost_usd`  (g) `redundant_tool_calls`

**A:** (a), (b), (c), (d), (e), (g). `llm_cost_usd` is NOT tracked — only token counts are estimated.

**Q:** Which of the following are stages of the RAG retrieval pipeline?
- (a) QueryExpander  (b) HybridSearcher  (c) SimpleReranker  (d) ContaminationFilter  (e) SeenDocExclusion  (f) PromptCompressor

**A:** (a), (b), (c), (d), (e). `PromptCompressor` is not a component — compression happens in Reflexion summary generation, not retrieval.

**Q:** Which research papers directly informed the v2.3-v2.5 lessons-learned pipeline?
- (a) ExpeL (Zhao et al.)  (b) Reflexion (Shinn et al.)  (c) VOYAGER (Wang et al.)  (d) RAFT  (e) Toolformer  (f) Park et al. (generative agents)

**A:** (a), (b), (c), (d), (f). Toolformer is not cited in this pipeline.

---

## SECTION 15 — TRUE / FALSE RAPID FIRE

**Q: (T/F)** The agent uses LangChain as its underlying framework.
**A:** FALSE — it uses FAIR (`fairlib`), not LangChain.

**Q: (T/F)** The SafeKnowledgeQueryTool filters docs by URL matching.
**A:** FALSE — as of v2.4, contamination filtering is content-based (site fingerprint Jaccard ≥ 0.60). URL-based filtering was removed because CTF URLs rotate.

**Q: (T/F)** The `use_llm_for_lessons` flag replaces ALL fields in `LessonsLearnedDoc` with LLM-generated text.
**A:** FALSE — it replaces only THREE fields (`causal_diagnosis`, `reflexion_summary`, per-rule `causal_explanation`). Structurally load-bearing fields (`triggering_condition`, `tool_sequence`, `winning_inputs`) stay deterministic.

**Q: (T/F)** Parallel tool use is the default execution mode.
**A:** FALSE — `enable_parallel_tools=False` by default. It is opt-in and only supported when the adapter is Anthropic (native `tool_use` blocks).

**Q: (T/F)** The opener pack (robots.txt + path enumeration) runs BEFORE the LLM loop begins, with no LLM reasoning involved.
**A:** TRUE — it executes two zero-reasoning tool calls pre-loop, saving 2-3 LLM turns.

**Q: (T/F)** The LessonsLearnedDoc and the legacy FailureAnalysis dataclass are both still used in the codebase.
**A:** TRUE — `LessonsLearnedDoc` is the unified v2.3+ type, but `FailureAnalysis` is retained for backward compatibility with the legacy AUGMENTED pipeline (now deprecated but still dispatched when legacy RAG modes are used).

**Q: (T/F)** The classifier uses a fine-tuned transformer to categorize CTF challenges.
**A:** FALSE — it is rule-based (keyword + pattern matching). No ML model, no live LLM call. This ensures deterministic and fast classification.

**Q: (T/F)** Atomic rules have a `rule_type` field that can only be "do" or "do_not".
**A:** TRUE — this binary distinction drives RAG retrieval: positive exemplars (do) for action guidance, negative exemplars (do_not) for anti-patterns. Matches the positive/negative exemplar framing in the ExpeL paper.

---

## SECTION 16 — ONE-MINUTE ELEVATOR PITCH (FOR Q&A)

> *"The CTF Solver is an autonomous penetration-testing agent built on the FAIR framework, orchestrating ~55 specialized security tools through a ReAct reasoning loop. It supports OpenAI, Anthropic, Ollama, and hybrid LLM backends. What makes it distinct is the lessons-learned pipeline: after every run, a deterministic analyzer extracts 2-5 atomic transferable rules from the run trace and writes them to a FAISS-backed knowledge base. Prior attempts on the same challenge are compressed into a Reflexion-style verbal summary and injected into future prompts — a direct implementation of Shinn et al.'s NeurIPS 2023 pattern. A content-based contamination filter prevents the knowledge base from simply memorizing the current target, so the system actually generalizes across challenges. Optional gpt-4o-mini enrichment adds causal depth to lessons at ~$0.0003 per run, but load-bearing structural fields stay deterministic to preserve dedup and retrieval invariants."*

---

## APPENDIX — FILE MAP (WHERE TO LOOK)

| Concern | File |
|---------|------|
| Agent construction | [ctf_solver/agent.py](ctf_solver/agent.py) |
| CLI entry + pipeline wiring | [ctf_solver/runner.py](ctf_solver/runner.py) |
| Config dataclass + RAGMode enum | [ctf_solver/config.py](ctf_solver/config.py) |
| Lessons-learned pipeline | [ctf_solver/failure_analyzer.py](ctf_solver/failure_analyzer.py) |
| Wisdom doc consolidation | [ctf_solver/consolidate_knowledge.py](ctf_solver/consolidate_knowledge.py) |
| Run metrics + token proxy | [ctf_solver/run_tracker.py](ctf_solver/run_tracker.py) |
| Taxonomy (tool → category) | [ctf_solver/taxonomy.py](ctf_solver/taxonomy.py) |
| Source-code taint analysis | [ctf_solver/source_analyzer.py](ctf_solver/source_analyzer.py) |
| Vector store + SafeKnowledgeQueryTool | [ctf_solver/rag/](ctf_solver/rag/) |
| LLM adapters (Anthropic, Ollama, Hybrid) | [ctf_solver/llm/](ctf_solver/llm/) |
| Tool implementations | [ctf_solver/tools/](ctf_solver/tools/) |
| LoggingToolWrapper + StuckDetector | [ctf_solver/tools/logging_wrapper.py](ctf_solver/tools/logging_wrapper.py) |
| Streamlit UI | [ctf_solver/ui/streamlit_app.py](ctf_solver/ui/streamlit_app.py) |
| Tests | [tests/](tests/) |

---

*Good luck at MORS. If someone asks a question you can't answer, the honest response is "that's a region of the system I'd want to walk through the code on" — never bluff architecture details in front of a technical audience.*
