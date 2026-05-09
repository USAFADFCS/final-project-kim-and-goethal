"""
CLI runner for CTF Solver.

Provides command-line interface for running the CTF solving agent.
"""

import argparse
import asyncio
import logging
import os
import re
import sys
import time
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional

# Quiet the transformers ``__path__`` deprecation flood at import time
# (see ctf_solver/ui/streamlit_app.py for the full rationale). Set
# before any submodule import so the env var is in place when
# ``sentence-transformers`` initialises.
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
warnings.filterwarnings("ignore", message=r"Accessing `__path__` from .*")

from ctf_solver.agent import build_agent
from ctf_solver.config import (
    COMMON_FLAG_PATTERNS,
    RAG_ALL_READ_MODES,
    RAG_EXPERIENCE_MODES,
    RAG_WRITE_MODES,
    SolverConfig,
    extract_candidate_flags,
)
from ctf_solver.consolidate_knowledge import consolidate_lessons_knowledge
from ctf_solver.failure_analyzer import (
    _detect_partial_successes,
    find_and_compress_prior_lesson_with_sources,
    run_lessons_learned_pipeline,
)
from ctf_solver.prompts import get_initial_message
from ctf_solver.rag import get_active_knowledge_tool
from ctf_solver.run_tracker import RunTracker
from ctf_solver.tools.core import summarize_for_llm

logger = logging.getLogger(__name__)


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="CTF Solver - Platform-agnostic agentic CTF solving framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage with URL and description
  python -m ctf_solver.runner --challenge-url https://example.com/challenge \\
      --description "Find the hidden flag in this web challenge"

  # With custom flag pattern (PicoCTF)
  python -m ctf_solver.runner --challenge-url https://saturn.picoctf.net:12345 \\
      --platform-name PicoCTF --flag-regex "picoCTF\\{[^}]+\\}"

  # With hints and custom docs directory
  python -m ctf_solver.runner --challenge-url https://challenge.ctf.com \\
      --hints "Check robots.txt" --docs-dir ./my_notes

  # Using a preset flag pattern
  python -m ctf_solver.runner --challenge-url https://app.hackthebox.com/... \\
      --flag-preset htb
        """,
    )

    # Challenge configuration
    parser.add_argument(
        "--challenge-url",
        required=False,
        help="URL of the CTF challenge to solve",
    )
    parser.add_argument(
        "--description",
        required=False,
        help="Description of the challenge",
    )
    parser.add_argument(
        "--hints",
        required=False,
        help="Hints for the challenge (can be multiline)",
    )

    # Platform configuration
    parser.add_argument(
        "--platform-name",
        default="Generic CTF",
        help="Name of the CTF platform (default: Generic CTF)",
    )
    parser.add_argument(
        "--flag-regex",
        required=False,
        help="Regular expression pattern for flag detection",
    )
    parser.add_argument(
        "--flag-preset",
        choices=list(COMMON_FLAG_PATTERNS.keys()),
        help="Use a preset flag pattern (picoctf, metactf, htb, thm, flag, ctf, generic)",
    )

    # Agent configuration
    parser.add_argument(
        "--model",
        default=None,
        help=(
            "Model name. Hosted: gpt-4o, gpt-5.2, claude-sonnet-4-6, "
            "claude-opus-4-6. Local via Ollama (auto-detected by name:tag "
            "form), recommended order: gemma4:26b (tools + thinking + 262k "
            "ctx), llama3.1:latest (best ReAct compliance), "
            "mistral-small:latest (larger, also tools-capable), "
            "gpt-oss:20b (thinking mode). edgerunner-medium:latest is "
            "refusal-resistant but not instruction-tuned for ReAct format — "
            "use it for raw payload generation, not as the agent driver. "
            "Default: from CTF_MODEL_NAME env var or gpt-4o."
        ),
    )
    parser.add_argument(
        "--ollama-num-ctx",
        type=int,
        default=None,
        help=(
            "Ollama context window override (default: 16384). The CTF "
            "agent's tool-instruction region is ~10k tokens; Ollama's "
            "Modelfile default (often 4096) silently truncates the system "
            "prompt and produces empty/garbage responses. Raise to 32768+ "
            "for long multi-turn runs. Ignored for non-Ollama providers. "
            "Env var: CTF_OLLAMA_NUM_CTX."
        ),
    )
    parser.add_argument(
        "--agent-prompt",
        required=False,
        help="Custom system prompt for the agent",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=20,
        help="Maximum number of agent reasoning steps (default: 20)",
    )
    parser.add_argument(
        "--history-window-size",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Sliding-window cap on planner history sent to the LLM each turn. "
            "Default: 16 (= 2 anchors + 14 most-recent messages, ~7 turns; tuned "
            "for Ollama 16k contexts).  Pass 0 to disable windowing and send full "
            "memory.  Env var: CTF_HISTORY_WINDOW (also accepts 'none'/'off')."
        ),
    )

    # Knowledge base configuration
    parser.add_argument(
        "--docs-dir",
        action="append",
        dest="docs_dirs",
        default=[],
        help="Directory containing knowledge base documents (can be repeated)",
    )
    parser.add_argument(
        "--kb-file",
        action="append",
        dest="kb_files",
        default=[],
        help="Specific file to include in knowledge base (can be repeated)",
    )

    # Challenge name
    parser.add_argument(
        "--challenge-name",
        required=False,
        metavar="NAME",
        help=(
            "Human-readable name for the challenge (e.g. 'Great Paywall'). "
            "Used for naming lessons-learned docs and filtering same-challenge "
            "docs from RAG retrieval to prevent contamination."
        ),
    )

    # RAG mode
    parser.add_argument(
        "--rag-mode",
        choices=[
            "none",
            "original",
            "lessons_readonly",
            "lessons_write",
            "lessons_buildonly",
        ],
        default=None,
        help=(
            "Knowledge base mode. "
            "'none': disabled. "
            "'original': curated docs only. "
            "'lessons_readonly': curated docs + read lessons DB (never writes). "
            "'lessons_write': curated docs + read/write lessons DB (saves atomic rules after every run). "
            "'lessons_buildonly': curated docs only during run; saves atomic rules after every run (no RAG reads from lessons DB)."
        ),
    )

    # Runtime configuration
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    # Source code files
    parser.add_argument(
        "--source-file",
        action="append",
        dest="source_files",
        default=[],
        metavar="PATH",
        help=(
            "Path to a source file provided by the challenge (can be repeated). "
            "The agent will read these before making HTTP requests to identify vulnerabilities."
        ),
    )

    # LLM-enhanced lessons generation
    parser.add_argument(
        "--llm-lessons",
        action="store_true",
        help="Enrich lesson docs with gpt-4o-mini causal explanations (uses OPENAI_API_KEY)",
    )
    parser.add_argument(
        "--lessons-model",
        default="gpt-4o-mini",
        help="Model to use for lesson generation (default: gpt-4o-mini)",
    )

    # Grammar-constrained decoding (Ollama / local models)
    parser.add_argument(
        "--grammar-mode",
        choices=["auto", "none", "json_schema"],
        default=None,
        help=(
            "Constrain local model decoding to the ReAct JSON envelope. "
            "'auto' (default via config): apply to Ollama and MLX, no-op "
            "elsewhere. 'none': disable. 'json_schema': force apply. "
            "Overrides CTF_GRAMMAR_MODE."
        ),
    )

    # Explicit provider selection (overrides model-name auto-detection).
    parser.add_argument(
        "--llm-provider",
        choices=["openai", "anthropic", "ollama", "mlx", "hybrid"],
        default=None,
        help=(
            "Explicit LLM provider. Default: inferred from --model (claude* → "
            "anthropic, mlx-community/* → mlx, name:tag → ollama, else openai). "
            "Overrides CTF_LLM_PROVIDER."
        ),
    )

    # MLX-specific tuning (only read when provider is mlx)
    parser.add_argument(
        "--mlx-kv-bits",
        type=int,
        default=None,
        help=(
            "KV-cache quantization for MLX generation (e.g. 4 for 4-bit KV "
            "after a 512-token warmup). Saves ~6 GB on long contexts. "
            "Env var: CTF_MLX_KV_BITS. Ignored for non-MLX providers."
        ),
    )
    parser.add_argument(
        "--mlx-seed",
        type=int,
        default=None,
        help=(
            "Random seed for MLX reproducibility (sets mx.random.seed). "
            "Env var: CTF_MLX_SEED. Ignored for non-MLX providers."
        ),
    )

    # Legacy compatibility (deprecated)
    parser.add_argument(
        "--base-url",
        required=False,
        help="(Deprecated) Use --challenge-url instead",
    )
    parser.add_argument(
        "--challenge",
        required=False,
        help="(Deprecated) Legacy challenge name - use --description instead",
    )
    parser.add_argument(
        "--task",
        required=False,
        help="(Deprecated) Use --description instead",
    )

    return parser.parse_args(args)


def _load_source_files(paths: List[str]) -> Dict[str, str]:
    """Read source file paths into a filename → content mapping.

    Supports plain text files, ZIP archives, and TAR archives
    (.tar, .tar.gz, .tar.bz2, .tgz, .tbz2).
    """
    import tarfile
    import zipfile

    _TEXT_EXTENSIONS = {
        ".py",
        ".php",
        ".js",
        ".ts",
        ".java",
        ".go",
        ".rb",
        ".c",
        ".h",
        ".cpp",
        ".cs",
        ".sql",
        ".yaml",
        ".yml",
        ".json",
        ".html",
        ".xml",
        ".sh",
        ".env",
        ".conf",
        ".cfg",
        ".ini",
        ".toml",
        ".txt",
        ".md",
        ".htm",
        ".jsx",
        ".tsx",
        ".rs",
        ".swift",
        ".kt",
    }

    def _add_text(filename: str, data: bytes) -> None:
        ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
        if ext not in _TEXT_EXTENSIONS:
            return
        try:
            result[filename] = data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                result[filename] = data.decode("latin-1")
            except UnicodeDecodeError:
                pass

    result: Dict[str, str] = {}
    for raw_path in paths:
        p = Path(raw_path)
        if not p.exists():
            print(f"[WARNING] Source file not found: {raw_path}", file=sys.stderr)
            continue
        name_lower = p.name.lower()
        try:
            if name_lower.endswith(".zip"):
                with zipfile.ZipFile(p) as zf:
                    for member in zf.namelist():
                        if member.endswith("/"):
                            continue
                        member_name = member.split("/")[-1] if "/" in member else member
                        _add_text(member_name, zf.read(member))
            elif (
                name_lower.endswith(".tar")
                or name_lower.endswith(".tar.gz")
                or name_lower.endswith(".tar.bz2")
                or name_lower.endswith(".tgz")
                or name_lower.endswith(".tbz2")
            ):
                with tarfile.open(str(p), mode="r:*") as tf:
                    for member in tf.getmembers():
                        if not member.isfile():
                            continue
                        f = tf.extractfile(member)
                        if f is None:
                            continue
                        member_name = (
                            member.name.split("/")[-1]
                            if "/" in member.name
                            else member.name
                        )
                        _add_text(member_name, f.read())
            else:
                raw = p.read_bytes()
                _add_text(p.name, raw)
        except Exception as exc:
            print(f"[WARNING] Could not read {raw_path}: {exc}", file=sys.stderr)
    return result


def build_config_from_args(args: argparse.Namespace) -> SolverConfig:
    """Build SolverConfig from parsed arguments."""
    # Start with environment-based config
    config = SolverConfig.from_env()

    # Handle legacy arguments with deprecation warnings
    challenge_url = args.challenge_url
    if args.base_url and not challenge_url:
        print(
            "[WARNING] --base-url is deprecated. Use --challenge-url instead.",
            file=sys.stderr,
        )
        challenge_url = args.base_url

    description = args.description
    if args.task and not description:
        print(
            "[WARNING] --task is deprecated. Use --description instead.",
            file=sys.stderr,
        )
        description = args.task

    if args.challenge and not description:
        print(
            "[WARNING] --challenge is deprecated. Use --description instead.",
            file=sys.stderr,
        )
        description = f"Solve the {args.challenge} challenge"

    # Determine flag regex
    flag_regex = args.flag_regex
    if args.flag_preset and not flag_regex:
        flag_regex = COMMON_FLAG_PATTERNS.get(args.flag_preset)

    # Load source files if provided
    source_files = _load_source_files(args.source_files) if args.source_files else None

    # Derive challenge name from args or URL if not provided
    challenge_name = getattr(args, "challenge_name", None)

    # Merge with command-line arguments
    return config.merge_with_args(
        platform_name=(
            args.platform_name if args.platform_name != "Generic CTF" else None
        ),
        model_name=args.model,
        agent_system_prompt=args.agent_prompt,
        flag_regex=flag_regex,
        challenge_url=challenge_url,
        challenge_description=description,
        challenge_hints=args.hints,
        challenge_name=challenge_name,
        source_files=source_files,
        docs_dirs=args.docs_dirs if args.docs_dirs else None,
        kb_files=args.kb_files if args.kb_files else None,
        max_steps=args.max_steps if args.max_steps != 20 else None,
        # 0 is the sentinel for "disable windowing" — _windowed_history
        # treats 0 the same as None so it round-trips through merge_with_args
        # (which skips None overrides).
        history_window_size=args.history_window_size,
        verbose=args.verbose if args.verbose else None,
        rag_mode=args.rag_mode if args.rag_mode else None,
        use_llm_for_lessons=True if args.llm_lessons else None,
        lessons_llm_model=(
            args.lessons_model if args.lessons_model != "gpt-4o-mini" else None
        ),
        ollama_num_ctx=(
            args.ollama_num_ctx if args.ollama_num_ctx is not None else None
        ),
        grammar_mode=args.grammar_mode,
        llm_provider=args.llm_provider,
        mlx_kv_bits=args.mlx_kv_bits,
        mlx_seed=args.mlx_seed,
    )


async def run_agent(config: SolverConfig) -> str:
    """
    Run the CTF solving agent with the given configuration.

    Args:
        config: Solver configuration

    Returns:
        Agent's final response
    """
    # Set up logging
    log_level = logging.DEBUG if config.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    print("\n" + "=" * 60)
    print("CTF Solver - Platform-Agnostic CTF Solving Agent")
    print("=" * 60)
    print(f"Platform: {config.platform_name}")
    print(f"Flag Pattern: {config.flag_regex}")
    if config.challenge_url:
        print(f"Challenge URL: {config.challenge_url}")
    if config.challenge_description:
        print(f"Description: {config.challenge_description[:100]}...")
    print("=" * 60 + "\n")

    # Build the agent — create tracker externally so we can pass real data to
    # run_lessons_learned_pipeline after the run (fixes the empty-tracker bug).
    logger.info("Building CTF solver agent...")
    tracker = RunTracker()
    tracker.challenge_url = config.challenge_url or ""
    tracker.challenge_description = config.challenge_description or ""

    # Phase C: buffer structured per-step events on the tracker. The batch
    # log writer flushes events_buffer to <slug>.events.jsonl at end-of-run.
    def _event_writer(evt: Dict[str, Any]) -> None:
        tracker.events_buffer.append(evt)

    agent = build_agent(config, tracker=tracker, event_writer=_event_writer)
    logger.info("Agent built successfully.")

    # Generate initial message
    if config.source_files:
        print(f"Source files: {', '.join(sorted(config.source_files.keys()))}")
    initial_message = get_initial_message(
        platform_name=config.platform_name,
        flag_regex=config.flag_regex,
        challenge_url=config.challenge_url,
        challenge_description=config.challenge_description,
        challenge_hints=config.challenge_hints,
        source_files=config.source_files or None,
    )

    # Reflexion injection: if a prior lesson exists for this challenge (matched
    # by challenge_name only — URL matching was removed as fragile), inject a
    # compressed verbal reflection so the agent avoids repeating past mistakes.
    # (Shinn et al. NeurIPS 2023; Wang et al. LONGMEM 2024)
    if config.rag_mode in RAG_EXPERIENCE_MODES and (
        config.challenge_name or config.challenge_url
    ):
        prior_reflection, reflexion_sources = (
            find_and_compress_prior_lesson_with_sources(
                challenge_name=config.challenge_name,
                challenge_url=config.challenge_url,
                lessons_docs_dir=config.lessons_docs_dir,
                fallback_failure_docs_dir=config.failure_docs_dir,
                challenge_description=config.challenge_description,
            )
        )
        if prior_reflection:
            print("[Reflexion] Prior lesson found — injecting compressed reflection.")
            tracker.prior_reflection_injected = True
            # Phase A4: structured payload for tracing (the bool flag above
            # is preserved for back-compat with existing analysis code).
            tracker.reflexion_payload = {
                "text": prior_reflection,
                "sources": list(reflexion_sources),
                "char_count": len(prior_reflection),
            }
            # Phase C: structured event so events.jsonl shows the injection.
            tracker.events_buffer.append(
                {
                    "event": "rag_reflexion",
                    "step": 0,
                    "sources": list(reflexion_sources),
                    "text_len": len(prior_reflection),
                    "ts": time.time(),
                }
            )
            initial_message += (
                "\n\n## Prior Attempt Analysis\n"
                "> A previous run on this challenge was analyzed. "
                "Use the lesson below to avoid repeating past mistakes.\n\n"
                + prior_reflection
            )

    # Proactive RAG injection: even when no challenge-specific prior lesson exists,
    # query the knowledge base with the challenge description upfront so the agent
    # always sees relevant prior knowledge before its first action — not just when
    # it happens to call ctf_knowledge_query mid-run.  Gated by
    # ``enable_proactive_rag`` (default on) so the agent can opt out when it
    # prefers on-demand retrieval and tighter first-turn prompts.
    # v3.8: fires in any RAG mode that has a KB loaded (ORIGINAL too) so
    # curated-only setups also benefit; previously gated only on the
    # experience modes which left ORIGINAL users out.
    if config.rag_mode in RAG_ALL_READ_MODES and config.enable_proactive_rag:
        active_tool = get_active_knowledge_tool()
        if active_tool is not None:
            query = (
                config.challenge_description
                or config.challenge_name
                or "web CTF exploitation techniques"
            )
            print(
                f"[RAG] Proactive knowledge injection attempted (query: {query!r:.80})."
            )
            proactive_results = active_tool.use(query)
            # Phase A2/A4: capture the per-chunk retrieval records that the
            # tool just stashed. Done unconditionally (even on "no relevant
            # information") so the brief slide can show "queried, but pool
            # was empty" cases too.
            retrieval_records = list(getattr(active_tool, "last_retrieval_records", []))
            if proactive_results and "No relevant information" not in proactive_results:
                print(
                    "[RAG] Proactive knowledge injection succeeded — results injected."
                )
                # Cap the injected block so it cannot crowd out tool
                # observations on local-model 16k contexts (v3.10 P3a).
                # Pre-cap can run ~2.6 KB; post-cap is ~1.5 KB.
                trimmed = summarize_for_llm(
                    proactive_results, max_chars=1500, flag_regex=None
                )
                tracker.proactive_rag_payload = {
                    "query": query,
                    "raw_text": proactive_results,
                    "trimmed_text": trimmed,
                    "raw_char_count": len(proactive_results),
                    "trimmed_char_count": len(trimmed),
                    "retrieval_records": retrieval_records,
                    "injected": True,
                }
                tracker.events_buffer.append(
                    {
                        "event": "rag_proactive",
                        "step": 0,
                        "query": query,
                        "n_records": len(retrieval_records),
                        "trimmed_char_count": len(trimmed),
                        "ts": time.time(),
                    }
                )
                initial_message += (
                    "\n\n## Relevant Background Knowledge\n"
                    "> Retrieved from the knowledge base before the run. "
                    "Apply these lessons to your approach.\n\n" + trimmed
                )
            else:
                print("[RAG] Proactive knowledge injection: no relevant results found.")
                tracker.proactive_rag_payload = {
                    "query": query,
                    "raw_text": proactive_results or "",
                    "trimmed_text": "",
                    "raw_char_count": len(proactive_results or ""),
                    "trimmed_char_count": 0,
                    "retrieval_records": retrieval_records,
                    "injected": False,
                }

    print("\n=== Agent Input ===")
    print(initial_message)
    print("=" * 40 + "\n")

    # Run the agent
    tracker.start()
    try:
        response = await agent.arun(initial_message)
    except Exception as exc:
        logger.exception("Error while running agent:")
        print(f"\n[ERROR] Agent encountered an error: {exc}")
        return f"Error: {exc}"
    finally:
        tracker.stop()

    # Extract and log potential flags
    candidate_flags: List[str] = []
    if isinstance(response, str):
        candidate_flags = extract_candidate_flags(response, config.flag_regex)
        # Also scan all tool outputs
        for entry in tracker.tool_call_log:
            candidate_flags.extend(
                extract_candidate_flags(entry.get("output", ""), config.flag_regex)
            )
        candidate_flags = list(dict.fromkeys(candidate_flags))  # deduplicate
        for flag in candidate_flags:
            print(f"\n[FLAG DETECTED] {flag}")

    tracker.candidate_flags_found = candidate_flags
    tracker.run_succeeded = bool(candidate_flags)

    # Set 3-way outcome metric
    if candidate_flags:
        tracker.outcome = "success"
    elif _detect_partial_successes(tracker.tool_call_log):
        tracker.outcome = "partial"
    else:
        tracker.outcome = "failure"

    # Phase B2-B3: roll up token usage from per-call records (populated by
    # TokenTrackingAdapter) into the tracker's authoritative fields and
    # compute cost. No-op if the adapter never appended any records (e.g.
    # tiktoken missing AND fairlib's char-based path took over).
    if tracker.per_call_tokens:
        # Don't overwrite per_call_tokens — set_token_usage_from_adapter
        # replaces it; pass a copy so the original list survives.
        tracker.set_token_usage_from_adapter(
            list(tracker.per_call_tokens), config.model_name
        )

    print("\n=== Agent Final Answer ===")
    print(response)
    print("=" * 40 + "\n")

    # Write experience-database docs after every run in WRITE modes.
    # All write modes now route through the unified lessons-learned pipeline;
    # the old AUGMENTED/monolithic pipeline was removed in favor of atomic
    # rule docs (ExpeL-style).
    if config.rag_mode in RAG_WRITE_MODES:
        experience_data = {
            "challenge_url": config.challenge_url or "",
            "challenge_description": config.challenge_description or "",
            "challenge_name": config.challenge_name or "",
        }

        written_paths = run_lessons_learned_pipeline(
            config_data=experience_data,
            tracker_data=tracker.to_dict(),
            tool_call_log=tracker.tool_call_log,
            agent_response=response,
            candidate_flags=candidate_flags,
            lessons_docs_dir=config.lessons_docs_dir,
            max_steps=config.max_steps,
            actual_steps=tracker.steps,
            flag_regex=config.flag_regex,
            site_fingerprint=tracker.site_fingerprint,
            use_llm=config.use_llm_for_lessons,
            openai_api_key=config.openai_api_key or "",
            lessons_llm_model=config.lessons_llm_model,
        )
        if written_paths:
            print(f"[Lessons DB] {len(written_paths)} rule doc(s) saved.")
            # Consolidate lessons by category (fires when ≥2 docs per category)
            consolidated = consolidate_lessons_knowledge(config.lessons_docs_dir)
            if consolidated:
                print(
                    f"[Lessons DB] {len(consolidated)} category wisdom doc(s) generated."
                )
            # Rebuild index so new docs are queryable in the same session
            active_tool = get_active_knowledge_tool()
            if active_tool is not None:
                active_tool.refresh_index()
        else:
            print("[Lessons DB] No new rule docs (duplicate run or confidence bumped).")

    return response


async def interactive_mode() -> None:
    """Run in interactive mode when no arguments are provided."""
    print("\n" + "=" * 60)
    print("CTF Solver - Interactive Mode")
    print("=" * 60)
    print("\nNo command-line arguments detected.")
    print("You can describe the web CTF challenge in a single line.\n")

    # Get challenge description
    description = input("Describe the challenge (or paste URL + description): ").strip()
    if not description:
        print("[ERROR] No description provided. Exiting.")
        return

    # Try to extract URL from description
    url_match = re.search(r"https?://\S+", description)
    challenge_url = None
    if url_match:
        challenge_url = url_match.group(0).rstrip(".,)'\"")
        print(f"[INFO] Detected URL: {challenge_url}")

    # Ask for flag format
    print("\nCommon flag formats:")
    for i, (name, pattern) in enumerate(COMMON_FLAG_PATTERNS.items(), 1):
        print(f"  {i}. {name}: {pattern}")

    flag_choice = input(
        "\nEnter number for preset (or custom regex, or press Enter for generic): "
    ).strip()

    flag_regex = None
    if flag_choice.isdigit():
        idx = int(flag_choice) - 1
        patterns = list(COMMON_FLAG_PATTERNS.values())
        if 0 <= idx < len(patterns):
            flag_regex = patterns[idx]
    elif flag_choice:
        flag_regex = flag_choice

    # Build config
    config = SolverConfig(
        challenge_url=challenge_url,
        challenge_description=description,
        flag_regex=flag_regex or SolverConfig.flag_regex,
    )

    # Run agent
    await run_agent(config)


async def main() -> None:
    """Main entry point for CLI."""
    # Check if running with no arguments
    if len(sys.argv) == 1:
        await interactive_mode()
        return

    # Parse arguments
    args = parse_args()

    # Build config
    config = build_config_from_args(args)

    # Validate we have something to work with
    if not config.challenge_url and not config.challenge_description:
        print(
            "[ERROR] Please provide at least --challenge-url or --description",
            file=sys.stderr,
        )
        sys.exit(1)

    # Run the agent
    await run_agent(config)


def _warn_if_unsafe_libomp_env() -> None:
    """On darwin venvs that ship multiple libomp.dylib copies (torch +
    sklearn + faiss-cpu), the first ``faiss::IndexIDMap::search_ex``
    call segfaults during the proactive RAG injection.  ``scripts/run.sh``
    sets ``DYLD_INSERT_LIBRARIES`` to force a single libomp; users who
    invoke ``python -m ctf_solver.runner`` directly bypass that and hit
    the crash with exit code 0 + no traceback.  Print one line so the
    next debugger sees the cause immediately.
    """
    if sys.platform != "darwin":
        return
    if os.environ.get("DYLD_INSERT_LIBRARIES"):
        return
    # Skip the warning when the user explicitly turned RAG off — the
    # FAISS path won't run, so the libomp race can't trigger.
    argv = sys.argv
    rag_off = "--rag-mode=none" in argv or (
        "--rag-mode" in argv
        and argv.index("--rag-mode") + 1 < len(argv)
        and argv[argv.index("--rag-mode") + 1] == "none"
    )
    if rag_off:
        return
    venv = Path(sys.prefix)
    faiss_omp = (
        venv
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
        / "faiss"
        / ".dylibs"
        / "libomp.dylib"
    )
    torch_omp = (
        venv
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
        / "torch"
        / "lib"
        / "libomp.dylib"
    )
    if faiss_omp.is_file() and torch_omp.is_file():
        print(
            "[WARN] Detected multiple libomp.dylib copies in the active venv "
            "(faiss + torch). On Apple Silicon this can SIGSEGV the proactive "
            "RAG query without a Python traceback (exit code 0). Run via "
            "scripts/run.sh which sets DYLD_INSERT_LIBRARIES, or pass "
            "--rag-mode none. Memory note: memory/faiss_libomp_crash.md.",
            file=sys.stderr,
        )


def cli_main() -> None:
    """Entry point for console script."""
    _warn_if_unsafe_libomp_env()
    asyncio.run(main())


if __name__ == "__main__":
    cli_main()
