"""
CLI runner for CTF Solver.

Provides command-line interface for running the CTF solving agent.
"""

import argparse
import asyncio
import logging
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

from ctf_solver.agent import build_agent
from ctf_solver.config import (
    COMMON_FLAG_PATTERNS,
    RAG_EXPERIENCE_MODES,
    RAG_WRITE_MODES,
    RAGMode,
    SolverConfig,
    extract_candidate_flags,
)
from ctf_solver.consolidate_knowledge import consolidate_lessons_knowledge
from ctf_solver.failure_analyzer import (
    _detect_partial_successes,
    find_and_compress_prior_lesson,
    run_failure_analysis_pipeline,
    run_lessons_learned_pipeline,
    run_success_knowledge_pipeline,
)
from ctf_solver.prompts import get_initial_message
from ctf_solver.rag import get_active_knowledge_tool
from ctf_solver.run_tracker import RunTracker

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
        help="Use a preset flag pattern (picoctf, htb, thm, flag, ctf, generic)",
    )

    # Agent configuration
    parser.add_argument(
        "--model",
        choices=["gpt-4o", "gpt-5.2"],
        default=None,
        help="OpenAI model to use (default: from CTF_MODEL_NAME env var or gpt-4o)",
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
            "none", "original",
            "augmented_readonly", "augmented",                  # legacy names
            "lessons_readonly", "lessons_write", "lessons_buildonly",  # new names
        ],
        default=None,
        help=(
            "Knowledge base mode. "
            "'none': disabled. "
            "'original': curated docs only. "
            "'lessons_readonly': curated docs + read lessons DB (never writes). "
            "'lessons_write': curated docs + read/write lessons DB (saves atomic rules after every run). "
            "'lessons_buildonly': curated docs only during run; saves atomic rules after every run (no RAG reads from lessons DB). "
            "'augmented'/'augmented_readonly': legacy aliases for lessons_write/lessons_readonly."
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
    """Read source file paths into a filename → content mapping."""
    result: Dict[str, str] = {}
    for raw_path in paths:
        p = Path(raw_path)
        if not p.exists():
            print(f"[WARNING] Source file not found: {raw_path}", file=sys.stderr)
            continue
        try:
            result[p.name] = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                result[p.name] = p.read_text(encoding="latin-1")
            except Exception as exc:
                print(
                    f"[WARNING] Could not read {raw_path}: {exc}", file=sys.stderr
                )
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
        verbose=args.verbose if args.verbose else None,
        rag_mode=args.rag_mode if args.rag_mode else None,
        use_llm_for_lessons=True if args.llm_lessons else None,
        lessons_llm_model=args.lessons_model if args.lessons_model != "gpt-4o-mini" else None,
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
    agent = build_agent(config, tracker=tracker)
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
    if config.rag_mode in RAG_EXPERIENCE_MODES and config.challenge_name:
        prior_reflection = find_and_compress_prior_lesson(
            challenge_name=config.challenge_name,
            challenge_url=config.challenge_url,
            lessons_docs_dir=config.lessons_docs_dir,
            fallback_failure_docs_dir=config.failure_docs_dir,
        )
        if prior_reflection:
            print("[Reflexion] Prior lesson found — injecting compressed reflection.")
            tracker.prior_reflection_injected = True
            initial_message += (
                "\n\n## Prior Attempt Analysis\n"
                "> A previous run on this challenge was analyzed. "
                "Use the lesson below to avoid repeating past mistakes.\n\n"
                + prior_reflection
            )

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

    print("\n=== Agent Final Answer ===")
    print(response)
    print("=" * 40 + "\n")

    # Write experience-database docs after every run in WRITE modes.
    # LESSONS_WRITE uses the new unified lessons-learned pipeline (atomic rules).
    # AUGMENTED uses the legacy failure/success pipeline for backward compat.
    if config.rag_mode in RAG_WRITE_MODES:
        experience_data = {
            "challenge_url": config.challenge_url or "",
            "challenge_description": config.challenge_description or "",
            "challenge_name": config.challenge_name or "",
        }

        if config.rag_mode in (RAGMode.LESSONS_WRITE, RAGMode.LESSONS_BUILDONLY):
            # New unified pipeline: always runs, produces atomic rule docs
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
                    print(f"[Lessons DB] {len(consolidated)} category wisdom doc(s) generated.")
                # Rebuild index so new docs are queryable in the same session
                active_tool = get_active_knowledge_tool()
                if active_tool is not None:
                    active_tool.refresh_index()
            else:
                print("[Lessons DB] No new rule docs (duplicate run or confidence bumped).")
        else:
            # Legacy AUGMENTED mode: separate failure/success pipeline
            if not candidate_flags:
                doc_path = run_failure_analysis_pipeline(
                    config_data=experience_data,
                    tracker_data=tracker.to_dict(),
                    tool_call_log=tracker.tool_call_log,
                    agent_response=response,
                    candidate_flags=candidate_flags,
                    failure_docs_dir=config.failure_docs_dir,
                    max_steps=config.max_steps,
                    actual_steps=tracker.steps,
                    flag_regex=config.flag_regex,
                )
                if doc_path:
                    print(f"[Experience DB] Failure doc saved: {doc_path}")
            else:
                doc_path = run_success_knowledge_pipeline(
                    config_data=experience_data,
                    tracker_data=tracker.to_dict(),
                    tool_call_log=tracker.tool_call_log,
                    agent_response=response,
                    candidate_flags=candidate_flags,
                    failure_docs_dir=config.failure_docs_dir,
                )
                if doc_path:
                    print(f"[Experience DB] Success doc saved: {doc_path}")

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


def cli_main() -> None:
    """Entry point for console script."""
    asyncio.run(main())


if __name__ == "__main__":
    cli_main()
