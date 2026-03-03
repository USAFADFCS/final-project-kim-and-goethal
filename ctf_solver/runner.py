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

from ctf_solver.config import (
    SolverConfig,
    RAGMode,
    extract_candidate_flags,
    COMMON_FLAG_PATTERNS,
)
from ctf_solver.agent import build_agent
from ctf_solver.prompts import get_initial_message
from ctf_solver.failure_analyzer import (
    find_prior_failure_doc,
    run_failure_analysis_pipeline,
    run_success_knowledge_pipeline,
)

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

    # RAG mode
    parser.add_argument(
        "--rag-mode",
        choices=["none", "original", "augmented_readonly", "augmented"],
        default=None,
        help=(
            "Knowledge base mode. "
            "'none': disabled. "
            "'original': curated docs only. "
            "'augmented_readonly': docs + read experience DB. "
            "'augmented': docs + read/write experience DB (saves failure/success docs)."
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
        source_files=source_files,
        docs_dirs=args.docs_dirs if args.docs_dirs else None,
        kb_files=args.kb_files if args.kb_files else None,
        max_steps=args.max_steps if args.max_steps != 20 else None,
        verbose=args.verbose if args.verbose else None,
        rag_mode=args.rag_mode if args.rag_mode else None,
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

    # Build the agent
    logger.info("Building CTF solver agent...")
    agent = build_agent(config)
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

    # Reflexion injection: if a prior failure doc exists for this URL, prepend it
    # so the agent avoids repeating the same mistakes (Shinn et al. 2023).
    if (
        config.rag_mode in (RAGMode.AUGMENTED, RAGMode.AUGMENTED_READONLY)
        and config.challenge_url
    ):
        prior_failure = find_prior_failure_doc(
            config.challenge_url, config.failure_docs_dir
        )
        if prior_failure:
            print("[Reflexion] Prior failure analysis found — injecting into context.")
            initial_message += (
                "\n\n## Prior Attempt Analysis\n"
                "> A previous run on this challenge URL failed. "
                "Carefully review the analysis below and **avoid repeating these mistakes**.\n\n"
                + prior_failure
            )

    print("\n=== Agent Input ===")
    print(initial_message)
    print("=" * 40 + "\n")

    # Run the agent
    try:
        response = await agent.arun(initial_message)
    except Exception as exc:
        logger.exception("Error while running agent:")
        print(f"\n[ERROR] Agent encountered an error: {exc}")
        return f"Error: {exc}"

    # Extract and log potential flags
    candidate_flags: List[str] = []
    if isinstance(response, str):
        candidate_flags = extract_candidate_flags(response, config.flag_regex)
        for flag in candidate_flags:
            print(f"\n[FLAG DETECTED] {flag}")

    print("\n=== Agent Final Answer ===")
    print(response)
    print("=" * 40 + "\n")

    # Write experience-database docs when mode is AUGMENTED
    if config.rag_mode == RAGMode.AUGMENTED:
        experience_data = {
            "challenge_url": config.challenge_url or "",
            "challenge_description": config.challenge_description or "",
        }
        run_succeeded = bool(candidate_flags)
        if not run_succeeded:
            doc_path = run_failure_analysis_pipeline(
                config_data=experience_data,
                tracker_data={"steps": 0, "tool_calls": {}, "duration_seconds": 0.0},
                tool_call_log=[],
                agent_response=response,
                candidate_flags=candidate_flags,
                failure_docs_dir=config.failure_docs_dir,
                max_steps=config.max_steps,
                actual_steps=config.max_steps,
                flag_regex=config.flag_regex,
            )
            if doc_path:
                print(f"[Experience DB] Failure doc saved: {doc_path}")
        else:
            doc_path = run_success_knowledge_pipeline(
                config_data=experience_data,
                tracker_data={"steps": 0, "tool_calls": {}, "duration_seconds": 0.0},
                tool_call_log=[],
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
