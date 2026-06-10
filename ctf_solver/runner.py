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
    RAG_ALL_READ_MODES,  # noqa: F401 — kept for test_v38 source-string smoke check
    SolverConfig,
)
from ctf_solver.prompts import get_initial_message
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
        help="Use a preset flag pattern (picoctf, metactf, htb, thm, flag, ctf, generic)",
    )
    parser.add_argument(
        "--strict-flag-regex",
        required=False,
        help=(
            "Regex for the post-run grader's [FLAG DETECTED] line.  Only "
            "broad-match flags that ALSO match this pattern are counted "
            "as confirmed; others are logged as [FLAG CANDIDATE] for audit "
            "only.  Default matches known CTF platform prefixes "
            "(picoCTF|MetaCTF|HTB|THM|...).  Env: CTF_STRICT_FLAG_REGEX."
        ),
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
        "--enable-thinking",
        action="store_true",
        default=None,
        help=(
            "Opt in to chain-of-thought for reasoning-capable Ollama models "
            "(gpt-oss, gemma4, nemotron-3 thinking). Off by default — CTF "
            "tool selection rarely benefits from CoT and thinking tokens "
            "add 5-30s per turn on a local model. Env: CTF_ENABLE_THINKING. "
            "Ignored for hosted providers (think= is Ollama-only)."
        ),
    )
    parser.add_argument(
        "--observation-max-chars",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Truncate each tool observation to N chars before appending "
            "it to the next turn's prompt. Bounds prompt growth across "
            "long runs. Default: no truncation (full observation). "
            "Recommended value for local providers: 4000. The full "
            "observation is still seen by the phase-machine for signal "
            "detection. Env var: CTF_OBSERVATION_MAX_CHARS."
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
            "Default: 7 (= 2 anchors + last 5 tool observations under the "
            "default observations-counting mode).  Pass 0 to disable windowing "
            "and send full memory.  Env var: CTF_HISTORY_WINDOW (also accepts "
            "'none'/'off')."
        ),
    )
    parser.add_argument(
        "--history-window-mode",
        type=str,
        default=None,
        choices=("messages", "observations"),
        help=(
            "How --history-window-size counts.  'observations' (default since "
            "2026-05-17 A/B experiment) counts only tool-output observation "
            "messages, matching EnIGMA's Last5Observations and D-CIPHER's "
            "len_observations=5 semantics.  'messages' counts every Message "
            "(legacy behavior).  Env var: CTF_HISTORY_WINDOW_MODE."
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

    # Eval-harness adapters (ctf_solver/eval/). When either is set, the runner
    # delegates to the benchmark adapter instead of the normal URL/description
    # path. Both need their backing dependency (nyuctf / Docker) at run time.
    parser.add_argument(
        "--nyu-challenge",
        required=False,
        metavar="CANONICAL",
        help=(
            "Run a NYU CTF Bench web challenge by canonical name "
            "(e.g. '2021q-web-no_pass_needed') via ctf_solver.eval.nyu_adapter. "
            "Requires the 'nyuctf' package and Docker."
        ),
    )
    parser.add_argument(
        "--nyu-split",
        default="test",
        choices=["development", "test"],
        help="NYU dataset split for --nyu-challenge (default: test).",
    )
    parser.add_argument(
        "--cybench-task-dir",
        required=False,
        metavar="PATH",
        help=(
            "Run a Cybench web task by directory (containing metadata/"
            "metadata.json) via ctf_solver.eval.cybench_adapter, emitting a "
            "TaskRunCompletion JSON under <task-dir>/logs. Requires Docker."
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

    Thin wrapper around ``ctf_solver.ui.core.load_source_files_from_bytes``
    that adds CLI-specific stderr warnings for missing or unreadable paths.
    Supports plain text files, ZIP archives, and TAR archives
    (.tar, .tar.gz, .tar.bz2, .tgz, .tbz2).
    """
    from ctf_solver.ui.core import load_source_files_from_bytes

    named_blobs: list[tuple[str, bytes]] = []
    for raw_path in paths:
        p = Path(raw_path)
        if not p.exists():
            print(f"[WARNING] Source file not found: {raw_path}", file=sys.stderr)
            continue
        try:
            named_blobs.append((p.name, p.read_bytes()))
        except OSError as exc:
            print(f"[WARNING] Could not read {raw_path}: {exc}", file=sys.stderr)
    return load_source_files_from_bytes(named_blobs)


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
        strict_flag_regex=args.strict_flag_regex,
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
        history_window_mode=args.history_window_mode,
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
        # Perf-audit fixes #1 and #5. store_true gives False when absent
        # (argparse default) — only forward when the flag was explicitly
        # set so merge_with_args' None-skip semantics preserve defaults.
        enable_thinking=(True if args.enable_thinking else None),
        observation_max_chars=args.observation_max_chars,
    )


# Tools whose first output is treated as the recon HTTP body for the
# classifier diagnostic.
_RECON_TOOLS = ("http_fetch", "form_submit")
# Cap the recon body fed to the classifier (latency guard). The tool_call_log
# already truncates each output to 2000 chars, so this rarely bites — it's a
# defensive upper bound documented by the plan (~8 KB).
_CLASSIFIER_DIAGNOSTIC_MAX_CHARS = 8192


def _first_recon_body(tool_call_log: List[Dict[str, Any]]) -> str:
    """Return the first non-empty http_fetch / form_submit output, or ""."""
    for entry in tool_call_log:
        if entry.get("tool") in _RECON_TOOLS:
            out = entry.get("output") or ""
            if out.strip():
                return out
    return ""


def run_classifier_http_diagnostic(
    config: SolverConfig,
    tracker: RunTracker,
    log_callback: Optional[Any] = None,
) -> None:
    """Parity-sprint item #3 — DIAGNOSTIC ONLY, changes no agent behavior.

    Re-fires the keyword classifier twice and records the verdicts on
    ``tracker`` so a 12-batch re-run can histogram confidence deltas:

    * ``build_time_*`` — description + hints only (what actually drove the
      run; the overlay decision was made here at ``build_agent`` time).
    * ``post_http_*`` — the same classifier with the first recon HTTP body in
      hand, plus ``would_have_applied_overlay`` (whether the overlay would
      render at all given ``MIN_OVERLAY_CONFIDENCE``).

    The active overlay is NOT swapped — this never mutates the prompt or the
    loop. Fully exception-safe: any failure leaves the tracker fields at their
    defaults and the run proceeds untouched.
    """
    log_fn = log_callback or (lambda *_a, **_k: None)
    try:
        from ctf_solver.agent import classify_challenge
        from ctf_solver.prompts.category_overlays import build_category_overlay
    except Exception:  # pragma: no cover — import guard only
        return

    _silent = lambda *_a, **_k: None  # noqa: E731 — classifier's own log sink

    # Build-time view (description + hints only).
    try:
        build_result = classify_challenge(config, log_callback=_silent)
        tracker.build_time_category = build_result.primary_category.value
        tracker.build_time_confidence = float(build_result.confidence)
    except Exception:
        return

    body = _first_recon_body(tracker.tool_call_log)
    if not body:
        # No HTTP recon captured — nothing to compare; leave post_http_* unset.
        log_fn(
            "[Classifier-Diagnostic] no recon HTTP body captured; "
            f"build={tracker.build_time_category}@"
            f"{tracker.build_time_confidence:.2f}"
        )
        return

    body = body[:_CLASSIFIER_DIAGNOSTIC_MAX_CHARS]
    try:
        post_result = classify_challenge(
            config, response_content=body, log_callback=_silent
        )
        tracker.post_http_category = post_result.primary_category.value
        tracker.post_http_confidence = float(post_result.confidence)
        overlay = build_category_overlay(post_result)
        tracker.would_have_applied_overlay = bool(overlay)
        tracker.post_http_overlay_text = overlay
    except Exception:
        return

    log_fn(
        "[Classifier-Diagnostic] "
        f"build={tracker.build_time_category}@{tracker.build_time_confidence:.2f} "
        f"post_http={tracker.post_http_category}@{tracker.post_http_confidence:.2f} "
        f"would_apply_overlay={tracker.would_have_applied_overlay}"
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

    from ctf_solver.ui.core import (
        determine_outcome,
        extract_flags_from_run,
        inject_proactive_rag,
        inject_reflexion,
        write_lessons_if_enabled,
    )

    # Reflexion + proactive RAG injection. CLI uses append+directive form for
    # reflexion and trims proactive results to 1500 chars (v3.10 P3a fix to
    # prevent crowding out tool observations on local-model 16k contexts).
    initial_message = inject_reflexion(
        initial_message, config, tracker, prepend=False, log_callback=print
    )
    initial_message = inject_proactive_rag(
        initial_message, config, tracker, trim=True, log_callback=print
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

    # Parity-sprint item #3 (DIAGNOSTIC ONLY — changes no agent behavior):
    # re-classify with the first recon HTTP body in hand and log how the
    # classifier WOULD have behaved. The active overlay (decided at
    # build_agent time on the sparse description) is left untouched. A 12-batch
    # re-run then histograms (build_time_confidence, post_http_confidence): if
    # super_quick_logic_invitational + microdosing still read UNKNOWN with the
    # page in hand, the never-fired-overlay theory is dead. Exception-safe.
    run_classifier_http_diagnostic(config, tracker, log_callback=print)

    candidate_flags = extract_flags_from_run(
        response, tracker.tool_call_log, config.flag_regex, dedup=True
    )
    # 2026-05-17: split candidates into strict (known CTF prefix) vs broad.
    # See memory/window_mode_failure_analysis.md gap G7 — the broad regex
    # alone catches JS / CSS literals like `try{...}` or
    # `slate:{50:"#f8fafc"...}` that aren't real flags.  Strict matches get
    # the headline [FLAG DETECTED] marker; non-strict are downgraded to
    # [FLAG CANDIDATE] for audit only and don't count run_succeeded.
    import re as _re

    _strict_re = _re.compile(config.strict_flag_regex)
    confirmed_flags = [f for f in candidate_flags if _strict_re.search(f)]
    for flag in confirmed_flags:
        print(f"\n[FLAG DETECTED] {flag}")
    for flag in candidate_flags:
        if flag not in confirmed_flags:
            print(f"\n[FLAG CANDIDATE] {flag}")
    tracker.candidate_flags_found = candidate_flags
    tracker.confirmed_flags_found = confirmed_flags
    tracker.run_succeeded = bool(confirmed_flags)
    tracker.outcome = determine_outcome(confirmed_flags, tracker.tool_call_log)

    # Phase B2-B3: roll up token usage from per-call records (populated by
    # TokenTrackingAdapter) into the tracker's authoritative fields and
    # compute cost. No-op if the adapter never appended any records (e.g.
    # tiktoken missing AND fairlib's char-based path took over).
    if tracker.per_call_tokens:
        # Don't overwrite per_call_tokens — set_token_usage_from_adapter
        # replaces it; pass a copy so the original list survives.
        tracker.set_token_usage_from_adapter(
            list(tracker.per_call_tokens), config.model_name, config.llm_provider
        )

    print("\n=== Agent Final Answer ===")
    print(response)
    print("=" * 40 + "\n")

    write_lessons_if_enabled(
        config, tracker, response, candidate_flags, log_callback=print
    )

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


# The eval-harness layer lives in ctf_solver/eval/ (_core + nyu_adapter +
# cybench_adapter + ab_harness) with stats in ctf_solver/eval/stats.py and the
# CLI at scripts/eval_stats.py. Wired here via --nyu-challenge / --cybench-task-dir
# (see _run_eval_adapter). Rationale: memory/comparative_eval_harnesses.md.
async def main() -> None:
    """Main entry point for CLI."""
    # Check if running with no arguments
    if len(sys.argv) == 1:
        await interactive_mode()
        return

    # Parse arguments
    args = parse_args()

    # Eval-harness adapters take precedence over the normal run path. The
    # adapter chain is synchronous and calls asyncio.run() internally (via
    # run_against_target_sync), so it must run OFF this already-running event
    # loop — dispatch it on a worker thread to give that inner asyncio.run()
    # a fresh loop. (Calling asyncio.run() inside a running loop raises.)
    if getattr(args, "nyu_challenge", None) or getattr(args, "cybench_task_dir", None):
        await asyncio.to_thread(_run_eval_adapter, args)
        return

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


def _run_eval_adapter(args: argparse.Namespace) -> None:
    """Dispatch a single benchmark run via the eval adapters and print a
    one-line verdict. Adapter dependencies (nyuctf / Docker) are imported
    lazily inside the adapters and surface as clear errors here."""
    model = getattr(args, "model", None)
    provider = getattr(args, "llm_provider", None)
    max_steps = getattr(args, "max_steps", None)
    try:
        if args.nyu_challenge:
            from ctf_solver.eval.nyu_adapter import run_nyu_challenge

            result = run_nyu_challenge(
                args.nyu_challenge,
                split=getattr(args, "nyu_split", "test"),
                model=model,
                provider=provider,
                max_steps=max_steps,
                log_callback=print,
            )
        else:
            from ctf_solver.eval.cybench_adapter import run_cybench_task

            result = run_cybench_task(
                args.cybench_task_dir,
                model=model,
                provider=provider,
                max_steps=max_steps,
                log_callback=print,
            )
    except (ImportError, RuntimeError, ValueError, FileNotFoundError) as exc:
        print(f"[ERROR] eval adapter failed: {exc}", file=sys.stderr)
        sys.exit(1)

    print("\n=== Eval result ===")
    print(
        f"challenge={result.challenge} solved={result.solved} "
        f"flag_match={result.flag_match} outcome={result.outcome} "
        f"steps={result.steps} cost_v2=${result.est_cost_usd_v2:.4f}"
    )
    if result.error:
        print(f"error: {result.error}")


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
