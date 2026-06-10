"""UI-agnostic helpers shared by the Streamlit frontend and the upcoming
PySide6 frontend.

Contents (after Phase 1 of the Qt rewrite):

- Constants used by both UIs: ``PLATFORM_OPTIONS``, ``MODEL_OPTIONS``,
  ``GRAMMAR_OPTIONS``, ``RAG_MODE_LABELS``, ``RAG_MODE_LEGACY_MAP``.
- Pure helpers: ``is_local_model``, ``validate_url``.
- Source-file loader ``load_source_files_from_bytes`` (used by both the
  Streamlit uploader and the CLI path-based wrapper in ``runner.py``).
- ``save_challenge_log`` — writes the per-run .log file under
  ``challenge_logs/``.
- Run-orchestration helpers extracted from the duplicated logic in
  ``runner.run_agent`` and ``streamlit_app.run_agent_async``:
  ``inject_reflexion``, ``inject_proactive_rag``, ``extract_flags_from_run``,
  ``determine_outcome``, ``write_lessons_if_enabled``. Behavior flags
  (``prepend``, ``trim``, ``dedup``) preserve each caller's existing
  prompt-construction and flag-handling defaults; the upcoming Qt UI will
  use the CLI-style defaults (trim, dedup, append+directive reflexion) for
  better local-model behavior — see the Phase 1 audit in the rewrite plan.
"""

from __future__ import annotations

import io
import os
import re
import tarfile
import time
import zipfile
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable, Optional

if TYPE_CHECKING:
    from ctf_solver.config import SolverConfig
    from ctf_solver.run_tracker import RunTracker

PLATFORM_OPTIONS: list[str] = [
    "Generic CTF",
    "MetaCTF",
    "PicoCTF",
    "HackTheBox",
    "TryHackMe",
    "CTFd",
    "Other",
]

MODEL_OPTIONS: list[str] = [
    # Hosted
    "gpt-5.2",
    "gpt-4o",
    "claude-sonnet-4-6",
    "claude-opus-4-6",
    "claude-haiku-4-5",
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    # Local via MLX (Apple Silicon). Outlines grammar-constrains output to the
    # ReAct schema so the strict planner gets guaranteed valid JSON. Requires
    # launching the host process from ~/mlx-env with outlines[mlxlm].
    "mlx-community/gemma-4-26b-a4b-it-4bit",
    # Local via Ollama — auto-routed by name:tag form. Order = recommended
    # preference as the agent driver. nemotron-3-super:120b-a12b-q4_K_M is
    # the heaviest local — Ollama's official stock Nemotron 3 Super 120B-A12B
    # MoE (12.7B active, 1M ctx, LatentMoE). Loads reliably because Ollama
    # itself built the GGUF against their bundled engine. Not abliterated;
    # use a permissive system prompt for offensive payload generation.
    # Requires 100+ GB unified memory. nemotron3-prism:30b-q6 is the
    # daily-driver — PRISM-abliterated Nemotron 3 Nano 30B-A3B MoE
    # (3.5B active, 1M ctx, BFCL 53.8%, SWE-bench 38.8%), refusal-stripped
    # so it will generate offensive payloads without system-prompt nudging.
    # gemma4:26b also has tools + thinking + 262k ctx (the prior local
    # default). llama3.1 produces valid ReAct output first-try.
    # mistral-small and gpt-oss also have the "tools" capability.
    # edgerunner-medium is listed last because it is refusal-resistant but
    # NOT instruction-tuned for structured ReAct output — use it as a raw
    # payload generator, not as the agent driver.
    "nemotron-3-super:120b-a12b-q4_K_M",
    "nemotron3-prism:30b-q6",
    "gemma4:26b",
    "llama3.1:latest",
    "mistral-small:latest",
    "gpt-oss:20b",
    "edgerunner-medium:latest",
]

GRAMMAR_OPTIONS: dict[str, str] = {
    "Auto (enforce JSON schema)": "auto",
    "None (no constraint)": "none",
    "Force JSON schema": "json_schema",
}

# Display label → internal rag_mode value. Order matches the UI radio group:
# the user moves from "no knowledge" → "read curated" → "use lessons" →
# "build lessons" → both.
RAG_MODE_LABELS: dict[str, str] = {
    "No RAG": "none",
    "Curated Docs Only": "original",
    "Curated + Use Lessons DB": "lessons_readonly",
    "Curated + Build Lessons DB (no reading)": "lessons_buildonly",
    "Curated + Build & Use Lessons DB": "lessons_write",
}

# Pre-v2.3 mode names that older session state or saved configs may carry.
RAG_MODE_LEGACY_MAP: dict[str, str] = {
    "augmented": "lessons_write",
    "augmented_readonly": "lessons_readonly",
}


def is_local_model(name: str) -> bool:
    """True when ``name`` selects a local backend (Ollama tag or MLX prefix)."""
    if not name:
        return False
    return ":" in name or name.startswith("mlx-community/")


_URL_PATTERN = re.compile(
    r"^https?://"
    r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"
    r"localhost|"
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?::\d+)?"
    r"(?:/?|[/?]\S+)$",
    re.IGNORECASE,
)


def validate_url(url: str) -> tuple[bool, str]:
    """Return ``(ok, error_message)``. Empty string is treated as not-provided
    and returns ``(True, "")``; callers handle required-field semantics."""
    if not url:
        return True, ""
    if _URL_PATTERN.match(url):
        return True, ""
    return False, "Invalid URL format. Must start with http:// or https://"


_TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
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
)


def _basename(member: str) -> str:
    return member.split("/")[-1] if "/" in member else member


def _decode_if_text(filename: str, data: bytes, result: dict[str, str]) -> None:
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


def _is_tar_name(name_lower: str) -> bool:
    return (
        name_lower.endswith(".tar")
        or name_lower.endswith(".tar.gz")
        or name_lower.endswith(".tar.bz2")
        or name_lower.endswith(".tgz")
        or name_lower.endswith(".tbz2")
    )


def save_challenge_log(
    config: "SolverConfig",
    *,
    project_root: Path,
    rag_mode: str,
    logs: list[str],
    stats: dict,
    final_answer: str,
    candidate_flags: list[str],
) -> Path:
    """Write a human-readable run log to ``<project_root>/challenge_logs/`` and
    return its path. Filename: ``<slug>_<outcome>_<YYYYMMDD_HHMMSS>.log``."""
    from ctf_solver import __version__

    log_dir = project_root / "challenge_logs"
    os.makedirs(log_dir, exist_ok=True)

    ts = datetime.now()
    ts_str = ts.strftime("%Y%m%d_%H%M%S")
    name_slug = re.sub(r"[^a-zA-Z0-9]+", "_", config.challenge_name or "unnamed")
    name_slug = name_slug.strip("_")[:50] or "unnamed"
    outcome = stats.get("outcome", "unknown")
    filename = f"{name_slug}_{outcome}_{ts_str}.log"

    lines: list[str] = []
    lines.append("=" * 70)
    lines.append(f"CTF Solver Run Log — v{__version__}")
    lines.append(f"Timestamp: {ts.isoformat()}")
    lines.append("=" * 70)

    lines.append("")
    lines.append("--- Configuration ---")
    lines.append(f"Platform:    {config.platform_name}")
    lines.append(f"Challenge:   {config.challenge_name or '(unnamed)'}")
    lines.append(f"URL:         {config.challenge_url or '(none)'}")
    lines.append(f"Flag regex:  {config.flag_regex}")
    lines.append(f"Model:       {config.model_name}")
    lines.append(f"Max steps:   {config.max_steps}")
    lines.append(f"RAG mode:    {rag_mode}")
    if config.challenge_description:
        lines.append(f"Description: {config.challenge_description}")
    if config.challenge_hints:
        lines.append(f"Hints:       {config.challenge_hints}")

    lines.append("")
    lines.append("--- Execution Log ---")
    lines.extend(logs)

    tool_call_log = stats.get("tool_call_log") or []
    if tool_call_log:
        lines.append("")
        lines.append("--- Detailed Tool Calls ---")
        for i, call in enumerate(tool_call_log, 1):
            lines.append(f"\n[Call {i}] {call.get('tool', '?')}")
            lines.append(f"  Input:  {call.get('input', '')}")
            lines.append(f"  Output: {call.get('output', '')}")

    lines.append("")
    lines.append("--- Final Answer ---")
    lines.append(final_answer or "(no answer)")

    lines.append("")
    lines.append("--- Candidate Flags ---")
    if candidate_flags:
        for flag in candidate_flags:
            lines.append(f"  {flag}")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("--- Run Statistics ---")
    for key, val in stats.items():
        if key == "tool_call_log":
            continue
        if key == "tool_calls" and isinstance(val, dict):
            lines.append(f"  {key}:")
            for tool_name, count in sorted(val.items(), key=lambda x: -x[1]):
                lines.append(f"    {tool_name}: {count}")
        else:
            lines.append(f"  {key}: {val}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF LOG")
    lines.append("=" * 70)

    log_path = log_dir / filename
    log_path.write_text("\n".join(lines), encoding="utf-8")
    return log_path


# ---------------------------------------------------------------------------
# Phase 1 Day 3 helpers — shared orchestration pieces called by both
# runner.run_agent (CLI) and streamlit_app.run_agent_async (Streamlit).
# Behavior flags preserve each caller's existing prompt-construction and
# flag-handling choices; Qt will pass the unified "good defaults" later.
# ---------------------------------------------------------------------------


def determine_outcome(candidate_flags: list[str], tool_call_log: list[dict]) -> str:
    """Three-way run outcome: success | partial | failure.

    Mirrors the logic both run_agent functions duplicated. Uses
    ``failure_analyzer._detect_partial_successes`` to spot SQLi/SSTI-style
    confirmation signals in tool outputs when no flag was extracted.
    """
    if candidate_flags:
        return "success"
    from ctf_solver.failure_analyzer import _detect_partial_successes

    if _detect_partial_successes(tool_call_log):
        return "partial"
    return "failure"


def extract_flags_from_run(
    response: Any,
    tool_call_log: list[dict],
    flag_regex: str,
    *,
    dedup: bool,
) -> list[str]:
    """Scan the agent response + all tool outputs for candidate flags.

    ``dedup=True`` (CLI default) preserves first-occurrence order via
    ``dict.fromkeys``. ``dedup=False`` (Streamlit default) returns whatever
    the underlying ``extract_candidate_flags`` produces, duplicates included.
    """
    from ctf_solver.config import extract_candidate_flags

    text = response if isinstance(response, str) else ""
    flags = list(extract_candidate_flags(text, flag_regex))
    for entry in tool_call_log:
        flags.extend(extract_candidate_flags(entry.get("output", ""), flag_regex))
    if dedup:
        flags = list(dict.fromkeys(flags))
    return flags


def inject_reflexion(
    initial_message: str,
    config: "SolverConfig",
    tracker: "RunTracker",
    *,
    prepend: bool,
    log_callback: Optional[Callable[[str], None]] = None,
) -> str:
    """Inject compressed prior-run reflection into the initial agent prompt.

    Gated by ``rag_mode in RAG_EXPERIENCE_MODES`` and the presence of a
    challenge name or URL. ``prepend=True`` (Streamlit) places the lesson
    before the task; ``prepend=False`` (CLI) appends after with a directive
    line. Updates ``tracker.prior_reflection_injected``, stores
    ``tracker.reflexion_payload``, and emits a ``rag_reflexion`` event into
    ``tracker.events_buffer`` when an injection actually happens.
    """
    from ctf_solver.config import RAG_EXPERIENCE_MODES
    from ctf_solver.failure_analyzer import (
        find_and_compress_prior_lesson_with_sources,
    )

    if config.rag_mode not in RAG_EXPERIENCE_MODES:
        return initial_message
    if not (config.challenge_name or config.challenge_url):
        return initial_message

    prior_reflection, reflexion_sources = find_and_compress_prior_lesson_with_sources(
        challenge_name=config.challenge_name,
        challenge_url=config.challenge_url,
        lessons_docs_dir=str(config.lessons_docs_dir),
        fallback_failure_docs_dir=str(config.failure_docs_dir),
        challenge_description=config.challenge_description,
    )
    if not prior_reflection:
        return initial_message

    tracker.prior_reflection_injected = True
    tracker.reflexion_payload = {
        "text": prior_reflection,
        "sources": list(reflexion_sources),
        "char_count": len(prior_reflection),
    }
    tracker.events_buffer.append(
        {
            "event": "rag_reflexion",
            "step": 0,
            "sources": list(reflexion_sources),
            "text_len": len(prior_reflection),
            "ts": time.time(),
        }
    )

    if prepend:
        new_message = (
            "## Prior Attempt Analysis\n\n"
            + prior_reflection
            + "\n\n---\n\n"
            + initial_message
        )
        if log_callback is not None:
            log_callback("[Reflexion] Prior lesson injected into prompt.")
    else:
        new_message = initial_message + (
            "\n\n## Prior Attempt Analysis\n"
            "> A previous run on this challenge was analyzed. "
            "Use the lesson below to avoid repeating past mistakes.\n\n"
            + prior_reflection
        )
        if log_callback is not None:
            log_callback(
                "[Reflexion] Prior lesson found — injecting compressed reflection."
            )

    return new_message


def inject_proactive_rag(
    initial_message: str,
    config: "SolverConfig",
    tracker: "RunTracker",
    *,
    trim: bool,
    log_callback: Optional[Callable[[str], None]] = None,
) -> str:
    """Inject a proactive RAG query result into the initial agent prompt.

    Gated by ``rag_mode in RAG_ALL_READ_MODES`` and
    ``config.enable_proactive_rag``. ``trim=True`` (CLI) caps the injected
    block to 1500 chars via ``summarize_for_llm`` so it doesn't crowd out
    tool observations on local-model contexts. ``trim=False`` (Streamlit)
    injects untrimmed. Stores ``tracker.proactive_rag_payload`` and emits a
    ``rag_proactive`` event.
    """
    from ctf_solver.config import RAG_ALL_READ_MODES
    from ctf_solver.rag import get_active_knowledge_tool
    from ctf_solver.tools.core import summarize_for_llm

    if config.rag_mode not in RAG_ALL_READ_MODES:
        return initial_message
    if not config.enable_proactive_rag:
        return initial_message

    active_tool = get_active_knowledge_tool()
    if active_tool is None:
        return initial_message

    query = (
        config.challenge_description
        or config.challenge_name
        or "web CTF exploitation techniques"
    )
    if log_callback is not None:
        log_callback(
            f"[RAG] Proactive knowledge injection attempted (query: {query!r:.80})."
        )

    proactive_results = active_tool.use(query)
    retrieval_records = list(getattr(active_tool, "last_retrieval_records", []))

    if proactive_results and "No relevant information" not in proactive_results:
        if log_callback is not None:
            log_callback(
                "[RAG] Proactive knowledge injection succeeded — results injected."
            )
        if trim:
            text_to_inject = summarize_for_llm(
                proactive_results, max_chars=1500, flag_regex=None
            )
        else:
            text_to_inject = proactive_results
        tracker.proactive_rag_payload = {
            "query": query,
            "raw_text": proactive_results,
            "trimmed_text": text_to_inject,
            "raw_char_count": len(proactive_results),
            "trimmed_char_count": len(text_to_inject),
            "retrieval_records": retrieval_records,
            "injected": True,
        }
        tracker.events_buffer.append(
            {
                "event": "rag_proactive",
                "step": 0,
                "query": query,
                "n_records": len(retrieval_records),
                "trimmed_char_count": len(text_to_inject),
                "ts": time.time(),
            }
        )
        return initial_message + (
            "\n\n## Relevant Background Knowledge\n"
            "> Retrieved from the knowledge base before the run. "
            "Apply these lessons to your approach.\n\n" + text_to_inject
        )

    if log_callback is not None:
        log_callback("[RAG] Proactive knowledge injection: no relevant results found.")
    tracker.proactive_rag_payload = {
        "query": query,
        "raw_text": proactive_results or "",
        "trimmed_text": "",
        "raw_char_count": len(proactive_results or ""),
        "trimmed_char_count": 0,
        "retrieval_records": retrieval_records,
        "injected": False,
    }
    return initial_message


def write_lessons_if_enabled(
    config: "SolverConfig",
    tracker: "RunTracker",
    response: str,
    candidate_flags: list[str],
    *,
    log_callback: Optional[Callable[[str], None]] = None,
) -> bool:
    """Run the lessons-learned pipeline post-run when ``rag_mode`` is a write
    mode. Consolidates lessons by category and rebuilds the RAG index so new
    docs are queryable in the same session. Returns True iff new docs were
    written. No-op outside write modes.
    """
    from ctf_solver.config import RAG_WRITE_MODES
    from ctf_solver.consolidate_knowledge import consolidate_lessons_knowledge
    from ctf_solver.failure_analyzer import run_lessons_learned_pipeline
    from ctf_solver.rag import get_active_knowledge_tool

    if config.rag_mode not in RAG_WRITE_MODES:
        return False

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
    if not written_paths:
        if log_callback is not None:
            log_callback(
                "[Lessons DB] No new rule docs (duplicate or no rules extracted)."
            )
        return False

    tracker.failure_doc_generated = True
    if log_callback is not None:
        log_callback(f"[Lessons DB] {len(written_paths)} rule doc(s) saved.")
    consolidated = consolidate_lessons_knowledge(config.lessons_docs_dir)
    if consolidated and log_callback is not None:
        log_callback(
            f"[Lessons DB] {len(consolidated)} category wisdom doc(s) generated."
        )
    active_tool = get_active_knowledge_tool()
    if active_tool is not None:
        active_tool.refresh_index()
        if log_callback is not None:
            log_callback("[RAG] Index rebuilt with new lesson docs.")
    return True


def load_source_files_from_bytes(
    named_blobs: Iterable[tuple[str, bytes]],
) -> dict[str, str]:
    """Decode ``(name, bytes)`` pairs into a ``filename → text`` mapping.

    Source files with non-text extensions are silently filtered. ZIP and TAR
    archives (.tar / .tar.gz / .tar.bz2 / .tgz / .tbz2) are extracted; only
    the basename of each member is kept. Bad archives are silently skipped —
    callers wanting verbose error reporting wrap this function.
    """
    result: dict[str, str] = {}
    for name, raw in named_blobs:
        name_lower = name.lower()
        if name_lower.endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                    for member in zf.namelist():
                        if member.endswith("/"):
                            continue
                        _decode_if_text(_basename(member), zf.read(member), result)
            except zipfile.BadZipFile:
                pass
        elif _is_tar_name(name_lower):
            try:
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tf:
                    for tinfo in tf.getmembers():
                        if not tinfo.isfile():
                            continue
                        fobj = tf.extractfile(tinfo)
                        if fobj is None:
                            continue
                        _decode_if_text(_basename(tinfo.name), fobj.read(), result)
            except (tarfile.TarError, EOFError, OSError):
                pass
        else:
            _decode_if_text(name, raw, result)
    return result
