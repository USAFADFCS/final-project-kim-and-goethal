"""
Streamlit GUI for CTF Solver.

Provides a web-based interface for configuring and running the CTF solving agent.

Run with:
    streamlit run ctf_solver/ui/streamlit_app.py
"""

# =============================================================================
# CRITICAL: Set environment variables BEFORE any other imports
# This prevents segmentation faults on Apple Silicon (M1/M2/M3/M4) caused by
# multiprocessing conflicts with HuggingFace tokenizers and FAISS.
# =============================================================================
import os
import sys

# Disable tokenizers parallelism to prevent fork-related crashes
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# Force OpenMP to use single thread (prevents FAISS threading issues)
os.environ["OMP_NUM_THREADS"] = "1"

# Disable MKL threading (if using Intel MKL)
os.environ["MKL_NUM_THREADS"] = "1"

# Quiet the ~200-line flood of ``[transformers] Accessing __path__ from
# .models.<X>.image_processing_<X>`` deprecation warnings emitted at
# import time when ``sentence-transformers`` pulls in ``transformers``.
# Upstream issue (transformers >= 4.50): the lazy-import shim eagerly
# walks every image-processing module and each access fires a
# ``__path__`` alias DeprecationWarning. Harmless but noisy. Two
# layers of suppression cover both paths the warning may take:
#   - ``TRANSFORMERS_VERBOSITY`` for warnings emitted via
#     ``transformers.utils.logging``;
#   - ``warnings.filterwarnings`` for warnings emitted via
#     ``warnings.warn`` (the actual current path).
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
import warnings  # noqa: E402

warnings.filterwarnings(
    "ignore",
    message=r"Accessing `__path__` from .*",
)

# Now safe to import everything else
import asyncio
import json
import queue
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import streamlit as st

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ctf_solver.config import (
    COMMON_FLAG_PATTERNS,
    DEFAULT_FLAG_REGEX,
    SolverConfig,
    _find_and_load_dotenv,
    extract_candidate_flags,
    validate_flag_regex,
)

# Load .env file at startup
_find_and_load_dotenv()
from ctf_solver.agent import build_agent
from ctf_solver.batch import (
    BatchItem,
    BatchResult,
    ensure_batch_output_dir,
    items_to_rows,
    items_to_tsv_text,
    load_batch_tsv,
    rows_to_items,
    write_batch_summary,
)
from ctf_solver.config import (
    RAG_ALL_READ_MODES,  # noqa: F401 — kept for test_v38 source-string smoke check
)
from ctf_solver.prompts import DEFAULT_SYSTEM_PROMPT, get_initial_message
from ctf_solver.run_tracker import RunTracker
from ctf_solver.ui.core import (
    GRAMMAR_OPTIONS,
    MODEL_OPTIONS,
    PLATFORM_OPTIONS,
    RAG_MODE_LABELS,
    RAG_MODE_LEGACY_MAP,
    is_local_model,
    validate_url,
)

# Page configuration
st.set_page_config(
    page_title="CTF Solver",
    page_icon="🚩",
    layout="wide",
    initial_sidebar_state="expanded",
)


def get_project_root() -> Path:
    """Get the project root directory (where ctf_solver package is located)."""
    return Path(__file__).parent.parent.parent.resolve()


def init_session_state():
    """Initialize session state variables."""
    project_root = get_project_root()

    # Default knowledge base paths (relative to project root)
    default_docs_dirs = "docs/"
    default_kb_files = "Book-3-Web-Exploitation.pdf"

    defaults = {
        # Configuration
        "platform_name": "Generic CTF",
        "flag_regex": DEFAULT_FLAG_REGEX,
        "challenge_url": "",
        "challenge_description": "",
        "challenge_hints": "",
        "agent_prompt": DEFAULT_SYSTEM_PROMPT,
        "model_name": "gpt-5.2",
        "max_steps": 30,
        "docs_dirs": default_docs_dirs,  # Actual default, not just placeholder
        "kb_files": default_kb_files,  # Actual default, not just placeholder
        "project_root": str(project_root),
        # Runtime state
        "logs": [],
        "is_running": False,
        "final_answer": None,
        "candidate_flags": [],
        "execution_trace": [],
        "run_history": [],
        "error_message": None,
        "run_stats": None,
        # RAG study settings
        "rag_mode": "original",
        "auto_analyze_failures": False,
        "use_llm_for_lessons": False,
        # Grammar-constrained decoding for local (Ollama) models
        "grammar_mode": "auto",
        # Challenge name for contamination filtering and lessons-learned doc naming
        "challenge_name": "",
        # Source code files (filename → content)
        "source_files": {},
        # Logging
        "save_logs": True,
        # Batch mode state
        "run_mode": "single",  # "single" | "batch"
        "batch_rows": [  # initial empty row so st.data_editor has structure
            {"name": "", "url": "", "description": "", "hints": ""},
        ],
        "batch_results": [],  # List[BatchResult] from the most recent batch
        "is_running_batch": False,
        "batch_output_dir": None,  # Path to out/batch_<ts>/ for the last run
        # Live agent-trace state (events from agent.py's trace_callback)
        "trace_events": [],  # List[Dict] — populated as the agent runs
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def log_callback(message: str):
    """Callback to capture log messages."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.logs.append(f"[{timestamp}] {message}")


async def run_agent_async(
    config: SolverConfig,
    trace_callback: Optional[callable] = None,  # type: ignore[valid-type]
) -> str:
    """Run the agent asynchronously with run statistics tracking.

    ``trace_callback`` receives structured event dicts from the agent as
    it runs — see ``CTFAgent.__init__`` for the event shape. When this
    function runs on a background thread (see ``run_agent`` below), the
    callback typically enqueues events to a ``queue.Queue`` that the main
    Streamlit thread polls to render the live trace.
    """
    tracker = RunTracker()
    tracker.challenge_url = config.challenge_url or ""
    tracker.challenge_description = config.challenge_description or ""

    # Phase C: buffer structured per-step events on the tracker so the
    # batch log writer can flush them to <slug>.events.jsonl alongside
    # the per-run .log file.
    def _event_writer(evt: Dict[str, Any]) -> None:
        tracker.events_buffer.append(evt)

    agent = build_agent(
        config,
        log_callback=log_callback,
        tracker=tracker,
        trace_callback=trace_callback,
        event_writer=_event_writer,
    )

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

    # Streamlit uses prepend form for reflexion and injects proactive RAG
    # untrimmed. Both call sites preserved via the helpers' flag args; Qt
    # will switch to CLI-style defaults (trim, append+directive) for better
    # local-model behavior.
    initial_message = inject_reflexion(
        initial_message, config, tracker, prepend=True, log_callback=log_callback
    )
    initial_message = inject_proactive_rag(
        initial_message, config, tracker, trim=False, log_callback=log_callback
    )

    st.session_state.execution_trace.append(
        {
            "type": "input",
            "content": initial_message,
            "timestamp": datetime.now().isoformat(),
        }
    )

    tracker.start()
    response = await agent.arun(initial_message)
    tracker.stop()

    candidate_flags = extract_flags_from_run(
        response, tracker.tool_call_log, config.flag_regex, dedup=False
    )
    tracker.candidate_flags_found = candidate_flags
    tracker.outcome = determine_outcome(candidate_flags, tracker.tool_call_log)
    tracker.run_succeeded = tracker.outcome == "success"

    # Phase B2-B3: roll up token usage from per-call records into the
    # tracker's authoritative fields and compute cost. Mirrors the
    # CLI runner's behavior so streamlit-driven batches get the same
    # cost columns in their results.tsv.
    if tracker.per_call_tokens:
        tracker.set_token_usage_from_adapter(
            list(tracker.per_call_tokens), config.model_name
        )

    write_lessons_if_enabled(
        config, tracker, response, candidate_flags, log_callback=log_callback
    )

    run_stats = tracker.to_dict()
    run_stats["tool_call_log"] = tracker.tool_call_log
    st.session_state.run_stats = run_stats

    st.session_state.execution_trace.append(
        {
            "type": "output",
            "content": response,
            "timestamp": datetime.now().isoformat(),
        }
    )

    return response


# =============================================================================
# Live agent-trace plumbing
# =============================================================================


_TRACE_STEP_ICONS = {
    "thought_action": "🧠",
    "observation": "👁",
    "final_answer": "🏁",
    "stall_nudge": "⚠️",
    "llm_thinking": "💭",
}


def _event_order_key(event: Dict[str, Any]) -> int:
    """Order events WITHIN a step: thinking first (model's internal
    reasoning), then the structured thought/action, then observation,
    with stall_nudge ahead of everything and final_answer last."""
    return {
        "stall_nudge": 0,
        "llm_thinking": 1,
        "thought_action": 2,
        "observation": 3,
        "final_answer": 4,
    }.get(event.get("type", ""), 5)


def _render_trace(events: List[Dict[str, Any]]) -> None:
    """Render the live agent trace inside whatever container is active."""
    if not events:
        st.caption("Waiting for the first Thought...")
        return

    # Group events by step so the UI shows one expandable block per step.
    by_step: Dict[int, List[Dict[str, Any]]] = {}
    for evt in events:
        by_step.setdefault(evt.get("step", 0), []).append(evt)

    for step in sorted(by_step.keys()):
        step_events = sorted(by_step[step], key=_event_order_key)
        # Header: use the first thought_action in the step as the summary;
        # fall back to any event type present.
        summary = f"Step {step}"
        ta = next((e for e in step_events if e["type"] == "thought_action"), None)
        fa = next((e for e in step_events if e["type"] == "final_answer"), None)
        thinking_present = any(e["type"] == "llm_thinking" for e in step_events)
        if ta:
            preview = ta["thought"][:80]
            thinking_marker = "💭 " if thinking_present else ""
            summary = f"{thinking_marker}🧠 Step {step} — {ta['tool']} · {preview}"
        elif fa:
            summary = f"🏁 Step {step} — Final Answer"

        with st.expander(summary, expanded=(step == max(by_step.keys()))):
            for evt in step_events:
                etype = evt["type"]
                icon = _TRACE_STEP_ICONS.get(etype, "·")
                if etype == "llm_thinking":
                    # Internal chain-of-thought from thinking-capable
                    # Ollama models (gpt-oss, gemma4). Rendered italic-
                    # gray so it reads as "background reasoning" rather
                    # than the primary thought.
                    st.markdown(f"{icon} **Model thinking** (internal)")
                    st.markdown(
                        f"<div style='opacity:0.75; font-style:italic; "
                        f"border-left: 3px solid #888; padding-left: 10px; "
                        f"white-space: pre-wrap;'>{evt['content']}</div>",
                        unsafe_allow_html=True,
                    )
                elif etype == "thought_action":
                    st.markdown(f"{icon} **Thought:** {evt['thought']}")
                    st.markdown(f"🔧 **Action:** `{evt['tool']}`")
                    st.code(evt["tool_input"], language="json")
                elif etype == "observation":
                    st.markdown(
                        f"{icon} **Observation** from `{evt['tool']}` "
                        "(first 500 chars):"
                    )
                    st.code(evt["observation"])
                elif etype == "final_answer":
                    st.markdown(f"{icon} **Final Answer:**")
                    st.markdown(evt["text"])
                elif etype == "stall_nudge":
                    st.warning(
                        f"Tier {evt.get('tier', '?')} stall nudge fired\n\n"
                        f"{evt['content']}"
                    )


def _run_agent_streaming(
    config: SolverConfig,
    trace_placeholder,
    status_placeholder,
    events_list: List[Dict[str, Any]],
    status_prefix: str = "",
) -> tuple[str, Optional[Exception]]:
    """Run the agent in a background thread, streaming trace events into
    ``events_list`` and rendering into the supplied placeholders.

    Returns ``(response, error_or_None)``. Never raises — the caller
    (batch) needs to continue to the next item on per-item failure. The
    caller owns ``events_list`` lifecycle (single-run passes
    ``st.session_state.trace_events``; batch resets a fresh list per item).
    """
    event_queue: queue.Queue = queue.Queue()
    result: Dict[str, Any] = {}

    def _trace_cb(event: Dict[str, Any]) -> None:
        event_queue.put(event)

    def _bg_run() -> None:
        try:
            # Each thread gets its own event loop (asyncio requirement).
            response = asyncio.run(run_agent_async(config, trace_callback=_trace_cb))
            result["response"] = response
        except Exception as exc:
            result["error"] = exc

    thread = threading.Thread(target=_bg_run, daemon=True)
    # Attach the current Streamlit ScriptRunContext so that session_state
    # writes from the agent's log_callback don't emit "missing
    # ScriptRunContext" warnings. Imported locally because the module
    # path has moved across Streamlit versions; both paths are tried.
    try:
        from streamlit.runtime.scriptrunner import (
            add_script_run_ctx,
            get_script_run_ctx,
        )

        ctx = get_script_run_ctx()
        if ctx is not None:
            add_script_run_ctx(thread, ctx)
    except Exception:
        pass
    thread.start()
    start_time = time.time()

    # Poll the queue while the background thread is alive. We block up to
    # 0.3s per iteration so the UI stays responsive without busy-looping.
    while thread.is_alive() or not event_queue.empty():
        try:
            evt = event_queue.get(timeout=0.3)
            events_list.append(evt)
            with trace_placeholder.container():
                _render_trace(events_list)
            with status_placeholder.container():
                elapsed = time.time() - start_time
                step = evt.get("step", "?")
                st.caption(
                    f"{status_prefix}⏱ {elapsed:.1f}s elapsed · currently at step {step}"
                )
        except queue.Empty:
            continue

    thread.join(timeout=5.0)

    with trace_placeholder.container():
        _render_trace(events_list)
    with status_placeholder.container():
        st.caption(
            f"{status_prefix}✅ Run complete · {time.time() - start_time:.1f}s total"
        )

    return result.get("response", ""), result.get("error")


def _run_agent_with_live_trace(config: SolverConfig) -> tuple[str, List[str]]:
    """Single-run wrapper around ``_run_agent_streaming`` that preserves
    the original contract (raises on error, returns candidate flags)."""
    st.markdown("### 🧠 Live Agent Trace")
    trace_placeholder = st.empty()
    status_placeholder = st.empty()

    response, err = _run_agent_streaming(
        config,
        trace_placeholder=trace_placeholder,
        status_placeholder=status_placeholder,
        events_list=st.session_state.trace_events,
        status_prefix="",
    )
    if err is not None:
        raise err
    return response, []


def run_agent():
    """Run the CTF solving agent."""
    st.session_state.is_running = True
    st.session_state.logs = []
    st.session_state.final_answer = None
    st.session_state.candidate_flags = []
    st.session_state.execution_trace = []
    st.session_state.error_message = None
    st.session_state.run_stats = None

    # Get project root for resolving relative paths
    project_root = Path(st.session_state.get("project_root", get_project_root()))

    # Parse docs_dirs and kb_files, resolving relative paths
    docs_dirs = []
    for d in st.session_state.docs_dirs.split("\n"):
        d = d.strip()
        if d:
            # Resolve relative paths against project root
            path = Path(d)
            if not path.is_absolute():
                path = project_root / path
            docs_dirs.append(str(path))

    kb_files = []
    for f in st.session_state.kb_files.split("\n"):
        f = f.strip()
        if f:
            # Resolve relative paths against project root
            path = Path(f)
            if not path.is_absolute():
                path = project_root / path
            kb_files.append(str(path))

    # Build config with RAG mode
    rag_mode_str = st.session_state.get("rag_mode", "original")
    auto_analyze = st.session_state.get("auto_analyze_failures", False)
    use_llm_lessons = st.session_state.get("use_llm_for_lessons", False)

    # Determine API key and base URL based on selected model
    selected_model = st.session_state.model_name
    if selected_model.startswith("gemini"):
        # Gemini models use GENAI.mil via OpenAI-compatible endpoint
        api_key = os.getenv("GENAI_API_KEY", "")
        base_url = os.getenv("GENAI_BASE_URL", "https://api.genai.mil/v1")
    else:
        api_key = os.getenv("OPENAI_API_KEY", "")
        base_url = None

    config = SolverConfig(
        platform_name=st.session_state.platform_name,
        agent_system_prompt=(
            st.session_state.agent_prompt
            if st.session_state.agent_prompt != DEFAULT_SYSTEM_PROMPT
            else None
        ),
        flag_regex=st.session_state.flag_regex,
        challenge_url=st.session_state.challenge_url or None,
        challenge_description=st.session_state.challenge_description or None,
        challenge_hints=st.session_state.challenge_hints or None,
        challenge_name=st.session_state.get("challenge_name") or None,
        source_files=dict(st.session_state.get("source_files", {})),
        docs_dirs=docs_dirs,
        kb_files=kb_files,
        max_steps=st.session_state.max_steps,
        model_name=selected_model,
        rag_mode=rag_mode_str,
        auto_analyze_failures=auto_analyze,
        use_llm_for_lessons=use_llm_lessons,
        openai_api_key=api_key,
        llm_base_url=base_url,
        lessons_llm_model=st.session_state.get("lessons_llm_model", "gpt-4o-mini"),
        grammar_mode=st.session_state.get("grammar_mode", "auto"),
    )

    try:
        # Reset the live trace for this run and run the agent in a
        # background thread so the main Streamlit thread can poll trace
        # events and update the UI in real time.
        st.session_state.trace_events = []
        response, flags = _run_agent_with_live_trace(config)

        st.session_state.final_answer = response

        if response and not flags:
            flags = extract_candidate_flags(response, config.flag_regex)
            st.session_state.candidate_flags = flags
        elif flags:
            st.session_state.candidate_flags = flags

        # Add to run history
        st.session_state.run_history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "url": config.challenge_url,
                "description": config.challenge_description,
                "answer": response,
                "flags": flags if response else [],
                "stats": st.session_state.run_stats,
                "rag_mode": rag_mode_str,
                "run_succeeded": len(flags) > 0 if response else False,
            }
        )

        # Save log file if enabled
        if st.session_state.get("save_logs", True):
            try:
                _save_challenge_log(config)
            except Exception as log_err:
                log_callback(f"[WARN] Failed to save log file: {log_err}")

    except Exception as e:
        st.session_state.error_message = str(e)
        log_callback(f"[ERROR] {e}")

    finally:
        st.session_state.is_running = False


# =============================================================================
# Batch run — loops run_agent_async over a list of challenges, shares KB state
# =============================================================================


def _build_config_for_batch_item(item: BatchItem) -> SolverConfig:
    """Build a SolverConfig for one batch item, reusing the sidebar's shared
    settings (model, max_steps, RAG mode, ollama_num_ctx, etc.)."""
    project_root = Path(st.session_state.get("project_root", get_project_root()))

    docs_dirs = []
    for d in st.session_state.docs_dirs.split("\n"):
        d = d.strip()
        if d:
            path = Path(d)
            if not path.is_absolute():
                path = project_root / d
            docs_dirs.append(str(path))

    kb_files = []
    for f in st.session_state.kb_files.split("\n"):
        f = f.strip()
        if f:
            path = Path(f)
            if not path.is_absolute():
                path = project_root / f
            kb_files.append(str(path))

    selected_model = st.session_state.model_name
    if selected_model.startswith("gemini"):
        api_key = os.getenv("GENAI_API_KEY", "")
        base_url = os.getenv("GENAI_BASE_URL", "https://api.genai.mil/v1")
    else:
        api_key = os.getenv("OPENAI_API_KEY", "")
        base_url = None

    return SolverConfig(
        platform_name=st.session_state.platform_name,
        agent_system_prompt=(
            st.session_state.agent_prompt
            if st.session_state.agent_prompt != DEFAULT_SYSTEM_PROMPT
            else None
        ),
        flag_regex=st.session_state.flag_regex,
        challenge_url=item.url or None,
        challenge_description=item.description or None,
        challenge_hints=item.hints or None,
        challenge_name=item.name or None,
        source_files={},  # batch mode does not plumb per-item source files (yet)
        docs_dirs=docs_dirs,
        kb_files=kb_files,
        max_steps=st.session_state.max_steps,
        model_name=selected_model,
        rag_mode=st.session_state.get("rag_mode", "original"),
        auto_analyze_failures=st.session_state.get("auto_analyze_failures", False),
        use_llm_for_lessons=st.session_state.get("use_llm_for_lessons", False),
        openai_api_key=api_key,
        llm_base_url=base_url,
        lessons_llm_model=st.session_state.get("lessons_llm_model", "gpt-4o-mini"),
        grammar_mode=st.session_state.get("grammar_mode", "auto"),
    )


def _write_batch_item_log(
    out_dir: Path,
    item: BatchItem,
    config: SolverConfig,
    response: str,
    stats: dict,
    logs: list,
    candidate_flags: list,
) -> Path:
    """Write a per-challenge log file under the batch output directory.

    Format matches the existing ``out/batch_20260417/*.log`` shape the user
    already has on disk — a single plain-text file per challenge, enough
    context to audit the run without opening the full tracker dict.

    Phase A5: also write ``<slug>.injections.json`` next to the log when
    the tracker captured a Reflexion or proactive-RAG payload, so post-run
    analysis can show exactly what was prepended to the agent prompt.
    """
    log_path = out_dir / f"{item.slug}.log"
    lines: List[str] = []
    lines.append(f"# Challenge: {item.name}")
    lines.append(f"URL: {item.url}")
    lines.append(f"Description: {item.description}")
    if item.hints:
        lines.append(f"Hints: {item.hints}")
    lines.append(f"Model: {config.model_name}")
    lines.append(f"RAG mode: {config.rag_mode}")
    lines.append(f"Outcome: {stats.get('outcome', 'unknown')}")
    if candidate_flags:
        lines.append(f"Flags: {', '.join(candidate_flags)}")
    lines.append(f"Steps: {stats.get('steps', 0)}")
    lines.append(f"Duration: {stats.get('duration_seconds', 0):.1f}s")
    lines.append("")
    lines.append("## Execution log")
    lines.extend(logs)
    lines.append("")
    lines.append("## Final answer")
    lines.append(response or "")
    log_path.write_text("\n".join(lines), encoding="utf-8")

    # Phase A5: sidecar injections.json — only emitted when at least one of
    # the two payloads is populated, to avoid littering empty files for
    # ``rag_mode == NONE`` runs.
    refl_payload = stats.get("reflexion_payload")
    rag_payload = stats.get("proactive_rag_payload")
    if refl_payload or rag_payload:
        injections_path = out_dir / f"{item.slug}.injections.json"
        try:
            injections_path.write_text(
                json.dumps(
                    {
                        "challenge_name": item.name,
                        "rag_mode": str(config.rag_mode),
                        "outcome": stats.get("outcome", "unknown"),
                        "reflexion": refl_payload,
                        "proactive": rag_payload,
                    },
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        except (OSError, TypeError, ValueError) as exc:
            # Non-fatal: the .log file is the source of truth for the run;
            # the injections sidecar is purely diagnostic.
            log_callback(f"[Batch] WARN: could not write injections JSON: {exc}")

    # Phase C: per-step structured events. One JSON object per line so the
    # figure-rendering script can pandas.read_json(lines=True) it directly.
    events = stats.get("events_buffer") or []
    if events:
        events_path = out_dir / f"{item.slug}.events.jsonl"
        try:
            with events_path.open("w", encoding="utf-8") as ef:
                for evt in events:
                    ef.write(json.dumps(evt, ensure_ascii=False) + "\n")
        except (OSError, TypeError, ValueError) as exc:
            log_callback(f"[Batch] WARN: could not write events JSONL: {exc}")
    return log_path


def run_batch():
    """Execute the current list of batch items sequentially."""
    items = rows_to_items(st.session_state.batch_rows)
    if not items:
        st.session_state.error_message = (
            "Batch table is empty. Add at least one challenge."
        )
        return

    project_root = Path(st.session_state.get("project_root", get_project_root()))
    out_dir = ensure_batch_output_dir(project_root / "out")
    st.session_state.batch_output_dir = str(out_dir)
    st.session_state.batch_results = []
    st.session_state.is_running_batch = True
    st.session_state.error_message = None

    # Shared live-trace UI — status/progress above, trace placeholder below.
    # The streaming helper renders into the two placeholders per item.
    st.markdown("### 🧠 Live Agent Trace")
    progress_placeholder = st.empty()
    status_placeholder = st.empty()
    trace_placeholder = st.empty()

    try:
        for idx, item in enumerate(items, start=1):
            # Reset per-challenge session state so the single-challenge tabs
            # display the CURRENT item during the batch run.
            st.session_state.logs = []
            st.session_state.final_answer = None
            st.session_state.candidate_flags = []
            st.session_state.execution_trace = []
            st.session_state.trace_events = []
            st.session_state.run_stats = None

            with progress_placeholder.container():
                st.info(f"**[{idx}/{len(items)}] Running:** {item.name or '(unnamed)'}")

            log_callback(
                f"[Batch] ({idx}/{len(items)}) Starting: {item.name} → {item.url}"
            )
            config = _build_config_for_batch_item(item)

            start = datetime.now()
            # TODO: thread a cancellation token through _run_agent_streaming →
            # run_agent_async → CTFAgent.arun so a "Cancel Batch" button can
            # stop the current item mid-run instead of waiting for it to end.
            response, err = _run_agent_streaming(
                config,
                trace_placeholder=trace_placeholder,
                status_placeholder=status_placeholder,
                events_list=st.session_state.trace_events,
                status_prefix=f"[{idx}/{len(items)}] ",
            )
            error = f"{type(err).__name__}: {err}" if err is not None else None
            if error:
                log_callback(f"[Batch] ({idx}/{len(items)}) ERROR: {error}")
                # Surface errors inline so the user sees *why* a batch is
                # blowing through items in 0.3s (Ollama down, missing key,
                # agent-build exception) instead of only seeing it in the
                # collapsed result expander after the whole batch ends.
                with status_placeholder.container():
                    st.error(
                        f"[{idx}/{len(items)}] {item.name or '(unnamed)'} — {error}"
                    )
                time.sleep(1.0)

            duration = (datetime.now() - start).total_seconds()

            # Flag extraction
            flags: List[str] = []
            if response:
                flags = extract_candidate_flags(response, config.flag_regex) or []

            # Outcome: error > whatever tracker reported > failure
            stats = st.session_state.get("run_stats") or {}
            if error is not None:
                outcome = "error"
            else:
                outcome = stats.get("outcome") or ("success" if flags else "failure")

            # Persist log + append to results
            log_path: Optional[str] = None
            try:
                written = _write_batch_item_log(
                    out_dir=out_dir,
                    item=item,
                    config=config,
                    response=response or "",
                    stats={**stats, "outcome": outcome},
                    logs=list(st.session_state.logs),
                    candidate_flags=flags,
                )
                log_path = str(written)
            except Exception as log_err:
                log_callback(f"[Batch] WARN: could not write log: {log_err}")

            result = BatchResult(
                item=item,
                outcome=outcome,
                flag=flags[0] if flags else None,
                steps=int(stats.get("steps", 0) or 0),
                duration_seconds=duration,
                error=error,
                stats=stats,
                log_path=log_path,
            )
            st.session_state.batch_results.append(result)
            log_callback(
                f"[Batch] ({idx}/{len(items)}) Done: {item.name} — "
                f"{result.outcome_emoji} {outcome} "
                f"({result.steps} steps, {result.duration_seconds:.1f}s)"
            )

        # Final summary TSV
        try:
            write_batch_summary(st.session_state.batch_results, out_dir / "results.tsv")
            log_callback(f"[Batch] Summary written to {out_dir / 'results.tsv'}")
        except Exception as sum_err:
            log_callback(f"[Batch] WARN: could not write summary: {sum_err}")

        with progress_placeholder.container():
            st.success(
                f"Batch complete — {len(st.session_state.batch_results)} challenge(s) processed."
            )

    finally:
        st.session_state.is_running_batch = False


def _save_challenge_log(config: SolverConfig) -> None:
    """Save a run log via ``core.save_challenge_log`` and notify the UI."""
    from ctf_solver.ui.core import save_challenge_log

    project_root = Path(st.session_state.get("project_root", get_project_root()))
    log_path = save_challenge_log(
        config,
        project_root=project_root,
        rag_mode=st.session_state.get("rag_mode", "?"),
        logs=list(st.session_state.logs),
        stats=st.session_state.run_stats or {},
        final_answer=st.session_state.final_answer or "",
        candidate_flags=list(st.session_state.candidate_flags or []),
    )
    log_callback(f"[LOG] Run log saved to {log_path}")


def render_sidebar():
    """Render the configuration sidebar."""
    st.sidebar.title("🚩 CTF Solver")
    st.sidebar.markdown("---")

    # Platform configuration
    st.sidebar.header("Platform Settings")

    _current = st.session_state.platform_name
    if _current in PLATFORM_OPTIONS:
        _idx = PLATFORM_OPTIONS.index(_current)
    else:
        _idx = PLATFORM_OPTIONS.index("Other")

    _selection = st.sidebar.selectbox(
        "Platform",
        options=PLATFORM_OPTIONS,
        index=_idx,
        help="Select the CTF platform",
    )
    if _selection == "Other":
        st.session_state.platform_name = st.sidebar.text_input(
            "Custom Platform Name",
            value=_current if _current not in PLATFORM_OPTIONS else "",
        )
    else:
        st.session_state.platform_name = _selection

    st.session_state.challenge_name = st.sidebar.text_input(
        "Challenge Name (for lessons tracking)",
        value=st.session_state.get("challenge_name", ""),
        help="Name used for lessons-learned deduplication and reflexion injection",
    )

    # Flag pattern selector
    preset = st.sidebar.selectbox(
        "Flag Pattern Preset",
        options=["Custom"] + list(COMMON_FLAG_PATTERNS.keys()),
        help="Select a common flag format or enter a custom regex",
    )

    if preset != "Custom":
        st.session_state.flag_regex = COMMON_FLAG_PATTERNS[preset]
    else:
        st.session_state.flag_regex = st.sidebar.text_input(
            "Custom Flag Regex",
            value=st.session_state.flag_regex,
            help="Regular expression pattern for flag detection",
        )

    # Validate regex
    is_valid, error = validate_flag_regex(st.session_state.flag_regex)
    if not is_valid:
        st.sidebar.error(f"Invalid regex: {error}")

    st.sidebar.markdown("---")

    # Agent configuration
    st.sidebar.header("Agent Settings")

    current_model = st.session_state.get("model_name", "gpt-5.2")
    current_index = (
        MODEL_OPTIONS.index(current_model) if current_model in MODEL_OPTIONS else 0
    )
    st.session_state.model_name = st.sidebar.selectbox(
        "LLM Model",
        options=MODEL_OPTIONS,
        index=current_index,
        help=(
            "Hosted: Gemini (GENAI.mil), Anthropic Claude, OpenAI. "
            "Local via MLX (Apple Silicon): mlx-community/gemma-4-26b-a4b-it-4bit — "
            "fastest local option on M-series (~90-113 tok/s), Outlines guarantees "
            "valid ReAct JSON via grammar-constrained decoding. "
            "Local via Ollama, ranked by ReAct format compliance: "
            "gemma4:26b > llama3.1 > mistral-small > gpt-oss > "
            "edgerunner-medium. gemma4:26b is the most capable local "
            "option (tools + thinking + 262k ctx). edgerunner-medium is "
            "refusal-resistant but doesn't follow ReAct format — prefer "
            "it for raw payload generation, not as the agent driver."
        ),
    )

    # MLX reminder: the UI can select the MLX model, but the Streamlit
    # process itself must be running inside ~/mlx-env with outlines[mlxlm]
    # installed, otherwise the first invoke raises ImportError. Surface the
    # check here so the user sees the fix before clicking Run.
    if st.session_state.model_name.startswith("mlx-community/"):
        try:
            import mlx_lm  # noqa: F401
            import outlines  # noqa: F401

            st.sidebar.caption("✓ MLX stack available in this venv")
        except ImportError:
            st.sidebar.warning(
                "MLX model selected but `mlx_lm` / `outlines` not importable. "
                "Stop Streamlit, then: "
                "`source ~/mlx-env/bin/activate && "
                'pip install "outlines[mlxlm]"` and relaunch.'
            )

    st.session_state.max_steps = st.sidebar.slider(
        "Max Steps",
        min_value=5,
        max_value=50,
        value=st.session_state.max_steps,
        help="Maximum number of reasoning steps before stopping",
    )

    # Grammar-constrained decoding is only meaningful for local models
    # (Ollama via ``format=<schema>`` or MLX via Outlines).
    if is_local_model(st.session_state.get("model_name", "")):
        grammar_labels = list(GRAMMAR_OPTIONS.keys())
        current_grammar = st.session_state.get("grammar_mode", "auto")
        current_grammar_idx = (
            list(GRAMMAR_OPTIONS.values()).index(current_grammar)
            if current_grammar in GRAMMAR_OPTIONS.values()
            else 0
        )
        selected_grammar_label = st.sidebar.selectbox(
            "Grammar Constraint",
            options=grammar_labels,
            index=current_grammar_idx,
            help=(
                "Grammar-constrained decoding for local models. For Ollama, "
                "passes the ReAct JSON schema via ``format=``. For MLX, uses "
                "Outlines' FSM to mask logits against the schema — guaranteed "
                "valid JSON. Eliminates 'Could not parse ReAct response' "
                "errors that waste steps on small models. Use 'None' for "
                "A/B comparison runs."
            ),
        )
        st.session_state.grammar_mode = GRAMMAR_OPTIONS[selected_grammar_label]

    st.session_state.save_logs = st.sidebar.checkbox(
        "Save run logs",
        value=st.session_state.get("save_logs", True),
        help="Save detailed logs of each run to the challenge_logs/ folder",
    )

    st.sidebar.markdown("---")

    # Knowledge base configuration
    st.sidebar.header("Knowledge Base")

    st.session_state.docs_dirs = st.sidebar.text_area(
        "Document Directories",
        value=st.session_state.docs_dirs,
        height=100,
        help="Directories containing knowledge base documents (one per line). Relative paths are resolved from the project root.",
    )

    st.session_state.kb_files = st.sidebar.text_area(
        "Specific Files",
        value=st.session_state.kb_files,
        height=100,
        help="Specific files to include in knowledge base (one per line). Relative paths are resolved from the project root.",
    )

    # Show project root for clarity
    st.sidebar.caption(
        f"📁 Project root: {st.session_state.get('project_root', 'unknown')}"
    )

    # Reset KB settings button
    if st.sidebar.button("🔄 Reset KB to Defaults", use_container_width=True):
        st.session_state.docs_dirs = "docs/"
        st.session_state.kb_files = "Book-3-Web-Exploitation.pdf"
        st.rerun()

    st.sidebar.markdown("---")

    # RAG / Experience Database Mode
    st.sidebar.header("Knowledge Base Mode")

    rag_mode_labels = list(RAG_MODE_LABELS.keys())
    current_mode = st.session_state.get("rag_mode", "original")
    current_mode = RAG_MODE_LEGACY_MAP.get(current_mode, current_mode)
    current_idx = (
        list(RAG_MODE_LABELS.values()).index(current_mode)
        if current_mode in RAG_MODE_LABELS.values()
        else 1
    )

    selected_label = st.sidebar.radio(
        "Mode",
        options=rag_mode_labels,
        index=current_idx,
        help=(
            "**No RAG:** Agent has no knowledge base.\n\n"
            "**Curated Docs Only:** Uses the curated docs/ knowledge base only.\n\n"
            "**Curated + Use Lessons DB:** Also reads past lessons-learned docs "
            "(atomic rules from prior runs) — never writes new ones. "
            "Use for the read-only phase of your experiment.\n\n"
            "**Curated + Build Lessons DB (no reading):** Curated docs only during the run; "
            "writes new atomic rule docs after every run but does NOT read from the lessons DB. "
            "Use to build the experience database on a fresh set of challenges.\n\n"
            "**Curated + Build & Use Lessons DB:** Reads past lessons AND writes new "
            "atomic rule docs after every run. Use when building the experience database."
        ),
    )
    st.session_state.rag_mode = RAG_MODE_LABELS[selected_label]

    # auto_analyze_failures: derived from rag_mode (kept for backward compat)
    st.session_state.auto_analyze_failures = st.session_state.rag_mode in (
        "lessons_write",
        "lessons_buildonly",
    )

    # LLM-enhanced lesson generation (only meaningful in write modes)
    if st.session_state.rag_mode in ("lessons_write", "lessons_buildonly"):
        st.session_state.use_llm_for_lessons = st.sidebar.checkbox(
            "Enrich lessons with gpt-4o-mini",
            value=st.session_state.get("use_llm_for_lessons", False),
            help=(
                "After each run, call gpt-4o-mini to write richer causal explanations "
                "and reflexion summaries (~$0.0003/run). Uses your OPENAI_API_KEY."
            ),
        )
    else:
        st.session_state.use_llm_for_lessons = False

    # Show lessons database stats for modes that use it (read or write)
    if st.session_state.rag_mode in (
        "lessons_write",
        "lessons_buildonly",
        "lessons_readonly",
    ):
        project_root = Path(st.session_state.get("project_root", get_project_root()))
        lessons_dir = project_root / "out" / "lessons_knowledge"
        failure_dir = project_root / "out" / "failure_knowledge"
        lessons_count = (
            len(list(lessons_dir.glob("lessons_*.md"))) if lessons_dir.exists() else 0
        )
        failure_count = (
            len(list(failure_dir.glob("failure_*.md"))) if failure_dir.exists() else 0
        )
        success_count = (
            len(list(failure_dir.glob("success_*.md"))) if failure_dir.exists() else 0
        )
        total_legacy = failure_count + success_count
        msg = f"Lessons DB: {lessons_count} rule doc(s)"
        if total_legacy:
            msg += f" | Legacy: {total_legacy} doc(s)"
        st.sidebar.caption(msg)

    st.sidebar.markdown("---")

    # API key status
    api_key = os.getenv("OPENAI_API_KEY", "")
    if api_key:
        st.sidebar.success("✓ OpenAI API key configured")
    else:
        st.sidebar.error("✗ OpenAI API key not found")
        st.sidebar.info("Set OPENAI_API_KEY in your environment or .env file")


def _render_run_statistics():
    """Render the Run Statistics tab content."""
    stats = st.session_state.run_stats
    if not stats:
        st.info("No statistics yet. Run the agent to see performance data.")
        return

    st.markdown("### Run Statistics")

    # RAG mode and outcome
    rag_mode_display = stats.get("rag_mode", "unknown")
    outcome = stats.get("outcome", "pending")
    outcome_text = {
        "success": "Success ✅",
        "partial": "Partial 🔶",
        "failure": "Failed ❌",
    }.get(outcome, outcome.capitalize())

    rc1, rc2, rc3, rc4 = st.columns(4)
    rc1.metric("RAG Mode", rag_mode_display.capitalize())
    rc2.metric("Outcome", outcome_text)
    rc3.metric("RAG Queries", stats.get("rag_queries_made", 0))
    rc4.metric(
        "Prior Reflection", "Yes" if stats.get("prior_reflection_injected") else "No"
    )

    rc5, rc6 = st.columns(2)
    rc5.metric("Unique Tools Used", stats.get("unique_tools_used", 0))
    if stats.get("failure_doc_generated"):
        rc6.metric("Lesson Doc", "Generated")
    else:
        rc6.metric("Lesson Doc", "N/A")

    st.markdown("---")

    # Top-level metrics in columns
    c1, c2, c3, c4 = st.columns(4)
    duration = stats["duration_seconds"]
    if duration >= 60:
        time_display = f"{int(duration // 60)}m {duration % 60:.1f}s"
    else:
        time_display = f"{duration:.1f}s"

    c1.metric("Solve Time", time_display)
    c2.metric("Steps (tool calls)", stats["steps"])
    c3.metric("LLM Calls", stats["llm_calls"])
    c4.metric("Tokens (est.)", f"~{stats['total_tokens_est']:,}")

    # Token breakdown
    st.markdown("---")
    st.markdown("#### Token Breakdown (estimated)")
    tc1, tc2 = st.columns(2)
    tc1.metric("Prompt Tokens", f"~{stats['prompt_tokens_est']:,}")
    tc2.metric("Completion Tokens", f"~{stats['completion_tokens_est']:,}")

    # Tool usage breakdown
    st.markdown("---")
    st.markdown("#### Tools Used")
    tool_calls = stats.get("tool_calls", {})
    if tool_calls:
        # Sort by usage count descending
        sorted_tools = sorted(tool_calls.items(), key=lambda x: x[1], reverse=True)
        for tool_name, count in sorted_tools:
            st.markdown(f"- **{tool_name}**: {count} call{'s' if count != 1 else ''}")
    else:
        st.info("No tools were called during this run.")

    st.caption("Token counts are rough estimates (~4 characters per token).")


def _process_uploaded_files(uploaded_files) -> Dict[str, str]:
    """Decode Streamlit ``UploadedFile`` objects into a filename → content
    mapping. Thin wrapper around ``core.load_source_files_from_bytes``."""
    from ctf_solver.ui.core import load_source_files_from_bytes

    return load_source_files_from_bytes((uf.name, uf.read()) for uf in uploaded_files)


def render_batch_panel():
    """Render the batch-run UI: table editor, import/export, run, results."""
    st.subheader("Batch Run")
    st.caption(
        "Queue up multiple challenges and run them sequentially. The "
        "knowledge base is shared across the batch (lessons written by "
        "challenge N are available to challenge N+1). Sidebar settings "
        "(model, max steps, RAG mode) apply to every challenge."
    )

    # --- Import / export ---
    import_col, export_col = st.columns(2)
    with import_col:
        uploaded = st.file_uploader(
            "Import TSV",
            type=["tsv", "txt"],
            accept_multiple_files=False,
            help=(
                "Load a TSV with columns name, url, description, hints. "
                "Legacy format (slug, name, url, description) is also "
                "accepted; slug is ignored and hints defaults to empty."
            ),
            key="batch_import_uploader",
        )
        if uploaded is not None and not st.session_state.is_running_batch:
            try:
                tmp = Path(get_project_root()) / ".streamlit_batch_upload.tsv"
                tmp.write_bytes(uploaded.getvalue())
                items = load_batch_tsv(tmp)
                tmp.unlink(missing_ok=True)
                if items:
                    st.session_state.batch_rows = items_to_rows(items)
                    st.success(
                        f"Loaded {len(items)} challenge(s) from {uploaded.name}."
                    )
                else:
                    st.warning("TSV parsed but contained no challenges.")
            except Exception as e:
                st.error(f"Failed to parse TSV: {e}")

    with export_col:
        # Export the current rows as TSV (even partial — useful for saving
        # a batch before hitting run).
        current_items = rows_to_items(st.session_state.batch_rows)
        tsv_text = items_to_tsv_text(current_items) if current_items else ""
        st.download_button(
            "Export TSV",
            data=tsv_text or "name\turl\tdescription\thints\n",
            file_name=f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.tsv",
            mime="text/tab-separated-values",
            disabled=not current_items,
            help="Download the current batch table as a TSV.",
        )

    # --- Editable table ---
    edited = st.data_editor(
        st.session_state.batch_rows,
        num_rows="dynamic",
        use_container_width=True,
        disabled=st.session_state.is_running_batch,
        column_config={
            "name": st.column_config.TextColumn(
                "Name",
                help="Short human-readable name (also used as slug for logs and lessons)",
                required=False,
                width="small",
            ),
            "url": st.column_config.TextColumn(
                "URL",
                help="Challenge URL",
                width="medium",
            ),
            "description": st.column_config.TextColumn(
                "Description",
                help="Challenge description / goal",
                width="large",
            ),
            "hints": st.column_config.TextColumn(
                "Hints",
                help="Optional hints given by the challenge",
                width="medium",
            ),
        },
        key="batch_rows_editor",
    )
    st.session_state.batch_rows = edited

    # --- Run / Clear buttons ---
    run_col, clear_col, spacer = st.columns([1, 1, 3])
    ready_items = rows_to_items(st.session_state.batch_rows)
    missing_api_key = not os.getenv("OPENAI_API_KEY") and not os.getenv("GENAI_API_KEY")
    run_disabled = (
        st.session_state.is_running_batch
        or st.session_state.is_running
        or not ready_items
        or missing_api_key
    )
    with run_col:
        if st.button(
            (
                "🚀 Run Batch"
                if not st.session_state.is_running_batch
                else "⏳ Running Batch..."
            ),
            type="primary",
            disabled=run_disabled,
            use_container_width=True,
        ):
            run_batch()
    with clear_col:
        if st.button(
            "🗑️ Clear Results",
            disabled=st.session_state.is_running_batch,
            use_container_width=True,
        ):
            st.session_state.batch_results = []
            st.session_state.error_message = None
            st.rerun()

    if missing_api_key:
        st.info(
            "Set OPENAI_API_KEY (or GENAI_API_KEY) in your environment to enable batch runs."
        )

    if st.session_state.error_message:
        st.error(st.session_state.error_message)

    st.markdown("---")

    # --- Results panel ---
    results = st.session_state.batch_results
    if not results:
        st.info(
            f"No batch results yet. Add {len(ready_items) or '…'} challenge(s) "
            "above and hit Run Batch."
        )
        return

    # Summary metrics
    successes = sum(1 for r in results if r.outcome == "success")
    partials = sum(1 for r in results if r.outcome == "partial")
    failures = sum(1 for r in results if r.outcome == "failure")
    errors = sum(1 for r in results if r.outcome == "error")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total", len(results))
    m2.metric("✅ Success", successes)
    m3.metric("⚠️ Partial", partials)
    m4.metric("❌ Failure", failures)
    m5.metric("💥 Error", errors)

    if st.session_state.batch_output_dir:
        st.caption(f"Output dir: `{st.session_state.batch_output_dir}`")

    st.markdown("### Results")
    for r in results:
        header = (
            f"{r.outcome_emoji} **{r.item.name or '(unnamed)'}** — "
            f"{r.outcome} | {r.steps} steps | {r.duration_seconds:.1f}s"
        )
        if r.flag:
            header += f" | 🚩 `{r.flag}`"
        with st.expander(header):
            st.markdown(f"**URL:** {r.item.url or '(none)'}")
            if r.item.description:
                st.markdown(f"**Description:** {r.item.description}")
            if r.item.hints:
                st.markdown(f"**Hints:** {r.item.hints}")
            if r.error:
                st.error(f"Error: {r.error}")
            if r.log_path:
                st.caption(f"Log: `{r.log_path}`")
            if r.stats:
                token_est = r.stats.get("total_tokens_est")
                if token_est:
                    st.caption(
                        f"Tokens ≈ {token_est} | "
                        f"RAG queries: {r.stats.get('rag_queries_made', 0)} | "
                        f"Unique tools: {r.stats.get('unique_tools_used', 0)}"
                    )


def render_main_panel():
    """Render the main panel."""
    st.title("🚩 CTF Solver")
    st.markdown("*Platform-agnostic agentic CTF solving framework*")

    # Mode selector: single challenge vs batch. Reset cross-mode state when
    # the user actually flips the switch so stale trace/final-answer from
    # the prior mode doesn't bleed into the new one.
    prev_mode = st.session_state.get("run_mode", "single")
    st.session_state.run_mode = st.radio(
        "Mode",
        options=["single", "batch"],
        format_func=lambda m: (
            "🎯 Single challenge" if m == "single" else "📋 Batch run"
        ),
        index=0 if prev_mode == "single" else 1,
        horizontal=True,
        label_visibility="collapsed",
        disabled=st.session_state.is_running or st.session_state.is_running_batch,
    )
    if st.session_state.run_mode != prev_mode:
        st.session_state.trace_events = []
        st.session_state.final_answer = None
        st.session_state.candidate_flags = []
        st.session_state.error_message = None
        st.session_state.logs = []

    if st.session_state.run_mode == "batch":
        render_batch_panel()
        return

    # Challenge configuration
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Challenge Configuration")

        st.session_state.challenge_url = st.text_input(
            "Challenge URL",
            value=st.session_state.challenge_url,
            placeholder="https://example.ctf.com/challenge",
            help="URL of the CTF challenge",
        )

        # Validate URL
        is_valid, error = validate_url(st.session_state.challenge_url)
        if not is_valid:
            st.error(error)

        st.session_state.challenge_name = st.text_input(
            "Challenge Name (optional)",
            value=st.session_state.get("challenge_name", ""),
            placeholder="e.g. Great Paywall",
            help=(
                "A short human-readable name for this challenge. "
                "Used to name lessons-learned docs and to prevent the agent from "
                "reading its own prior notes when re-attempting the same challenge."
            ),
        )

        st.session_state.challenge_description = st.text_area(
            "Challenge Description",
            value=st.session_state.challenge_description,
            height=100,
            placeholder="Describe the challenge...",
            help="Description or context for the challenge",
        )

        st.session_state.challenge_hints = st.text_area(
            "Challenge Hints",
            value=st.session_state.challenge_hints,
            height=80,
            placeholder="Any hints provided by the challenge...",
            help="Hints that might help solve the challenge",
        )

        # Source code file uploader
        uploaded = st.file_uploader(
            "Source Code Files (optional)",
            accept_multiple_files=True,
            type=[
                "py",
                "php",
                "js",
                "ts",
                "java",
                "go",
                "rb",
                "c",
                "h",
                "cpp",
                "cs",
                "sql",
                "yaml",
                "yml",
                "json",
                "html",
                "xml",
                "sh",
                "txt",
                "md",
                "zip",
                "tar",
                "gz",
                "tgz",
                "bz2",
                "tbz2",
                "env",
                "conf",
                "cfg",
                "ini",
                "toml",
                "jsx",
                "tsx",
                "rs",
            ],
            help=(
                "Drop source files provided by the challenge here. "
                "The agent will read them to identify vulnerabilities before making HTTP requests. "
                "ZIP and TAR archives (.tar, .tar.gz, .tar.bz2) are automatically extracted."
            ),
        )
        if uploaded:
            st.session_state.source_files = _process_uploaded_files(uploaded)
        elif not st.session_state.get("source_files"):
            st.session_state.source_files = {}

        if st.session_state.get("source_files"):
            fnames = list(st.session_state.source_files.keys())
            st.caption(
                f"Source files loaded: {', '.join(fnames[:5])}"
                + (f" (+{len(fnames)-5} more)" if len(fnames) > 5 else "")
            )

    with col2:
        st.subheader("Quick Info")
        st.info(f"**Platform:** {st.session_state.platform_name}")
        st.info(f"**Max Steps:** {st.session_state.max_steps}")

        # Flag pattern preview
        st.markdown("**Flag Pattern:**")
        st.code(st.session_state.flag_regex, language=None)

    # Agent prompt (collapsible)
    with st.expander("📝 Agent System Prompt (Advanced)", expanded=False):
        st.session_state.agent_prompt = st.text_area(
            "System Prompt",
            value=st.session_state.agent_prompt,
            height=300,
            help="Customize the agent's system prompt",
        )
        if st.button("Reset to Default"):
            st.session_state.agent_prompt = DEFAULT_SYSTEM_PROMPT
            st.rerun()

    # Run button
    st.markdown("---")

    col1, col2, col3 = st.columns([1, 1, 2])

    with col1:
        run_disabled = (
            st.session_state.is_running
            or not os.getenv("OPENAI_API_KEY")
            or not validate_flag_regex(st.session_state.flag_regex)[0]
        )

        if st.button(
            "🚀 Run Agent" if not st.session_state.is_running else "⏳ Running...",
            type="primary",
            disabled=run_disabled,
            use_container_width=True,
        ):
            run_agent()
            st.rerun()

    with col2:
        if st.button("🗑️ Clear Results", use_container_width=True):
            st.session_state.logs = []
            st.session_state.final_answer = None
            st.session_state.candidate_flags = []
            st.session_state.execution_trace = []
            st.session_state.error_message = None
            st.session_state.run_stats = None
            st.rerun()

    # Results section
    st.markdown("---")

    if st.session_state.error_message:
        st.error(f"**Error:** {st.session_state.error_message}")

    # Persistent live agent trace — visible after a run finishes so the
    # user can scroll back through the Thought/Action/Observation history.
    # During a run, _run_agent_with_live_trace renders into its own
    # placeholders; this block shows the final state between runs.
    if not st.session_state.is_running and st.session_state.get("trace_events"):
        with st.expander("🧠 Agent Trace (last run)", expanded=False):
            _render_trace(st.session_state.trace_events)

    # Display results in tabs
    if st.session_state.final_answer or st.session_state.logs:
        tab1, tab2, tab3, tab4, tab5 = st.tabs(
            [
                "📋 Final Answer",
                "🚩 Candidate Flags",
                "📈 Run Statistics",
                "📜 Execution Log",
                "📊 History",
            ]
        )

        with tab1:
            if st.session_state.final_answer:
                st.markdown("### Agent's Final Answer")
                st.markdown(st.session_state.final_answer)
            else:
                st.info("Run the agent to see results here.")

        with tab2:
            if st.session_state.candidate_flags:
                st.markdown("### Candidate Flags Found")
                for i, flag in enumerate(st.session_state.candidate_flags, 1):
                    st.code(flag, language=None)
            else:
                st.info("No candidate flags detected yet.")

        with tab3:
            _render_run_statistics()

        with tab4:
            st.markdown("### Execution Log")
            if st.session_state.logs:
                log_text = "\n".join(st.session_state.logs)
                st.text_area(
                    "Log Output",
                    value=log_text,
                    height=400,
                    disabled=True,
                    label_visibility="collapsed",
                )
            else:
                st.info("No logs yet. Run the agent to see execution details.")

        with tab5:
            st.markdown("### Run History")
            if st.session_state.run_history:
                for i, run in enumerate(reversed(st.session_state.run_history), 1):
                    run_num = len(st.session_state.run_history) - i + 1
                    rag_label = run.get("rag_mode", "?").capitalize()
                    succeeded = run.get("run_succeeded", False)
                    status_icon = "✅" if succeeded else "❌"
                    with st.expander(
                        f"Run {run_num} [{rag_label}] {status_icon} - {run['timestamp'][:19]}"
                    ):
                        if run["url"]:
                            st.markdown(f"**URL:** {run['url']}")
                        if run["description"]:
                            st.markdown(
                                f"**Description:** {run['description'][:100]}..."
                            )
                        st.markdown(
                            f"**RAG Mode:** {rag_label} | **Outcome:** {'Success' if succeeded else 'Failed'}"
                        )
                        if run["flags"]:
                            st.markdown(f"**Flags Found:** {', '.join(run['flags'])}")
                        if run.get("stats"):
                            stats = run["stats"]
                            st.markdown(
                                f"**Stats:** {stats['duration_seconds']}s | "
                                f"{stats['steps']} steps | "
                                f"~{stats['total_tokens_est']} tokens"
                            )
                        st.markdown("**Answer:**")
                        st.markdown(
                            run["answer"][:500] + "..."
                            if len(run["answer"]) > 500
                            else run["answer"]
                        )
            else:
                st.info("No run history yet.")


def main():
    """Main entry point for Streamlit app."""
    init_session_state()
    render_sidebar()
    render_main_panel()


if __name__ == "__main__":
    main()
