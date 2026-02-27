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

# Now safe to import everything else
import asyncio
import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import streamlit as st

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ctf_solver.config import (
    SolverConfig,
    RAGMode,
    extract_candidate_flags,
    validate_flag_regex,
    COMMON_FLAG_PATTERNS,
    DEFAULT_FLAG_REGEX,
    _find_and_load_dotenv,
)

# Load .env file at startup
_find_and_load_dotenv()
from ctf_solver.agent import build_agent
from ctf_solver.prompts import get_initial_message, DEFAULT_SYSTEM_PROMPT
from ctf_solver.run_tracker import RunTracker
from ctf_solver.failure_analyzer import run_failure_analysis_pipeline


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
        "max_steps": 20,
        "docs_dirs": default_docs_dirs,  # Actual default, not just placeholder
        "kb_files": default_kb_files,    # Actual default, not just placeholder
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
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def log_callback(message: str):
    """Callback to capture log messages."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.logs.append(f"[{timestamp}] {message}")


def validate_url(url: str) -> tuple[bool, str]:
    """Validate URL format."""
    if not url:
        return True, ""  # Empty is OK (optional field)

    url_pattern = re.compile(
        r"^https?://"  # http:// or https://
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"  # domain
        r"localhost|"  # localhost
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # IP
        r"(?::\d+)?"  # optional port
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )

    if url_pattern.match(url):
        return True, ""
    return False, "Invalid URL format. Must start with http:// or https://"


async def run_agent_async(config: SolverConfig) -> str:
    """Run the agent asynchronously with run statistics tracking."""
    tracker = RunTracker()
    tracker.challenge_url = config.challenge_url or ""
    tracker.challenge_description = config.challenge_description or ""
    agent = build_agent(config, log_callback=log_callback, tracker=tracker)

    initial_message = get_initial_message(
        platform_name=config.platform_name,
        flag_regex=config.flag_regex,
        challenge_url=config.challenge_url,
        challenge_description=config.challenge_description,
        challenge_hints=config.challenge_hints,
    )

    st.session_state.execution_trace.append({
        "type": "input",
        "content": initial_message,
        "timestamp": datetime.now().isoformat(),
    })

    tracker.start()
    response = await agent.arun(initial_message)
    tracker.stop()

    # Extract candidate flags from response and all tool output
    all_text = response or ""
    for entry in tracker.tool_call_log:
        all_text += "\n" + entry.get("output", "")
    candidate_flags = extract_candidate_flags(all_text, config.flag_regex)
    tracker.candidate_flags_found = candidate_flags

    # Determine success
    tracker.run_succeeded = len(candidate_flags) > 0

    # Run failure analysis if enabled
    if config.auto_analyze_failures and not tracker.run_succeeded:
        config_data = {
            "challenge_url": config.challenge_url,
            "challenge_description": config.challenge_description,
        }
        failure_doc_path = run_failure_analysis_pipeline(
            config_data=config_data,
            tracker_data=tracker.to_dict(),
            tool_call_log=tracker.tool_call_log,
            agent_response=response,
            candidate_flags=candidate_flags,
            failure_docs_dir=config.failure_docs_dir,
            max_steps=config.max_steps,
            actual_steps=tracker.steps,
            flag_regex=config.flag_regex,
        )
        if failure_doc_path:
            tracker.failure_doc_generated = True
            log_callback(f"[Failure Analysis] Generated knowledge doc: {failure_doc_path}")
        else:
            log_callback("[Failure Analysis] No failure doc generated (run may have succeeded)")

    st.session_state.run_stats = tracker.to_dict()

    st.session_state.execution_trace.append({
        "type": "output",
        "content": response,
        "timestamp": datetime.now().isoformat(),
    })

    return response


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

    config = SolverConfig(
        platform_name=st.session_state.platform_name,
        agent_system_prompt=st.session_state.agent_prompt if st.session_state.agent_prompt != DEFAULT_SYSTEM_PROMPT else None,
        flag_regex=st.session_state.flag_regex,
        challenge_url=st.session_state.challenge_url or None,
        challenge_description=st.session_state.challenge_description or None,
        challenge_hints=st.session_state.challenge_hints or None,
        docs_dirs=docs_dirs,
        kb_files=kb_files,
        max_steps=st.session_state.max_steps,
        rag_mode=rag_mode_str,
        auto_analyze_failures=auto_analyze,
    )

    try:
        # Run the agent
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        response = loop.run_until_complete(run_agent_async(config))
        loop.close()

        st.session_state.final_answer = response

        # Extract candidate flags
        if response:
            flags = extract_candidate_flags(response, config.flag_regex)
            st.session_state.candidate_flags = flags

        # Add to run history
        st.session_state.run_history.append({
            "timestamp": datetime.now().isoformat(),
            "url": config.challenge_url,
            "description": config.challenge_description,
            "answer": response,
            "flags": flags if response else [],
            "stats": st.session_state.run_stats,
            "rag_mode": rag_mode_str,
            "run_succeeded": len(flags) > 0 if response else False,
        })

    except Exception as e:
        st.session_state.error_message = str(e)
        log_callback(f"[ERROR] {e}")

    finally:
        st.session_state.is_running = False


def render_sidebar():
    """Render the configuration sidebar."""
    st.sidebar.title("🚩 CTF Solver")
    st.sidebar.markdown("---")

    # Platform configuration
    st.sidebar.header("Platform Settings")

    st.session_state.platform_name = st.sidebar.text_input(
        "Platform Name",
        value=st.session_state.platform_name,
        help="Name of the CTF platform (e.g., PicoCTF, HackTheBox, TryHackMe)",
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

    st.session_state.max_steps = st.sidebar.slider(
        "Max Steps",
        min_value=5,
        max_value=50,
        value=st.session_state.max_steps,
        help="Maximum number of reasoning steps before stopping",
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
    st.sidebar.caption(f"📁 Project root: {st.session_state.get('project_root', 'unknown')}")

    # Reset KB settings button
    if st.sidebar.button("🔄 Reset KB to Defaults", use_container_width=True):
        st.session_state.docs_dirs = "docs/"
        st.session_state.kb_files = "Book-3-Web-Exploitation.pdf"
        st.rerun()

    st.sidebar.markdown("---")

    # RAG Study Mode
    st.sidebar.header("RAG Study Mode")

    rag_mode_options = {
        "No RAG": "none",
        "Original (docs only)": "original",
        "Augmented (docs + failure knowledge)": "augmented",
    }
    rag_mode_labels = list(rag_mode_options.keys())
    # Find current selection index
    current_mode = st.session_state.get("rag_mode", "original")
    current_idx = list(rag_mode_options.values()).index(current_mode) if current_mode in rag_mode_options.values() else 1

    selected_label = st.sidebar.radio(
        "RAG Mode",
        options=rag_mode_labels,
        index=current_idx,
        help=(
            "**No RAG**: Agent has no knowledge base.\n\n"
            "**Original**: Agent uses the original docs/ knowledge base.\n\n"
            "**Augmented**: Agent uses original docs + auto-generated failure knowledge."
        ),
    )
    st.session_state.rag_mode = rag_mode_options[selected_label]

    # Auto-analyze checkbox (only relevant for augmented mode)
    if st.session_state.rag_mode == "augmented":
        st.session_state.auto_analyze_failures = st.sidebar.checkbox(
            "Auto-analyze failures",
            value=st.session_state.get("auto_analyze_failures", False),
            help="When enabled, failed runs are automatically analyzed and a knowledge document is generated.",
        )

        # Show count of existing failure docs
        project_root = Path(st.session_state.get("project_root", get_project_root()))
        failure_dir = project_root / "out" / "failure_knowledge"
        if failure_dir.exists():
            failure_doc_count = len(list(failure_dir.glob("failure_*.md")))
            st.sidebar.caption(f"📄 Failure knowledge docs: {failure_doc_count}")
        else:
            st.sidebar.caption("📄 Failure knowledge docs: 0")
    else:
        st.session_state.auto_analyze_failures = False

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
    run_succeeded = stats.get("run_succeeded", False)
    outcome_text = "Success" if run_succeeded else "Failed"
    outcome_color = "green" if run_succeeded else "red"

    rc1, rc2, rc3 = st.columns(3)
    rc1.metric("RAG Mode", rag_mode_display.capitalize())
    rc2.metric("Outcome", outcome_text)
    if stats.get("failure_doc_generated"):
        rc3.metric("Failure Doc", "Generated")
    else:
        rc3.metric("Failure Doc", "N/A")

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


def render_main_panel():
    """Render the main panel."""
    st.title("🚩 CTF Solver")
    st.markdown("*Platform-agnostic agentic CTF solving framework*")

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

    # Display results in tabs
    if st.session_state.final_answer or st.session_state.logs:
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📋 Final Answer",
            "🚩 Candidate Flags",
            "📈 Run Statistics",
            "📜 Execution Log",
            "📊 History",
        ])

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
                    with st.expander(f"Run {run_num} [{rag_label}] {status_icon} - {run['timestamp'][:19]}"):
                        if run["url"]:
                            st.markdown(f"**URL:** {run['url']}")
                        if run["description"]:
                            st.markdown(f"**Description:** {run['description'][:100]}...")
                        st.markdown(f"**RAG Mode:** {rag_label} | **Outcome:** {'Success' if succeeded else 'Failed'}")
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
                        st.markdown(run["answer"][:500] + "..." if len(run["answer"]) > 500 else run["answer"])
            else:
                st.info("No run history yet.")


def main():
    """Main entry point for Streamlit app."""
    init_session_state()
    render_sidebar()
    render_main_panel()


if __name__ == "__main__":
    main()
