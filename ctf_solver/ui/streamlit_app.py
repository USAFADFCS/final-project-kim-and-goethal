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
    """Run the agent asynchronously."""
    agent = build_agent(config, log_callback=log_callback)

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

    response = await agent.arun(initial_message)

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

    # Build config
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

    # API key status
    api_key = os.getenv("OPENAI_API_KEY", "")
    if api_key:
        st.sidebar.success("✓ OpenAI API key configured")
    else:
        st.sidebar.error("✗ OpenAI API key not found")
        st.sidebar.info("Set OPENAI_API_KEY in your environment or .env file")


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
            st.rerun()

    # Results section
    st.markdown("---")

    if st.session_state.error_message:
        st.error(f"**Error:** {st.session_state.error_message}")

    # Display results in tabs
    if st.session_state.final_answer or st.session_state.logs:
        tab1, tab2, tab3, tab4 = st.tabs([
            "📋 Final Answer",
            "🚩 Candidate Flags",
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

        with tab4:
            st.markdown("### Run History")
            if st.session_state.run_history:
                for i, run in enumerate(reversed(st.session_state.run_history), 1):
                    with st.expander(f"Run {len(st.session_state.run_history) - i + 1} - {run['timestamp'][:19]}"):
                        if run["url"]:
                            st.markdown(f"**URL:** {run['url']}")
                        if run["description"]:
                            st.markdown(f"**Description:** {run['description'][:100]}...")
                        if run["flags"]:
                            st.markdown(f"**Flags Found:** {', '.join(run['flags'])}")
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
