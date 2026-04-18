"""
Configuration model for the CTF Solver.

Provides a typed configuration with sensible defaults that can be overridden
via CLI arguments, environment variables, or programmatic configuration.
"""

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union

from dotenv import load_dotenv


class LLMProviderType(str, Enum):
    """Supported LLM providers for configuration."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    HYBRID = "hybrid"


class RAGMode(str, Enum):
    """RAG modes for the academic study on lessons-learned knowledge augmentation."""

    NONE = "none"  # No knowledge base at all
    ORIGINAL = "original"  # Only the original docs in docs/
    # Unified lessons-learned modes (the pre-v2.3 AUGMENTED / AUGMENTED_READONLY
    # aliases were removed when the monolithic failure/success pipeline was
    # retired; existing disk corpora keep working because _build_rag_config
    # still reads the legacy failure_docs_dir as an additional source).
    LESSONS_WRITE = "lessons_write"  # Curated docs + experience DB; writes atomic rules after every run
    LESSONS_READONLY = (
        "lessons_readonly"  # Curated docs + experience DB; reads only, never writes
    )
    LESSONS_BUILDONLY = "lessons_buildonly"  # Curated docs only during run; writes atomic rules after every run


# ---------------------------------------------------------------------------
# Convenience sets for mode-checking throughout the codebase
# ---------------------------------------------------------------------------

#: Modes that write new experience docs after every run.
RAG_WRITE_MODES: frozenset = frozenset(
    {RAGMode.LESSONS_WRITE, RAGMode.LESSONS_BUILDONLY}
)

#: Modes that read from the experience database.
RAG_EXPERIENCE_MODES: frozenset = frozenset(
    {
        RAGMode.LESSONS_WRITE,
        RAGMode.LESSONS_READONLY,
    }
)


def _find_and_load_dotenv() -> None:
    """Find and load .env file from project root or current directory."""
    # Try multiple locations for .env
    possible_paths = [
        Path.cwd() / ".env",  # Current directory
        Path(__file__).parent.parent / ".env",  # Project root (ctf_solver/../.env)
        Path(__file__).parent.parent.parent / ".env",  # One level up from project
    ]

    for env_path in possible_paths:
        if env_path.exists():
            load_dotenv(env_path)
            return

    # Fallback to default load_dotenv behavior
    load_dotenv()


# Default flag regex that supports common CTF formats:
# - PREFIX{content} where PREFIX is alphanumeric/underscore (e.g., picoCTF{}, flag{}, HTB{})
# - {content} alone (rare but possible)
# - Content limited to 200 chars, no nested braces or newlines
DEFAULT_FLAG_REGEX = r"[A-Za-z0-9_]+\{[^\n\r{}]{1,200}\}"

# Common CTF flag patterns for reference
COMMON_FLAG_PATTERNS = {
    "picoctf": r"picoCTF\{[^\n\r{}]{1,200}\}",
    "htb": r"HTB\{[^\n\r{}]{1,200}\}",
    "thm": r"THM\{[^\n\r{}]{1,200}\}",
    "flag": r"flag\{[^\n\r{}]{1,200}\}",
    "ctf": r"CTF\{[^\n\r{}]{1,200}\}",
    "generic": DEFAULT_FLAG_REGEX,
}


# Inner-brace content that indicates a test/placeholder/example flag.
# Matched case-insensitively against the text INSIDE the braces.
_PLACEHOLDER_FLAG_CONTENTS = frozenset(
    {
        "test_flag",
        "flag",
        "flag_here",
        "example",
        "example_flag",
        "placeholder",
        "your_flag_here",
        "xxx",
        "test",
        "sample",
        "dummy",
        "changeme",
        "replace_me",
        "insert_flag",
        "todo",
    }
)


def _is_placeholder_flag(candidate: str) -> bool:
    """Return True if *candidate* looks like a test/placeholder flag."""
    brace_open = candidate.find("{")
    brace_close = candidate.rfind("}")
    if brace_open == -1 or brace_close == -1 or brace_close <= brace_open:
        return False
    inner = candidate[brace_open + 1 : brace_close].strip().lower()
    return inner in _PLACEHOLDER_FLAG_CONTENTS


# Content-shape patterns that identify agent-generated noise (JSON, CSS, PHP).
# Observed in the 2026-04-17 MetaCTF batch — e.g. Socket.IO frames like
# 0{"sid":"…"} had valid alphanumeric prefixes but JSON-object shape inside.
_JSON_KEY_RE = re.compile(r'"[^"]{1,60}"\s*:')
_CSS_PROP_RE = re.compile(
    r"\b(?:opacity|transform|margin|padding|color|display|position|"
    r"background|font|width|height|border|flex|grid)\s*:",
    re.IGNORECASE,
)
_PHP_SHAPE_RE = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|"
    r"\bsystem\(|\bshell_exec\(|\beval\(|\bpassthru\("
)


def _is_noise_flag(candidate: str) -> bool:
    """Return True if *candidate* is either a placeholder OR a shape-matched
    non-flag (JSON object, CSS rule, PHP payload). Extends
    ``_is_placeholder_flag`` with content-aware heuristics that catch the
    false positives observed in live CTF runs."""
    if _is_placeholder_flag(candidate):
        return True
    brace_open = candidate.find("{")
    brace_close = candidate.rfind("}")
    if brace_open == -1 or brace_close == -1 or brace_close <= brace_open:
        return False
    inner = candidate[brace_open + 1 : brace_close]
    if _JSON_KEY_RE.search(inner):
        return True
    if _CSS_PROP_RE.search(inner):
        return True
    if _PHP_SHAPE_RE.search(inner):
        return True
    return False


@dataclass
class SolverConfig:
    """
    Configuration for the CTF Solver agent.

    Attributes:
        platform_name: Name of the CTF platform (for display/logging)
        agent_system_prompt: Custom system prompt for the agent (if None, uses default template)
        flag_regex: Regex pattern for extracting candidate flags
        challenge_url: Target URL for the challenge
        challenge_description: Description of the challenge
        challenge_hints: Hints provided for the challenge
        docs_dirs: List of directories containing knowledge base documents
        kb_files: List of specific files to include in the knowledge base
        max_steps: Maximum number of agent reasoning steps
        model_name: LLM model to use
        openai_api_key: OpenAI API key (loaded from env if not provided)
        verbose: Enable verbose logging
        vector_store_dir: Directory for storing/loading vector indices
        cache_enabled: Enable HTTP response caching
        cache_ttl: Cache time-to-live in seconds
        cache_max_entries: Maximum number of cached entries
        cache_max_size_bytes: Maximum total cache size in bytes
        async_enabled: Enable parallel tool execution
        async_max_workers: Maximum number of concurrent workers
        async_timeout: Timeout for async operations in seconds
        deduplication_enabled: Enable request deduplication
        llm_provider: LLM provider to use (openai, anthropic, ollama, hybrid)
        anthropic_api_key: Anthropic API key (loaded from env if not provided)
        llm_base_url: Base URL for LLM API (for custom endpoints or Ollama)
    """

    # Platform configuration
    platform_name: str = "Generic CTF"

    # Agent configuration
    agent_system_prompt: Optional[str] = None
    max_steps: int = 20
    # Optional sliding-window cap on planner history. None = send full memory
    # (legacy). Set to e.g. 20 to bound per-turn input at ~2k history tokens
    # for long runs.  First 2 messages (original task + primed context) are
    # always preserved; only the middle is truncated.
    history_window_size: Optional[int] = None
    # Default-on: run a small deterministic recon batch (robots.txt + common
    # path enumeration) before the LLM loop starts, injecting results as
    # observations. Saves 2-3 LLM turns on every challenge with a challenge_url.
    # Short-circuited when challenge_url is None so headless / unit-test paths
    # are unaffected (see build_agent() in agent.py).
    enable_opener_pack: bool = True
    # Opt-in: route LLM calls through the native-tools adapter + multi-tool-per-turn
    # loop (``_arun_native_tools`` / ``_arun_native_tools_openai``).  Default off
    # for safety — tests exercise the legacy JSON-ReAct path.
    enable_parallel_tools: bool = False
    # Opt-in: wrap the shared ``requests.Session`` with ``CachedSession`` so
    # repeat GET/HEAD calls hit a TTL cache and concurrent duplicates dedup.
    # Off by default because caching can mask intentional re-probes (e.g.
    # checking whether an endpoint changed state).  Enable for idempotent
    # workloads where you want to shrink tool outputs + save HTTP round-trips.
    enable_response_cache: bool = False
    # TTL (seconds) for cached GET/HEAD responses when enable_response_cache=True.
    response_cache_ttl_seconds: float = 120.0
    # Max entries in the response cache (LRU eviction above this).
    response_cache_max_entries: int = 500
    # Controls the one-shot RAG query that ``runner``/``streamlit_app`` fire
    # before the agent loop starts.  When True (default, preserves legacy
    # behavior), relevant knowledge-base hits for the challenge description
    # are injected into the initial prompt.  When False, the agent retrieves
    # on demand by calling ``ctf_knowledge_query`` mid-run — saves ~150-400
    # tokens on the first turn when the proactive retrieval produces no
    # useful hits.
    enable_proactive_rag: bool = True
    model_name: str = "gpt-4o"
    llm_provider: Union[str, LLMProviderType] = LLMProviderType.OPENAI

    # Flag configuration
    flag_regex: str = DEFAULT_FLAG_REGEX

    # Challenge configuration
    challenge_url: Optional[str] = None
    challenge_description: Optional[str] = None
    challenge_hints: Optional[str] = None
    # Human-readable challenge name (e.g. "Great Paywall"). Used for:
    # - Naming lessons-learned docs (slug form)
    # - Contamination filtering: excludes same-challenge docs from RAG retrieval
    challenge_name: Optional[str] = None
    # Source files provided by the challenge (filename → content).
    # When non-empty, the agent receives the source code at the start of the run
    # so it can identify the vulnerability before making live HTTP requests.
    source_files: Dict[str, str] = field(default_factory=dict)

    # Knowledge base configuration
    docs_dirs: List[str] = field(default_factory=list)
    kb_files: List[str] = field(default_factory=list)
    vector_store_dir: str = "out/ctf_vector_store"

    # RAG study configuration
    rag_mode: Union[str, "RAGMode"] = RAGMode.ORIGINAL
    failure_docs_dir: str = "out/failure_knowledge"
    lessons_docs_dir: str = "out/lessons_knowledge"
    auto_analyze_failures: bool = False

    # LLM-enhanced lessons generation (opt-in; uses openai_api_key)
    use_llm_for_lessons: bool = False
    lessons_llm_model: str = "gpt-4o-mini"

    # API configuration
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    llm_base_url: Optional[str] = None

    # LLM tuning
    max_tokens: int = 4096
    llm_timeout: float = 120.0

    # Runtime configuration
    verbose: bool = False

    # Caching configuration
    cache_enabled: bool = True
    cache_ttl: float = 300.0  # 5 minutes
    cache_max_entries: int = 1000
    cache_max_size_bytes: int = 50 * 1024 * 1024  # 50MB

    # Async execution configuration
    async_enabled: bool = True
    async_max_workers: int = 10
    async_timeout: float = 30.0

    # Request deduplication
    deduplication_enabled: bool = True

    def __post_init__(self):
        """Load environment variables and validate configuration."""
        _find_and_load_dotenv()

        # Normalize LLM provider to enum
        if isinstance(self.llm_provider, str):
            try:
                self.llm_provider = LLMProviderType(self.llm_provider.lower())
            except ValueError:
                # Keep as string if not a valid enum value
                pass

        # Normalize RAG mode to enum
        if isinstance(self.rag_mode, str):
            try:
                self.rag_mode = RAGMode(self.rag_mode.lower())
            except ValueError:
                self.rag_mode = RAGMode.ORIGINAL

        # Load API keys from environment if not provided
        if not self.openai_api_key:
            self.openai_api_key = os.getenv("OPENAI_API_KEY")
        if not self.anthropic_api_key:
            self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
        if not self.llm_base_url:
            self.llm_base_url = os.getenv("LLM_BASE_URL")

        # Validate flag regex
        try:
            re.compile(self.flag_regex)
        except re.error as e:
            raise ValueError(f"Invalid flag_regex pattern: {e}")

    @classmethod
    def from_env(cls) -> "SolverConfig":
        """Create configuration from environment variables."""
        _find_and_load_dotenv()

        docs_dirs = []
        if os.getenv("CTF_DOCS_DIR"):
            docs_dirs = [os.getenv("CTF_DOCS_DIR")]

        kb_files = []
        if os.getenv("CTF_KB_FILES"):
            kb_files = os.getenv("CTF_KB_FILES").split(",")

        return cls(
            platform_name=os.getenv("CTF_PLATFORM_NAME", "Generic CTF"),
            flag_regex=os.getenv("CTF_FLAG_REGEX", DEFAULT_FLAG_REGEX),
            challenge_url=os.getenv("CTF_CHALLENGE_URL"),
            challenge_description=os.getenv("CTF_CHALLENGE_DESCRIPTION"),
            challenge_hints=os.getenv("CTF_CHALLENGE_HINTS"),
            docs_dirs=docs_dirs,
            kb_files=kb_files,
            max_steps=int(os.getenv("CTF_MAX_STEPS", "20")),
            model_name=os.getenv("CTF_MODEL_NAME", "gpt-4o"),
            llm_provider=os.getenv("CTF_LLM_PROVIDER", "openai"),
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            llm_base_url=os.getenv("LLM_BASE_URL"),
            verbose=os.getenv("CTF_VERBOSE", "").lower() in ("true", "1", "yes"),
            vector_store_dir=os.getenv("CTF_VECTOR_STORE_DIR", "out/ctf_vector_store"),
            # Caching configuration
            cache_enabled=os.getenv("CTF_CACHE_ENABLED", "true").lower()
            in ("true", "1", "yes"),
            cache_ttl=float(os.getenv("CTF_CACHE_TTL", "300")),
            cache_max_entries=int(os.getenv("CTF_CACHE_MAX_ENTRIES", "1000")),
            cache_max_size_bytes=int(
                os.getenv("CTF_CACHE_MAX_SIZE_BYTES", str(50 * 1024 * 1024))
            ),
            # Async configuration
            async_enabled=os.getenv("CTF_ASYNC_ENABLED", "true").lower()
            in ("true", "1", "yes"),
            async_max_workers=int(os.getenv("CTF_ASYNC_MAX_WORKERS", "10")),
            async_timeout=float(os.getenv("CTF_ASYNC_TIMEOUT", "30")),
            # Deduplication
            deduplication_enabled=os.getenv("CTF_DEDUP_ENABLED", "true").lower()
            in ("true", "1", "yes"),
            # LLM-enhanced lessons
            use_llm_for_lessons=os.getenv("CTF_LLM_LESSONS", "").lower()
            in ("true", "1", "yes"),
            lessons_llm_model=os.getenv("CTF_LESSONS_MODEL", "gpt-4o-mini"),
        )

    def merge_with_args(self, **kwargs) -> "SolverConfig":
        """
        Create a new config merging current values with provided arguments.

        Arguments take precedence over current values.
        """
        current = {
            "platform_name": self.platform_name,
            "agent_system_prompt": self.agent_system_prompt,
            "flag_regex": self.flag_regex,
            "challenge_url": self.challenge_url,
            "challenge_description": self.challenge_description,
            "challenge_hints": self.challenge_hints,
            "challenge_name": self.challenge_name,
            "source_files": dict(self.source_files),
            "docs_dirs": self.docs_dirs.copy(),
            "kb_files": self.kb_files.copy(),
            "max_steps": self.max_steps,
            "model_name": self.model_name,
            "llm_provider": self.llm_provider,
            "openai_api_key": self.openai_api_key,
            "anthropic_api_key": self.anthropic_api_key,
            "llm_base_url": self.llm_base_url,
            "verbose": self.verbose,
            "vector_store_dir": self.vector_store_dir,
            # RAG study configuration
            "rag_mode": self.rag_mode,
            "failure_docs_dir": self.failure_docs_dir,
            "lessons_docs_dir": self.lessons_docs_dir,
            "auto_analyze_failures": self.auto_analyze_failures,
            # LLM-enhanced lessons
            "use_llm_for_lessons": self.use_llm_for_lessons,
            "lessons_llm_model": self.lessons_llm_model,
            # Caching configuration
            "cache_enabled": self.cache_enabled,
            "cache_ttl": self.cache_ttl,
            "cache_max_entries": self.cache_max_entries,
            "cache_max_size_bytes": self.cache_max_size_bytes,
            # Async configuration
            "async_enabled": self.async_enabled,
            "async_max_workers": self.async_max_workers,
            "async_timeout": self.async_timeout,
            # Deduplication
            "deduplication_enabled": self.deduplication_enabled,
        }

        # Only update with non-None values
        for key, value in kwargs.items():
            if value is not None and key in current:
                current[key] = value

        return SolverConfig(**current)

    def get_all_kb_paths(self) -> List[Path]:
        """Get all knowledge base file paths from docs_dirs and kb_files.

        Paths can be absolute or relative. Relative paths are resolved from
        the current working directory.
        """
        paths = []

        # Add specific files
        for f in self.kb_files:
            p = Path(f).resolve()
            if p.exists() and p.is_file():
                paths.append(p)

        # Add files from directories
        for d in self.docs_dirs:
            dir_path = Path(d).resolve()
            if dir_path.exists() and dir_path.is_dir():
                paths.extend(sorted(dir_path.glob("*.md")))
                paths.extend(sorted(dir_path.glob("*.txt")))
                paths.extend(sorted(dir_path.glob("*.pdf")))

        return paths


def extract_candidate_flags(text: str, regex: str = DEFAULT_FLAG_REGEX) -> List[str]:
    """
    Extract candidate flags from text using the provided regex pattern.

    Args:
        text: Text to search for flags
        regex: Regex pattern for flag matching

    Returns:
        List of candidate flag strings
    """
    try:
        pattern = re.compile(regex)
        raw = pattern.findall(text)
        return [m for m in raw if not _is_noise_flag(m)]
    except re.error:
        return []


def is_valid_flag(candidate: str, regex: str = DEFAULT_FLAG_REGEX) -> bool:
    """
    Check if a candidate string matches the flag pattern.

    Args:
        candidate: Candidate flag string
        regex: Regex pattern for validation

    Returns:
        True if the candidate matches the pattern
    """
    if _is_noise_flag(candidate):
        return False
    try:
        pattern = re.compile(f"^{regex}$")
        return bool(pattern.match(candidate))
    except re.error:
        return False


def validate_flag_regex(regex: str) -> tuple[bool, str]:
    """
    Validate a flag regex pattern.

    Args:
        regex: Regex pattern to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        re.compile(regex)
        return True, ""
    except re.error as e:
        return False, str(e)
