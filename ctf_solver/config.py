"""
Configuration model for the CTF Solver.

Provides a typed configuration with sensible defaults that can be overridden
via CLI arguments, environment variables, or programmatic configuration.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv


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
DEFAULT_FLAG_REGEX = r"(?:[A-Za-z0-9_]+)?\{[^\n\r{}]{1,200}\}"

# Common CTF flag patterns for reference
COMMON_FLAG_PATTERNS = {
    "picoctf": r"picoCTF\{[^\n\r{}]{1,200}\}",
    "htb": r"HTB\{[^\n\r{}]{1,200}\}",
    "thm": r"THM\{[^\n\r{}]{1,200}\}",
    "flag": r"flag\{[^\n\r{}]{1,200}\}",
    "ctf": r"CTF\{[^\n\r{}]{1,200}\}",
    "generic": DEFAULT_FLAG_REGEX,
}


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
    """

    # Platform configuration
    platform_name: str = "Generic CTF"

    # Agent configuration
    agent_system_prompt: Optional[str] = None
    max_steps: int = 20
    model_name: str = "gpt-4o"

    # Flag configuration
    flag_regex: str = DEFAULT_FLAG_REGEX

    # Challenge configuration
    challenge_url: Optional[str] = None
    challenge_description: Optional[str] = None
    challenge_hints: Optional[str] = None

    # Knowledge base configuration
    docs_dirs: List[str] = field(default_factory=list)
    kb_files: List[str] = field(default_factory=list)
    vector_store_dir: str = "out/ctf_vector_store"

    # API configuration
    openai_api_key: Optional[str] = None

    # Runtime configuration
    verbose: bool = False

    def __post_init__(self):
        """Load environment variables and validate configuration."""
        _find_and_load_dotenv()

        # Load API key from environment if not provided
        if not self.openai_api_key:
            self.openai_api_key = os.getenv("OPENAI_API_KEY")

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
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            verbose=os.getenv("CTF_VERBOSE", "").lower() in ("true", "1", "yes"),
            vector_store_dir=os.getenv("CTF_VECTOR_STORE_DIR", "out/ctf_vector_store"),
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
            "docs_dirs": self.docs_dirs.copy(),
            "kb_files": self.kb_files.copy(),
            "max_steps": self.max_steps,
            "model_name": self.model_name,
            "openai_api_key": self.openai_api_key,
            "verbose": self.verbose,
            "vector_store_dir": self.vector_store_dir,
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
        return pattern.findall(text)
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
