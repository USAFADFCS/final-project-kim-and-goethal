"""
Prompt templates for CTF Solver.

Provides customizable prompt templates with placeholder substitution
for different CTF platforms and challenge types.
"""

from ctf_solver.prompts.templates import (
    DEFAULT_SYSTEM_PROMPT,
    DEFAULT_ROLE_DEFINITION,
    get_system_prompt,
    get_role_definition,
    get_initial_message,
    ROBOTS_EXAMPLE,
    JS_ANALYSIS_EXAMPLE,
)

__all__ = [
    "DEFAULT_SYSTEM_PROMPT",
    "DEFAULT_ROLE_DEFINITION",
    "get_system_prompt",
    "get_role_definition",
    "get_initial_message",
    "ROBOTS_EXAMPLE",
    "JS_ANALYSIS_EXAMPLE",
]
