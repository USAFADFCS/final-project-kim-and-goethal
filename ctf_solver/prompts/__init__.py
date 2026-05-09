"""
Prompt templates for CTF Solver.

Provides customizable prompt templates with placeholder substitution
for different CTF platforms and challenge types.
"""

from ctf_solver.prompts.templates import (
    COOKIE_BYPASS_EXAMPLE,
    DEEP_RECON_EXAMPLE,
    DEFAULT_ROLE_DEFINITION,
    DEFAULT_SYSTEM_PROMPT,
    JS_ANALYSIS_EXAMPLE,
    JSON_API_EXAMPLE,
    ROBOTS_EXAMPLE,
    SELF_REFLECTION_EXAMPLE,
    XXE_RAW_BODY_EXAMPLE,
    get_initial_message,
    get_role_definition,
    get_system_prompt,
)

__all__ = [
    "DEFAULT_SYSTEM_PROMPT",
    "DEFAULT_ROLE_DEFINITION",
    "get_system_prompt",
    "get_role_definition",
    "get_initial_message",
    "ROBOTS_EXAMPLE",
    "JS_ANALYSIS_EXAMPLE",
    "SELF_REFLECTION_EXAMPLE",
    "JSON_API_EXAMPLE",
    "COOKIE_BYPASS_EXAMPLE",
    "DEEP_RECON_EXAMPLE",
    "XXE_RAW_BODY_EXAMPLE",
]
