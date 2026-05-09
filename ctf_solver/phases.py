"""
Phase state machine for the CTF agent (v3.8 P1).

The pre-v3.8 agent treats reconnaissance vs. exploitation as a *convention*
the system prompt asks the model to follow.  The recon-only marker
``_RECON_TOOLS`` in ``agent.py`` only *reports* whether the model has
strayed yet; it never *blocks* the model from calling, e.g.,
``sqli_data_dumper`` before any ``sqli_probe`` confirmation.  For a 26B
local model the convention is too easy to ignore.

The ``PhaseStateMachine`` formalises four phases in execution order::

    RECON ─► CLASSIFY ─► EXPLOIT ─► EXTRACT

Each phase has an *allowed-tool set*.  ``allowed(tool_name)`` returns
True when ``tool_name`` is permitted in the *current* phase OR in any
earlier phase (i.e. you can always re-do recon).  Calling a forbidden
tool returns False and surfaces a helpful error string for the agent
loop to relay to the model as an observation.

Phase transitions are *signal-driven*: the machine watches every
observation and tool call for promotion triggers (e.g. ``sqli_probe``
returning a positive signal moves RECON/CLASSIFY → EXPLOIT for the
sql_injection category).  Transitions only move forward — the machine
never demotes mid-run, because demotion would let a stuck model
re-enter recon indefinitely without ever attempting exploitation.

The state machine is deliberately permissive about *recon* tools
(always allowed) and *category-agnostic exploitation* (e.g.
``encoding``, ``ctf_knowledge_query``, ``attack_planner``).  It
specifically gates the high-confusion exploit tools — the SQL/SSTI/XSS/
LFI/XXE/cmdi/JWT/file-upload families — behind an observed phase signal.

Disabled by default for now (``enabled=False``) so existing tests keep
passing; the agent enables it explicitly.  See ``CTFAgent`` integration
in ``agent.py``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


class Phase(str, Enum):
    """Phases of the agent's run, in execution order."""

    RECON = "recon"
    CLASSIFY = "classify"
    EXPLOIT = "exploit"
    EXTRACT = "extract"


# Order of phases — used for "is X reachable from Y" comparisons.
_PHASE_ORDER: Dict[Phase, int] = {
    Phase.RECON: 0,
    Phase.CLASSIFY: 1,
    Phase.EXPLOIT: 2,
    Phase.EXTRACT: 3,
}


# Tools always permitted in any phase.  These are recon / utility / RAG /
# planning / answer-emission tools that any phase can legitimately use.
_ALWAYS_ALLOWED: FrozenSet[str] = frozenset(
    {
        # Core recon
        "http_fetch",
        "form_submit",
        "auto_form_submit",
        "html_inspector",
        "javascript_source",
        "robots_txt",
        "cookie_inspector",
        "cookie_set",
        "deep_recon",
        "path_enumerator",
        "backup_file_finder",
        "security_header_analyzer",
        # Search & analysis
        "regex_search",
        "response_search",
        "sql_pattern_hint",
        "response_diff",
        "response_fingerprint",
        "timing_compare",
        # Utility / planning / RAG / answer
        "encoding",
        "hash_identifier",
        "ctf_knowledge_query",
        "attack_planner",
        "shell_execute",  # crypto/encoding/local-only utility
        "final_answer",
    }
)


# Mapping from category → exploitation-tool set.  These tools are
# unlocked only after a phase signal in the matching category fires.
_CATEGORY_TOOLS: Dict[str, FrozenSet[str]] = {
    "sql_injection": frozenset(
        {
            "sqli_probe",
            "sqli_column_counter",
            "sqli_data_dumper",
            "blind_sqli_boolean",
            "blind_sqli_time",
            "sqli_attack",
        }
    ),
    "ssti": frozenset({"ssti_probe", "ssti_exploit_suggester"}),
    "xss": frozenset(
        {
            "xss_probe",
            "xss_payload_generator",
            "csp_analyzer",
            "css_injection_payload_generator",
            "xss_attack",
        }
    ),
    "lfi": frozenset({"lfi_probe", "lfi_payload_generator", "php_filter_chain"}),
    "xxe": frozenset(
        {"xxe_probe", "xxe_payload_generator", "xxe_doctype_builder", "xxe_attack"}
    ),
    "cmdi": frozenset({"cmdi_probe", "cmdi_payload_generator"}),
    "nosql": frozenset({"nosql_probe", "nosql_payload_generator"}),
    "ssrf": frozenset({"ssrf_probe", "ssrf_payload_generator"}),
    "xpath": frozenset(
        {"xpath_probe", "xpath_blind_boolean", "xpath_payload_generator"}
    ),
    "crypto": frozenset(
        {
            "crypto_probe",
            "crypto_analyzer",
            "crypto_payload_generator",
            "crypto_attack",
        }
    ),
    "deserialization": frozenset(
        {"deserialization_probe", "deserialization_payload_generator"}
    ),
    "jwt": frozenset({"jwt_tool"}),
    "session_forgery": frozenset({"flask_session_forge"}),
    "file_upload": frozenset({"file_upload", "upload_location_finder"}),
    "graphql": frozenset({"graphql_introspection", "graphql_query"}),
    "websocket": frozenset({"websocket_probe"}),
    "wasm": frozenset({"wasm_analyzer"}),
    "smuggling": frozenset({"http_smuggling_probe"}),
    "filter_bypass": frozenset({"filter_enumerator", "payload_mutator"}),
    "fuzzer": frozenset({"request_repeater"}),
    "misc": frozenset(
        {
            "crlf_probe",
            "php_type_juggling",
            "prototype_pollution_probe",
            "idor_enumerator",
            "open_redirect_probe",
            "parser_differential_probe",
            "race_condition",
            "oauth_probe",
            "oauth_payload_generator",
            "dom_clobbering_payload_generator",
            "css_exfiltration_builder",
        }
    ),
}


# Signal patterns — when found in a tool *observation*, promote phase.
# Each entry is (regex, category, target_phase).
_PROMOTION_SIGNALS: List[Tuple[re.Pattern, str, Phase]] = [
    # SQLi confirm — typical SqliProbeTool / sql_pattern_hint output.
    (
        re.compile(r"\bsql\s*injection\s*detected", re.IGNORECASE),
        "sql_injection",
        Phase.EXPLOIT,
    ),
    (
        re.compile(
            r"\b(SQL|database|sqlite|mysql|postgresql)\b.*\berror", re.IGNORECASE
        ),
        "sql_injection",
        Phase.EXPLOIT,
    ),
    (re.compile(r"\bunion\s+select\b", re.IGNORECASE), "sql_injection", Phase.EXPLOIT),
    # SSTI confirm — arithmetic probes that evaluate.
    (
        re.compile(
            r"\b(?:49|7777777|36|81)\b.*ssti|ssti.*\b(?:49|7777777)\b", re.IGNORECASE
        ),
        "ssti",
        Phase.EXPLOIT,
    ),
    (
        re.compile(r"template\s+injection\s+(?:detected|confirmed)", re.IGNORECASE),
        "ssti",
        Phase.EXPLOIT,
    ),
    # XSS reflection
    (
        re.compile(r"reflect(?:ed|ion).*\bunencoded|xss.*detected", re.IGNORECASE),
        "xss",
        Phase.EXPLOIT,
    ),
    # LFI
    (re.compile(r"root:x:0:0:|/etc/passwd", re.IGNORECASE), "lfi", Phase.EXPLOIT),
    (
        re.compile(
            r"\blfi\s+detected|file\s+inclusion\s+(?:detected|confirmed)", re.IGNORECASE
        ),
        "lfi",
        Phase.EXPLOIT,
    ),
    # XXE
    (
        re.compile(r"xxe.*(?:detected|confirmed)|external\s+entity", re.IGNORECASE),
        "xxe",
        Phase.EXPLOIT,
    ),
    # cmdi
    (
        re.compile(
            r"command\s+injection\s+(?:detected|confirmed)|cmdi\s+detected",
            re.IGNORECASE,
        ),
        "cmdi",
        Phase.EXPLOIT,
    ),
    # NoSQL
    (
        re.compile(r"nosql\s+injection\s+(?:detected|confirmed)", re.IGNORECASE),
        "nosql",
        Phase.EXPLOIT,
    ),
    # XPath
    (
        re.compile(r"xpath\s+injection\s+(?:detected|confirmed)", re.IGNORECASE),
        "xpath",
        Phase.EXPLOIT,
    ),
    # SSRF
    (
        re.compile(r"ssrf\s+(?:detected|confirmed)", re.IGNORECASE),
        "ssrf",
        Phase.EXPLOIT,
    ),
    # JWT
    (
        re.compile(
            r"jwt.*(?:weak|none|alg).*(?:detected|confirmed)|jwt\s+vulnerab",
            re.IGNORECASE,
        ),
        "jwt",
        Phase.EXPLOIT,
    ),
    # GraphQL
    (
        re.compile(r"graphql.*introspection.*enabled|__schema", re.IGNORECASE),
        "graphql",
        Phase.EXPLOIT,
    ),
]


@dataclass
class PhaseStateMachine:
    """State machine controlling which tools are allowed at any moment.

    Disabled by default; the agent flips ``enabled=True`` after wiring
    this in (so existing tests that build CTFAgent directly do not see
    a behaviour change).
    """

    enabled: bool = False
    phase: Phase = Phase.RECON
    allowed_categories: Set[str] = field(default_factory=set)
    transition_log: List[Tuple[Phase, str]] = field(default_factory=list)

    def allowed(self, tool_name: str) -> bool:
        """True iff ``tool_name`` is permitted in the current state."""
        if not self.enabled:
            return True
        if tool_name in _ALWAYS_ALLOWED:
            return True
        # Find which category this tool belongs to (if any).
        for category, tools in _CATEGORY_TOOLS.items():
            if tool_name in tools:
                # In RECON or CLASSIFY, attack tools require a confirmed
                # category signal first.  In EXPLOIT/EXTRACT, allow once
                # the category is on the unlocked list.
                return category in self.allowed_categories
        # Tool not in any registry — be permissive (allows new/unknown tools
        # to function without code changes here).
        return True

    def reason_blocked(self, tool_name: str) -> str:
        """Human-readable explanation when ``allowed`` returns False."""
        for category, tools in _CATEGORY_TOOLS.items():
            if tool_name in tools:
                return (
                    f"Tool '{tool_name}' is gated behind a confirmed "
                    f"{category} signal. Run a recon/probe tool first to "
                    "confirm the vulnerability category, then retry. "
                    "Alternatively, call 'attack_planner' or "
                    "'ctf_knowledge_query' for guidance on which probe to "
                    "use first."
                )
        return f"Tool '{tool_name}' is not permitted in phase '{self.phase.value}'."

    def observe(self, tool_name: str, observation: str) -> Optional[Tuple[Phase, str]]:
        """Inspect a tool's observation for promotion signals.

        Side effect: may advance ``self.phase`` and add categories to
        ``self.allowed_categories``.  Returns ``(target_phase, category)``
        when a promotion fired, else None.

        Calling an attack-tool successfully (no ``Error:``-prefixed
        observation) also unlocks its category — this catches cases where
        the tool's output doesn't match the regex but the call clearly
        succeeded.
        """
        if not self.enabled:
            return None

        text = observation or ""
        # Pattern-driven promotion
        for pattern, category, target in _PROMOTION_SIGNALS:
            if pattern.search(text):
                fired = self._promote(target, category)
                if fired:
                    return (target, category)

        # Soft-promote on successful exploit-tool call: if this tool is
        # in some category, the call did not begin with "Error:", and the
        # category is not yet allowed, treat as an implicit confirmation.
        if tool_name and not text.lstrip().startswith("Error:"):
            for category, tools in _CATEGORY_TOOLS.items():
                if tool_name in tools and category not in self.allowed_categories:
                    fired = self._promote(Phase.EXPLOIT, category)
                    if fired:
                        return (Phase.EXPLOIT, category)
        return None

    def mark_extract(self) -> None:
        """Move the machine to EXTRACT phase (e.g. when a flag-shaped
        string appears in an observation).  No-op if already there."""
        if not self.enabled:
            return
        self._promote(Phase.EXTRACT, "*")

    def _promote(self, target: Phase, category: str) -> bool:
        new_phase = (
            target if _PHASE_ORDER[target] > _PHASE_ORDER[self.phase] else self.phase
        )
        unlocked = (
            category != "*"
            and target == Phase.EXPLOIT
            and category not in self.allowed_categories
        )
        if new_phase == self.phase and not unlocked and category == "*":
            return False
        if unlocked:
            self.allowed_categories.add(category)
        if new_phase != self.phase:
            self.phase = new_phase
        self.transition_log.append((self.phase, category))
        return True

    def reset(self) -> None:
        self.phase = Phase.RECON
        self.allowed_categories.clear()
        self.transition_log.clear()
