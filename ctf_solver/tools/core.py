"""Shared utilities for tool implementations (Batch D #6).

All 37+ FAIR-style tools historically hand-rolled the same JSON parsing
boilerplate (~15 LOC × 37 files ≈ 555 LOC).  ``parse_json_input`` gives
them a single call and a consistent error message so new tools avoid the
drift, and existing tools can migrate incrementally (``http_tools.py`` is
the first adopter — a proof-of-concept for the rest of the suite).

Error format is the most common variant across the existing codebase:
``[ToolName] Error: tool_input must be JSON. Decoding failed with: <exc>``.
Migrating a tool should not change the error string it produces — verify
against the tool's own tests before switching.
"""

from __future__ import annotations

import ast
import json
import re
from typing import Any, Dict, List, Optional, Pattern, Tuple, Union

# ---------------------------------------------------------------------------
# parse_json_input auto-repair + error-hint classifier (v3.3 Phase 3b)
# ---------------------------------------------------------------------------
#
# Local-LLM agent runs produce two observable classes of ``tool_input must be
# JSON`` failure the model cannot self-recover from:
#
#   1. Unambiguous malformations that can be repaired deterministically —
#      bare URLs (``'http://host/path'``) and Python call syntax
#      (``http_fetch(url='...')``) — see v3.3 Phase 3b run analysis.
#   2. Ambiguous malformations (unescaped quotes inside ``raw_body`` XML,
#      literal newlines in JSON strings, truncated output) that we will
#      NOT auto-repair — the risk of silently corrupting a legitimate
#      payload is too high. Instead we emit a context-aware hint that
#      tells the LLM exactly how to fix it on the next turn.
#
# Repair is strictly opt-in via keyword args so existing callers are
# unaffected.

_BARE_URL_RE = re.compile(r"^https?://\S+$")

# Matches ``tool_name(foo='bar', x="y")`` — used only when
# ``allow_python_call_syntax=True`` AND the leading identifier matches
# the caller's tool name exactly. Strict boundaries prevent collision
# with legitimate JSON whose outer value looks callable.
_PYTHON_CALL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(([^)]*)\)\s*$")
_PYTHON_KV_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)(?:,\s*|$)")


def _classify_json_error_hint(exc: json.JSONDecodeError, tool_input: str) -> str:
    """Return a one-line actionable hint for a JSONDecodeError.

    Empty string means "no applicable hint" — caller falls through to
    the generic message unchanged.
    """
    msg = exc.msg or ""
    # "Expecting value: line 1 column 1 (char 0)" == input was not JSON
    # at all (bare string, URL, Python call, etc.).
    if "Expecting value" in msg and exc.pos == 0:
        return (
            "Input is not JSON. Pass a JSON object like "
            '`{"url": "..."}`, not a bare URL or string.'
        )
    # Unescaped double quotes inside a string value — overwhelmingly the
    # ``raw_body`` XML case.
    if "Expecting" in msg and "delimiter" in msg and "raw_body" in tool_input:
        return (
            "Your JSON likely has unescaped double quotes inside "
            '`raw_body`. Inner double quotes must be written as `\\"`. '
            'Example: `{"raw_body": "<?xml version=\\"1.0\\"?>..."}`.'
        )
    if "Invalid control character" in msg:
        return (
            "Your JSON string contains an unescaped newline or control "
            "character. Replace real newlines with `\\n` (two chars, "
            "not a literal newline)."
        )
    if "Unterminated string" in msg:
        return (
            "A string is missing its closing quote (or your output was "
            "truncated). Re-emit the full JSON object in one piece."
        )
    return ""


def _try_python_call_repair(
    tool_input: str, tool_name: str
) -> Optional[Dict[str, Any]]:
    """Parse ``tool_name(key='value', ...)`` into a kwargs dict.

    Returns None if the input is not a well-formed call to exactly
    ``tool_name``. Values are evaluated with ``ast.literal_eval`` so
    only literals (strings, numbers, bools, None, lists, dicts, tuples)
    are accepted — no arbitrary code execution.
    """
    m = _PYTHON_CALL_RE.match(tool_input.strip())
    if not m:
        return None
    if m.group(1) != tool_name:
        return None
    args_str = m.group(2).strip()
    if not args_str:
        return {}
    kwargs: Dict[str, Any] = {}
    for k_m in _PYTHON_KV_RE.finditer(args_str):
        key = k_m.group(1)
        raw_val = k_m.group(2).strip()
        try:
            kwargs[key] = ast.literal_eval(raw_val)
        except (ValueError, SyntaxError):
            return None
    if not kwargs:
        return None
    return kwargs


def parse_json_input(
    tool_input: str,
    tool_name: str,
    *,
    url_field: Optional[str] = None,
    allow_python_call_syntax: bool = False,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Parse ``tool_input`` as JSON, with optional auto-repair.

    Returns ``(data, None)`` on success or ``(None, error_message)`` on
    JSON decode failure.  Empty / None / whitespace input returns
    ``({}, None)`` — the tool can then apply its own defaults.

    Args:
        tool_input: The raw string the agent passed.
        tool_name: Used in error messages AND as the recognized leading
            identifier for ``allow_python_call_syntax`` parsing.
        url_field: If set, a bare HTTP(S) URL (no whitespace, no braces,
            matches ``^https?://\\S+$``) is auto-wrapped as
            ``{url_field: url}``. Opt-in only — off by default.
        allow_python_call_syntax: If True, input of the form
            ``<tool_name>(key='value', ...)`` is parsed as kwargs. Values
            are evaluated via ``ast.literal_eval`` (safe subset).

    On ``JSONDecodeError`` the returned message is the mechanical format
    (``[ToolName] Error: tool_input must be JSON. Decoding failed with:
    <exc>``) plus an optional ``\\n  → Hint: ...`` line when the error
    matches a known category — existing code that matches on the
    mechanical prefix continues to work.
    """
    if not tool_input or not tool_input.strip():
        return {}, None

    stripped = tool_input.strip()

    # Auto-repair 1: bare URL → wrap as {url_field: url}. Only fires
    # when the caller opted in (url_field is set) AND the input is an
    # unambiguous single URL — no whitespace, no braces, starts with
    # http:// or https://.
    if url_field is not None and "{" not in stripped and _BARE_URL_RE.match(stripped):
        return {url_field: stripped}, None

    # Auto-repair 2: Python call syntax → kwargs dict. Only fires when
    # the caller explicitly opts in AND the leading identifier matches
    # tool_name exactly.
    if allow_python_call_syntax:
        repaired = _try_python_call_repair(stripped, tool_name)
        if repaired is not None:
            return repaired, None

    try:
        data = json.loads(tool_input)
    except json.JSONDecodeError as exc:
        base = (
            f"[{tool_name}] Error: tool_input must be JSON. "
            f"Decoding failed with: {exc}"
        )
        hint = _classify_json_error_hint(exc, tool_input)
        if hint:
            return None, f"{base}\n  → Hint: {hint}"
        return None, base
    if not isinstance(data, dict):
        return (
            None,
            f"[{tool_name}] Error: tool_input must be a JSON object, "
            f"got {type(data).__name__}.",
        )
    return data, None


# ---------------------------------------------------------------------------
# summarize_for_llm — observation-summarization helper (v3.3 Phase 2)
# ---------------------------------------------------------------------------
#
# Tool observations on local (Ollama) models eat the entire context window
# on pages with heavy CSS/JS boilerplate. ``http_fetch`` bodies routinely
# hand the LLM ~4 KB of <style>...</style> rules and 200 chars of useful
# markup. By step 7 on the 16k num_ctx default the model starts emitting
# empty content (cf. recentTestRun.txt run 4).
#
# This helper strips known-zero-signal structures (<style>, <script>),
# collapses runs of identical lines, and truncates to a caller-provided
# cap — while preserving any flag-regex matches via a hard contract so
# the agent's flag-detection path can never lose a flag that was hiding
# inside a stripped element. The helper is idempotent: applying twice
# produces the same result as once, because our placeholders (``[style:
# N bytes]``, ``[... N more identical lines ...]``, ``[... truncated]``)
# do not themselves match the stripping regexes.

_STYLE_RE = re.compile(r"<style\b[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL)
_SCRIPT_RE = re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
_SCRIPT_SRC_ATTR_RE = re.compile(r'\bsrc\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)

# Hash-pattern detection (v3.10 P1). Match isolated 32 / 64 hex-char tokens —
# the boundary lookarounds prevent matching part of a longer hex blob (so a
# 40-char SHA1 is not double-counted as MD5+8 hex). Detected outside of
# already-stripped <style>/<script> regions; flag matches are excluded by
# pre-scanning before this fires.
_MD5_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])")
_SHA256_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")
_HASH_HINT_LIMIT = 3
_HASH_HINT_TAG = "[CTF HINT:"


def _detect_hash_hints(text: str, preserved_flags: List[str]) -> List[str]:
    """Return up to ``_HASH_HINT_LIMIT`` deterministic hint lines for hex
    tokens in ``text``. Excludes substrings that appear inside any of the
    pre-collected ``preserved_flags`` to avoid hint-on-flag.
    """
    hints: List[str] = []
    seen: set = set()

    def _is_inside_flag(token: str) -> bool:
        return any(token in f for f in preserved_flags)

    def _short(token: str) -> str:
        return token[:6] + "…" if len(token) > 8 else token

    for match in _MD5_RE.finditer(text):
        token = match.group(0)
        if token.lower() in seen or _is_inside_flag(token):
            continue
        seen.add(token.lower())
        hints.append(
            f"{_HASH_HINT_TAG} 32-char hex token '{_short(token)}' looks "
            "like an MD5. Try idor_enumerator with id_type='md5' to "
            "enumerate md5(N) for integer IDs, or encoding with "
            "operation='md5' to confirm the plaintext.]"
        )
        if len(hints) >= _HASH_HINT_LIMIT:
            return hints

    for match in _SHA256_RE.finditer(text):
        token = match.group(0)
        if token.lower() in seen or _is_inside_flag(token):
            continue
        seen.add(token.lower())
        hints.append(
            f"{_HASH_HINT_TAG} 64-char hex token '{_short(token)}' looks "
            "like a SHA-256. Try encoding with operation='sha256' to "
            "confirm the plaintext.]"
        )
        if len(hints) >= _HASH_HINT_LIMIT:
            break

    return hints


def apply_hash_hints(text: str, *, preserved_flags: Optional[List[str]] = None) -> str:
    """Append hash-pattern hint lines to ``text`` when applicable.

    Public counterpart to ``_detect_hash_hints`` for callers that already
    have a finalized observation string and just want hint lines added —
    e.g. ``LoggingToolWrapper`` applying hints universally to every tool
    output, including fields like ``URL:`` that sit outside any
    ``summarize_for_llm`` body pass.

    Idempotent: re-applying does not duplicate hints (``_HASH_HINT_TAG``
    presence in the input short-circuits detection).
    """
    if not text or _HASH_HINT_TAG in text:
        return text
    hints = _detect_hash_hints(text, preserved_flags or [])
    if not hints:
        return text
    return text + "\n" + "\n".join(hints)


def _compile_flag_regex(
    flag_regex: Union[Pattern[str], str, None],
) -> Optional[Pattern[str]]:
    """Normalize the flag-regex argument to a compiled pattern (or None).

    Accepts a compiled ``re.Pattern``, a raw pattern string, or None.
    Invalid patterns degrade silently — summarization must never crash
    on a bad flag_regex; we just skip preservation for that call.
    """
    if flag_regex is None:
        return None
    if isinstance(flag_regex, re.Pattern):
        return flag_regex
    try:
        return re.compile(flag_regex)
    except re.error:
        return None


def _collapse_identical_lines(text: str) -> str:
    """Collapse runs of 3+ consecutive identical lines into the first
    occurrence plus a ``[... N more identical lines ...]`` marker.

    Two repeats are left untouched so legitimate short lists are not
    destroyed (e.g. a <ul> with two identical <li> entries after CSS
    stripping). Three repeats signals boilerplate.
    """
    lines = text.split("\n")
    out: List[str] = []
    i = 0
    while i < len(lines):
        j = i
        while j < len(lines) and lines[j] == lines[i]:
            j += 1
        run = j - i
        if run >= 3:
            out.append(lines[i])
            out.append(f"[... {run - 1} more identical lines ...]")
        else:
            out.extend(lines[i:j])
        i = j
    return "\n".join(out)


def summarize_for_llm(
    text: str,
    *,
    max_chars: int = 4000,
    flag_regex: Union[Pattern[str], str, None] = None,
) -> str:
    """Strip low-signal boilerplate from a tool observation.

    Transforms applied, in order:

    1. ``<style>...</style>`` bodies → ``[style: N bytes]``.
    2. ``<script>...</script>`` bodies → ``[script: N bytes]``,
       preserving the ``src="..."`` attribute when present (external
       script URLs are often valuable recon targets, so we keep them
       visible even though the body is stripped).
    3. Runs of 3+ consecutive identical lines collapse to a single
       occurrence plus a summary marker.
    4. If the result still exceeds ``max_chars``, truncate and append
       ``\\n[... truncated]``.
    5. Flag-preservation contract: any substring matching
       ``flag_regex`` in the original that does not appear in the
       final output is appended as
       ``[Flag pattern matches preserved from stripped regions: ...]``
       so the agent's downstream flag-detection never loses a flag
       that was embedded in a stripped region.

    Args:
        text: The raw tool observation (HTML body, recon dump, etc.).
        max_chars: Hard cap on the returned string length. Must be > 0.
            Output may be shorter — this is an upper bound, not a target.
        flag_regex: Optional flag pattern. Pass as compiled Pattern for
            hot paths, as a string for convenience, or None to skip
            preservation entirely (e.g. for RAG doc chunks which never
            contain flags). Invalid patterns degrade silently.

    Returns:
        The summarized observation string. Empty input returns "".

    Idempotent: ``summarize_for_llm(summarize_for_llm(x)) ==
    summarize_for_llm(x)`` for any reasonable input.
    """
    if not text:
        return ""
    if max_chars <= 0:
        # Degenerate cap — just strip and preserve flags, no length guard.
        max_chars = len(text)

    compiled_flag_re = _compile_flag_regex(flag_regex)

    # 1. Pre-scan for flag matches in the ORIGINAL text so we can enforce
    # the preservation contract at the end. Using finditer to collect
    # the raw matched strings; dedupe while preserving order.
    preserved_flags: List[str] = []
    if compiled_flag_re is not None:
        seen: set = set()
        for m in compiled_flag_re.finditer(text):
            match = m.group(0)
            if match not in seen:
                seen.add(match)
                preserved_flags.append(match)

    # 2. Strip <style>...</style> bodies.
    def _style_sub(m: "re.Match[str]") -> str:
        return f"[style: {len(m.group(0))} bytes]"

    out = _STYLE_RE.sub(_style_sub, text)

    # 3. Strip <script>...</script> bodies. Preserve the src attribute
    # when it exists — external script URLs are often the next recon
    # target (e.g. /assets/app.js with inline credentials).
    def _script_sub(m: "re.Match[str]") -> str:
        whole = m.group(0)
        src_match = _SCRIPT_SRC_ATTR_RE.search(whole)
        if src_match:
            return f'[script src="{src_match.group(1)}": {len(whole)} bytes]'
        return f"[script: {len(whole)} bytes]"

    out = _SCRIPT_RE.sub(_script_sub, out)

    # 4. Collapse repeated lines.
    out = _collapse_identical_lines(out)

    # 4b. Hash-pattern hints (v3.10 P1). Detect on the post-strip text so
    # boilerplate hex inside <style>/<script> doesn't generate noise, but
    # before truncation so hints survive even when the body is capped.
    # Idempotency is preserved by short-circuiting when hints are already
    # present in the input — re-running summarize_for_llm cannot duplicate
    # them.
    hash_hints: List[str] = []
    if _HASH_HINT_TAG not in text:
        hash_hints = _detect_hash_hints(out, preserved_flags)

    # 5. Truncate if still over cap.
    truncation_marker = "\n[... truncated]"
    if len(out) > max_chars:
        # Reserve space for the marker so the total stays under max_chars.
        keep = max(0, max_chars - len(truncation_marker))
        out = out[:keep] + truncation_marker

    # 6. Flag-preservation contract. Substring check is sufficient —
    # flags are short, appearing verbatim counts as preserved.
    if preserved_flags:
        missing = [f for f in preserved_flags if f not in out]
        if missing:
            preserved_line = (
                "\n[Flag pattern matches preserved from stripped regions: "
                + ", ".join(missing)
                + "]"
            )
            out = out + preserved_line

    # 7. Append hash-pattern hints AFTER truncation so they are guaranteed
    # visible regardless of body cap.
    if hash_hints:
        out = out + "\n" + "\n".join(hash_hints)

    return out


__all__ = ["parse_json_input", "summarize_for_llm"]
