"""
Per-category prompt overlays (Tier 2.5).

When the classifier confidently labels a challenge, this module
produces a short markdown section that:

  - Reorders the tool catalog by category (front-loads the most
    relevant tools)
  - Pulls the existing per-category approach steps from the
    classifier's APPROACH_SUGGESTIONS table
  - Adds concise do / do-not guidance the prompt template does not
    already cover — derived from observed failure modes in the
    obs7 + tier1 runs (see ``memory/window_mode_failure_analysis.md``)

The overlay is rendered only when classifier confidence clears
``MIN_OVERLAY_CONFIDENCE``; otherwise the prompt stays neutral so
weak signals don't push the agent down the wrong path.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ctf_solver.classifier.challenge_classifier import (
    APPROACH_SUGGESTIONS,
    TOOL_PRIORITIES,
    ChallengeCategory,
    ClassificationResult,
)

# Below this confidence we add no overlay. The classifier is keyword-
# driven so its confidence is calibrated to "this many distinctive
# tokens appeared"; 0.40 is the elbow where most positive signals are
# real and most weak signals fall off.
MIN_OVERLAY_CONFIDENCE = 0.40

# Short do/don't anti-patterns per category. Sourced from observed
# failure modes — keep these terse, they are appended to the system
# prompt as bullets and burn context.
_CATEGORY_GUIDANCE: Dict[ChallengeCategory, Dict[str, List[str]]] = {
    ChallengeCategory.AUTHENTICATION: {
        "do": [
            "Decode the session cookie BEFORE attempting any auth bypass "
            "(`flask_session_forge analyze` for Flask, `jwt decode` for "
            "JWT). The cookie often reveals the access-control field "
            "name and the data the server reads back.",
            "If the session is signed (Flask/JWT), try `brute_secret` "
            "with a small CTF-typical wordlist before assuming the key "
            "is strong.",
            "When the cookie carries server-side state that drives the "
            "next request (e.g. a current question or counter), use "
            "`submit_until_done` in regex_extract mode to drive the "
            "loop server-side instead of one step per iteration.",
        ],
        "do_not": [
            "Pivot to SQLi probing on /submit *before* you have proven "
            "auth bypass — most 403/redirect responses on a session-"
            "gated endpoint are about session state, not query "
            "injection.",
            "Manually re-fetch the same page to 'get a fresh cookie' — "
            "the shared session jar already tracks Set-Cookie.",
        ],
    },
    ChallengeCategory.FILE_INCLUSION: {
        "do": [
            "Probe parameters that look path-shaped (?file=, ?page=, "
            "?include=) with `lfi_probe` BEFORE any other category. A "
            "single positive LFI dwarfs every other lead.",
            "When direct read returns empty/escaped, try "
            "`lfi_payload_generator` with php://filter chains and "
            "encoding bypasses.",
        ],
        "do_not": [
            "Spend more than two steps on /search-style endpoints "
            "before reaching for `lfi_probe`. A search page rarely "
            "yields the flag.",
            "Assume a 500 on /search means the bug is *in* /search — "
            "in MetaCTF-style challenges the vuln is usually adjacent.",
        ],
    },
    ChallengeCategory.SQL_INJECTION: {
        "do": [
            "Run `sqli_probe` with `error_based` first; the error "
            "message is usually enough to fingerprint the DB and "
            "decide whether UNION or blind is appropriate.",
            "After UNION column mismatch confirms injection, immediately "
            "step to `sqli_column_counter` rather than crafting payloads "
            "by hand.",
        ],
        "do_not": [
            "Submit raw injection strings via `http_fetch` when "
            "`sqli_probe` exists — you lose the structured baseline/"
            "diff that `sqli_probe` gives you.",
        ],
    },
    ChallengeCategory.SSTI: {
        "do": [
            "Confirm the engine with `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` "
            "before reaching for engine-specific payloads. The 49/36/81 "
            "fingerprint table is in `ssti_exploit_suggester`.",
        ],
        "do_not": [
            "Try Jinja2 payloads on responses that returned `${7*7}` "
            "untouched — that's a different engine.",
        ],
    },
    ChallengeCategory.JWT: {
        "do": [
            "Decode the token with `jwt decode` first, then try the "
            "alg=none and HS256-with-public-key confusions before any "
            "secret brute-force.",
        ],
        "do_not": [
            "Crack a strong HS256 secret on agent step time; if the "
            "wordlist is large, hand it off to `submit_until_done`.",
        ],
    },
    ChallengeCategory.FILE_UPLOAD: {
        "do": [
            "Find the upload location with `upload_location_finder` "
            "BEFORE crafting a webshell. If the upload writes outside "
            "the web root, your shell never executes.",
            "Try polyglot files (GIF89a magic + PHP) when the server "
            "validates magic bytes.",
        ],
        "do_not": [
            "Trust client-side extension checks — always retry with "
            "the bypass set even if the form looks restrictive.",
        ],
    },
    ChallengeCategory.XSS: {
        "do": [
            "Look for an admin-bot / report URL on the page; if one "
            "exists, the XSS is almost always cookie-exfiltration via "
            "the admin's session.",
            "Use `csp_analyzer` BEFORE picking a payload — CSP shapes "
            "what's possible (inline blocked, sources whitelisted, etc).",
        ],
        "do_not": [
            "Test alert(1) payloads on a server that rejects '<script>' "
            "— move straight to event-handler attribute payloads.",
        ],
    },
}


def build_category_overlay(
    result: Optional[ClassificationResult],
) -> str:
    """Render the category overlay markdown for a classification result.

    Returns an empty string when:
      - ``result`` is None
      - the primary category is UNKNOWN
      - confidence is below ``MIN_OVERLAY_CONFIDENCE``
    """
    if result is None:
        return ""
    if result.primary_category == ChallengeCategory.UNKNOWN:
        return ""
    if result.confidence < MIN_OVERLAY_CONFIDENCE:
        return ""

    cat = result.primary_category
    parts: List[str] = [
        "## Category-specific guidance",
        "",
        f"This challenge is most likely **{cat.value}** "
        f"(classifier confidence {result.confidence:.0%}). The "
        "general tool catalog above stays valid, but the items below "
        "should bias your first 3-5 steps.",
        "",
    ]

    priority_tools = TOOL_PRIORITIES.get(cat, [])
    if priority_tools:
        parts.append("### Priority tools")
        parts.append("Try these in roughly this order:")
        parts.append("")
        for tool in priority_tools[:6]:
            parts.append(f"- `{tool}`")
        parts.append("")

    approach = APPROACH_SUGGESTIONS.get(cat)
    if approach:
        parts.append("### Approach")
        parts.append(approach)
        parts.append("")

    guidance = _CATEGORY_GUIDANCE.get(cat)
    if guidance:
        dos = guidance.get("do") or []
        donts = guidance.get("do_not") or []
        if dos:
            parts.append("### Do")
            for line in dos:
                parts.append(f"- {line}")
            parts.append("")
        if donts:
            parts.append("### Do NOT")
            for line in donts:
                parts.append(f"- {line}")
            parts.append("")

    if result.secondary_categories:
        secondary = ", ".join(
            f"{cat.value} ({conf:.0%})" for cat, conf in result.secondary_categories[:2]
        )
        parts.append(
            "If the primary category lead stalls, also consider: " + secondary + "."
        )

    return "\n".join(parts).rstrip() + "\n"
