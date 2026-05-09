"""
Recon DAG (v3.8 P2).

Generalises the static ``opener_pack`` (two zero-reasoning calls before
the LLM turns on) into a *DAG* — a sequence of recon steps where each
step can either be a static ``(tool_name, input_dict)`` tuple OR a
callable that inspects all prior observations and decides whether to
emit a next step.

The DAG runs deterministically before the LLM loop. If the flag-scan in
``LoggingToolWrapper`` already finds the flag during DAG execution, the
agent loop short-circuits at start and the run finishes without any
LLM tokens spent — the cleanest possible win for a 26B local model.

Static stages (always run when ``challenge_url`` is set):
  1. ``robots_txt`` — surface hidden paths via /robots.txt
  2. ``security_header_analyzer`` — flag CSP / cookies / hint headers
  3. ``deep_recon`` — combined fetch + heuristic dump on root URL
  4. ``html_inspector`` — extract forms / scripts / comments / metas
  5. ``path_enumerator`` — common-path brute on the root

Conditional stages (callables, fire when their trigger pattern matches
some prior observation):
  - ``_maybe_promote_role`` — if any ``Set-Cookie: role=<not-admin>``
    is seen, set ``role=admin`` and re-fetch the root URL.
  - ``_maybe_followup_path`` — if ``deep_recon`` / path_enumerator
    discovered a ``/login`` / ``/admin`` / ``/dashboard`` path, fetch
    it as a follow-up.

Disabled by default (``enable_recon_dag=False``); the legacy two-call
``opener_pack`` is the v3.7 behaviour and stays the default to keep
existing tests stable.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urljoin

# Public step shape: either a static (name, input) pair or a callable that
# may inspect prior observations and return one (or None to skip).
ReconStep = Union[
    Tuple[str, Dict[str, Any]],
    Callable[
        [List[Tuple[str, str]]],
        Optional[Tuple[str, Dict[str, Any]]],
    ],
]


_ROLE_COOKIE_RE = re.compile(
    r"Set-Cookie:\s*([A-Za-z_][A-Za-z0-9_-]*)=([^;\r\n]+)", re.IGNORECASE
)
_ROLE_NAME_RE = re.compile(r"^(role|user|priv|access)$", re.IGNORECASE)
_INTERESTING_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])(/(?:login|admin|dashboard|account|profile|api|debug|console|panel)[A-Za-z0-9_/.\-?&=#]*)",
    re.IGNORECASE,
)


def _join_observations(observations: List[Tuple[str, str]]) -> str:
    return "\n\n".join(out for _, out in observations)


def _maybe_promote_role_factory(
    base_url: str,
) -> Callable[[List[Tuple[str, str]]], Optional[Tuple[str, Dict[str, Any]]]]:
    """Return a callable: if any prior observation has ``Set-Cookie: role=…``
    with a non-admin value, set ``role=admin`` and re-fetch the root URL.

    This is one of the most common picoCTF web patterns — the server
    sets a role cookie and the bypass is to flip it to ``admin``.
    """
    seen_state: Dict[str, bool] = {"fired": False}

    def _step(
        observations: List[Tuple[str, str]],
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        if seen_state["fired"]:
            return None
        joined = _join_observations(observations)
        for cookie_match in _ROLE_COOKIE_RE.finditer(joined):
            cookie_name = cookie_match.group(1)
            cookie_value = cookie_match.group(2).strip()
            if not _ROLE_NAME_RE.match(cookie_name):
                continue
            if cookie_value.lower() in ("admin", "root", "superuser"):
                # Already admin — nothing to escalate.
                continue
            seen_state["fired"] = True
            # Strip protocol and port for the cookie domain.
            from urllib.parse import urlparse

            parsed = urlparse(base_url)
            domain = parsed.hostname or ""
            return (
                "cookie_set",
                {
                    "domain": domain,
                    "name": cookie_name,
                    "value": "admin",
                    "path": "/",
                },
            )
        return None

    return _step


def _maybe_followup_fetch_factory(
    base_url: str,
) -> Callable[[List[Tuple[str, str]]], Optional[Tuple[str, Dict[str, Any]]]]:
    """If recon revealed an interesting authenticated path (/login, /admin,
    /dashboard, etc.), fetch it as a follow-up so the model sees its
    contents in the very first turn."""
    seen_state: Dict[str, bool] = {"fired": False}

    def _step(
        observations: List[Tuple[str, str]],
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        if seen_state["fired"]:
            return None
        joined = _join_observations(observations)
        match = _INTERESTING_PATH_RE.search(joined)
        if not match:
            return None
        path = match.group(1)
        full = urljoin(base_url, path)
        if full.rstrip("/") == base_url.rstrip("/"):
            return None
        seen_state["fired"] = True
        return ("http_fetch", {"url": full, "method": "GET"})

    return _step


def compose_recon_dag(challenge_url: Optional[str]) -> List[ReconStep]:
    """Build the v3.8 recon DAG.

    Returns an empty list when ``challenge_url`` is missing — the DAG is
    a URL-rooted exercise; without a URL, the legacy / no-opener path
    is correct.
    """
    if not challenge_url:
        return []
    static_steps: List[ReconStep] = [
        ("robots_txt", {"base_url": challenge_url}),
        ("security_header_analyzer", {"url": challenge_url}),
        ("deep_recon", {"url": challenge_url}),
        ("html_inspector", {"url": challenge_url}),
        (
            "path_enumerator",
            {
                "url": challenge_url,
                "wordlist": "common",
                "max_paths": 20,
                "timeout": 5,
            },
        ),
    ]
    conditional_steps: List[ReconStep] = [
        _maybe_promote_role_factory(challenge_url),
        _maybe_followup_fetch_factory(challenge_url),
    ]
    return static_steps + conditional_steps


__all__ = ["ReconStep", "compose_recon_dag"]
