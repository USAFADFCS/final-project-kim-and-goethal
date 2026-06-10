"""Parity-sprint item #3: classifier HTTP-body diagnostic (LOG-ONLY).

The category overlay never fired in the 12-MetaCTF batch because
``classify_challenge`` runs at ``build_agent`` time on the sparse description
only (UNKNOWN → no overlay). This diagnostic re-fires the classifier a second
time with the first recon HTTP body in hand and records both verdicts on the
``RunTracker`` — WITHOUT changing any agent behavior. A 12-batch re-run then
histograms ``(build_time_confidence, post_http_confidence)``.

These tests pin the *mechanism*: the diagnostic populates the right fields,
gates the would-have-applied flag on ``build_category_overlay``, is
exception-safe, and never mutates the config. The realistic fixtures (a
microdosing-style login page and a super_quick_logic-style nginx error body)
document the decisive cases — but the tests assert only valid-range outputs,
because whether those bodies break UNKNOWN is the empirical question the
batch re-run answers, not something to hard-code here.
"""

import ctf_solver.agent as agent_module
import ctf_solver.runner as runner_module
from ctf_solver.classifier.challenge_classifier import (
    ChallengeCategory,
    ClassificationResult,
)
from ctf_solver.config import SolverConfig
from ctf_solver.prompts.category_overlays import build_category_overlay
from ctf_solver.run_tracker import RunTracker
from ctf_solver.runner import _first_recon_body, run_classifier_http_diagnostic

# --- Realistic recon fixtures (extracted from out/batch_window_test logs) ----

MICRODOSING_LOGIN_BODY = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - MicroDose Analytics</title>
</head>
<body>
    <nav><a href="/login">Login</a></nav>
    <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Sign In</button>
    </form>
</body>
</html>"""

SUPER_QUICK_LOGIC_ERROR_BODY = (
    "<html>\r\n<head><title>400 Bad Request</title></head>\r\n"
    "<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n"
    "<hr><center>nginx</center>\r\n</body>\r\n</html>"
)

# A body with unambiguous SQL-injection signal, used for mechanism tests where
# we want the *real* classifier to land somewhere non-trivial.
SQLI_BODY = (
    "<html><body>"
    "You have an error in your SQL syntax near 'OR 1=1' at line 1. "
    "SELECT * FROM users WHERE username = '' sqlite3 mysql_fetch_array"
    "</body></html>"
)


def _cfg(**kw) -> SolverConfig:
    base = dict(
        challenge_url="http://example.test/",
        challenge_description="A web challenge.",
        challenge_name="fixture",
    )
    base.update(kw)
    return SolverConfig(**base)


def _tracker_with_recon(body: str, tool: str = "http_fetch") -> RunTracker:
    t = RunTracker()
    t.tool_call_log = [{"tool": tool, "input": "GET /", "output": body}]
    return t


# ---------------------------------------------------------------------------
# _first_recon_body
# ---------------------------------------------------------------------------


def test_first_recon_body_picks_first_http_tool():
    log = [
        {"tool": "ctf_knowledge_query", "output": "rag stuff"},
        {"tool": "http_fetch", "output": "first page"},
        {"tool": "http_fetch", "output": "second page"},
    ]
    assert _first_recon_body(log) == "first page"


def test_first_recon_body_accepts_form_submit():
    log = [{"tool": "form_submit", "output": "after login"}]
    assert _first_recon_body(log) == "after login"


def test_first_recon_body_skips_empty_outputs():
    log = [
        {"tool": "http_fetch", "output": "   "},
        {"tool": "http_fetch", "output": "real body"},
    ]
    assert _first_recon_body(log) == "real body"


def test_first_recon_body_none_when_no_http():
    log = [{"tool": "shell_execute", "output": "ls output"}]
    assert _first_recon_body(log) == ""


# ---------------------------------------------------------------------------
# Mechanism: deterministic via monkeypatched classifier
# ---------------------------------------------------------------------------


def _patch_classifier(monkeypatch, build_result, post_result):
    """Patch agent.classify_challenge to return controlled results.

    ``build_result`` is returned when ``response_content`` is None (build-time
    call); ``post_result`` is returned otherwise (post-HTTP call).
    """

    def fake(config, response_content=None, log_callback=None):
        return build_result if response_content is None else post_result

    monkeypatch.setattr(agent_module, "classify_challenge", fake)


def test_records_both_verdicts_and_overlay_when_confident(monkeypatch):
    build = ClassificationResult(ChallengeCategory.UNKNOWN, 0.0)
    post = ClassificationResult(ChallengeCategory.SQL_INJECTION, 0.9)
    _patch_classifier(monkeypatch, build, post)

    t = _tracker_with_recon(SQLI_BODY)
    run_classifier_http_diagnostic(_cfg(), t)

    assert t.build_time_category == "unknown"
    assert t.build_time_confidence == 0.0
    assert t.post_http_category == "sql_injection"
    assert t.post_http_confidence == 0.9
    # 0.9 >= MIN_OVERLAY_CONFIDENCE and category != UNKNOWN → overlay renders.
    assert t.would_have_applied_overlay is True
    assert t.post_http_overlay_text == build_category_overlay(post)
    assert t.post_http_overlay_text != ""


def test_overlay_suppressed_below_min_confidence(monkeypatch):
    build = ClassificationResult(ChallengeCategory.UNKNOWN, 0.0)
    # Non-UNKNOWN but under MIN_OVERLAY_CONFIDENCE (0.40).
    post = ClassificationResult(ChallengeCategory.SQL_INJECTION, 0.20)
    _patch_classifier(monkeypatch, build, post)

    t = _tracker_with_recon(SQLI_BODY)
    run_classifier_http_diagnostic(_cfg(), t)

    assert t.post_http_category == "sql_injection"
    assert t.post_http_confidence == 0.20
    assert t.would_have_applied_overlay is False
    assert t.post_http_overlay_text == ""


def test_overlay_suppressed_when_still_unknown(monkeypatch):
    # The decisive "overlay theory is dead" shape: page in hand, still UNKNOWN.
    build = ClassificationResult(ChallengeCategory.UNKNOWN, 0.0)
    post = ClassificationResult(ChallengeCategory.UNKNOWN, 0.0)
    _patch_classifier(monkeypatch, build, post)

    t = _tracker_with_recon(SUPER_QUICK_LOGIC_ERROR_BODY)
    run_classifier_http_diagnostic(_cfg(), t)

    assert t.post_http_category == "unknown"
    assert t.would_have_applied_overlay is False


def test_no_recon_body_leaves_post_http_default(monkeypatch):
    build = ClassificationResult(ChallengeCategory.AUTHENTICATION, 0.7)
    post = ClassificationResult(ChallengeCategory.SQL_INJECTION, 0.9)
    _patch_classifier(monkeypatch, build, post)

    t = RunTracker()  # empty tool_call_log → no recon body
    run_classifier_http_diagnostic(_cfg(), t)

    # Build-time still recorded; post-HTTP untouched (the post fake never fires).
    assert t.build_time_category == "authentication"
    assert t.build_time_confidence == 0.7
    assert t.post_http_category == ""
    assert t.post_http_confidence == 0.0
    assert t.would_have_applied_overlay is False


def test_exception_safe(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("classifier blew up")

    monkeypatch.setattr(agent_module, "classify_challenge", boom)

    t = _tracker_with_recon(SQLI_BODY)
    # Must not raise; fields stay at defaults.
    run_classifier_http_diagnostic(_cfg(), t)
    assert t.build_time_category == ""
    assert t.post_http_category == ""
    assert t.would_have_applied_overlay is False


def test_diagnostic_does_not_mutate_config(monkeypatch):
    build = ClassificationResult(ChallengeCategory.UNKNOWN, 0.0)
    post = ClassificationResult(ChallengeCategory.SSTI, 0.8)
    _patch_classifier(monkeypatch, build, post)

    cfg = _cfg()
    before = dict(cfg.__dict__)
    t = _tracker_with_recon("{{7*7}} template body")
    ret = run_classifier_http_diagnostic(cfg, t)

    assert ret is None  # log-only, returns nothing
    assert cfg.__dict__ == before  # zero behavior/config change


def test_body_truncated_to_cap(monkeypatch):
    seen = {}

    def fake(config, response_content=None, log_callback=None):
        if response_content is not None:
            seen["len"] = len(response_content)
        return ClassificationResult(ChallengeCategory.UNKNOWN, 0.0)

    monkeypatch.setattr(agent_module, "classify_challenge", fake)

    huge = "A" * 50_000
    t = _tracker_with_recon(huge)
    run_classifier_http_diagnostic(_cfg(), t)
    assert seen["len"] == runner_module._CLASSIFIER_DIAGNOSTIC_MAX_CHARS


# ---------------------------------------------------------------------------
# Real classifier on realistic fixtures (honest valid-range assertions only)
# ---------------------------------------------------------------------------


def _valid_category(value: str) -> bool:
    return value in {c.value for c in ChallengeCategory}


def test_real_classifier_runs_on_microdosing_login():
    t = _tracker_with_recon(MICRODOSING_LOGIN_BODY)
    run_classifier_http_diagnostic(_cfg(challenge_name="microdosing"), t)
    # The diagnostic ran end-to-end with the real classifier.
    assert _valid_category(t.post_http_category)
    assert 0.0 <= t.post_http_confidence <= 1.0
    # Consistency: the flag agrees with the gate, whatever the verdict was.
    expect_overlay = (
        t.post_http_category != "unknown" and t.post_http_confidence >= 0.40
    )
    assert t.would_have_applied_overlay is expect_overlay


def test_real_classifier_runs_on_super_quick_logic_error():
    t = _tracker_with_recon(SUPER_QUICK_LOGIC_ERROR_BODY)
    run_classifier_http_diagnostic(
        _cfg(challenge_name="super_quick_logic_invitational"), t
    )
    assert _valid_category(t.post_http_category)
    assert 0.0 <= t.post_http_confidence <= 1.0


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def test_to_dict_exposes_diagnostic_fields(monkeypatch):
    build = ClassificationResult(ChallengeCategory.UNKNOWN, 0.0)
    post = ClassificationResult(ChallengeCategory.JWT, 0.85)
    _patch_classifier(monkeypatch, build, post)

    t = _tracker_with_recon("eyJhbGciOiJIUzI1NiJ9 jwt token here")
    run_classifier_http_diagnostic(_cfg(), t)
    d = t.to_dict()
    for key in (
        "build_time_category",
        "build_time_confidence",
        "post_http_category",
        "post_http_confidence",
        "would_have_applied_overlay",
    ):
        assert key in d
    assert d["post_http_category"] == "jwt"
    assert d["would_have_applied_overlay"] is True
