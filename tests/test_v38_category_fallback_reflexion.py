"""
v3.8 P2: category-fallback Reflexion injection.

When ``find_and_compress_prior_lesson`` finds no per-challenge match,
it should classify the new challenge from name/URL/description and
return a Reflexion summary built from same-category prior runs.
"""

from pathlib import Path

from ctf_solver.failure_analyzer import find_and_compress_prior_lesson


def _write_lesson(
    docs_dir: Path,
    *,
    name_slug: str,
    category_label: str,
    outcome: str,
    what_happened: str,
) -> Path:
    """Write a minimal lesson doc that the function's regexes will pick up."""
    docs_dir.mkdir(parents=True, exist_ok=True)
    body = (
        f"# {category_label}: example\n\n"
        f"**Type:** experience_{outcome}\n"
        f"**Category:** {category_label}\n"
        f"**Challenge:** {name_slug}\n"
        f"\n"
        f"## What Happened\n\n"
        f"{what_happened}\n\n"
        f"## Key Exploit Inputs\n\n"
        f"Notable inputs:\n\n- payload=foo\n"
    )
    path = docs_dir / f"lessons_001_{name_slug}.md"
    path.write_text(body, encoding="utf-8")
    return path


class TestNoOpWhenNoSignal:
    def test_returns_none_with_no_inputs(self, tmp_path):
        out = find_and_compress_prior_lesson(
            challenge_name=None,
            challenge_url=None,
            lessons_docs_dir=str(tmp_path / "lessons"),
            fallback_failure_docs_dir=str(tmp_path / "failures"),
        )
        assert out is None

    def test_returns_none_when_classifier_unknown(self, tmp_path):
        # Name + URL with no recognizable pattern → classifier UNKNOWN.
        out = find_and_compress_prior_lesson(
            challenge_name="cardamom",
            challenge_url="http://example.com/zzz",
            lessons_docs_dir=str(tmp_path / "lessons"),
            fallback_failure_docs_dir=str(tmp_path / "failures"),
        )
        assert out is None


class TestPerChallengeWinsWhenAvailable:
    def test_per_challenge_match_skips_category_fallback(self, tmp_path):
        lessons_dir = tmp_path / "lessons"
        # Per-challenge doc for the requested challenge name.
        _write_lesson(
            lessons_dir,
            name_slug="login_bypass_demo",
            category_label="SQL Injection",
            outcome="success",
            what_happened="Used UNION-based payload to dump users table.",
        )
        # Another doc in the same category, different challenge — fallback would
        # use this only if per-challenge match doesn't fire.
        _write_lesson(
            lessons_dir,
            name_slug="another_sqli",
            category_label="SQL Injection",
            outcome="failure",
            what_happened="Different attack chain, failed.",
        )
        out = find_and_compress_prior_lesson(
            challenge_name="login_bypass_demo",
            challenge_url=None,
            lessons_docs_dir=str(lessons_dir),
            fallback_failure_docs_dir=str(tmp_path / "failures"),
        )
        assert out is not None
        assert "Prior runs on 'login_bypass_demo'" in out
        # The "category fallback" header should NOT appear when per-challenge wins.
        assert "falling back to" not in out


class TestCategoryFallbackFires:
    def test_fires_when_no_per_challenge_match(self, tmp_path):
        lessons_dir = tmp_path / "lessons"
        # No doc matches the new challenge name. But there's a SQL Injection
        # success in the lessons dir.
        _write_lesson(
            lessons_dir,
            name_slug="prior_sqli_lab",
            category_label="SQL Injection",
            outcome="success",
            what_happened="Boolean-blind extracted admin password.",
        )
        out = find_and_compress_prior_lesson(
            challenge_name="brand_new_sqli_target",
            challenge_url="http://example.com/login?id=1",
            challenge_description="Login form with SQL injection on the id parameter.",
            lessons_docs_dir=str(lessons_dir),
            fallback_failure_docs_dir=str(tmp_path / "failures"),
        )
        assert out is not None
        assert "falling back to category lessons" in out
        assert "SQL Injection" in out
        assert "Boolean-blind extracted" in out

    def test_includes_failure_when_present(self, tmp_path):
        lessons_dir = tmp_path / "lessons"
        _write_lesson(
            lessons_dir,
            name_slug="ssti_a",
            category_label="Server-Side Template Injection",
            outcome="success",
            what_happened="{{7*7}} returned 49 — confirmed Jinja2; reached config['SECRET'].",
        )
        _write_lesson(
            lessons_dir,
            name_slug="ssti_b",
            category_label="Server-Side Template Injection",
            outcome="failure",
            what_happened="Tried Twig payloads on Jinja2 target — wrong syntax.",
        )
        out = find_and_compress_prior_lesson(
            challenge_name="ssti_target",
            challenge_url=None,
            challenge_description="Server-side template injection challenge.",
            lessons_docs_dir=str(lessons_dir),
            fallback_failure_docs_dir=str(tmp_path / "failures"),
        )
        assert out is not None
        assert "✓ A success" in out
        assert "✗ A failure" in out
        assert "{{7*7}}" in out

    def test_no_match_in_category_returns_none(self, tmp_path):
        lessons_dir = tmp_path / "lessons"
        # A lesson exists, but for a different category.
        _write_lesson(
            lessons_dir,
            name_slug="some_xss",
            category_label="Cross-Site Scripting (XSS)",
            outcome="success",
            what_happened="Stored XSS via comment field.",
        )
        # The new challenge classifies as something else (XXE) → no match.
        out = find_and_compress_prior_lesson(
            challenge_name="new_xxe",
            challenge_url=None,
            challenge_description="XML external entity attack with DOCTYPE injection.",
            lessons_docs_dir=str(lessons_dir),
            fallback_failure_docs_dir=str(tmp_path / "failures"),
        )
        # XXE has no lessons here → fallback returns None (legacy failure_*.md
        # path also empty).
        assert out is None
