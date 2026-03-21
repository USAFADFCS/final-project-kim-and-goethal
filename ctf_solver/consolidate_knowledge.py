"""
Knowledge consolidation for the CTF Solver experience database.

Merges multiple failure docs for the same vulnerability category into a single
high-signal semantic summary ("category wisdom" doc).  Run this script after
accumulating enough failure docs to reduce noise and surface common patterns.

This implements the "sleep-time compute" / memory-consolidation pattern from
the Letta (2024) and ExpeL (AAAI 2024) literature: episodic memories (specific
run records) are distilled into semantic memory (distilled patterns) offline,
without any live LLM call, keeping costs at zero.

Usage:
    python -m ctf_solver.consolidate_knowledge
    python -m ctf_solver.consolidate_knowledge --dir out/failure_knowledge --min-docs 5
"""

import argparse
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Doc parsing helpers
# ---------------------------------------------------------------------------


def _parse_category_from_doc(content: str) -> Optional[str]:
    """Extract the human-readable category label from a failure doc header."""
    match = re.search(r"\*\*Category:\*\*\s*(.+)", content)
    if not match:
        return None
    return match.group(1).strip()


def _extract_tools_from_doc(content: str) -> List[str]:
    """Extract tool names listed in the 'Tools Used' section."""
    return re.findall(r"`([a-z_]+)`:\s*\d+ call", content)


def _extract_suggestions_from_doc(content: str) -> List[str]:
    """Extract numbered suggestions from Section 7."""
    return [
        m.strip()
        for m in re.findall(r"^\d+\.\s+(.+)$", content, re.MULTILINE)
        if m.strip()
    ]


def _extract_errors_from_doc(content: str) -> List[str]:
    """Extract bullet-point errors from Section 5."""
    in_errors = False
    errors: List[str] = []
    for line in content.splitlines():
        if re.search(r"##\s*5\.", line):
            in_errors = True
            continue
        if in_errors and re.match(r"##\s*[6-9]", line):
            break
        if in_errors and line.startswith("- "):
            errors.append(line[2:].strip())
    return errors


def _extract_urls_from_doc(content: str) -> List[str]:
    """Extract challenge URLs embedded in a failure doc."""
    return re.findall(r"\*\*URL:\*\*\s*`([^`]+)`", content)


# ---------------------------------------------------------------------------
# Consolidated doc generation
# ---------------------------------------------------------------------------


def _category_slug(label: str) -> str:
    """Convert a human-readable category label to a filesystem-safe slug."""
    return (
        label.lower()
        .replace(" ", "_")
        .replace("(", "")
        .replace(")", "")
        .replace("/", "_")
        .replace("-", "_")
    )


def _generate_consolidated_doc(category_label: str, docs: List[str]) -> str:
    """
    Generate a consolidated wisdom document from *docs* failure docs.

    The output is a markdown document whose tags include ``consolidated`` and
    ``high-priority`` so that the RAG reranker can boost it appropriately.

    Args:
        category_label: Human-readable category name (e.g. "SQL Injection").
        docs: List of failure doc *contents* (markdown strings) for this category.

    Returns:
        Markdown string ready to be saved.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    slug = _category_slug(category_label)

    # Aggregate tool frequencies
    tool_counter: Counter = Counter()
    for doc in docs:
        for tool in _extract_tools_from_doc(doc):
            tool_counter[tool] += 1

    # Aggregate errors
    error_counter: Counter = Counter()
    for doc in docs:
        for err in _extract_errors_from_doc(doc):
            error_counter[err] += 1

    # Aggregate suggestions — deduplicate keeping the most common first
    suggestion_counter: Counter = Counter()
    for doc in docs:
        for s in _extract_suggestions_from_doc(doc):
            suggestion_counter[s] += 1

    # Keep suggestions appearing in >= 2 docs (common patterns) plus up to 3 unique ones
    common = [s for s, c in suggestion_counter.most_common() if c >= 2]
    unique = [s for s, c in suggestion_counter.most_common() if c == 1][:3]
    seen: set = set()
    deduplicated: List[str] = []
    for s in common + unique:
        if s not in seen:
            seen.add(s)
            deduplicated.append(s)

    # Aggregate unique URLs
    all_urls: set = set()
    for doc in docs:
        all_urls.update(_extract_urls_from_doc(doc))

    # Build the document
    lines = [
        f"# Consolidated Wisdom: {category_label}",
        "",
        f"> **Auto-generated:** {timestamp}",
        f"> **Category:** {category_label}",
        f"> **Type:** Consolidated failure wisdom ({len(docs)} docs merged)",
        "",
        "---",
        "",
        f"**Tags:** `consolidated, {slug}, wisdom, high-priority, lessons-learned`",
        "",
        "> **Agent Note:** This document summarises patterns extracted from multiple"
        " failed runs for this category.  Use it to skip approaches that consistently"
        " fail and to focus on what is most likely to succeed.",
        "",
        "## 1. Coverage",
        "",
        f"- **Source failure docs:** {len(docs)}",
        f"- **Unique challenge URLs:** {len(all_urls)}",
    ]

    if all_urls:
        lines.append("")
        lines.append("**URLs covered:**")
        for url in sorted(all_urls)[:10]:
            lines.append(f"- `{url}`")

    lines += [
        "",
        "## 2. Consistently Failing Tools",
        "",
        "**Tags:** `negative-knowledge, " + slug + ", tools-to-avoid`",
        "",
        "These tools appeared frequently across failed runs — they are unlikely to"
        " be the winning approach alone:",
        "",
    ]

    if tool_counter:
        for tool, count in tool_counter.most_common(10):
            pct = int(count / len(docs) * 100)
            lines.append(f"- `{tool}`: failed across {count}/{len(docs)} runs ({pct}%)")
    else:
        lines.append("- No consistent tool pattern detected across source docs")

    if error_counter:
        lines += [
            "",
            "## 3. Common Errors",
            "",
            f"**Tags:** `common-errors, {slug}, debugging`",
            "",
        ]
        for err, _ in error_counter.most_common(10):
            lines.append(f"- {err}")

    lines += [
        "",
        "## 4. Consolidated Suggestions",
        "",
        f"**Tags:** `consolidated-suggestions, {slug}, strategy`",
        "",
        "> **Agent Takeaway:** These suggestions appeared across multiple failed runs."
        " Prioritise them at the start of the next attempt.",
        "",
    ]

    if deduplicated:
        for i, suggestion in enumerate(deduplicated, 1):
            lines.append(f"{i}. {suggestion}")
    else:
        lines += [
            "- Try a fundamentally different attack vector",
            "- Consult additional knowledge-base entries for this category",
        ]

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def consolidate_failure_knowledge(
    failure_docs_dir: str = "out/failure_knowledge",
    min_docs_per_category: int = 5,
) -> List[str]:
    """
    Consolidate experience docs by category into semantic wisdom summaries.

    For each vulnerability category that has >= *min_docs_per_category* individual
    failure docs, generates a ``consolidated_<category>_<timestamp>.md`` file in the
    same directory.  Skips categories that already have a consolidated doc.

    Args:
        failure_docs_dir: Directory containing ``failure_*.md`` files.
        min_docs_per_category: Minimum individual docs before consolidation fires.

    Returns:
        List of file paths (strings) of newly generated consolidated docs.
    """
    docs_dir = Path(failure_docs_dir)
    if not docs_dir.exists():
        return []

    # Group failure docs by category
    category_docs: Dict[str, List[str]] = defaultdict(list)
    for doc_path in sorted(docs_dir.glob("failure_*.md")):
        try:
            content = doc_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        category = _parse_category_from_doc(content)
        if category:
            category_docs[category].append(content)

    generated: List[str] = []
    for category_label, docs in category_docs.items():
        if len(docs) < min_docs_per_category:
            continue

        slug = _category_slug(category_label)

        # Skip if a consolidated doc already exists for this category
        if list(docs_dir.glob(f"consolidated_{slug}*.md")):
            continue

        consolidated = _generate_consolidated_doc(category_label, docs)
        timestamp_slug = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        out_path = docs_dir / f"consolidated_{slug}_{timestamp_slug}.md"
        out_path.write_text(consolidated, encoding="utf-8")
        generated.append(str(out_path))
        print(
            f"[Consolidation] {category_label}: merged {len(docs)} failure docs → {out_path.name}"
        )

    return generated


# ---------------------------------------------------------------------------
# Lessons knowledge consolidation (atomic rules → category wisdom)
# ---------------------------------------------------------------------------


def _extract_outcome_from_lessons_doc(content: str) -> str:
    """Extract outcome (success/failure/partial) from a lessons_*.md doc."""
    m = re.search(r"\*\*Type:\*\*\s*experience_(\w+)", content)
    return m.group(1) if m else "unknown"


def _extract_takeaways_from_lessons_doc(content: str) -> List[str]:
    """Extract **Agent takeaway** lines from a lessons_*.md doc."""
    return [m.strip() for m in re.findall(r"\*\*Agent takeaway:\*\*\s*(.+)", content)]


def _extract_quick_path_from_lessons_doc(content: str) -> str:
    """Extract the Quick Exploitation Path section from a lessons_*.md doc."""
    m = re.search(r"## Quick Exploitation Path\n\n(.+?)(?:\n\n##|\Z)", content, re.DOTALL)
    return m.group(1).strip() if m else ""


def _extract_exploit_inputs_from_lessons_doc(content: str) -> List[str]:
    """Extract Key Exploit Input bullet lines from a lessons_*.md doc."""
    m = re.search(r"## Key Exploit Inputs\n\n.+?\n\n((?:- .+\n?)+)", content, re.DOTALL)
    if not m:
        return []
    return [line[2:].strip() for line in m.group(1).strip().splitlines() if line.startswith("- ")]


def _extract_failed_approaches_from_lessons_doc(content: str) -> List[str]:
    """Extract 'What Did NOT Work' bullets from a lessons_*.md doc."""
    m = re.search(
        r"## What Did NOT Work.*?\n\n.+?\n\n((?:- .+\n?)+)", content, re.DOTALL
    )
    if not m:
        return []
    return [line[2:].strip() for line in m.group(1).strip().splitlines() if line.startswith("- ")]


def _extract_template_engine_from_lessons_doc(content: str) -> str:
    """Extract **Template engine:** metadata from a lessons_*.md doc."""
    m = re.search(r"\*\*Template engine:\*\*\s*(.+)", content)
    return m.group(1).strip() if m else ""


def _generate_consolidated_lessons_doc(
    category_label: str,
    success_docs: List[str],
    failure_docs: List[str],
) -> str:
    """
    Generate a consolidated wisdom doc from multiple atomic lessons_ docs.

    Aggregates: winning tool sequences, exploit inputs, failed approaches,
    template engine info, and key takeaways. The result is tagged
    'consolidated, high-priority' so the RAG reranker boosts it appropriately.

    Implements ExpeL (Zhao 2024) sleep-time compute: episodic memories (specific
    atomic rules) are distilled into semantic wisdom (pattern summaries) without
    any LLM call.
    """
    slug = _category_slug(category_label)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    n_total = len(success_docs) + len(failure_docs)

    # Aggregate takeaways (from success docs first — positive knowledge)
    all_takeaways: Counter = Counter()
    for doc in success_docs + failure_docs:
        for t in _extract_takeaways_from_lessons_doc(doc):
            all_takeaways[t] += 1
    top_takeaways = [t for t, _ in all_takeaways.most_common(5)]

    # Aggregate exploit inputs
    all_exploit_inputs: List[str] = []
    seen_inputs: set = set()
    for doc in success_docs:
        for inp in _extract_exploit_inputs_from_lessons_doc(doc):
            if inp not in seen_inputs:
                all_exploit_inputs.append(inp)
                seen_inputs.add(inp)

    # Aggregate failed approaches (negative knowledge)
    failed_counter: Counter = Counter()
    for doc in failure_docs + success_docs:
        for fa in _extract_failed_approaches_from_lessons_doc(doc):
            failed_counter[fa] += 1
    top_failed = [fa for fa, _ in failed_counter.most_common(4)]

    # Best Quick Exploitation Path (from most recent success doc)
    best_path = ""
    for doc in success_docs:
        best_path = _extract_quick_path_from_lessons_doc(doc)
        if best_path:
            break

    # Template engine (if consistent across docs)
    engines: Counter = Counter()
    for doc in success_docs:
        eng = _extract_template_engine_from_lessons_doc(doc)
        if eng:
            engines[eng] += 1
    engine_note = f" ({engines.most_common(1)[0][0]})" if engines else ""

    lines = [
        f"# Consolidated Lessons: {category_label}{engine_note}",
        "",
        f"> **Auto-generated:** {timestamp}",
        f"> **Category:** {category_label}",
        f"> **Type:** consolidated_lessons ({n_total} docs — {len(success_docs)} success, {len(failure_docs)} failure)",
        f"> **Tags:** `consolidated, {slug}, lessons, high-priority, wisdom`",
        "",
        "> **Agent Note:** This consolidates patterns from multiple runs on this category.",
        "> Use the Quick Exploitation Path as your primary action guide.",
        "",
        "---",
        "",
        "## Coverage",
        "",
        f"- **Total atomic rule docs:** {n_total}",
        f"- **Success runs:** {len(success_docs)}",
        f"- **Failure/partial runs:** {len(failure_docs)}",
    ]

    if best_path:
        lines += ["", "## Best Exploitation Path (from most recent success)", "", best_path]

    if top_takeaways:
        lines += [
            "", "## Key Takeaways (ranked by frequency across runs)", "",
        ]
        for i, t in enumerate(top_takeaways, 1):
            lines.append(f"{i}. {t}")

    if all_exploit_inputs:
        lines += ["", "## Confirmed Winning Inputs", "",
                  "These exact requests produced the flag:", ""]
        for inp in all_exploit_inputs[:4]:
            lines.append(f"- {inp}")

    if top_failed:
        lines += ["", "## What Does NOT Work (Negative Knowledge)", "",
                  "Avoid these approaches — consistently failed:", ""]
        for fa in top_failed:
            lines.append(f"- {fa}")

    lines.append("")
    return "\n".join(lines)


def consolidate_lessons_knowledge(
    lessons_docs_dir: str = "out/lessons_knowledge",
    min_docs_per_category: int = 2,
) -> List[str]:
    """
    Consolidate atomic lessons_ docs by category into high-signal wisdom summaries.

    Fires when a category has >= min_docs_per_category lessons_ docs (default: 2).
    Much lower threshold than failure consolidation (5) because lessons docs are
    already distilled — 2 experiences from the same category is enough to identify
    a pattern.

    Generates ``consolidated_lessons_<category>_<timestamp>.md`` files in
    lessons_docs_dir. Existing consolidated docs are regenerated if there are new
    source docs since the last consolidation.

    Implements ExpeL (Zhao 2024) sleep-time compute pattern.

    Args:
        lessons_docs_dir: Directory containing ``lessons_*.md`` files.
        min_docs_per_category: Minimum docs per category to trigger consolidation.

    Returns:
        List of file paths of generated consolidated docs.
    """
    docs_dir = Path(lessons_docs_dir)
    if not docs_dir.exists():
        return []

    # Group lessons_ docs (not consolidated_ docs) by category
    category_success: Dict[str, List[str]] = defaultdict(list)
    category_failure: Dict[str, List[str]] = defaultdict(list)

    for doc_path in sorted(docs_dir.glob("lessons_*.md")):
        try:
            content = doc_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        category = _parse_category_from_doc(content)
        if not category:
            continue
        outcome = _extract_outcome_from_lessons_doc(content)
        if outcome == "success":
            category_success[category].append(content)
        else:
            category_failure[category].append(content)

    all_categories = set(category_success) | set(category_failure)
    generated: List[str] = []

    for category_label in all_categories:
        success_docs = category_success.get(category_label, [])
        failure_docs = category_failure.get(category_label, [])
        total = len(success_docs) + len(failure_docs)

        if total < min_docs_per_category:
            continue

        slug = _category_slug(category_label)

        # Regenerate if source docs are newer than the existing consolidated doc
        existing = sorted(docs_dir.glob(f"consolidated_lessons_{slug}*.md"))
        if existing:
            consolidated_mtime = existing[-1].stat().st_mtime
            source_mtimes = [
                doc_path.stat().st_mtime
                for doc_path in docs_dir.glob("lessons_*.md")
            ]
            if source_mtimes and max(source_mtimes) <= consolidated_mtime:
                continue  # No new source docs since last consolidation

        consolidated = _generate_consolidated_lessons_doc(
            category_label, success_docs, failure_docs
        )
        timestamp_slug = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        out_path = docs_dir / f"consolidated_lessons_{slug}_{timestamp_slug}.md"
        out_path.write_text(consolidated, encoding="utf-8")
        generated.append(str(out_path))
        print(
            f"[LessonsConsolidation] {category_label}: {total} docs → {out_path.name}"
        )

    return generated


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Consolidate CTF knowledge docs into category wisdom summaries."
    )
    parser.add_argument(
        "--dir",
        default="out/failure_knowledge",
        help="Directory containing failure_*.md files (default: out/failure_knowledge)",
    )
    parser.add_argument(
        "--lessons-dir",
        default="out/lessons_knowledge",
        help="Directory containing lessons_*.md files (default: out/lessons_knowledge)",
    )
    parser.add_argument(
        "--min-docs",
        type=int,
        default=5,
        help="Minimum failure docs per category to trigger consolidation (default: 5)",
    )
    parser.add_argument(
        "--min-lessons",
        type=int,
        default=2,
        help="Minimum lessons docs per category to trigger lessons consolidation (default: 2)",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    failure_paths = consolidate_failure_knowledge(
        failure_docs_dir=args.dir,
        min_docs_per_category=args.min_docs,
    )
    lessons_paths = consolidate_lessons_knowledge(
        lessons_docs_dir=args.lessons_dir,
        min_docs_per_category=args.min_lessons,
    )
    total = len(failure_paths) + len(lessons_paths)
    if total:
        print(f"\n[Consolidation] Generated {total} consolidated doc(s).")
    else:
        print(
            "[Consolidation] No categories met the threshold — nothing to consolidate."
        )


if __name__ == "__main__":
    main()
