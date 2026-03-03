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
# CLI entry point
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Consolidate CTF failure-knowledge docs into category wisdom summaries."
    )
    parser.add_argument(
        "--dir",
        default="out/failure_knowledge",
        help="Directory containing failure_*.md files (default: out/failure_knowledge)",
    )
    parser.add_argument(
        "--min-docs",
        type=int,
        default=5,
        help="Minimum docs per category to trigger consolidation (default: 5)",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    paths = consolidate_failure_knowledge(
        failure_docs_dir=args.dir,
        min_docs_per_category=args.min_docs,
    )
    if paths:
        print(f"\n[Consolidation] Generated {len(paths)} consolidated doc(s).")
    else:
        print(
            "[Consolidation] No categories met the threshold — nothing to consolidate."
        )


if __name__ == "__main__":
    main()
