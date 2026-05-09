"""
Batch-run support for the CTF Solver.

Lets a user queue up a list of challenges and execute them one-by-one,
sharing the knowledge-base state (so lessons written by challenge N are
available to challenge N+1). Pure-Python helpers here; the Streamlit UI
plumbs these into its per-run loop.

Storage format (TSV):

    name<TAB>url<TAB>description<TAB>hints

The legacy ``slug<TAB>name<TAB>url<TAB>description`` format written to
``out/batch_20260417/challenges.tsv`` is also accepted — the slug column
is ignored since we derive slugs from ``name`` at run time.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union

PathLike = Union[str, Path]

_TSV_HEADER_CURRENT = ("name", "url", "description", "hints")
_TSV_HEADER_LEGACY = ("slug", "name", "url", "description")


@dataclass
class BatchItem:
    """A single challenge queued up in a batch."""

    name: str
    url: str = ""
    description: str = ""
    hints: str = ""

    @property
    def slug(self) -> str:
        """Filesystem-safe slug derived from ``name``.

        ``"Great Paywall"`` → ``"great_paywall"``. Falls back to
        ``"unnamed"`` when the name is blank or collapses to empty.
        """
        # TODO: disambiguate slug collisions at the caller (``run_batch``)
        # by appending ``_2``/``_3`` when two items in the same batch
        # produce the same slug — otherwise per-item log files overwrite
        # each other silently. Keep this dataclass property pure.
        slug = re.sub(r"[^a-zA-Z0-9]+", "_", (self.name or "").strip().lower())
        slug = slug.strip("_")
        return slug or "unnamed"


@dataclass
class BatchResult:
    """Outcome of running a single ``BatchItem`` through the agent."""

    item: BatchItem
    outcome: str  # "success" | "partial" | "failure" | "error"
    flag: Optional[str] = None
    steps: int = 0
    duration_seconds: float = 0.0
    error: Optional[str] = None
    stats: Optional[Dict] = None
    log_path: Optional[str] = None

    @property
    def outcome_emoji(self) -> str:
        return {
            "success": "✅",
            "partial": "⚠️",
            "failure": "❌",
            "error": "💥",
        }.get(self.outcome, "❓")


def load_batch_tsv(path: PathLike) -> List[BatchItem]:
    """Load a list of ``BatchItem`` from a TSV at ``path``.

    Accepts the current 4-column format (``name, url, description, hints``)
    and the legacy 4-column format (``slug, name, url, description``) —
    the legacy slug column is dropped and we re-derive slugs from name.

    Raises ``ValueError`` if the header can't be matched.
    """
    p = Path(path)
    with p.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh, delimiter="\t")
        rows = [r for r in reader if any(c.strip() for c in r)]

    if not rows:
        return []

    header = tuple(c.strip().lower() for c in rows[0])
    body = rows[1:]

    items: List[BatchItem] = []
    if header[: len(_TSV_HEADER_CURRENT)] == _TSV_HEADER_CURRENT:
        for row in body:
            row = row + [""] * (4 - len(row))  # pad short rows
            items.append(
                BatchItem(
                    name=row[0].strip(),
                    url=row[1].strip(),
                    description=row[2].strip(),
                    hints=row[3].strip(),
                )
            )
    elif header[: len(_TSV_HEADER_LEGACY)] == _TSV_HEADER_LEGACY:
        # Legacy: slug, name, url, description. No hints column — default "".
        for row in body:
            row = row + [""] * (4 - len(row))
            items.append(
                BatchItem(
                    name=row[1].strip(),
                    url=row[2].strip(),
                    description=row[3].strip(),
                    hints="",
                )
            )
    else:
        raise ValueError(
            f"Unrecognized TSV header {header!r}. Expected "
            f"{_TSV_HEADER_CURRENT!r} or legacy {_TSV_HEADER_LEGACY!r}."
        )

    return items


def save_batch_tsv(items: List[BatchItem], path: PathLike) -> None:
    """Write ``items`` to a TSV with the current 4-column header."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, delimiter="\t")
        writer.writerow(_TSV_HEADER_CURRENT)
        for it in items:
            writer.writerow([it.name, it.url, it.description, it.hints])


def items_to_tsv_text(items: List[BatchItem]) -> str:
    """Serialize ``items`` to a TSV string — for download buttons."""
    from io import StringIO

    buf = StringIO()
    writer = csv.writer(buf, delimiter="\t")
    writer.writerow(_TSV_HEADER_CURRENT)
    for it in items:
        writer.writerow([it.name, it.url, it.description, it.hints])
    return buf.getvalue()


def items_to_rows(items: List[BatchItem]) -> List[Dict[str, str]]:
    """Convert items to a list of dicts suitable for ``st.data_editor``."""
    return [
        {
            "name": it.name,
            "url": it.url,
            "description": it.description,
            "hints": it.hints,
        }
        for it in items
    ]


def rows_to_items(rows: List[Dict[str, str]]) -> List[BatchItem]:
    """Inverse of ``items_to_rows``. Skips rows where every field is blank
    — ``st.data_editor`` leaves trailing empty rows when the user adds a
    blank row but doesn't fill it in."""
    items: List[BatchItem] = []
    for row in rows:
        name = str(row.get("name", "") or "").strip()
        url = str(row.get("url", "") or "").strip()
        description = str(row.get("description", "") or "").strip()
        hints = str(row.get("hints", "") or "").strip()
        if not (name or url or description or hints):
            continue
        items.append(
            BatchItem(name=name, url=url, description=description, hints=hints)
        )
    return items


def ensure_batch_output_dir(base_out_dir: PathLike = "out") -> Path:
    """Create and return ``<base_out_dir>/batch_<timestamp>/``."""
    # TODO: add sub-second granularity (e.g. ``%Y%m%d_%H%M%S_%f``) if two
    # batches ever launch within the same second and collide on dir name.
    # Low priority for single-user workflow; becomes relevant if the UI
    # ever supports concurrent batches.
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    p = Path(base_out_dir) / f"batch_{stamp}"
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_batch_summary(results: List[BatchResult], summary_path: PathLike) -> None:
    """Write a per-challenge summary TSV at ``summary_path``.

    Phase B3: appends Phase B token columns (``prompt_tokens``,
    ``completion_tokens``, ``cached_tokens``, ``est_cost_usd``) when the
    per-item ``stats`` dict carries them — populated by Phase B2's
    ``set_token_usage_from_adapter`` call. Items without those fields
    (e.g. local Ollama runs) emit zeroes.
    """
    p = Path(summary_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, delimiter="\t")
        w.writerow(
            [
                "slug",
                "name",
                "url",
                "outcome",
                "flag",
                "steps",
                "duration_seconds",
                "prompt_tokens",
                "completion_tokens",
                "cached_tokens",
                "est_cost_usd",
                "error",
                "log_path",
            ]
        )
        for r in results:
            stats = r.stats or {}
            w.writerow(
                [
                    r.item.slug,
                    r.item.name,
                    r.item.url,
                    r.outcome,
                    r.flag or "",
                    r.steps,
                    f"{r.duration_seconds:.1f}",
                    int(stats.get("actual_prompt_tokens", 0) or 0),
                    int(stats.get("actual_completion_tokens", 0) or 0),
                    int(stats.get("cached_prompt_tokens", 0) or 0),
                    f"{float(stats.get('est_cost_usd', 0.0) or 0.0):.6f}",
                    (r.error or "").replace("\t", " ").replace("\n", " "),
                    r.log_path or "",
                ]
            )


__all__ = [
    "BatchItem",
    "BatchResult",
    "load_batch_tsv",
    "save_batch_tsv",
    "items_to_tsv_text",
    "items_to_rows",
    "rows_to_items",
    "ensure_batch_output_dir",
    "write_batch_summary",
]
