"""Parse the May 3 A/B batches and emit a markdown table for the brief.

Columns:
  # | Challenge | Mode | Outcome | Steps | Time(s) | RAG queries | Reflexion |
  Unique tools | Tokens

Run order: batch1 (LESSONS_BUILDONLY) treasure_map → microdosing,
then batch2 (LESSONS_WRITE) same 13 challenges.
"""
from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
B1 = ROOT / "out" / "batch_20260503_005241"  # LESSONS_BUILDONLY
B2 = ROOT / "out" / "batch_20260503_012947"  # LESSONS_WRITE

TOOL_RE = re.compile(r"Tool call -> (\w+)")
RAG_QUERY_RE = re.compile(r"Tool call -> ctf_knowledge_query")
REFLEXION_RE = re.compile(r"\[Reflexion\] Prior lesson injected into prompt")

ORDER = [
    "treasure_map",
    "direct_login",
    "door_to_door",
    "open_application",
    "livestream",
    "dot_matrix_destruction",
    "super_quick_logic_invitational",
    "snowfall_wishes",
    "cracking_the_javashop",
    "admin_portal",
    "cookie_crackdown",
    "great_paywall",
    "microdosing",
]

DISPLAY_NAME = {
    "treasure_map": "Treasure Map",
    "direct_login": "Direct Login",
    "door_to_door": "Door to Door",
    "open_application": "Open Application",
    "livestream": "Livestream",
    "dot_matrix_destruction": "Dot-Matrix Destruction",
    "super_quick_logic_invitational": "Super Quick Logic",
    "snowfall_wishes": "Snowfall Wishes",
    "cracking_the_javashop": "Cracking the Javashop",
    "admin_portal": "Admin Portal",
    "cookie_crackdown": "Cookie Crackdown",
    "great_paywall": "Great Paywall",
    "microdosing": "Microdosing",
}


def load_tsv(batch_dir: Path) -> dict:
    tsv = batch_dir / "results.tsv"
    out = {}
    with tsv.open() as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            out[row["slug"]] = row
    return out


def parse_log(path: Path) -> dict:
    text = path.read_text(errors="replace")
    tool_calls = TOOL_RE.findall(text)
    rag_queries = len(RAG_QUERY_RE.findall(text))
    reflexion = bool(REFLEXION_RE.search(text))
    unique_tools = sorted(set(tool_calls))
    return {
        "rag_queries": rag_queries,
        "reflexion": reflexion,
        "unique_tools_count": len(unique_tools),
        "unique_tools_list": unique_tools,
        "total_tool_calls": len(tool_calls),
    }


def emoji_outcome(outcome: str) -> str:
    if outcome == "success":
        return "✅"
    if outcome == "partial":
        return "◐"
    if outcome == "failure":
        return "❌"
    return outcome


def main() -> None:
    b1_tsv = load_tsv(B1)
    b2_tsv = load_tsv(B2)

    rows = []
    run_idx = 0
    for batch_dir, batch_tsv, mode_label in [
        (B1, b1_tsv, "Curated only (BUILDONLY)"),
        (B2, b2_tsv, "Curated + Lessons (WRITE)"),
    ]:
        for slug in ORDER:
            run_idx += 1
            tsv = batch_tsv.get(slug, {})
            log_path = batch_dir / f"{slug}.log"
            log_info = parse_log(log_path) if log_path.exists() else {}
            rows.append(
                {
                    "n": run_idx,
                    "challenge": DISPLAY_NAME.get(slug, slug),
                    "mode": mode_label,
                    "lessons_db_used": "Yes" if "WRITE" in mode_label else "No",
                    "outcome": tsv.get("outcome", "?"),
                    "steps": tsv.get("steps", "?"),
                    "time_s": tsv.get("duration_seconds", "?"),
                    "rag_queries": log_info.get("rag_queries", "?"),
                    "reflexion": "Yes" if log_info.get("reflexion") else "No",
                    "unique_tools": log_info.get("unique_tools_count", "?"),
                    "tokens": "n/a",
                }
            )

    # Markdown
    print("| # | Challenge | Lessons DB | Outcome | Steps | Time (s) | "
          "RAG queries | Prior reflexion | Unique tools | Tokens |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        print(
            f"| {r['n']} | {r['challenge']} | {r['lessons_db_used']} | "
            f"{emoji_outcome(r['outcome'])} {r['outcome']} | {r['steps']} | "
            f"{r['time_s']} | {r['rag_queries']} | {r['reflexion']} | "
            f"{r['unique_tools']} | {r['tokens']} |"
        )

    # CSV
    csv_path = ROOT / "out" / "may3_run_table.csv"
    with csv_path.open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "n", "challenge", "mode", "lessons_db_used", "outcome",
                "steps", "time_s", "rag_queries", "reflexion",
                "unique_tools", "tokens",
            ],
        )
        w.writeheader()
        w.writerows(rows)
    sys.stderr.write(f"\nWrote {csv_path}\n")


if __name__ == "__main__":
    main()
