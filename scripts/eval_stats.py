#!/usr/bin/env python3
"""CLI: paired A/B statistics over an eval_results.jsonl.

Thin wrapper over ``ctf_solver.eval.stats`` (where the McNemar / Wilcoxon
logic lives and is unit-tested). Pairs runs by (challenge, run_idx) across two
``config_label`` arms.

Usage:
    python scripts/eval_stats.py out/eval/eval_results.jsonl \\
        --baseline baseline --treatment treatment --metric steps
    python scripts/eval_stats.py results.jsonl -b A -t B --json
"""

import argparse
import json
import sys
from pathlib import Path

# Allow running as a bare script (scripts/ isn't a package).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf_solver.eval.stats import (  # noqa: E402
    CONTINUOUS_METRICS,
    analyze,
    format_report,
    load_records,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", help="path to eval_results.jsonl")
    parser.add_argument("-b", "--baseline", required=True, help="baseline config_label")
    parser.add_argument(
        "-t", "--treatment", required=True, help="treatment config_label"
    )
    parser.add_argument(
        "-m",
        "--metric",
        default="steps",
        choices=CONTINUOUS_METRICS,
        help="continuous metric for the Wilcoxon test (default: steps)",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit the report as JSON, not text"
    )
    args = parser.parse_args(argv)

    records = load_records(args.results)
    report = analyze(records, args.baseline, args.treatment, args.metric)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
