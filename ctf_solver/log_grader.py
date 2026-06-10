"""Grade a runner log: did the run confirm a flag?

Single source of truth for the batch grader (``out/batch_window_test/
run_batch.sh``). The runner prints ``[FLAG DETECTED] <flag>`` for every
strict-regex-confirmed flag and ``[FLAG CANDIDATE] <flag>`` for broad-match
audit-only hits (see ``ctf_solver/runner.py`` — the strict/broad split feeds
``RunTracker.confirmed_flags_found``). Grading on the ``[FLAG DETECTED]``
marker therefore agrees with ``confirmed_flags_found`` *by construction*:
both derive from the same strict-regex pass inside the runner.

This replaces the old case-sensitive grep in ``run_batch.sh`` that matched
the pattern ``(metaCTF|MCTF|FLAG|flag)`` followed by ``{...}`` — it missed
``MetaCTF{`` (capital ``C``) and counted false positives like JS object
literals (``try{...}``).

Usage from the shell grader:
    flag_line=$(.venv/bin/python -m ctf_solver.log_grader "$log_file")
    flag_seen=$(printf '%s' "$flag_line" | cut -f1)
    flag=$(printf '%s' "$flag_line" | cut -f2)
"""

import re
from typing import Optional, Tuple

# Matches the runner's own confirmed-flag marker, anchored to line start.
# runner.py emits ``print(f"\\n[FLAG DETECTED] {flag}")`` so the marker always
# begins a line. re.MULTILINE lets ``^`` match at every line boundary.
_MARKER_RE = re.compile(r"^\[FLAG DETECTED\] (.+)$", re.MULTILINE)


def grade_log_text(text: str) -> Tuple[bool, Optional[str]]:
    """Return ``(flag_seen, flag)`` from a runner stdout/log string.

    ``flag_seen`` is True iff at least one ``[FLAG DETECTED]`` marker is
    present. ``flag`` is the first confirmed flag value (whitespace-stripped),
    or ``None`` when no marker is found. Only the ``[FLAG DETECTED]`` marker
    counts — ``[FLAG CANDIDATE]`` (broad-match, audit-only) is ignored, so the
    grader never credits a false-positive flag shape.
    """
    matches = _MARKER_RE.findall(text)
    if matches:
        return True, matches[0].strip()
    return False, None


def _main() -> int:
    import sys

    if len(sys.argv) >= 2:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()
    seen, flag = grade_log_text(text)
    # Tab-separated so the shell can `cut -f1`/`cut -f2`. Missing flag → "-".
    print(f"{'yes' if seen else 'no'}\t{flag if flag else '-'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
