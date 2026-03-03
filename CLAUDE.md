# CTF Solver Agent — Project Rules

## Task Tracking

- The codebase is the source of truth for all incomplete work, tracked via `# TODO:` comments in the relevant `.py` files.
- TODOs must be explicit and scoped:
  ```python
  # TODO: implement retry logic with exponential backoff, max 3 attempts
  ```
  Not:
  ```python
  # TODO: fix this
  ```
- Before starting work, scan the codebase for existing `# TODO:` comments and review what's outstanding.
- After completing a TODO, remove it. After discovering missing or incomplete work, insert a new `# TODO:` in the exact place it belongs.
- Never save task lists, status reports, or plan summaries to `.md` files. That creates cognitive debt — stale docs that drift from the actual code. The code carries the truth.

## Context & Architecture

- At session start, scan `memory/` for all `.md` files and read any that are relevant to the current task.
- **What goes where:**
  - `CLAUDE.md` — workflow rules and project conventions (this file).
  - `memory/*.md` — durable context: architectural decisions, design rationale, capability inventories, and the "why" behind non-obvious choices. These are reference docs, not task trackers.
  - `# TODO:` in code — the "what": specific incomplete work, right where it belongs.
- If you make a significant architectural decision during work, save it to an appropriately named file in `memory/`. Keep these files focused and current — update or remove entries that become outdated.
- `memory/` docs should help maintain context across sessions for a large codebase. They are not a dumping ground for session-specific state or analysis output.

## Workflow

- Work in small, focused scopes — one TODO or a small logical group at a time. This aligns with how Claude performs best: clear intent, limited blast radius.
- Write tests first (TDD) when implementing new features. Tests live in `tests/` and use pytest.
- After implementation, run the available linters and type checker before moving on:
  ```bash
  ruff check ctf_solver/ tests/
  black --check ctf_solver/ tests/
  mypy ctf_solver/
  ```
- When context feels heavy, proactively scan and organize `# TODO:` comments rather than dumping state to markdown files.

## Dev Tools

- **Formatter:** black (line-length 88)
- **Linter:** ruff (rules: E, F, I — E501 ignored)
- **Type checker:** mypy (Python 3.11)
- **Tests:** `pytest tests/`
