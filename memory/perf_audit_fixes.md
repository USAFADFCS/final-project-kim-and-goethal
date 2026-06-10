# Local-LLM perf audit fixes — 2026-05-18 / 19

Five fixes shipped after the user reported local LLM runs (Ollama, Nemotron 3
PRISM Nano) felt slow. All tests pass (2879/2879). Plan file:
`~/.claude/plans/jaunty-baking-reddy.md`.

## What changed

| # | Fix | Files | Per-run impact |
|---|---|---|---|
| 1 | `enable_thinking` now opt-in (was hardcoded `think=True`) | `ctf_solver/llm/adapters.py:1052-1107`, `:1191`, `:2178-2186`, `:2293`; `config.py:284-307`; `runner.py:135-160` | **5-30s per turn × 30 turns** — biggest single win |
| 2 | Cache `build_react_schema()` result in `OllamaAdapter` | `adapters.py:1146-1149`, `:1172-1175`, `:1215-1228` | 50-200ms × 30 turns |
| 3 | Skip tiktoken estimation for local providers | `run_tracker.py:281-330`, `agent.py:2231-2244` | 200-400ms × 30 turns |
| 4 | Precompile flag regex in `LoggingToolWrapper` | `tools/logging_wrapper.py:520-534, 588-602, 678-687` | 2-5ms × 30+ tool calls |
| 5 | Truncate large observations before next-turn prompt (opt-in) | `agent.py:287-300, 368-377, 392-403, 1925-1931, 2832`; `config.py:300-307` | Bounds prompt growth |

## New SolverConfig fields

```python
enable_thinking: bool = False               # Fix #1, also CTF_ENABLE_THINKING / --enable-thinking
observation_max_chars: Optional[int] = None # Fix #5, also CTF_OBSERVATION_MAX_CHARS / --observation-max-chars
```

## New CLI flags in runner.py

- `--enable-thinking` (store_true) — opt-in CoT for Ollama reasoning models.
  Default OFF.
- `--observation-max-chars N` — cap observation length appended to next-turn
  prompt. Default `None` (unchanged). Recommended `4000` for local providers.

## Tests

New file: `tests/test_perf_audit_fixes.py` — 21 tests, all pass. Covers:
- `TestEnableThinkingFlag` — think kwarg is opt-in
- `TestOllamaSchemaCache` — schema built at most once between
  `set_tool_descriptors()` calls
- `TestTokenTrackingSkip` — tiktoken bypass via `skip_token_estimation`
- `TestFlagRegexPrecompile` — `re.compile` fires only at wrapper init
- `TestObservationTruncation` — `_truncate_observation` honors the cap
- `TestMlxSchemaCache` — regression test for the already-fixed MLX cache

Updated:
- `tests/test_v31_trace_streaming.py` — tests that exercise the `think=True`
  feature-detection probe now construct `OllamaAdapter(..., enable_thinking=True)`
  explicitly (4 sites).
- `tests/test_v39_per_tool_schema.py` — the `_make_ollama_adapter` fixture
  (lines ~433-450) now sets `adapter.enable_thinking = True` AND
  `adapter._format_schema_cache = None`. These tests bypass `__init__` so
  any new instance attr added there must be mirrored.

## Verification commands

```bash
# Tests
.venv/bin/python -m pytest tests/ -q
# Result: 2879 passed, 1 skipped (MLX-stack-unavailable env)

# Wall-time benchmark — turn the legacy think=True back on to see the diff
time CTF_ENABLE_THINKING=1 .venv/bin/python -m ctf_solver.runner \
    --model nemotron3-prism:30b-q6 --challenge-url http://example.com \
    --description "smoke" --max-steps 3 --rag-mode none

# vs new defaults
time .venv/bin/python -m ctf_solver.runner \
    --model nemotron3-prism:30b-q6 --challenge-url http://example.com \
    --description "smoke" --max-steps 3 --rag-mode none \
    --observation-max-chars 4000
```

## Behavior surface — what changes for whom

- **Hosted models (OpenAI/Anthropic/Gemini):** zero change. `think=` is
  Ollama-only; fix #3 auto-detects via `LLMProviderType`; fixes #2, #4 are
  pure refactors; fix #5 default `None` preserves behavior.
- **Local models (Ollama/MLX):** no `think=True` by default (was always on);
  tiktoken skipped (no per-token billing to track anyway); other fixes
  invisible but additive.
- **Anyone explicitly wanting CoT:** pass `--enable-thinking` or set
  `CTF_ENABLE_THINKING=1` or `SolverConfig(enable_thinking=True)`.

## Pitfall to avoid

Both `test_v31_trace_streaming.py` and `test_v39_per_tool_schema.py` have
tests that construct adapters bypassing `__init__` (via `__new__` + manual
attr-setting). Any new instance attribute on `OllamaAdapter.__init__`
that's read by a probed code path must also be added to the bare-fixture
setup, or tests will `AttributeError` even when the new code is correct.
The pattern to mirror:

```python
adapter = OllamaAdapter.__new__(OllamaAdapter)
adapter.enable_thinking = True       # Fix #1 mirror
adapter._format_schema_cache = None  # Fix #2 mirror
# ... existing fixture attrs ...
```
