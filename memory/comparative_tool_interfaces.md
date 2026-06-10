# Comparative: tool interfaces

How each project declares, documents, and registers tools, vs.
`ctf_solver/tools/`.  Populated during Phase 1.

## Dimensions to compare

1. **Declaration**: Python class? Function decorator? YAML?
2. **Input schema**: free string? JSON object with typed fields?
   OpenAI function-call schema?
3. **Output contract**: just a string? structured result with
   `success`/`partial`/`failure` markers?
4. **Documentation injection**: how tool docs reach the system prompt;
   is there a max length per tool?
5. **State across calls**: are tools stateless per-invocation, or can
   they hold persistent state (e.g. EnIGMA's debugger)?
6. **Demonstration trajectories**: does the framework support
   few-shot examples *attached to the tool definition*?

## Reference: `ctf_solver` baseline

- 55 Python classes under
  [`ctf_solver/tools/`](../ctf_solver/tools/), all FAIR-pattern:
  `name`, `description`, `.use(tool_input: str) -> str`
- JSON parsing inside each tool via
  [`tools/core.py::parse_json_input`](../ctf_solver/tools/core.py)
- All tools wrapped by `LoggingToolWrapper` for stuck detection +
  flag extraction
- System-prompt tool documentation lives in
  [`prompts/templates.py`](../ctf_solver/prompts/templates.py) — manually
  curated, not auto-generated from tool classes
- Tools are stateless per `.use()` call (no debugger-style state)

## Findings (fill in during Phase 1)

### EnIGMA — done 2026-05-16

**Tools are *not* Python classes** — they are arbitrary shell or
python scripts under
[`SWE-agent-v0.7/config/commands/`](../agentic_systems_for_analysis/SWE-agent-v0.7/config/commands/),
self-describing via a YAML comment block embedded directly in the
script:

```python
# @yaml
# signature: decompile <binary_path> [--function_name <function_name>]
# docstring: Decompile a binary and prints the decompilation of a given function name
# arguments:
#   binary_path:
#       type: file path
#       description: The path to the binary to be decompiled
#       required: true
#   function_name:
#       type: string
#       description: The function name to be decompiled, or main by default
#       required: false

import argparse
# ... actual implementation ...
```

- **One file can declare multiple tools** — e.g.
  [`server_connection.sh`](../agentic_systems_for_analysis/SWE-agent-v0.7/config/commands/server_connection.sh)
  ships four (`connect_start`, `connect_sendline`, `connect_exec`,
  `connect_stop`) each with its own `# @yaml` block.
- **`ParseCommandDetailed`**
  ([sweagent/agent/commands.py:207](../agentic_systems_for_analysis/SWE-agent-v0.7/sweagent/agent/commands.py))
  parses these blocks at agent-build time and renders them into the
  `{command_docs}` placeholder of the system prompt template.
- **Execution = stdout-as-observation, period.** Bash invokes the
  script, stdout becomes the observation.  No JSON parsing, no
  retries, no structured success/failure markers.  The contract is
  *purely* `stdout` text.

**Composing a CTF run:** a YAML file (e.g.
[`config/ctf/ctf_web.yaml`](../agentic_systems_for_analysis/SWE-agent-v0.7/config/ctf/ctf_web.yaml))
just lists which command files to include under `command_files:`.
Toggling a tool *off* = removing one line.  This is what the
`ctf_web_no_interactive.yaml` ablation does: it deletes
`debug.sh`, `_connect.py`, and `server_connection.sh` from the
`command_files:` list.

**Demonstration trajectories** are real recorded solve runs, stored as
JSON files (e.g.
[`trajectories/demonstrations/ctf/web/i_got_id_demo.traj`](../agentic_systems_for_analysis/SWE-agent-v0.7/trajectories/demonstrations/ctf/web/i_got_id_demo.traj),
421 lines, CSAW-2016 Perl-CGI command injection).  Schema per step:
`{action, observation, response, state, thought}`.  YAML wires them
in via:
```yaml
demonstration_template: |
  Here is a demonstration of how to correctly accomplish this task.
  --- DEMONSTRATION ---
  {demonstration}
  --- END OF DEMONSTRATION ---
demonstrations:
- trajectories/demonstrations/ctf/web/i_got_id_demo.traj
```
This is one of EnIGMA's headline contributions.  No equivalent in
`ctf_solver` — our atomic-rule lessons capture *causal rules*, not
*verbatim trajectories*.

### EnIGMA — Interactive Agent Tools (IATs)

Only two ship in v0.7: `gdb` (debugger) and `connect` (netcat-style
server connection).  Configured in
[`sweagent/agent/interactive_commands.py`](../agentic_systems_for_analysis/SWE-agent-v0.7/sweagent/agent/interactive_commands.py)
— a 42-line module declaring:
```python
INTERACTIVE_SESSIONS_CONFIG = {
    "gdb": InteractiveSessionConfig(
        cmdline="gdb",
        terminal_prompt_pattern="(gdb) ",
        start_command="debug_start",
        exit_command="debug_stop",
        quit_commands_in_session=["quit"],
    ),
    "connect": InteractiveSessionConfig(
        cmdline="/root/commands/_connect",
        terminal_prompt_pattern="(nc) ",
        start_command="connect_start",
        exit_command="connect_stop",
        quit_commands_in_session=["quit"],
    ),
}
```

**Protocol:** an IAT bash function emits a sentinel marker the
runtime intercepts:
```bash
echo "<<INTERACTIVE||SESSION=connect||INTERACTIVE>>"
echo "<<INTERACTIVE||sendline foo||INTERACTIVE>>"
```
When the runtime sees `<<INTERACTIVE||...||INTERACTIVE>>` it routes
the inner command into the persistent `subprocess.Popen` for that
session instead of starting a new subprocess.  The session stays
alive between agent turns.  The agent gets `interactive_session: ...`
in its prompt state so it knows a session is open.

Notably **CTF-web doesn't really need IATs**.  They're for binary
exploitation (gdb) and raw socket exploits (connect).  Web work is
HTTP-stateful via cookies/headers, which our agent already handles
via the shared `requests.Session`.

### D-CIPHER tool wiring
*(Phase 1.3)*

### Cybench's tool set
Sanity check — confirmed not novel: Cybench's `SimpleAgent` is the
LM driving raw `bash -c`, no tool library at all (see
[cybench_protocol.md](cybench_protocol.md)).

## Verdict

**PORT THE `# @yaml` SELF-DESCRIBING TOOL PATTERN.**  Our 55 Python
FAIR tools currently duplicate their description in
[`ctf_solver/prompts/templates.py`](../ctf_solver/prompts/templates.py)
(45.6 KB of hand-curated tool docs).  Adopting EnIGMA's
`# @yaml`-block convention plus a parser that auto-generates the
`{command_docs}` injection eliminates that duplication and makes
adding a new tool a one-place change.  We keep the Python class +
`.use(json_str) -> str` runtime contract — only the documentation
mechanism changes.

**DO NOT PORT THE TOOL EXECUTION MODEL** (shell scripts called by
bash with stdout-as-observation).  Our typed JSON tool inputs and
structured `[ToolName] result=...` headers add genuine signal that
their stdout-only protocol can't represent.

**DEFER IATs.**  Useful pattern but the two ship-with-v0.7 sessions
(`gdb`, `connect`) are not relevant to CTF-web.  Revisit if/when we
expand into pwn or crypto challenges.

**DEFER VERBATIM-TRAJECTORY DEMONSTRATIONS.**  Promising as a
*supplement* to our atomic-rule RAG (different abstraction level:
verbatim run vs. distilled causal rule).  Worth a memo if/when
trajectory replay outperforms the lessons-learned DB on the Cybench
web subset.  Not for the Phase 3 pilot.

## Phase 3 pilot scope

**Goal:** auto-generate the `{command_docs}` section of our system
prompt from per-tool `# @yaml` blocks, replacing the hand-curated
tool docstrings in
[`prompts/templates.py`](../ctf_solver/prompts/templates.py).

**Minimal slice:**
1. Pick 3 tools spanning input complexity:
   [`http_tools.py`](../ctf_solver/tools/http_tools.py) (everyday),
   [`sqli_tools.py`](../ctf_solver/tools/sqli_tools.py) (high
   combinatorics),
   [`ssti_tools.py`](../ctf_solver/tools/ssti_tools.py) (16-engine
   payload table).
2. Add `# @yaml` block to the class docstring or as a module-level
   comment, matching EnIGMA's `signature: / docstring: / arguments:`
   schema.
3. Write a parser (small — maybe 60 LOC) that scans tool modules at
   agent-build time and renders Markdown tool docs.
4. Swap the hand-curated block in `prompts/templates.py` for a
   `{command_docs}` placeholder filled in by the parser.

Reassess scope after the slice: if the pattern feels natural and
the auto-generated docs are usable, roll out across all 55 tools.
