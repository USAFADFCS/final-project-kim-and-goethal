# CTF Solver - Platform-Agnostic Agentic CTF Solving Framework

A modular, extensible CTF (Capture The Flag) solving agent built on the FAIR agentic framework. This tool uses AI-powered reasoning with RAG (Retrieval-Augmented Generation) to solve web exploitation challenges from any CTF platform.

## Features

- **Platform Agnostic**: Works with PicoCTF, HackTheBox, TryHackMe, and any other CTF platform
- **Configurable Flag Patterns**: Supports custom regex patterns or common presets
- **RAG-Enhanced**: Consults a knowledge base of web exploitation techniques
- **Multiple Interfaces**: CLI, Interactive mode, and Streamlit GUI
- **Extensible Tools**: HTTP fetching, HTML/JS inspection, cookie manipulation, SQL pattern detection, and more
- **ReAct Planning**: Uses Reason-Act loop for step-by-step problem solving

## Quick Start

### Prerequisites

```bash
# Install dependencies (in addition to existing requirements.txt)
pip install streamlit
```

### 1. CLI Mode

```bash
# Basic usage
python ctf_agentic_solver.py --challenge-url https://example.com/challenge \
    --description "Find the hidden flag in this web challenge"

# With PicoCTF preset
python ctf_agentic_solver.py --challenge-url https://saturn.picoctf.net:12345 \
    --platform-name PicoCTF --flag-preset picoctf

# With custom flag pattern
python ctf_agentic_solver.py --challenge-url https://app.hackthebox.com/... \
    --flag-regex "HTB\{[^}]+\}"

# With hints and custom knowledge base
python ctf_agentic_solver.py --challenge-url https://challenge.ctf.com \
    --hints "Check robots.txt" \
    --docs-dir ./my_notes \
    --kb-file ./Book-3-Web-Exploitation.pdf
```

### 2. Interactive Mode

```bash
# Run without arguments for interactive prompts
python ctf_agentic_solver.py
```

### 3. Streamlit GUI

```bash
streamlit run ctf_solver/ui/streamlit_app.py
```

### 4. As a Python Module

```bash
python -m ctf_solver --challenge-url https://example.com/challenge
```

## CLI Options

| Option | Description |
|--------|-------------|
| `--challenge-url` | URL of the CTF challenge to solve |
| `--description` | Description of the challenge |
| `--hints` | Hints provided for the challenge |
| `--platform-name` | Name of the CTF platform (default: "Generic CTF") |
| `--flag-regex` | Custom regex pattern for flag detection |
| `--flag-preset` | Use a preset pattern: picoctf, htb, thm, flag, ctf, generic |
| `--agent-prompt` | Custom system prompt for the agent |
| `--max-steps` | Maximum reasoning steps (default: 20) |
| `--docs-dir` | Directory with knowledge base docs (repeatable) |
| `--kb-file` | Specific file for knowledge base (repeatable) |
| `--verbose` | Enable verbose logging |

## Flag Pattern Presets

| Preset | Pattern | Example |
|--------|---------|---------|
| `picoctf` | `picoCTF\{[^\n\r{}]{1,200}\}` | `picoCTF{example_flag}` |
| `htb` | `HTB\{[^\n\r{}]{1,200}\}` | `HTB{got_the_flag}` |
| `thm` | `THM\{[^\n\r{}]{1,200}\}` | `THM{tryhackme_flag}` |
| `flag` | `flag\{[^\n\r{}]{1,200}\}` | `flag{simple_flag}` |
| `ctf` | `CTF\{[^\n\r{}]{1,200}\}` | `CTF{competition_flag}` |
| `generic` | `(?:[A-Za-z0-9_]+)?\{[^\n\r{}]{1,200}\}` | Any `PREFIX{content}` format |

## Project Structure

```
ctf_solver/
├── __init__.py          # Package initialization
├── __main__.py          # Module entry point
├── config.py            # Configuration model and flag utilities
├── agent.py             # Agent construction
├── runner.py            # CLI runner
├── tools/
│   ├── __init__.py
│   ├── http_tools.py    # HttpFetchTool, FormSubmitTool
│   ├── html_tools.py    # HtmlInspectorTool, JavaScriptSourceTool
│   ├── search_tools.py  # RegexSearchTool, ResponseSearchTool, SqlPatternHintTool
│   ├── web_tools.py     # RobotsTxtTool, CookieInspectorTool, CookieSetTool
│   └── logging_wrapper.py
├── rag/
│   ├── __init__.py
│   └── knowledge_base.py  # RAG initialization and management
├── prompts/
│   ├── __init__.py
│   └── templates.py     # Prompt templates with placeholders
└── ui/
    ├── __init__.py
    └── streamlit_app.py  # Streamlit GUI

tests/
└── test_config.py       # Tests for config and flag extraction

ctf_agentic_solver.py    # Main entry point (backwards compatible)
```

## Available Tools

The agent has access to these tools:

| Tool | Description |
|------|-------------|
| `http_fetch` | HTTP GET/HEAD requests with session management |
| `form_submit` | Submit forms via GET/POST |
| `html_inspector` | Analyze HTML structure, links, comments |
| `javascript_source` | Extract and analyze JavaScript code |
| `robots_txt` | Fetch and parse robots.txt |
| `cookie_inspector` | View session cookies |
| `cookie_set` | Modify session cookies |
| `regex_search` | Search text with regex patterns |
| `response_search` | Find keywords in HTTP responses |
| `sql_pattern_hint` | Detect SQL-related patterns |
| `ctf_knowledge_query` | Query the RAG knowledge base |

## Migration from andrewtesting17.py

If you were using the old `andrewtesting17.py` script, here's how to migrate:

### Old Usage (Deprecated)
```bash
python andrewtesting17.py --base-url https://saturn.picoctf.net:12345 \
    --challenge SQLiLite
```

### New Usage
```bash
python ctf_agentic_solver.py --challenge-url https://saturn.picoctf.net:12345 \
    --flag-preset picoctf \
    --description "SQL injection challenge"
```

### Mapping of Old to New Arguments

| Old Argument | New Argument | Notes |
|--------------|--------------|-------|
| `--base-url` | `--challenge-url` | Renamed for clarity |
| `--challenge` | `--description` | Now accepts any description |
| `--task` | `--description` | Merged with description |
| (hardcoded) | `--flag-regex` or `--flag-preset` | Now configurable |
| (hardcoded) | `--platform-name` | Now configurable |

### Key Changes

1. **No hardcoded challenge names**: You can now describe any challenge
2. **Configurable flag patterns**: Use presets or custom regex
3. **Platform agnostic**: Works with any CTF platform
4. **Streamlit GUI**: Visual interface for configuration
5. **Better structure**: Modular package design

## Configuration

### Environment Variables

```bash
# Required
OPENAI_API_KEY=your_openai_api_key

# Optional
CTF_PLATFORM_NAME=Generic CTF
CTF_FLAG_REGEX=(?:[A-Za-z0-9_]+)?\{[^\n\r{}]{1,200}\}
CTF_DOCS_DIR=docs
CTF_MAX_STEPS=20
CTF_VERBOSE=false
```

### Programmatic Usage

```python
from ctf_solver import SolverConfig, build_agent
from ctf_solver.prompts import get_initial_message

# Create configuration
config = SolverConfig(
    platform_name="PicoCTF",
    flag_regex=r"picoCTF\{[^}]+\}",
    challenge_url="https://saturn.picoctf.net:12345",
    challenge_description="SQL injection challenge",
    docs_dirs=["docs/"],
    max_steps=25,
)

# Build agent
agent = build_agent(config)

# Generate initial message
message = get_initial_message(
    platform_name=config.platform_name,
    flag_regex=config.flag_regex,
    challenge_url=config.challenge_url,
    challenge_description=config.challenge_description,
)

# Run agent
response = await agent.arun(message)
print(response)
```

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_config.py -v
```

## Streamlit GUI Features

The Streamlit interface provides:

- **Configuration Panel**: Set platform, flag pattern, max steps, knowledge base
- **Challenge Input**: URL, description, and hints fields
- **Agent Prompt Editor**: Customize the system prompt
- **Live Execution Log**: See tool calls in real-time
- **Results Display**: Final answer, candidate flags, execution history
- **Input Validation**: URL format and regex validation

## Known Limitations

- Requires OpenAI API key (uses GPT-4 by default)
- RAG knowledge base is rebuilt on each run (caching planned)
- No concurrent challenge solving (sequential only)
- Web challenges only (no binary/pwn/crypto support yet)

## Future Improvements

- [ ] Support for additional LLM providers (Anthropic, local models)
- [ ] Persistent knowledge base caching
- [ ] Challenge auto-detection from URL
- [ ] Multi-challenge batch processing
- [ ] Export/import of agent sessions
- [ ] Plugin system for custom tools

## License

Part of the FAIR-LLM framework. See main README for licensing information.

## Contributors

- Andrew Kim (CTF Solver development)
- USAFA AI Center team (FAIR framework)
