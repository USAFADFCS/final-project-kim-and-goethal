[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/nwy6MBDZ)

# CTF Solver

A platform-agnostic agentic CTF solving framework built on the FAIR-LLM library.

## Overview

CTF Solver is an AI-powered agent designed to solve web-based Capture-The-Flag (CTF) challenges. It uses a ReAct (Reasoning + Acting) loop with specialized tools for web exploitation, combined with a RAG-enhanced knowledge base for CTF techniques.

## Features

### Tools (29 Total)

**HTTP & Web Tools**
- `http_fetch` - Fetch web pages and API endpoints
- `form_submit` - Submit HTML forms with custom data
- `robots_txt` - Check robots.txt for hidden paths
- `cookie_inspector` - Inspect session cookies
- `cookie_set` - Modify cookies for session manipulation

**HTML & JavaScript Analysis**
- `html_inspector` - Parse and analyze HTML structure
- `javascript_source` - Extract and analyze JavaScript code

**Search & Pattern Detection**
- `regex_search` - Search responses with regex patterns
- `response_search` - Search for keywords in responses
- `sql_pattern_hint` - Detect SQL injection indicators

**Encoding & Decoding**
- `encoding_tool` - Base64, URL, hex, ROT13, binary conversions
- `hash_identifier` - Identify hash types (MD5, SHA, bcrypt)

**SQL Injection**
- `sqli_probe` - Detect SQL injection vulnerabilities
- `sqli_column_counter` - Determine column count for UNION attacks
- `blind_sqli_boolean` - Boolean-based blind SQLi extraction
- `blind_sqli_time` - Time-based blind SQLi extraction
- `sqli_data_dumper` - Extract data from vulnerable endpoints

**JWT Authentication**
- `jwt_tool` - Decode, analyze, and forge JWT tokens

**SSTI (Server-Side Template Injection)**
- `ssti_probe` - Detect template injection vulnerabilities
- `ssti_exploit_suggester` - Suggest exploitation techniques

**File Upload**
- `file_upload` - Test file upload functionality
- `upload_location_finder` - Find where uploaded files are stored

**XXE (XML External Entity)**
- `xxe_probe` - Detect XXE vulnerabilities
- `xxe_payload_generator` - Generate XXE payloads
- `xxe_doctype_builder` - Build malicious DOCTYPE declarations

**Enumeration**
- `path_enumerator` - Discover hidden paths and directories
- `backup_file_finder` - Find backup files (.bak, .old, etc.)

**Response Analysis**
- `response_diff` - Compare responses to detect differences
- `timing_compare` - Measure response timing differences
- `response_fingerprinter` - Fingerprint web applications

**Knowledge Base**
- `ctf_knowledge_query` - RAG-powered CTF technique lookup

### Additional Features

- **Challenge Classification**: Automatically categorizes challenges (SQLi, XSS, JWT, SSTI, etc.)
- **Multi-LLM Support**: OpenAI, Anthropic Claude, Ollama, or Hybrid configurations
- **RAG Knowledge Base**: 20 reference documents covering common CTF techniques
- **Async Execution**: Parallel tool execution for faster solving
- **Response Caching**: Avoid redundant HTTP requests

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Set Up API Keys

Create a `.env` file:

```bash
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here  # Optional
```

## Usage

### Command Line

```bash
# Basic usage
python -m ctf_solver --challenge-url https://example.com/challenge \
    --description "Find the hidden flag"

# With PicoCTF flag format
python -m ctf_solver --challenge-url https://saturn.picoctf.net:12345 \
    --platform-name PicoCTF --flag-preset picoctf

# With hints
python -m ctf_solver --challenge-url https://challenge.ctf.com \
    --hints "Check robots.txt" --docs-dir ./my_notes

# Using HackTheBox preset
python -m ctf_solver --challenge-url https://app.hackthebox.com/... \
    --flag-preset htb
```

### Interactive Mode

```bash
python -m ctf_solver
```

Follow the prompts to describe your challenge.

### Programmatic Usage

```python
from ctf_solver import SolverConfig, build_agent
from ctf_solver.prompts import get_initial_message

# Configure
config = SolverConfig(
    challenge_url="https://example.com/challenge",
    challenge_description="Find the SQL injection vulnerability",
    platform_name="PicoCTF",
    flag_regex=r"picoCTF\{[^\n\r{}]{1,200}\}",
)

# Build and run agent
agent = build_agent(config)
message = get_initial_message(
    platform_name=config.platform_name,
    challenge_url=config.challenge_url,
    challenge_description=config.challenge_description,
)
response = await agent.arun(message)
print(response)
```

### Using the Challenge Classifier

```python
from ctf_solver import classify_challenge, get_classification_context, SolverConfig

config = SolverConfig(
    challenge_description="This login form seems vulnerable to SQL injection"
)

result = classify_challenge(config)
print(f"Category: {result.primary_category}")  # sql_injection
print(f"Confidence: {result.confidence:.2f}")
print(f"Suggested tools: {result.suggested_tools}")
```

## Configuration Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `platform_name` | `CTF_PLATFORM_NAME` | Generic CTF | Platform name for prompts |
| `challenge_url` | `CTF_CHALLENGE_URL` | None | Target challenge URL |
| `flag_regex` | `CTF_FLAG_REGEX` | Generic pattern | Flag detection regex |
| `max_steps` | `CTF_MAX_STEPS` | 20 | Max agent reasoning steps |
| `model_name` | `CTF_MODEL_NAME` | gpt-4o | LLM model to use |
| `llm_provider` | `CTF_LLM_PROVIDER` | openai | LLM provider |
| `cache_enabled` | `CTF_CACHE_ENABLED` | true | Enable response caching |
| `async_enabled` | `CTF_ASYNC_ENABLED` | true | Enable parallel execution |

## Flag Presets

| Preset | Pattern |
|--------|---------|
| `picoctf` | `picoCTF\{[^\n\r{}]{1,200}\}` |
| `htb` | `HTB\{[^\n\r{}]{1,200}\}` |
| `thm` | `THM\{[^\n\r{}]{1,200}\}` |
| `flag` | `flag\{[^\n\r{}]{1,200}\}` |
| `ctf` | `CTF\{[^\n\r{}]{1,200}\}` |
| `generic` | `(?:[A-Za-z0-9_]+)?\{[^\n\r{}]{1,200}\}` |

## Testing

Run the test suite:

```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=ctf_solver --cov-report=html

# Integration tests only
pytest tests/test_integration.py -v
```

## Project Structure

```
ctf_solver/
    __init__.py          # Package exports
    __main__.py          # CLI entry point
    agent.py             # Agent construction
    config.py            # Configuration model
    runner.py            # CLI runner
    classifier/          # Challenge classification
    llm/                 # Multi-LLM adapters
    prompts/             # Prompt templates
    rag/                 # RAG knowledge base
    tools/               # 29 exploitation tools
    utils/               # Utilities (async, caching)

docs/                    # 20 reference documents
tests/                   # 627 tests
```

## License

MIT License

## Contributors

Developed as part of the DATA422 Capstone Project.

Built on the FAIR-LLM framework by the USAFA AI Center team.
