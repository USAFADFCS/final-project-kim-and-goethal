"""
Pre-LLM source code analyzer for CTF challenges.

Prioritizes files by security relevance, tracks source-to-sink data
flows, checks dependency versions against known CVEs, and extracts
only security-relevant code sections to minimize LLM token usage.

Design inspired by Pysa (Facebook), Semgrep taint mode, and OWASP
source/sink classifications.  Zero required external dependencies
(stdlib only); opportunistically uses bandit/semgrep when available.
"""

import ast
import json
import re
import shutil
import subprocess
import tempfile
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ═══════════════════════════════════════════════════════════════════
# Vulnerability class definitions (Semgrep taint-mode inspired)
# ═══════════════════════════════════════════════════════════════════

_VULN_CLASSES: Dict[str, Dict[str, Any]] = {
    "RCE": {
        "sinks": [
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"\bsystem\s*\(",
            r"\bos\.(?:popen|system)\s*\(",
            r"\bsubprocess\.\w+\s*\(",
            r"\bchild_process\b",
            r"\b__import__\s*\(",
        ],
        "sanitizers": [r"\bshlex\.quote\s*\(", r"\bshlex\.split\s*\("],
        "severity": "critical",
    },
    "Deserialization": {
        "sinks": [
            r"\bpickle\.loads?\s*\(",
            r"\bunserialize\s*\(",
            r"\byaml\.load\s*\(",
            r"\byaml\.unsafe_load\s*\(",
            r"\bjsonpickle\.\w+\s*\(",
            r"\bshelve\.open\s*\(",
        ],
        "sanitizers": [r"\byaml\.safe_load\s*\("],
        "severity": "critical",
    },
    "SSTI": {
        "sinks": [
            r"\brender_template_string\s*\(",
            r"\bTemplate\s*\(",
            r"\bjinja2\.from_string\s*\(",
            r"\bEnvironment\s*\(",
        ],
        "sanitizers": [r"\bMarkup\.escape\s*\(", r"\bescape\s*\("],
        "severity": "critical",
    },
    "SQLi": {
        "sinks": [
            r"\.execute\s*\(.*\+",
            r"\.execute\s*\(.*%",
            r"\.query\s*\(.*\+",
            r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\{',
        ],
        "sanitizers": [
            r"\bparameterize\b",
            r"\bplaceholder\b",
            r"prepared_statement",
        ],
        "severity": "high",
    },
    "XSS": {
        "sinks": [
            r"\.innerHTML\s*=",
            r"\bdocument\.write\s*\(",
            r"res\.send\s*\(.*req\.",
            r"\.html\s*\(.*req\.",
        ],
        "sanitizers": [
            r"\bhtmlspecialchars\s*\(",
            r"\bDOMPurify\b",
            r"\bsanitize\s*\(",
            r"\bbleach\.clean\s*\(",
        ],
        "severity": "high",
    },
    "PathTraversal": {
        "sinks": [
            r"\bopen\s*\(.*(?:request|req\.|params|\$_)",
            r"os\.path\.join\s*\(.*(?:request|req\.)",
            r"send_file\s*\(.*(?:request|req\.)",
        ],
        "sanitizers": [
            r"\bos\.path\.basename\s*\(",
            r"\bsecure_filename\s*\(",
        ],
        "severity": "high",
    },
}

# Pre-compile all vuln-class patterns for speed.
_COMPILED_VULN_CLASSES: Dict[str, Dict[str, Any]] = {}
for _vc_name, _vc_def in _VULN_CLASSES.items():
    _COMPILED_VULN_CLASSES[_vc_name] = {
        "sinks": [re.compile(p, re.IGNORECASE) for p in _vc_def["sinks"]],
        "sanitizers": [
            re.compile(p, re.IGNORECASE) for p in _vc_def.get("sanitizers", [])
        ],
        "severity": _vc_def["severity"],
    }

# ═══════════════════════════════════════════════════════════════════
# User-input source patterns (per Pysa TaintSource[UserControlled])
# ═══════════════════════════════════════════════════════════════════

_PYTHON_SOURCES = re.compile(
    r"request\.(?:args|form|cookies|headers|json|data|values|files|environ)"
    r"|request\.get_json\("
    r"|session\["
    r"|request\.get\(",
)

_JS_SOURCES = re.compile(
    r"req\.(?:body|query|params|cookies|headers|session)" r"|req\.get\(",
)

_PHP_SOURCES = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b"
    r"|\$_SESSION\b"
    r"|file_get_contents\s*\(\s*['\"]php://input",
)

_RUBY_SOURCES = re.compile(
    r"params\[|request\.env|cookies\[|session\[",
)

# ═══════════════════════════════════════════════════════════════════
# File-level scoring constants
# ═══════════════════════════════════════════════════════════════════

_ENTRY_POINT_NAMES = frozenset(
    {
        "app.py",
        "server.py",
        "main.py",
        "index.js",
        "index.ts",
        "index.php",
        "server.js",
        "server.ts",
        "api.py",
        "api.js",
        "routes.py",
        "routes.js",
        "views.py",
        "init.py",
        "__init__.py",
        "main.rb",
        "app.rb",
        "config.ru",
        "manage.py",
        "wsgi.py",
        "handler.py",
        "handler.js",
        "util.py",
        "utils.py",
    }
)

_LOW_VALUE_NAMES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "pipfile",
        "pipfile.lock",
        "gemfile",
        "gemfile.lock",
        "cargo.toml",
        "cargo.lock",
        "go.sum",
        "go.mod",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        ".gitignore",
        ".dockerignore",
        "makefile",
        "readme.md",
        "readme.txt",
        "license",
        "license.md",
        "changelog.md",
        "tsconfig.json",
        "webpack.config.js",
        "vite.config.js",
        "vite.config.ts",
        "babel.config.js",
        ".eslintrc.js",
        ".eslintrc.json",
        ".prettierrc",
        "jest.config.js",
        "setup.py",
        "setup.cfg",
        "pyproject.toml",
        "tox.ini",
    }
)

_LOW_VALUE_PATH_SEGMENTS = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "spec",
        "migration",
        "migrations",
        "static",
        "public",
        "assets",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "__pycache__",
    }
)

# ═══════════════════════════════════════════════════════════════════
# Route / endpoint detection patterns
# ═══════════════════════════════════════════════════════════════════

_ROUTE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"@app\.(?:route|get|post|put|delete|patch)\(",
        r"@blueprint\.(?:route|get|post|put|delete)\(",
        r"@api\.(?:route|resource)\(",
        r"app\.(?:get|post|put|delete|patch|use|all)\(",
        r"router\.(?:get|post|put|delete|patch|use)\(",
        r"Route::",
        r"@(?:Get|Post|Put|Delete|Patch)Mapping",
        r"@RequestMapping",
        r"fastify\.(?:get|post|put|delete)\(",
        r"Slim\\App|->(?:get|post|put|delete)\(",
    ]
]

# ═══════════════════════════════════════════════════════════════════
# Additional dangerous-pattern detection (line-level, kept for
# backward compat with the scoring system)
# ═══════════════════════════════════════════════════════════════════

_DANGEROUS_SINKS = [
    # Code execution
    (re.compile(r"\beval\s*\("), "eval()"),
    (re.compile(r"\bexec\s*\("), "exec()"),
    (re.compile(r"\bsystem\s*\("), "system()"),
    (re.compile(r"\bunserialize\s*\("), "unserialize()"),
    (re.compile(r"\bpickle\.loads?\s*\("), "pickle.load()"),
    (re.compile(r"\byaml\.(?:load|unsafe_load)\s*\("), "yaml.load()"),
    (re.compile(r"\bsubprocess\b"), "subprocess"),
    (re.compile(r"\bchild_process\b"), "child_process"),
    (re.compile(r"\b__import__\s*\("), "__import__()"),
    (re.compile(r"\bos\.(?:popen|system)\s*\("), "os.system/popen()"),
    # Template injection
    (re.compile(r"\brender_template_string\s*\("), "render_template_string()"),
    # XSS
    (re.compile(r"\.innerHTML\s*="), "innerHTML assignment"),
    (re.compile(r"\bdocument\.write\s*\("), "document.write()"),
    # Input handling
    (re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\b"), "PHP superglobal"),
    # SQL
    (re.compile(r"\.query\s*\(.*\+\s*(?:req|request)"), "SQL query + user input"),
    # Auth / secrets
    (re.compile(r"\bJWT\.(?:decode|encode)\b", re.IGNORECASE), "JWT operation"),
    (re.compile(r"\bsecrets?\s*[:=]\s*['\"]"), "hardcoded secret"),
    (re.compile(r"password\s*[:=]\s*['\"](?!<%)"), "hardcoded password"),
    (re.compile(r"\bsign_message\b"), "cryptographic signing"),
    (re.compile(r"\brandom\.(?:random|randrange|randint)\b"), "insecure random"),
    # MIME / email
    (re.compile(r"\bMIMEMultipart\b|\bMIMEText\b"), "MIME construction"),
    (re.compile(r"\bsmtplib\b|\bnodemailer\b"), "email sending"),
    (re.compile(r"Content-Type:.*boundary=", re.IGNORECASE), "MIME boundary"),
    # Open redirect
    (re.compile(r"\bredirect\s*\(\s*(?:request|req\.)"), "open redirect"),
    (re.compile(r"res\.redirect\s*\(\s*req\."), "open redirect"),
    # Prototype pollution
    (re.compile(r"\b__proto__\b|constructor\s*\["), "prototype pollution indicator"),
    # CORS
    (re.compile(r"Access-Control-Allow-Origin.*\*"), "CORS wildcard"),
    # Path traversal
    (
        re.compile(r"os\.path\.join\s*\(.*(?:request|req\.)"),
        "path join with user input",
    ),
    (
        re.compile(r"\bopen\s*\(.*(?:request|req\.|params|\$_)"),
        "file open with user input",
    ),
    # S/MIME / PKI
    (
        re.compile(r"\bPKCS7\b|\bX509\b|\bcms\.sign\b", re.IGNORECASE),
        "S/MIME/PKI operation",
    ),
    # Auth patterns
    (re.compile(r"\bsmail\b"), "S/MIME library"),
]

# Auth-related patterns (for scoring).
_AUTH_PATTERNS = re.compile(
    r"\b(?:password|session|token|jwt|login|cookie|authenticat|"
    r"authorize|credentials|secret_key|api_key)\b",
    re.IGNORECASE,
)

# User-input patterns (for scoring).
_INPUT_PATTERNS = re.compile(
    r"(?:request\.|req\.body|req\.query|req\.params|"
    r"\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|"
    r"params\[|args\.get\(|form\.get\()",
)

# Database patterns (for scoring).
_DB_PATTERNS = re.compile(
    r"\b(?:query|execute|cursor|SELECT|INSERT|UPDATE|DELETE|"
    r"mongoose|sequelize|knex|prisma|sqlalchemy)\b",
    re.IGNORECASE,
)

# ═══════════════════════════════════════════════════════════════════
# Vulnerable dependency database (CVE-sourced)
# ═══════════════════════════════════════════════════════════════════

# (max_safe_version, description).  "*" means ALL versions vulnerable.
_VULNERABLE_VERSIONS: Dict[str, List[Tuple[str, str]]] = {
    # Python
    "flask": [("2.3.0", "Werkzeug debugger PIN bypass / debug mode RCE")],
    "jinja2": [("3.1.3", "CVE-2024-22195 xmlattr XSS injection")],
    "pyyaml": [("6.0", "CVE-2020-14343 arbitrary code execution via yaml.load()")],
    "pyjwt": [("2.4.0", "Algorithm confusion / none algorithm bypass")],
    "werkzeug": [("2.3.0", "Debugger console PIN prediction / RCE")],
    "lxml": [("4.9.0", "XXE enabled by default")],
    "itsdangerous": [("2.1.0", "Timing side-channel in signature comparison")],
    "pillow": [("9.0.0", "Multiple image processing RCE CVEs")],
    "cryptography": [("39.0.0", "Padding oracle / key derivation issues")],
    # Node.js
    "node-serialize": [("*", "CVE-2017-5941 RCE via IIFE — ALL versions")],
    "ejs": [("3.1.10", "CVE-2022-29078 SSTI via outputFunctionName")],
    "express-fileupload": [("*", "CVE-2020-7699 prototype pollution → EJS RCE")],
    "vm2": [("3.9.15", "CVE-2023-29017 sandbox escape → RCE")],
    "safe-eval": [("*", "Sandbox bypass → RCE — ALL versions")],
    "lodash": [("4.17.21", "CVE-2019-10744 prototype pollution")],
    "jsonwebtoken": [("9.0.0", "Algorithm confusion attacks")],
    "flat": [("*", "Prototype pollution via unflatten")],
    "serialize-javascript": [("3.1.0", "RCE via deserialization")],
    "express-session": [("1.17.0", "Session fixation")],
    # PHP (composer)
    "twig/twig": [("3.4.0", "Sandbox escape → SSTI")],
    "symfony/http-kernel": [("5.4.0", "Debug profiler information leak")],
    # Ruby
    "rails": [("7.0.0", "Multiple known CVEs")],
    "sinatra": [("3.0.0", "Path traversal in static file serving")],
}

# ═══════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════


@dataclass
class FlowFinding:
    """A source-to-sink data flow within a single function/block."""

    filename: str
    function_name: str
    source_match: str
    sink_match: str
    vuln_class: str
    line_range: Tuple[int, int]
    severity: str  # "critical", "high", "medium"


@dataclass
class DependencyFinding:
    """A known-vulnerable package version."""

    package: str
    version: str
    vulnerability: str
    source_file: str


@dataclass
class AnalysisResult:
    """Result of source code analysis."""

    prioritized_files: Dict[str, str]
    vuln_summary: str
    file_scores: Dict[str, int] = field(default_factory=dict)
    extracted_files: Optional[Dict[str, str]] = None
    flow_findings: List[FlowFinding] = field(default_factory=list)
    dependency_findings: List[DependencyFinding] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════
# A: Source-to-Sink Flow Tracking
# ═══════════════════════════════════════════════════════════════════


def _get_source_pattern(filename: str) -> re.Pattern:  # type: ignore[type-arg]
    """Return the appropriate user-input source regex for a file's language."""
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    if ext in (".js", ".ts", ".jsx", ".tsx", ".mjs"):
        return _JS_SOURCES
    if ext == ".php":
        return _PHP_SOURCES
    if ext == ".rb":
        return _RUBY_SOURCES
    return _PYTHON_SOURCES  # default


def _extract_blocks_braces(content: str) -> List[Tuple[str, int, int, str]]:
    """Extract function/route blocks from brace-delimited languages.

    Returns list of (block_name, start_line, end_line, block_text).
    """
    blocks: List[Tuple[str, int, int, str]] = []
    lines = content.splitlines()
    # Match common function/route patterns that precede a brace block.
    func_re = re.compile(
        r"(?:function\s+(\w+)|"
        r"(?:app|router|fastify)\.(?:get|post|put|delete|patch|use|all)\s*\(\s*['\"]([^'\"]+)['\"]|"
        r"(\w+)\s*(?:=\s*)?(?:async\s+)?(?:function|\(.*?\)\s*=>))"
    )

    i = 0
    while i < len(lines):
        m = func_re.search(lines[i])
        if m:
            name = m.group(1) or m.group(2) or m.group(3) or "anonymous"
            # Find opening brace
            brace_line = i
            while brace_line < len(lines) and "{" not in lines[brace_line]:
                brace_line += 1
                if brace_line - i > 3:
                    break
            if brace_line < len(lines) and "{" in lines[brace_line]:
                depth = 0
                start = i
                end = brace_line
                for j in range(brace_line, len(lines)):
                    depth += lines[j].count("{") - lines[j].count("}")
                    if depth <= 0:
                        end = j
                        break
                block_text = "\n".join(lines[start : end + 1])
                blocks.append((name, start + 1, end + 1, block_text))
                i = end + 1
                continue
        i += 1
    return blocks


def _detect_source_sink_flows(filename: str, content: str) -> List[FlowFinding]:
    """Detect source-to-sink flows within function bodies."""
    findings: List[FlowFinding] = []
    source_re = _get_source_pattern(filename)
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""

    # Collect blocks: (name, start_line, end_line, text)
    blocks: List[Tuple[str, int, int, str]] = []

    if ext == ".py":
        try:
            tree = ast.parse(content)
            lines = content.splitlines()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    start = node.lineno
                    end = getattr(node, "end_lineno", start + 10)
                    block_text = "\n".join(lines[start - 1 : end])
                    blocks.append((node.name, start, end, block_text))
        except SyntaxError:
            # Fallback: treat indented blocks as functions
            blocks = _extract_blocks_braces(content)
    else:
        blocks = _extract_blocks_braces(content)

    for func_name, start, end, block_text in blocks:
        # Check if user-input source is present in this block
        source_match = source_re.search(block_text)
        if not source_match:
            continue

        # Check each vulnerability class
        for vc_name, vc_def in _COMPILED_VULN_CLASSES.items():
            sink_match_str = None
            for sink_re in vc_def["sinks"]:
                sm = sink_re.search(block_text)
                if sm:
                    sink_match_str = sm.group(0).strip()
                    break
            if not sink_match_str:
                continue

            # Check sanitizers — if present, skip this flow
            sanitized = False
            for san_re in vc_def["sanitizers"]:
                if san_re.search(block_text):
                    sanitized = True
                    break
            if sanitized:
                continue

            findings.append(
                FlowFinding(
                    filename=filename,
                    function_name=func_name,
                    source_match=source_match.group(0).strip(),
                    sink_match=sink_match_str,
                    vuln_class=vc_name,
                    line_range=(start, end),
                    severity=vc_def["severity"],
                )
            )

    return findings


# ═══════════════════════════════════════════════════════════════════
# B: Smart Code Extraction
# ═══════════════════════════════════════════════════════════════════

_EXTRACTION_THRESHOLD = 200  # lines; files shorter than this are kept in full


def _extract_relevant_code(
    filename: str,
    content: str,
    flow_findings: List[FlowFinding],
    line_findings: List[str],
) -> Optional[str]:
    """Extract only security-relevant code sections from a file.

    Returns reduced content, or None if the file is small enough to
    include in full.
    """
    lines = content.splitlines()
    if len(lines) <= _EXTRACTION_THRESHOLD:
        return None  # small file, include in full

    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""

    # Collect line ranges that MUST be included.
    keep_ranges: List[Tuple[int, int]] = []

    # Always keep imports / top-level config (first 30 lines or until first
    # function definition, whichever is smaller)
    import_end = min(30, len(lines))
    for i, line in enumerate(lines[:60]):
        stripped = line.strip()
        if stripped.startswith(("def ", "async def ", "class ")) and i > 5:
            import_end = i
            break
    keep_ranges.append((0, import_end))

    # Include lines from flow findings
    for ff in flow_findings:
        if ff.filename == filename:
            keep_ranges.append((ff.line_range[0] - 1, ff.line_range[1]))

    # Include lines from line-level findings
    for finding in line_findings:
        # Parse "label at file:line" format
        if filename in finding:
            parts = finding.split(":")
            for p in parts:
                digits = re.search(r"(\d+)", p)
                if digits:
                    ln = int(digits.group(1)) - 1
                    # Include function context around the finding
                    start = max(0, ln - 5)
                    end = min(len(lines), ln + 20)
                    keep_ranges.append((start, end))
                    break

    if ext == ".py":
        # Use AST to include full function bodies for any function that
        # overlaps with keep_ranges, plus route-decorated functions.
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    start = node.lineno - 1
                    end = getattr(node, "end_lineno", start + 10)

                    # Check if this function overlaps with any keep range
                    overlaps = any(
                        not (end < ks or start > ke) for ks, ke in keep_ranges
                    )
                    # Check for route decorators
                    has_route = any(
                        "route" in ast.dump(d).lower() for d in node.decorator_list
                    )
                    if overlaps or has_route:
                        keep_ranges.append((start, end))
        except SyntaxError:
            pass

    # Merge overlapping ranges and sort
    keep_ranges.sort()
    merged: List[Tuple[int, int]] = []
    for start, end in keep_ranges:
        if merged and start <= merged[-1][1] + 2:  # allow 2-line gap
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    # Build extracted content
    output: List[str] = []
    prev_end = 0
    for start, end in merged:
        if start > prev_end:
            omitted = start - prev_end
            output.append(
                f"# ... [{omitted} lines omitted — not security-relevant] ..."
            )
            output.append("")
        output.extend(lines[start:end])
        prev_end = end

    if prev_end < len(lines):
        omitted = len(lines) - prev_end
        output.append(f"# ... [{omitted} lines omitted — not security-relevant] ...")

    return "\n".join(output)


# ═══════════════════════════════════════════════════════════════════
# C: Dependency Version Analysis
# ═══════════════════════════════════════════════════════════════════


def _version_lt(v1: str, v2: str) -> bool:
    """Return True if version *v1* is strictly less than *v2*."""

    def _parts(v: str) -> Tuple[int, ...]:
        return tuple(int(x) for x in re.findall(r"\d+", v)[:4])

    return _parts(v1) < _parts(v2)


def _parse_requirements_txt(content: str) -> Dict[str, str]:
    """Parse a requirements.txt into {package: version} dict."""
    result: Dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([a-zA-Z0-9_.-]+)\s*[=<>!~]+\s*([\d.]+)", line)
        if m:
            result[m.group(1).lower()] = m.group(2)
    return result


def _parse_package_json(content: str) -> Dict[str, str]:
    """Parse a package.json into {package: version} dict."""
    result: Dict[str, str] = {}
    try:
        data = json.loads(content)
        for section in ("dependencies", "devDependencies"):
            deps = data.get(section, {})
            if isinstance(deps, dict):
                for pkg, ver in deps.items():
                    # Strip semver prefixes: ^, ~, >=, etc.
                    clean = re.sub(r"^[^0-9*]+", "", str(ver))
                    result[pkg.lower()] = clean
    except (json.JSONDecodeError, TypeError):
        pass
    return result


def _parse_gemfile(content: str) -> Dict[str, str]:
    """Parse a Gemfile into {package: version} dict."""
    result: Dict[str, str] = {}
    for line in content.splitlines():
        m = re.match(
            r"""gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]~?>?\s*([\d.]+))?""",
            line.strip(),
        )
        if m and m.group(2):
            result[m.group(1).lower()] = m.group(2)
    return result


def _analyze_dependencies(files: Dict[str, str]) -> List[DependencyFinding]:
    """Check manifest files for known-vulnerable package versions."""
    findings: List[DependencyFinding] = []
    parsers = {
        "requirements.txt": _parse_requirements_txt,
        "pipfile": _parse_requirements_txt,  # good enough approximation
        "package.json": _parse_package_json,
        "gemfile": _parse_gemfile,
    }

    for fname, content in files.items():
        parser = parsers.get(fname.lower())
        if not parser:
            continue
        deps = parser(content)
        for pkg, ver in deps.items():
            if pkg in _VULNERABLE_VERSIONS:
                for max_safe, desc in _VULNERABLE_VERSIONS[pkg]:
                    if max_safe == "*" or (ver and _version_lt(ver, max_safe)):
                        findings.append(
                            DependencyFinding(
                                package=pkg,
                                version=ver or "unknown",
                                vulnerability=desc,
                                source_file=fname,
                            )
                        )

    return findings


# ═══════════════════════════════════════════════════════════════════
# D: Line-level pattern detection (enhanced from v1)
# ═══════════════════════════════════════════════════════════════════


def _detect_dangerous_patterns(filename: str, content: str) -> List[str]:
    """Return human-readable findings for security-relevant patterns."""
    findings: List[str] = []
    seen_labels: set = set()

    for line_no, line in enumerate(content.splitlines(), 1):
        for pat, label in _DANGEROUS_SINKS:
            if pat.search(line) and label not in seen_labels:
                seen_labels.add(label)
                snippet = line.strip()[:80]
                findings.append(f"{label} at {filename}:{line_no}  ({snippet})")

    return findings


# ═══════════════════════════════════════════════════════════════════
# E: Optional External Scanner (bandit / semgrep)
# ═══════════════════════════════════════════════════════════════════


def _find_semgrep_rules_dir() -> Optional[Path]:
    """Locate the bundled semgrep_rules/ directory with pre-downloaded YAML rules."""
    # Check relative to this file first (works in both installed and dev layouts)
    here = Path(__file__).resolve().parent
    candidates = [
        here.parent / "semgrep_rules",  # project_root/semgrep_rules
        here / "semgrep_rules",  # ctf_solver/semgrep_rules (unlikely but check)
    ]
    for d in candidates:
        if d.is_dir() and any(d.rglob("*.yaml")):
            return d
    return None


_TEXT_EXTS = frozenset(
    {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".java", ".go"}
)


def _run_external_scanner(files: Dict[str, str]) -> List[str]:
    """Opportunistically run semgrep and/or bandit if installed.

    Semgrep uses pre-downloaded local rules (no network).
    Bandit runs on Python files only.
    Returns deduplicated findings.
    """
    findings: List[str] = []
    bandit_path = shutil.which("bandit")
    semgrep_path = shutil.which("semgrep")

    if not bandit_path and not semgrep_path:
        return []

    # Write scannable files to a temp dir
    scannable = {
        f: c
        for f, c in files.items()
        if ("." + f.rsplit(".", 1)[-1].lower() if "." in f else "") in _TEXT_EXTS
    }
    if not scannable:
        return []

    tmpdir = None
    try:
        tmpdir = tempfile.mkdtemp(prefix="ctf_scan_")
        for fname, content in scannable.items():
            p = Path(tmpdir) / fname
            p.write_text(content, encoding="utf-8")

        # --- Semgrep (all languages, local rules, no network) ---
        if semgrep_path:
            rules_dir = _find_semgrep_rules_dir()
            if rules_dir:
                try:
                    result = subprocess.run(
                        [
                            semgrep_path,
                            "--config",
                            str(rules_dir),
                            tmpdir,
                            "--json",
                            "--quiet",
                            "--no-git-ignore",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    if result.stdout:
                        data = json.loads(result.stdout)
                        for r in data.get("results", [])[:15]:
                            msg = r.get("extra", {}).get("message", "?")
                            if len(msg) > 120:
                                msg = msg[:120] + "..."
                            sev = r.get("extra", {}).get("severity", "?")
                            fname = Path(r.get("path", "")).name
                            line = r.get("start", {}).get("line", "?")
                            findings.append(f"[semgrep {sev}] {msg} at {fname}:{line}")
                except (
                    subprocess.TimeoutExpired,
                    json.JSONDecodeError,
                    OSError,
                ):
                    pass

        # --- Bandit (Python only, supplements semgrep) ---
        if bandit_path:
            py_files = [f for f in scannable if f.endswith(".py")]
            if py_files:
                try:
                    result = subprocess.run(
                        [bandit_path, "-r", tmpdir, "-f", "json", "--quiet"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if result.stdout:
                        data = json.loads(result.stdout)
                        for issue in data.get("results", [])[:10]:
                            sev = issue.get("issue_severity", "?")
                            text = issue.get("issue_text", "?")
                            fname = Path(issue.get("filename", "")).name
                            line = issue.get("line_number", "?")
                            findings.append(f"[bandit {sev}] {text} at {fname}:{line}")
                except (
                    subprocess.TimeoutExpired,
                    json.JSONDecodeError,
                    OSError,
                ):
                    pass
    except OSError:
        pass
    finally:
        if tmpdir:
            import shutil as _shutil

            _shutil.rmtree(tmpdir, ignore_errors=True)

    return findings


# ═══════════════════════════════════════════════════════════════════
# Scoring
# ═══════════════════════════════════════════════════════════════════


def _score_file(filename: str, content: str) -> int:
    """Score a file by security relevance.  Higher = more important."""
    score = 0
    name_lower = filename.lower()

    if name_lower in _ENTRY_POINT_NAMES:
        score += 5

    if name_lower in _LOW_VALUE_NAMES:
        score -= 5

    for seg in _LOW_VALUE_PATH_SEGMENTS:
        if seg in name_lower:
            score -= 3
            break

    if len(content) > 50_000:
        score -= 10

    for pat in _ROUTE_PATTERNS:
        if pat.search(content):
            score += 10
            break

    for pat, _ in _DANGEROUS_SINKS:
        if pat.search(content):
            score += 10
            break

    if _AUTH_PATTERNS.search(content):
        score += 8

    if _INPUT_PATTERNS.search(content):
        score += 5

    if _DB_PATTERNS.search(content):
        score += 3

    return score


# ═══════════════════════════════════════════════════════════════════
# Summary generation
# ═══════════════════════════════════════════════════════════════════


def _count_routes(content: str) -> int:
    """Count route/endpoint definitions."""
    count = 0
    for pat in _ROUTE_PATTERNS:
        count += len(pat.findall(content))
    return count


def _detect_framework(files: Dict[str, str]) -> str:
    """Best-effort framework detection."""
    all_text = " ".join(files.values())[:20_000]
    names = {n.lower() for n in files}

    if "app.rb" in names or "config.ru" in names or "sinatra" in all_text.lower():
        return "Ruby/Sinatra"
    if "fastify" in all_text.lower():
        return "Node.js/Fastify"
    if "express" in all_text.lower():
        return "Node.js/Express"
    if "app.py" in names or "flask" in all_text.lower():
        return "Python/Flask"
    if "django" in all_text.lower():
        return "Python/Django"
    if "index.php" in names or "$_GET" in all_text:
        return "PHP"
    if "main.go" in names:
        return "Go"
    return "Unknown"


def _generate_vuln_summary(
    files: Dict[str, str],
    scores: Dict[str, int],
    line_findings: Dict[str, List[str]],
    flow_findings: List[FlowFinding],
    dep_findings: List[DependencyFinding],
    external_findings: List[str],
) -> str:
    """Generate a concise vulnerability summary for the LLM."""
    framework = _detect_framework(files)
    top_files = sorted(scores, key=scores.get, reverse=True)[:5]  # type: ignore[arg-type]
    total_routes = sum(_count_routes(files[f]) for f in files)

    lines = ["Source Code Analysis Summary:"]
    lines.append(f"- Framework: {framework} ({len(files)} source files)")
    if total_routes:
        lines.append(f"- {total_routes} route/endpoint definition(s) detected")
    lines.append(f"- Highest-value files: {', '.join(top_files)}")

    # 1. Flow findings (highest confidence)
    for ff in sorted(flow_findings, key=lambda f: f.severity):
        lines.append(
            f"- FLOW: {ff.source_match} → {ff.sink_match} in {ff.function_name}() "
            f"at {ff.filename}:{ff.line_range[0]}-{ff.line_range[1]} "
            f"[{ff.vuln_class}/{ff.severity.upper()}]"
        )

    # 2. Dependency findings
    for df in dep_findings:
        lines.append(
            f"- DEPENDENCY: {df.package}=={df.version} in {df.source_file} "
            f"— {df.vulnerability}"
        )

    # 3. External scanner findings
    for ef in external_findings[:5]:
        lines.append(f"- EXTERNAL: {ef}")

    # 4. Line-level findings (lowest confidence, fill remaining slots)
    remaining = 10 - (
        len(flow_findings) + len(dep_findings) + min(len(external_findings), 5)
    )
    if remaining > 0:
        all_line: List[str] = []
        seen_labels: set = set()
        for fname in top_files:
            for finding in line_findings.get(fname, []):
                label = finding.split(" at ")[0]
                if label not in seen_labels:
                    seen_labels.add(label)
                    all_line.append(f"- FINDING: {finding}")
        lines.extend(all_line[:remaining])

    if len(lines) <= 3:
        lines.append("- No obvious dangerous patterns detected in top files")
        lines.append("- The vulnerability may be logic-based — read the code carefully")

    # Recommended attack vector based on highest-severity flow
    if flow_findings:
        best = sorted(flow_findings, key=lambda f: f.severity)[0]
        lines.append(
            f"Recommended attack vector: {best.vuln_class} "
            f"via {best.sink_match} in {best.filename}"
        )

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════


def analyze_source_files(files: Dict[str, str]) -> AnalysisResult:
    """
    Analyze and prioritize source files for CTF vulnerability identification.

    Performs: file scoring → dependency analysis → line-level pattern
    detection → source-to-sink flow tracking → smart code extraction →
    optional external scanning → summary generation.
    """
    if not files:
        return AnalysisResult(
            prioritized_files={},
            vuln_summary="No source files provided.",
        )

    # 1. Score every file
    scores: Dict[str, int] = {f: _score_file(f, c) for f, c in files.items()}

    # 2. Dependency analysis
    dep_findings = _analyze_dependencies(files)
    # Boost score for manifest files with findings
    for df in dep_findings:
        if df.source_file in scores and scores[df.source_file] < 0:
            scores[df.source_file] = 0

    # 3. Sort by score
    ranked = sorted(files.items(), key=lambda item: (-scores[item[0]], item[0]))
    prioritized: Dict[str, str] = OrderedDict(ranked)

    # 4. Line-level pattern detection (top 10 files)
    line_findings: Dict[str, List[str]] = {}
    for fname, _ in ranked[:10]:
        found = _detect_dangerous_patterns(fname, files[fname])
        if found:
            line_findings[fname] = found

    # 5. Source-to-sink flow tracking (top 10 files)
    all_flows: List[FlowFinding] = []
    for fname, _ in ranked[:10]:
        flows = _detect_source_sink_flows(fname, files[fname])
        all_flows.extend(flows)
        # Boost score for files with flow findings
        if flows:
            scores[fname] = scores.get(fname, 0) + 3

    # Re-sort after flow-based score boosts
    ranked = sorted(files.items(), key=lambda item: (-scores[item[0]], item[0]))
    prioritized = OrderedDict(ranked)

    # 6. Smart code extraction (for large files)
    extracted: Dict[str, str] = OrderedDict()
    for fname, content in prioritized.items():
        file_flows = [f for f in all_flows if f.filename == fname]
        file_lines = line_findings.get(fname, [])
        reduced = _extract_relevant_code(fname, content, file_flows, file_lines)
        extracted[fname] = reduced if reduced is not None else content

    # 7. Optional external scanner
    external_findings = _run_external_scanner(files)

    # 8. Generate summary
    summary = _generate_vuln_summary(
        files, scores, line_findings, all_flows, dep_findings, external_findings
    )

    return AnalysisResult(
        prioritized_files=prioritized,
        vuln_summary=summary,
        file_scores=scores,
        extracted_files=extracted,
        flow_findings=all_flows,
        dependency_findings=dep_findings,
    )
