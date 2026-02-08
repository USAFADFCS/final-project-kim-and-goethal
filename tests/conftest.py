"""
Pytest configuration and shared fixtures for CTF Solver tests.

Provides common fixtures for mocking HTTP sessions, sample data,
and other testing utilities used across test modules.
"""

import base64
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import Mock, MagicMock

import pytest


# ==============================================================================
# HTTP Session Fixtures
# ==============================================================================


@pytest.fixture
def mock_session():
    """Create a mock requests.Session for HTTP testing."""
    session = Mock()
    session.get = Mock()
    session.post = Mock()
    session.cookies = Mock()
    session.headers = {}
    return session


@pytest.fixture
def mock_response_factory():
    """Factory fixture to create mock HTTP responses."""

    def _create_response(
        text: str = "OK",
        status_code: int = 200,
        headers: Dict[str, str] = None,
        json_data: Any = None,
    ) -> Mock:
        response = Mock()
        response.text = text
        response.status_code = status_code
        response.headers = headers or {}

        if json_data is not None:
            response.json.return_value = json_data
        else:
            response.json.side_effect = json.JSONDecodeError("No JSON", "", 0)

        return response

    return _create_response


@pytest.fixture
def successful_login_response(mock_response_factory):
    """Mock successful login response."""
    return mock_response_factory(
        text="<html><body><h1>Welcome admin!</h1><p>Dashboard</p></body></html>",
        status_code=200,
    )


@pytest.fixture
def failed_login_response(mock_response_factory):
    """Mock failed login response."""
    return mock_response_factory(
        text="<html><body><p>Invalid username or password</p></body></html>",
        status_code=200,
    )


@pytest.fixture
def sql_error_response(mock_response_factory):
    """Mock SQL error response."""
    return mock_response_factory(
        text="You have an error in your SQL syntax near ''",
        status_code=200,
    )


# ==============================================================================
# JWT Fixtures
# ==============================================================================


def b64_url_encode(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture
def jwt_factory():
    """Factory fixture to create test JWTs."""

    def _create_jwt(
        header: Dict[str, Any] = None,
        payload: Dict[str, Any] = None,
        secret: str = "secret",
    ) -> str:
        if header is None:
            header = {"alg": "HS256", "typ": "JWT"}
        if payload is None:
            payload = {"sub": "user123", "admin": False}

        header_b64 = b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = b64_url_encode(
            json.dumps(payload, separators=(",", ":")).encode()
        )
        signing_input = f"{header_b64}.{payload_b64}"
        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
        sig_b64 = b64_url_encode(sig)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    return _create_jwt


@pytest.fixture
def sample_jwt(jwt_factory):
    """Sample valid JWT for testing."""
    return jwt_factory(
        header={"alg": "HS256", "typ": "JWT"},
        payload={"sub": "1234567890", "name": "Test User", "iat": 1516239022},
    )


@pytest.fixture
def admin_jwt(jwt_factory):
    """JWT with admin claim for testing."""
    return jwt_factory(
        header={"alg": "HS256", "typ": "JWT"},
        payload={"sub": "admin", "role": "admin", "iat": 1516239022},
    )


@pytest.fixture
def none_alg_jwt():
    """JWT with alg:none for testing."""
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "admin", "role": "admin"}

    header_b64 = b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64_url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}."


# ==============================================================================
# File System Fixtures
# ==============================================================================


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_docs_dir(temp_dir):
    """Create sample documentation files for RAG testing."""
    docs_dir = temp_dir / "docs"
    docs_dir.mkdir()

    # Create sample markdown files
    (docs_dir / "sql_injection.md").write_text("""
# SQL Injection Guide

## When to Use
Use SQL injection when you find input fields that query a database.

## Payloads
- `' OR '1'='1`
- `admin' --`
- `UNION SELECT NULL, NULL`

## Agent Takeaway
SQL injection is one of the most common web vulnerabilities.
""")

    (docs_dir / "xss_attacks.md").write_text("""
# Cross-Site Scripting (XSS)

## When to Use
Look for user input reflected in the page output.

## Payloads
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert('XSS')>`

## Agent Takeaway
XSS allows attackers to inject client-side scripts.
""")

    return docs_dir


# ==============================================================================
# CTF Challenge Fixtures
# ==============================================================================


@pytest.fixture
def sample_challenge_descriptions():
    """Sample CTF challenge descriptions for testing."""
    return {
        "sqli": "Can you bypass the login? There must be a way to trick the database. "
        "The flag is stored in the 'flags' table.",
        "xss": "This search feature seems vulnerable. Can you pop an alert box? "
        "The flag will appear in the admin's cookies.",
        "jwt": "The authentication uses JSON Web Tokens. Can you forge a valid admin token? "
        "Try examining the token structure.",
        "ssti": "This template engine looks interesting. Can you execute code on the server? "
        "Try injecting template expressions like {{7*7}}.",
        "file_upload": "Upload your resume in PDF format. Only PDF files are accepted. "
        "Or are they?",
        "xxe": "The XML parser is configured insecurely. Can you read /etc/passwd?",
        "robots": "Explore the website for hidden paths. Where do robots fear to tread?",
    }


@pytest.fixture
def sample_ctf_flags():
    """Sample CTF flags for testing extraction."""
    return [
        "picoCTF{test_flag_123}",
        "flag{simple_flag}",
        "HTB{hackthebox_flag}",
        "ctf{lowercase_flag}",
        "FLAG{UPPERCASE_FLAG}",
    ]


# ==============================================================================
# Encoding Fixtures
# ==============================================================================


@pytest.fixture
def encoding_test_cases():
    """Test cases for encoding/decoding operations."""
    return [
        {
            "original": "Hello, World!",
            "base64": "SGVsbG8sIFdvcmxkIQ==",
            "url_encoded": "Hello%2C%20World%21",
            "hex": "48656c6c6f2c20576f726c6421",
        },
        {
            "original": "<script>alert('xss')</script>",
            "base64": "PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=",
            "url_encoded": "%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E",
        },
        {
            "original": "' OR '1'='1",
            "base64": "JyBPUiAnMSc9JzE=",
            "url_encoded": "%27%20OR%20%271%27%3D%271",
        },
    ]


# ==============================================================================
# Configuration Fixtures
# ==============================================================================


@pytest.fixture
def mock_solver_config(temp_dir):
    """Create a mock SolverConfig for testing."""
    mock_config = Mock()
    mock_config.target_url = "http://test.ctf.local"
    mock_config.timeout = 10.0
    mock_config.max_retries = 3
    mock_config.enable_caching = True
    mock_config.parallel_limit = 5

    # Knowledge base paths
    mock_config.kb_files = []
    mock_config.docs_dirs = [temp_dir / "docs"]
    mock_config.get_all_kb_paths = Mock(return_value=[])

    return mock_config


# ==============================================================================
# RAG Fixtures
# ==============================================================================


@pytest.fixture
def sample_documents():
    """Sample documents for RAG testing."""

    class MockDocument:
        def __init__(self, content: str, metadata: Dict = None):
            self.page_content = content
            self.metadata = metadata or {}

    return [
        MockDocument(
            "SQL injection allows attackers to manipulate database queries. "
            "Common payloads include ' OR '1'='1 and UNION SELECT.",
            {"source": "sql_guide.md", "section": "Introduction"},
        ),
        MockDocument(
            "XSS vulnerabilities occur when user input is reflected without sanitization. "
            "Use <script>alert(1)</script> to test.",
            {"source": "xss_guide.md", "section": "Testing"},
        ),
        MockDocument(
            "JWT tokens have three parts: header, payload, and signature. "
            "The alg:none attack works when signature verification is disabled.",
            {"source": "jwt_guide.md", "section": "Attacks"},
        ),
    ]


# ==============================================================================
# Pytest Hooks
# ==============================================================================


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "slow: marks tests as slow")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "requires_network: marks tests requiring network")


def pytest_collection_modifyitems(config, items):
    """Modify test collection based on markers."""
    # Skip slow tests unless --runslow is provided
    if not config.getoption("--runslow", default=False):
        skip_slow = pytest.mark.skip(reason="use --runslow to run")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--runslow",
        action="store_true",
        default=False,
        help="run slow tests",
    )
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="run integration tests",
    )
