"""
Query expansion for improved RAG retrieval in CTF solving.

Expands user queries with domain-specific synonyms, related terms,
and alternative phrasings to improve recall.
"""

import re
from typing import Dict, List, Set, Tuple


class QueryExpander:
    """
    Expands CTF-related queries with synonyms and related terms.

    Uses domain-specific mappings to expand queries for better recall
    without requiring external API calls or heavy NLP models.
    """

    # CTF-specific term mappings: term -> list of related terms
    TERM_EXPANSIONS: Dict[str, List[str]] = {
        # SQL Injection variants
        "sqli": ["sql injection", "sql", "database injection", "union", "blind sql"],
        "sql injection": [
            "sqli",
            "sql",
            "union injection",
            "blind sqli",
            "error-based",
        ],
        "union": ["union select", "sql union", "column count", "union injection"],
        "blind sqli": [
            "time-based",
            "boolean-based",
            "blind sql injection",
            "inferential",
        ],
        # XSS variants
        "xss": [
            "cross-site scripting",
            "script injection",
            "reflected xss",
            "stored xss",
            "dom xss",
        ],
        "cross-site scripting": ["xss", "script injection", "html injection"],
        "reflected xss": ["xss", "non-persistent xss", "type 1 xss"],
        "stored xss": ["persistent xss", "type 2 xss", "xss"],
        "dom xss": ["dom-based xss", "client-side xss", "type 0 xss"],
        # Injection attacks
        "injection": [
            "code injection",
            "command injection",
            "sql injection",
            "os injection",
        ],
        "command injection": [
            "os injection",
            "shell injection",
            "rce",
            "code execution",
        ],
        "rce": [
            "remote code execution",
            "code execution",
            "command injection",
            "shell",
        ],
        "ssti": [
            "server-side template injection",
            "template injection",
            "jinja",
            "twig",
        ],
        "template injection": ["ssti", "jinja2", "twig", "freemarker", "erb"],
        # Authentication
        "auth": ["authentication", "login", "session", "password", "credential"],
        "authentication": ["auth", "login", "password", "credential", "session"],
        "login": ["authentication", "sign in", "credential", "password", "auth bypass"],
        "bypass": ["auth bypass", "authentication bypass", "circumvent", "skip"],
        "jwt": ["json web token", "token", "bearer", "authentication"],
        # Web security
        "csrf": ["cross-site request forgery", "xsrf", "token", "state change"],
        "ssrf": ["server-side request forgery", "internal request", "localhost"],
        "xxe": ["xml external entity", "xml injection", "dtd", "entity expansion"],
        "lfi": ["local file inclusion", "file inclusion", "path traversal", "..%2f"],
        "rfi": ["remote file inclusion", "file inclusion", "php include"],
        "path traversal": ["directory traversal", "lfi", "..%2f", "dot dot slash"],
        # Serialization
        "deserialization": ["deserialize", "unserialize", "pickle", "object injection"],
        "pickle": ["python pickle", "deserialization", "unpickle", "__reduce__"],
        "serialize": ["serialization", "marshal", "object"],
        # Cryptography
        "crypto": ["cryptography", "encryption", "cipher", "hash"],
        "hash": ["hashing", "md5", "sha", "bcrypt", "password hash"],
        "encryption": ["encrypt", "cipher", "aes", "rsa", "decrypt"],
        # File upload
        "upload": ["file upload", "upload bypass", "webshell", "extension"],
        "webshell": ["shell", "backdoor", "php shell", "web shell"],
        # Race conditions
        "race": ["race condition", "toctou", "concurrency", "parallel"],
        "race condition": ["race", "toctou", "time of check", "concurrent"],
        "toctou": ["time of check time of use", "race condition", "race"],
        # GraphQL
        "graphql": ["graph ql", "graphql injection", "introspection", "query"],
        "introspection": ["graphql introspection", "__schema", "graphql"],
        # WebSocket
        "websocket": ["web socket", "ws", "wss", "socket", "real-time"],
        # Client-side / access control
        "paywall": [
            "client-side bypass",
            "dom bypass",
            "css overlay",
            "access control",
            "javascript validation bypass",
            "subscription bypass",
            "premium content",
        ],
        "client-side": [
            "javascript validation",
            "dom manipulation",
            "css bypass",
            "front-end bypass",
            "browser-side",
            "paywall",
        ],
        "dom": [
            "document object model",
            "dom manipulation",
            "dom clobbering",
            "client-side",
            "html element",
        ],
        "access control": [
            "authorization",
            "privilege escalation",
            "role bypass",
            "cookie manipulation",
            "client-side restriction",
        ],
        "overlay": ["css overlay", "modal", "paywall", "dom bypass", "display none"],
        # General web
        "cookie": ["session cookie", "http cookie", "cookie flag", "httponly"],
        "session": ["session cookie", "session id", "session management"],
        "header": ["http header", "request header", "response header"],
        "robots": ["robots.txt", "sitemap", "disallow", "crawler"],
        "flag": ["ctf flag", "capture the flag", "flag format"],
        # Techniques
        "bruteforce": ["brute force", "dictionary attack", "wordlist", "crack"],
        "enum": ["enumeration", "enumerate", "discovery", "scan"],
        "enumeration": ["enum", "discovery", "directory busting", "fuzzing"],
        "fuzzing": ["fuzz", "fuzzer", "mutation", "input testing"],
        "exploit": ["exploitation", "attack", "payload", "poc"],
    }

    # Phrases that should be kept together during expansion
    COMPOUND_TERMS: List[str] = [
        "sql injection",
        "cross-site scripting",
        "command injection",
        "template injection",
        "file inclusion",
        "race condition",
        "authentication bypass",
        "path traversal",
        "file upload",
        "remote code execution",
        "server-side request forgery",
        "cross-site request forgery",
        "xml external entity",
        "json web token",
    ]

    def __init__(self, max_expansions: int = 5):
        """
        Initialize QueryExpander.

        Args:
            max_expansions: Maximum number of expansion terms to add per query term
        """
        self.max_expansions = max_expansions
        # Build reverse mapping for efficient lookup
        self._build_normalized_mappings()

    def _build_normalized_mappings(self) -> None:
        """Build case-insensitive term mappings."""
        self._normalized_expansions: Dict[str, List[str]] = {}
        for term, expansions in self.TERM_EXPANSIONS.items():
            self._normalized_expansions[term.lower()] = expansions

    def _extract_terms(self, query: str) -> List[str]:
        """
        Extract terms from query, preserving compound terms.

        Args:
            query: The input query string

        Returns:
            List of terms (compound and single)
        """
        query_lower = query.lower()
        terms: List[str] = []

        # First, find all compound terms
        found_compounds: List[Tuple[int, int, str]] = []
        for compound in self.COMPOUND_TERMS:
            idx = query_lower.find(compound)
            if idx != -1:
                found_compounds.append((idx, idx + len(compound), compound))
                terms.append(compound)

        # Sort compounds by position for masking
        found_compounds.sort()

        # Mask compound terms to avoid extracting their parts
        masked_query = query_lower
        for start, end, compound in reversed(found_compounds):
            masked_query = (
                masked_query[:start] + " " * len(compound) + masked_query[end:]
            )

        # Extract remaining single terms (3+ characters)
        single_terms = re.findall(r"\b[a-z]{3,}\b", masked_query)
        terms.extend(single_terms)

        return terms

    def expand_query(self, query: str) -> str:
        """
        Expand a query with related terms.

        Args:
            query: The original query string

        Returns:
            Expanded query string with additional terms
        """
        if not query or not query.strip():
            return query

        terms = self._extract_terms(query)
        expansions: Set[str] = set()

        for term in terms:
            term_lower = term.lower()
            if term_lower in self._normalized_expansions:
                # Get expansions, limited to max_expansions
                related = self._normalized_expansions[term_lower][: self.max_expansions]
                expansions.update(related)

        # Remove terms already in original query
        query_lower = query.lower()
        new_terms = [exp for exp in expansions if exp.lower() not in query_lower]
        new_terms = new_terms[:8]  # Cap total expansions to prevent query dilution

        if new_terms:
            # Append expansions to original query
            return f"{query} {' '.join(new_terms)}"

        return query

    def get_expansion_terms(self, term: str) -> List[str]:
        """
        Get expansion terms for a single term.

        Args:
            term: A single term to expand

        Returns:
            List of related terms
        """
        term_lower = term.lower()
        return self._normalized_expansions.get(term_lower, [])

    def add_custom_expansion(self, term: str, expansions: List[str]) -> None:
        """
        Add custom term expansion.

        Args:
            term: The term to expand
            expansions: List of expansion terms
        """
        self.TERM_EXPANSIONS[term.lower()] = expansions
        self._normalized_expansions[term.lower()] = expansions


def create_query_expander(max_expansions: int = 5) -> QueryExpander:
    """
    Factory function to create a QueryExpander.

    Args:
        max_expansions: Maximum expansion terms per query term

    Returns:
        Configured QueryExpander instance
    """
    return QueryExpander(max_expansions=max_expansions)
