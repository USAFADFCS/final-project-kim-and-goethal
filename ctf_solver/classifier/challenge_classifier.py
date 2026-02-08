"""
Challenge Classification for CTF Solver.

Provides:
- ChallengeClassifier: Analyzes challenge descriptions and URLs to classify challenge types
- PatternMatcher: Matches URL and content patterns for vulnerability detection
- Tool priority mapping for intelligent tool selection
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


class ChallengeCategory(Enum):
    """Main categories of CTF web challenges."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SSTI = "ssti"
    XXE = "xxe"
    FILE_UPLOAD = "file_upload"
    FILE_INCLUSION = "file_inclusion"
    AUTHENTICATION = "authentication"
    JWT = "jwt"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    DESERIALIZATION = "deserialization"
    RACE_CONDITION = "race_condition"
    CRYPTO = "crypto"
    RECONNAISSANCE = "reconnaissance"
    UNKNOWN = "unknown"


@dataclass
class ClassificationResult:
    """Result of challenge classification."""
    primary_category: ChallengeCategory
    confidence: float  # 0.0 to 1.0
    secondary_categories: List[Tuple[ChallengeCategory, float]] = field(default_factory=list)
    matched_keywords: List[str] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)
    suggested_tools: List[str] = field(default_factory=list)
    suggested_approach: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "primary_category": self.primary_category.value,
            "confidence": self.confidence,
            "secondary_categories": [
                {"category": cat.value, "confidence": conf}
                for cat, conf in self.secondary_categories
            ],
            "matched_keywords": self.matched_keywords,
            "matched_patterns": self.matched_patterns,
            "suggested_tools": self.suggested_tools,
            "suggested_approach": self.suggested_approach,
        }


# Keyword patterns for each category with weights
# Format: (pattern, weight) - higher weight = stronger indicator
# Default weight is 1.0; specific patterns like "sqli" get higher weights
CATEGORY_KEYWORDS: Dict[ChallengeCategory, List[str]] = {
    ChallengeCategory.SQL_INJECTION: [
        r"\bsql\s*injection\b",  # Strong indicator
        r"\bsqli\b",  # Strong indicator
        r"\bsql\b", r"\binjection\b", r"\bdatabase\b",
        r"\bquery\b", r"\bselect\b", r"\bunion\b", r"\bor\s*1\s*=\s*1\b",
        r"\b'\s*or\b", r"\bblind\b", r"\bextract\b", r"\bdump\b",
        r"\bmysql\b", r"\bsqlite\b", r"\bpostgres\b", r"\bmssql\b",
        r"\blogin\b.*\bbypass\b", r"\bauthentication\b.*\bbypass\b",
    ],
    ChallengeCategory.XSS: [
        r"\bxss\b",  # Strong indicator
        r"\bcross.?site\s*scripting\b",  # Strong indicator
        r"\bcross.?site\b", r"\bscript\b", r"\balert\b",
        r"\breflected\b", r"\bstored\b", r"\bdom\b", r"\bcookie\b.*\bsteal\b",
        r"\bhtml\s*injection\b", r"\bjavascript\b.*\binjection\b",
    ],
    ChallengeCategory.SSTI: [
        r"\bssti\b",  # Strong indicator
        r"\btemplate\s*injection\b",  # Strong indicator
        r"\bjinja2?\b",  # Strong indicator - Jinja or Jinja2
        r"\btemplate\b", r"\btwig\b",
        r"\bfreemarker\b", r"\berb\b", r"\bsmarty\b", r"\bvelocity\b",
        r"\bmako\b", r"\bthymeleaf\b", r"\bpebble\b",
        r"\{\{.*\}\}", r"\{%.*%\}",
    ],
    ChallengeCategory.XXE: [
        r"\bxxe\b",  # Strong indicator
        r"\bxml\s*external\s*entity\b",  # Strong indicator
        r"\bxml\b",  # Basic indicator
        r"\bexternal\s*entity\b",
        r"\bdtd\b", r"\bdoctype\b", r"\bxml\s*injection\b",
        r"\bxml\s*parser\b", r"\bparse\s*xml\b",
        r"\bfile\s*read\b.*\bxml\b",
    ],
    ChallengeCategory.FILE_UPLOAD: [
        r"\bfile\s*upload\b",  # Strong indicator
        r"\bwebshell\b",  # Strong indicator
        r"\bupload\b", r"\bimage\s*upload\b",
        r"\bshell\b", r"\bphp\b.*\bupload\b",
        r"\bbypass\b.*\bextension\b", r"\bmime\b.*\btype\b",
        r"\bmagic\s*bytes\b", r"\bpolyglot\b",
    ],
    ChallengeCategory.FILE_INCLUSION: [
        r"\blfi\b",  # Strong indicator
        r"\brfi\b",  # Strong indicator
        r"\bfile\s*inclusion\b",  # Strong indicator
        r"\bpath\s*traversal\b", r"\bdirectory\s*traversal\b",
        r"\.\./", r"\.\.\\", r"\binclude\b.*\bfile\b",
        r"\bwrapper\b", r"php://", r"data://",
    ],
    ChallengeCategory.AUTHENTICATION: [
        r"\blogin\b", r"\bauthentication\b", r"\bpassword\b",
        r"\bcredentials\b", r"\bsession\b", r"\bauth\b",
        r"\bbrute\s*force\b", r"\bdefault\b.*\bpassword\b",
        r"\badmin\b.*\baccess\b", r"\bprivilege\b",
    ],
    ChallengeCategory.JWT: [
        r"\bjwt\b",  # Strong indicator
        r"\bjson\s*web\s*token\b",  # Strong indicator
        r"\btoken\b", r"\balgorithm\b.*\bnone\b",
        r"\bhs256\b", r"\brs256\b",
        r"\bsignature\b", r"\bclaim\b", r"\bbearer\b",
    ],
    ChallengeCategory.COMMAND_INJECTION: [
        r"\bcommand\s*injection\b",  # Strong indicator
        r"\bos\s*command\b",  # Strong indicator
        r"\brce\b", r"\bremote\s*code\s*execution\b",
        r"\bshell\b.*\bcommand\b",
        r"\bexec\b", r"\bsystem\b", r"\bping\b", r"\bcurl\b.*\binjection\b",
        r";\s*ls\b", r"\|\s*cat\b", r"`[^`]+`",
    ],
    ChallengeCategory.SSRF: [
        r"\bssrf\b",  # Strong indicator
        r"\bserver.?side\s*request\s*forgery\b",  # Strong indicator
        r"\bserver.?side\s*request\b",
        r"\burl\s*fetch\b", r"\binternal\b.*\bnetwork\b",
        r"\blocalhost\b", r"\b127\.0\.0\.1\b", r"\bmetadata\b",
        r"\bcloud\b.*\bmetadata\b", r"\baws\b.*\bmetadata\b",
    ],
    ChallengeCategory.DESERIALIZATION: [
        r"\bdeserialization\b", r"\bunserialize\b", r"\bpickle\b",
        r"\bobject\s*injection\b", r"\bphp\s*object\b",
        r"\byaml\b.*\binjection\b", r"\bjava\b.*\bobject\b",
    ],
    ChallengeCategory.RACE_CONDITION: [
        r"\brace\s*condition\b", r"\btoctou\b", r"\btime.?of.?check\b",
        r"\bconcurrent\b", r"\bparallel\b.*\brequest\b",
        r"\bdouble\s*spend\b", r"\batomic\b",
    ],
    ChallengeCategory.CRYPTO: [
        r"\bcrypto\b", r"\bencrypt\b", r"\bdecrypt\b", r"\bcipher\b",
        r"\bhash\b", r"\bmd5\b", r"\bsha\b", r"\baes\b", r"\brsa\b",
        r"\bbase64\b", r"\bxor\b", r"\brot13\b", r"\bpkcs\b",
    ],
    ChallengeCategory.RECONNAISSANCE: [
        r"\brecon\b", r"\benumerate\b", r"\bdiscover\b", r"\bfind\b",
        r"\bhidden\b", r"\bsecret\b", r"\brobots\.txt\b",
        r"\bdirectory\b.*\blist\b", r"\bbrute\s*force\b.*\bpath\b",
    ],
}

# URL patterns that indicate specific vulnerability types
URL_PATTERNS: Dict[ChallengeCategory, List[str]] = {
    ChallengeCategory.SQL_INJECTION: [
        r"\?.*id=\d+", r"\?.*user=", r"\?.*name=", r"\?.*search=",
        r"\?.*query=", r"\?.*q=", r"/login", r"/admin",
    ],
    ChallengeCategory.FILE_INCLUSION: [
        r"\?.*file=", r"\?.*page=", r"\?.*path=", r"\?.*include=",
        r"\?.*template=", r"\?.*lang=", r"\?.*doc=",
    ],
    ChallengeCategory.SSRF: [
        r"\?.*url=", r"\?.*redirect=", r"\?.*link=", r"\?.*fetch=",
        r"\?.*proxy=", r"\?.*callback=", r"\?.*image=",
    ],
    ChallengeCategory.FILE_UPLOAD: [
        r"/upload", r"/file", r"/image", r"/avatar", r"/profile",
        r"/attachment", r"/media",
    ],
    ChallengeCategory.AUTHENTICATION: [
        r"/login", r"/signin", r"/auth", r"/admin", r"/dashboard",
        r"/panel", r"/account", r"/user",
    ],
}

# Tool priority mapping for each category
TOOL_PRIORITIES: Dict[ChallengeCategory, List[str]] = {
    ChallengeCategory.SQL_INJECTION: [
        "sqli_probe", "sqli_column_counter", "blind_sqli_boolean",
        "blind_sqli_time", "sqli_data_dumper", "response_diff",
        "http_fetch", "form_submit",
    ],
    ChallengeCategory.XSS: [
        "http_fetch", "html_inspector", "javascript_source",
        "response_search", "cookie_inspector", "form_submit",
    ],
    ChallengeCategory.SSTI: [
        "ssti_probe", "ssti_exploit_suggester", "http_fetch",
        "form_submit", "response_search",
    ],
    ChallengeCategory.XXE: [
        "xxe_probe", "xxe_payload_generator", "xxe_doctype_builder",
        "http_fetch", "form_submit",
    ],
    ChallengeCategory.FILE_UPLOAD: [
        "file_upload", "upload_location_finder", "path_enumerator",
        "http_fetch", "html_inspector",
    ],
    ChallengeCategory.FILE_INCLUSION: [
        "http_fetch", "path_enumerator", "backup_file_finder",
        "response_search", "encoding",
    ],
    ChallengeCategory.AUTHENTICATION: [
        "http_fetch", "form_submit", "cookie_inspector", "cookie_set",
        "jwt", "response_diff", "timing_compare",
    ],
    ChallengeCategory.JWT: [
        "jwt", "http_fetch", "cookie_inspector", "encoding",
        "response_search",
    ],
    ChallengeCategory.COMMAND_INJECTION: [
        "http_fetch", "form_submit", "response_search",
        "timing_compare", "response_diff",
    ],
    ChallengeCategory.SSRF: [
        "http_fetch", "form_submit", "response_search",
        "response_diff",
    ],
    ChallengeCategory.DESERIALIZATION: [
        "http_fetch", "encoding", "form_submit", "response_search",
    ],
    ChallengeCategory.RACE_CONDITION: [
        "http_fetch", "form_submit", "timing_compare",
        "response_diff", "cookie_inspector",
    ],
    ChallengeCategory.CRYPTO: [
        "encoding", "hash_identifier", "http_fetch",
        "response_search", "jwt",
    ],
    ChallengeCategory.RECONNAISSANCE: [
        "robots_txt", "path_enumerator", "backup_file_finder",
        "http_fetch", "html_inspector", "javascript_source",
    ],
    ChallengeCategory.UNKNOWN: [
        "http_fetch", "html_inspector", "robots_txt",
        "path_enumerator", "response_search", "ctf_knowledge_query",
    ],
}

# Approach suggestions for each category
APPROACH_SUGGESTIONS: Dict[ChallengeCategory, str] = {
    ChallengeCategory.SQL_INJECTION: (
        "1. Identify injection points (forms, URL parameters)\n"
        "2. Test with basic payloads (' OR 1=1 --, etc.)\n"
        "3. Determine database type from error messages\n"
        "4. Use UNION-based or blind techniques to extract data\n"
        "5. Look for the flag in database tables"
    ),
    ChallengeCategory.XSS: (
        "1. Find user input reflection points\n"
        "2. Test for reflected/stored XSS\n"
        "3. Check for DOM-based XSS in JavaScript\n"
        "4. Bypass filters with encoding or alternative payloads\n"
        "5. Exfiltrate cookies or access restricted content"
    ),
    ChallengeCategory.SSTI: (
        "1. Identify template engine (test {{7*7}}, ${7*7}, etc.)\n"
        "2. Confirm SSTI vulnerability\n"
        "3. Determine template engine version\n"
        "4. Use engine-specific RCE payloads\n"
        "5. Read flag file or execute commands"
    ),
    ChallengeCategory.XXE: (
        "1. Find XML input endpoints\n"
        "2. Test with external entity declarations\n"
        "3. Try file read (/etc/passwd, flag.txt)\n"
        "4. Use PHP filter wrapper for base64 encoding\n"
        "5. Consider out-of-band data exfiltration"
    ),
    ChallengeCategory.FILE_UPLOAD: (
        "1. Analyze upload restrictions (extension, MIME, content)\n"
        "2. Test extension bypass techniques\n"
        "3. Try polyglot files (magic bytes + code)\n"
        "4. Find upload location\n"
        "5. Execute uploaded webshell"
    ),
    ChallengeCategory.FILE_INCLUSION: (
        "1. Identify file parameter\n"
        "2. Test path traversal (../../etc/passwd)\n"
        "3. Try wrapper protocols (php://filter, data://)\n"
        "4. Read source code for additional vulnerabilities\n"
        "5. Chain with log poisoning for RCE if possible"
    ),
    ChallengeCategory.AUTHENTICATION: (
        "1. Analyze login mechanism\n"
        "2. Test default credentials\n"
        "3. Check for bypass vulnerabilities\n"
        "4. Analyze session management\n"
        "5. Look for privilege escalation"
    ),
    ChallengeCategory.JWT: (
        "1. Decode and analyze JWT structure\n"
        "2. Test algorithm confusion (none, HS256 with public key)\n"
        "3. Check for weak secrets\n"
        "4. Modify claims (role, user ID)\n"
        "5. Forge token and escalate privileges"
    ),
    ChallengeCategory.COMMAND_INJECTION: (
        "1. Identify command execution points\n"
        "2. Test with command separators (; | && ||)\n"
        "3. Check for blind injection with timing\n"
        "4. Bypass filters with encoding/alternatives\n"
        "5. Read flag or establish reverse shell"
    ),
    ChallengeCategory.SSRF: (
        "1. Identify URL/fetch parameters\n"
        "2. Test internal network access (localhost, 127.0.0.1)\n"
        "3. Try cloud metadata endpoints\n"
        "4. Bypass filters with alternative notations\n"
        "5. Access internal services or read files"
    ),
    ChallengeCategory.DESERIALIZATION: (
        "1. Identify serialization format\n"
        "2. Analyze application for gadget chains\n"
        "3. Craft malicious serialized object\n"
        "4. Achieve RCE or file read\n"
        "5. Extract the flag"
    ),
    ChallengeCategory.RACE_CONDITION: (
        "1. Identify state-dependent operations\n"
        "2. Look for time-of-check to time-of-use gaps\n"
        "3. Send parallel requests\n"
        "4. Exploit inconsistent state\n"
        "5. Achieve double spending or bypass checks"
    ),
    ChallengeCategory.CRYPTO: (
        "1. Identify encryption/encoding scheme\n"
        "2. Look for weak algorithms or implementations\n"
        "3. Test for padding oracle, ECB mode issues\n"
        "4. Crack weak keys or find key leakage\n"
        "5. Decrypt or forge authenticated data"
    ),
    ChallengeCategory.RECONNAISSANCE: (
        "1. Check robots.txt and sitemap\n"
        "2. Enumerate directories and files\n"
        "3. Analyze HTML/JS for hidden paths\n"
        "4. Look for backup files and git leaks\n"
        "5. Find hidden functionality or secrets"
    ),
    ChallengeCategory.UNKNOWN: (
        "1. Perform basic reconnaissance\n"
        "2. Analyze the application structure\n"
        "3. Look for common vulnerability patterns\n"
        "4. Test input points for injection\n"
        "5. Consult CTF knowledge base for hints"
    ),
}


class PatternMatcher:
    """
    Matches URL and content patterns to identify vulnerability types.

    Provides regex-based pattern matching with scoring for
    vulnerability identification.
    """

    # Strong indicator patterns that should give higher weight
    STRONG_INDICATORS = {
        r"\bsql\s*injection\b", r"\bsqli\b",
        r"\bxss\b", r"\bcross.?site\s*scripting\b",
        r"\bssti\b", r"\btemplate\s*injection\b", r"\bjinja2?\b",
        r"\bxxe\b", r"\bxml\s*external\s*entity\b",
        r"\bfile\s*upload\b", r"\bwebshell\b",
        r"\blfi\b", r"\brfi\b", r"\bfile\s*inclusion\b",
        r"\bjwt\b", r"\bjson\s*web\s*token\b",
        r"\bcommand\s*injection\b", r"\bos\s*command\b",
        r"\bssrf\b", r"\bserver.?side\s*request\s*forgery\b",
    }

    def __init__(self):
        """Initialize the pattern matcher with compiled regexes."""
        self._keyword_patterns: Dict[ChallengeCategory, List[re.Pattern]] = {}
        self._url_patterns: Dict[ChallengeCategory, List[re.Pattern]] = {}
        self._strong_patterns: Set[str] = set()

        # Compile keyword patterns
        for category, patterns in CATEGORY_KEYWORDS.items():
            self._keyword_patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        # Compile URL patterns
        for category, patterns in URL_PATTERNS.items():
            self._url_patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        # Compile strong indicator patterns
        for pattern in self.STRONG_INDICATORS:
            self._strong_patterns.add(pattern.lower())

    def _is_strong_indicator(self, pattern: str) -> bool:
        """Check if a pattern is a strong indicator."""
        return pattern.lower() in self._strong_patterns

    def match_keywords(
        self,
        text: str,
    ) -> List[Tuple[ChallengeCategory, float, List[str]]]:
        """
        Match keywords in text against vulnerability patterns.

        Uses weighted scoring where strong indicators give higher scores.

        Args:
            text: Text to analyze (description, hints, response content)

        Returns:
            List of (category, score, matched_patterns) sorted by score
        """
        results = []

        for category, patterns in self._keyword_patterns.items():
            matches = []
            score = 0.0

            for pattern in patterns:
                if pattern.search(text):
                    matches.append(pattern.pattern)
                    # Strong indicators get higher weight
                    if self._is_strong_indicator(pattern.pattern):
                        score += 0.4
                    else:
                        score += 0.15

            if matches:
                # Cap score at 1.0
                score = min(1.0, score)
                results.append((category, score, matches))

        # Sort by score descending
        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def match_url(
        self,
        url: str,
    ) -> List[Tuple[ChallengeCategory, float, List[str]]]:
        """
        Match URL against vulnerability patterns.

        Uses weighted scoring where each URL pattern match gives 0.2 score.

        Args:
            url: URL to analyze

        Returns:
            List of (category, score, matched_patterns) sorted by score
        """
        results = []

        for category, patterns in self._url_patterns.items():
            matches = []
            score = 0.0

            for pattern in patterns:
                if pattern.search(url):
                    matches.append(pattern.pattern)
                    score += 0.25  # Each URL pattern match adds 0.25

            if matches:
                score = min(1.0, score)
                results.append((category, score, matches))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def analyze_url_structure(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL structure for potential vulnerability indicators.

        Args:
            url: URL to analyze

        Returns:
            Dictionary with analysis results
        """
        try:
            parsed = urlparse(url)
        except Exception:
            return {"error": "Invalid URL"}

        analysis = {
            "scheme": parsed.scheme,
            "host": parsed.netloc,
            "path": parsed.path,
            "has_query": bool(parsed.query),
            "query_params": [],
            "interesting_params": [],
            "path_hints": [],
        }

        # Parse query parameters
        if parsed.query:
            params = parsed.query.split("&")
            for param in params:
                if "=" in param:
                    key, value = param.split("=", 1)
                    analysis["query_params"].append({"key": key, "value": value})

                    # Check for interesting parameter names
                    interesting_keys = [
                        "id", "user", "name", "file", "page", "path",
                        "url", "redirect", "query", "search", "cmd",
                        "exec", "template", "include", "lang",
                    ]
                    if any(k in key.lower() for k in interesting_keys):
                        analysis["interesting_params"].append(key)

        # Analyze path
        path_parts = parsed.path.lower().split("/")
        interesting_paths = [
            "admin", "login", "upload", "api", "debug", "test",
            "backup", "config", "internal", "private",
        ]
        for part in path_parts:
            if any(ip in part for ip in interesting_paths):
                analysis["path_hints"].append(part)

        return analysis


class ChallengeClassifier:
    """
    Classifies CTF challenges based on descriptions, hints, and URLs.

    Uses keyword matching, URL pattern analysis, and heuristics to
    determine the most likely challenge type and suggest appropriate tools.

    Usage:
        classifier = ChallengeClassifier()

        result = classifier.classify(
            description="Login bypass challenge",
            url="http://ctf.example.com/login?user=admin",
            hints=["Think about SQL"],
        )

        print(f"Category: {result.primary_category.value}")
        print(f"Suggested tools: {result.suggested_tools}")
    """

    def __init__(self):
        """Initialize the classifier."""
        self.pattern_matcher = PatternMatcher()

    def classify(
        self,
        description: Optional[str] = None,
        url: Optional[str] = None,
        hints: Optional[List[str]] = None,
        response_content: Optional[str] = None,
    ) -> ClassificationResult:
        """
        Classify a challenge based on available information.

        Args:
            description: Challenge description text
            url: Challenge URL
            hints: List of hint strings
            response_content: HTTP response content for additional analysis

        Returns:
            ClassificationResult with category, confidence, and suggestions
        """
        scores: Dict[ChallengeCategory, float] = {}
        all_matched_keywords: List[str] = []
        all_matched_patterns: List[str] = []

        # Combine all text for keyword matching
        combined_text = ""
        if description:
            combined_text += description + " "
        if hints:
            combined_text += " ".join(hints) + " "
        if response_content:
            # Limit response content to avoid overwhelming the classifier
            combined_text += response_content[:5000]

        # Match keywords in combined text
        if combined_text.strip():
            keyword_matches = self.pattern_matcher.match_keywords(combined_text)
            for category, score, patterns in keyword_matches:
                scores[category] = scores.get(category, 0) + score * 0.6
                all_matched_keywords.extend(patterns)

        # Match URL patterns
        if url:
            url_matches = self.pattern_matcher.match_url(url)
            for category, score, patterns in url_matches:
                scores[category] = scores.get(category, 0) + score * 0.3
                all_matched_patterns.extend(patterns)

            # Analyze URL structure
            url_analysis = self.pattern_matcher.analyze_url_structure(url)
            if url_analysis.get("interesting_params"):
                # Boost SQL injection for ID-like parameters
                if any("id" in p.lower() for p in url_analysis["interesting_params"]):
                    scores[ChallengeCategory.SQL_INJECTION] = scores.get(
                        ChallengeCategory.SQL_INJECTION, 0
                    ) + 0.1
                # Boost file inclusion for file-like parameters
                if any(
                    p.lower() in ("file", "page", "path", "include")
                    for p in url_analysis["interesting_params"]
                ):
                    scores[ChallengeCategory.FILE_INCLUSION] = scores.get(
                        ChallengeCategory.FILE_INCLUSION, 0
                    ) + 0.1

        # Determine primary category
        if not scores:
            primary_category = ChallengeCategory.UNKNOWN
            confidence = 0.0
        else:
            sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
            primary_category = sorted_scores[0][0]
            confidence = min(1.0, sorted_scores[0][1])

            # Get secondary categories
            secondary_categories = [
                (cat, min(1.0, score))
                for cat, score in sorted_scores[1:4]
                if score > 0.1
            ]

        # Get suggested tools
        suggested_tools = TOOL_PRIORITIES.get(
            primary_category, TOOL_PRIORITIES[ChallengeCategory.UNKNOWN]
        )

        # Get approach suggestion
        suggested_approach = APPROACH_SUGGESTIONS.get(
            primary_category, APPROACH_SUGGESTIONS[ChallengeCategory.UNKNOWN]
        )

        return ClassificationResult(
            primary_category=primary_category,
            confidence=confidence,
            secondary_categories=secondary_categories if scores else [],
            matched_keywords=list(set(all_matched_keywords)),
            matched_patterns=list(set(all_matched_patterns)),
            suggested_tools=suggested_tools,
            suggested_approach=suggested_approach,
        )

    def classify_from_config(
        self,
        config: Any,  # SolverConfig
        response_content: Optional[str] = None,
    ) -> ClassificationResult:
        """
        Classify a challenge using configuration object.

        Args:
            config: SolverConfig object with challenge_url, description, hints
            response_content: Optional response content for analysis

        Returns:
            ClassificationResult
        """
        hints = None
        if hasattr(config, "challenge_hints") and config.challenge_hints:
            hints = [config.challenge_hints]

        return self.classify(
            description=getattr(config, "challenge_description", None),
            url=getattr(config, "challenge_url", None),
            hints=hints,
            response_content=response_content,
        )

    def get_tool_priority(
        self,
        category: ChallengeCategory,
    ) -> List[str]:
        """
        Get prioritized list of tools for a category.

        Args:
            category: Challenge category

        Returns:
            List of tool names in priority order
        """
        return TOOL_PRIORITIES.get(category, TOOL_PRIORITIES[ChallengeCategory.UNKNOWN])

    def get_all_categories(self) -> List[str]:
        """Get list of all category values."""
        return [c.value for c in ChallengeCategory]

    def suggest_initial_tools(
        self,
        classification: ClassificationResult,
        max_tools: int = 5,
    ) -> List[str]:
        """
        Suggest initial tools to use based on classification.

        Combines primary and secondary category tools, prioritizing
        by confidence.

        Args:
            classification: ClassificationResult from classify()
            max_tools: Maximum number of tools to suggest

        Returns:
            List of tool names
        """
        tool_set: Set[str] = set()
        tools_list: List[str] = []

        # Add primary category tools first
        for tool in classification.suggested_tools:
            if tool not in tool_set:
                tool_set.add(tool)
                tools_list.append(tool)
                if len(tools_list) >= max_tools:
                    break

        # Add secondary category tools if room
        if len(tools_list) < max_tools:
            for category, _ in classification.secondary_categories:
                for tool in self.get_tool_priority(category):
                    if tool not in tool_set:
                        tool_set.add(tool)
                        tools_list.append(tool)
                        if len(tools_list) >= max_tools:
                            break
                if len(tools_list) >= max_tools:
                    break

        return tools_list


def create_classifier() -> ChallengeClassifier:
    """Factory function to create a ChallengeClassifier instance."""
    return ChallengeClassifier()
