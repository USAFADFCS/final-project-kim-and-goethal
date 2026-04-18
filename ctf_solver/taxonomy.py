"""
Canonical tool → category taxonomy (Batch C #14).

Single source of truth for the ``tool_name → category_key`` mapping that
``failure_analyzer`` uses to slug filenames, dedup rule docs, and label
lessons-learned output.  ``CATEGORY_LABELS`` maps the canonical category
keys to human-readable display strings.

Previously three dicts across ``failure_analyzer._TOOL_TO_CATEGORY``,
``tools.logging_wrapper._TOOL_CATEGORIES``, and
``classifier.TOOL_PRIORITIES`` drifted independently.  The first is now an
alias of ``TOOL_TO_CATEGORY``; ``logging_wrapper`` intentionally remaps a
small subset for display-specific suggestion text (jwt_attacks → jwt,
attack_planner → planning, html_inspector → recon) and uses the canonical
dict as a drift-protection baseline via ``tests/test_taxonomy.py``.
``classifier.TOOL_PRIORITIES`` has a different shape (category → ordered
tool list) and a different purpose (suggestion prioritization per
challenge type), so it is not folded in.

Adding a new tool: add the ``name`` → ``category_key`` entry here first;
both failure_analyzer and the drift test will pick it up automatically.
"""

from typing import Dict

TOOL_TO_CATEGORY: Dict[str, str] = {
    # SQL injection
    "sqli_probe": "sql_injection",
    "sqli_column_counter": "sql_injection",
    "blind_sqli_boolean": "sql_injection",
    "blind_sqli_time": "sql_injection",
    "sqli_data_dumper": "sql_injection",
    "sql_pattern_hint": "sql_injection",
    # Auth / crypto
    "jwt_tool": "jwt_attacks",
    "cookie_inspector": "cookies_auth",
    "cookie_set": "cookies_auth",
    # Injections
    "ssti_probe": "ssti",
    "ssti_exploit_suggester": "ssti",
    "xpath_probe": "xpath_injection",
    "xpath_blind_boolean": "xpath_injection",
    "xpath_payload_generator": "xpath_injection",
    "cmdi_probe": "command_injection",
    "cmdi_payload_generator": "command_injection",
    "nosql_probe": "nosql_injection",
    "nosql_payload_generator": "nosql_injection",
    # File handling
    "file_upload": "file_upload",
    "upload_location_finder": "file_upload",
    "lfi_probe": "file_inclusion",
    "lfi_payload_generator": "file_inclusion",
    "php_filter_chain": "php_filter",
    # Parsers / serialization
    "xxe_probe": "xxe",
    "xxe_payload_generator": "xxe",
    "xxe_doctype_builder": "xxe",
    "deserialization_probe": "deserialization",
    "deserialization_payload_generator": "deserialization",
    "parser_differential_probe": "parser_differential",
    # XSS / client-side
    "xss_probe": "xss",
    "xss_payload_generator": "xss",
    "csp_analyzer": "xss",
    "dom_clobbering_payload_generator": "dom_clobbering",
    "css_injection_payload_generator": "css_injection",
    "css_exfiltration_builder": "css_injection",
    # Recon (no-exploit).  NOTE: ``http_fetch`` is intentionally NOT in this
    # dict — it's the most-used tool in every run, so including it would bias
    # ``failure_analyzer`` category inference toward "recon" for everything.
    # ``tools.logging_wrapper`` handles ``http_fetch`` separately for its
    # own display purposes (see _DISPLAY_ONLY_OVERRIDES in tests/test_taxonomy.py).
    "robots_txt": "recon",
    "path_enumerator": "recon",
    "backup_file_finder": "recon",
    "timing_compare": "recon",
    "response_diff": "recon",
    "request_repeater": "recon",
    "attack_planner": "recon",
    # Client-side analysis (still just looking, but richer than recon)
    "html_inspector": "client_side",
    "javascript_source": "client_side",
    # Filters / WAF
    "filter_enumerator": "filter_bypass",
    "payload_mutator": "filter_bypass",
    # Server-side attacks
    "ssrf_probe": "ssrf",
    "ssrf_payload_generator": "ssrf",
    "http_smuggling_probe": "http_smuggling",
    "flask_session_forge": "flask_session",
    "crlf_probe": "crlf_injection",
    # Crypto / deser adjacent
    "crypto_probe": "crypto",
    "crypto_analyzer": "crypto",
    "crypto_payload_generator": "crypto",
    # API / protocol
    "graphql_introspection": "graphql",
    "graphql_query": "graphql",
    "websocket_probe": "websocket",
    "oauth_probe": "oauth_oidc",
    "oauth_payload_generator": "oauth_oidc",
    # Concurrency / logic
    "race_condition": "race_condition",
    "php_type_juggling": "php_type_juggling",
    "prototype_pollution_probe": "prototype_pollution",
    "idor_enumerator": "idor",
    "open_redirect_probe": "open_redirect",
    # Binary
    "wasm_analyzer": "wasm_re",
    # Utilities
    "encoding": "encoding_obfuscation",
}


CATEGORY_LABELS: Dict[str, str] = {
    "sql_injection": "SQL Injection",
    "jwt_attacks": "JWT Attacks",
    "ssti": "Server-Side Template Injection",
    "file_upload": "File Upload Vulnerabilities",
    "xxe": "XML External Entity (XXE)",
    "cookies_auth": "Cookies / Session / Auth Bypass",
    "recon": "Reconnaissance & Hidden Paths",
    "client_side": "Client-Side (HTML/JS) Analysis",
    "command_injection": "Command Injection",
    "xpath_injection": "XPath Injection",
    "filter_bypass": "Filter/WAF Bypass",
    "file_inclusion": "Local/Remote File Inclusion",
    "nosql_injection": "NoSQL Injection",
    "ssrf": "Server-Side Request Forgery",
    "crypto": "Cryptographic Attacks",
    "deserialization": "Insecure Deserialization",
    "xss": "Cross-Site Scripting (XSS)",
    "graphql": "GraphQL Exploitation",
    "race_condition": "Race Condition",
    "crlf_injection": "CRLF / Header Injection",
    "php_type_juggling": "PHP Type Juggling",
    "prototype_pollution": "Prototype / Class Pollution",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "open_redirect": "Open Redirect",
    "css_injection": "CSS Injection / Exfiltration",
    "http_smuggling": "HTTP Request Smuggling",
    "flask_session": "Flask Session Cookie Forgery",
    "dom_clobbering": "DOM Clobbering",
    "oauth_oidc": "OAuth / OpenID Connect",
    "php_filter": "PHP Filter Chain",
    "parser_differential": "Parser Differential",
    "websocket": "WebSocket Exploitation",
    "wasm_re": "WASM / Reverse Engineering",
    "encoding_obfuscation": "Encoding / Obfuscation",
    "unknown": "General Web Exploitation",
}


__all__ = ["TOOL_TO_CATEGORY", "CATEGORY_LABELS"]
