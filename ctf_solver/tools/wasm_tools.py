"""
WebAssembly analysis tools for CTF solving.

Provides binary parsing and analysis of .wasm modules to extract
embedded flags, XOR-encoded keys, and validation logic without
requiring external tools (wasm2wat, wasmtime, etc.).
"""

import json
import re
from typing import Dict, List, Optional, Tuple

import requests

# Flag pattern — same regex as http_tools for consistency
_FLAG_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"((?:picoCTF|HTB|THM|FLAG|CTF|MetaCTF|[A-Za-z0-9_]{1,20})\{[^}\n\r]{1,200}\})",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# WASM binary format helpers
# ---------------------------------------------------------------------------


def _read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """Read an unsigned LEB128 integer from data at offset. Returns (value, new_offset)."""
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            break
        shift += 7
    return result, offset


def _read_string(data: bytes, offset: int) -> Tuple[str, int]:
    """Read a length-prefixed UTF-8 string. Returns (string, new_offset)."""
    length, offset = _read_uleb128(data, offset)
    s = data[offset : offset + length].decode("utf-8", "replace")
    return s, offset + length


def _parse_wasm_sections(binary: bytes) -> Dict[int, bytes]:
    """
    Parse a WASM binary into a dict of section_id -> payload bytes.

    Validates magic bytes (\x00asm) and version (1).

    Returns:
        Dict mapping section IDs to their payload bytes.

    Raises:
        ValueError: if binary does not start with WASM magic bytes.
    """
    if len(binary) < 8 or binary[:4] != b"\x00asm":
        raise ValueError("Not a valid WASM binary (missing \\x00asm magic bytes)")

    sections: Dict[int, bytes] = {}
    i = 8  # skip magic (4 bytes) + version (4 bytes)

    while i < len(binary):
        sid = binary[i]
        i += 1
        size, i = _read_uleb128(binary, i)
        sections[sid] = binary[i : i + size]
        i += size

    return sections


def _build_linear_memory(data_section: bytes, mem_size: int = 131072) -> bytearray:
    """
    Reconstruct WASM linear memory from the data section payload.

    Applies data segments to a zeroed memory array and returns it.
    Handles the MVP active segment format: memidx + i32.const offset + end + data.

    Args:
        data_section: Raw bytes of the WASM data section (id=11) payload.
        mem_size: Size of the memory array in bytes (default 128KB).

    Returns:
        bytearray with data segments applied at their respective offsets.
    """
    mem = bytearray(mem_size)
    j = 0
    count, j = _read_uleb128(data_section, j)

    for _ in range(count):
        # Memory index (MVP: always 0)
        _, j = _read_uleb128(data_section, j)
        # Offset expression: i32.const (0x41) <value> end (0x0b)
        if j >= len(data_section) or data_section[j] != 0x41:
            break  # unexpected opcode; stop parsing
        j += 1
        offset, j = _read_uleb128(data_section, j)
        j += 1  # skip end (0x0b)
        # Data bytes
        length, j = _read_uleb128(data_section, j)
        seg_data = data_section[j : j + length]
        j += length
        mem[offset : offset + length] = seg_data

    return mem


def _parse_exports(export_section: bytes) -> List[Tuple[str, int, int]]:
    """
    Parse the WASM export section (id=7).

    Returns:
        List of (name, kind, index) tuples.
        Kind: 0=func, 1=table, 2=memory, 3=global.
    """
    j = 0
    count, j = _read_uleb128(export_section, j)
    exports = []
    for _ in range(count):
        name, j = _read_string(export_section, j)
        kind = export_section[j]
        j += 1
        idx, j = _read_uleb128(export_section, j)
        exports.append((name, kind, idx))
    return exports


def _parse_globals(global_section: bytes) -> List[int]:
    """
    Parse the WASM global section (id=6).

    Returns list of initial i32 values (only i32.const init exprs supported).
    """
    j = 0
    count, j = _read_uleb128(global_section, j)
    values = []
    for _ in range(count):
        # valtype (1 byte) + mutability (1 byte)
        j += 2
        # init expression: i32.const (0x41) + LEB128 value + end (0x0b)
        if j < len(global_section) and global_section[j] == 0x41:
            j += 1
            val, j = _read_uleb128(global_section, j)
            j += 1  # skip end (0x0b)
        else:
            # Skip unknown init expression (3 bytes is a rough estimate)
            j = min(j + 3, len(global_section))
            val = 0
        values.append(val)
    return values


def _c_string_at(mem: bytearray, addr: int, max_len: int = 512) -> bytes:
    """Read a null-terminated byte string from linear memory at addr."""
    end = addr
    while end < len(mem) and end < addr + max_len and mem[end] != 0:
        end += 1
    return bytes(mem[addr:end])


_KNOWN_FLAG_PREFIXES = frozenset({"picoctf", "htb", "thm", "flag", "ctf", "metactf"})


def _is_plausible_flag(candidate: str) -> bool:
    """Return True if *candidate* looks like a real CTF flag, not binary noise."""
    brace = candidate.find("{")
    if brace == -1:
        return False
    prefix = candidate[:brace]
    inner = candidate[brace + 1 : candidate.rfind("}")]

    # Known CTF prefixes always pass
    if prefix.lower() in _KNOWN_FLAG_PREFIXES:
        return True

    # Single-char prefixes are never real flags
    if len(prefix) < 2:
        return False

    if not inner:
        return False

    # Reject if >40% whitespace inside braces
    ws_ratio = inner.count(" ") / len(inner)
    if ws_ratio > 0.4:
        return False

    # Reject if <50% alphanumeric/underscore inside braces
    alnum_count = sum(c.isalnum() or c == "_" for c in inner)
    if alnum_count / len(inner) < 0.5:
        return False

    return True


def _scan_bytes_for_flags(data: bytes) -> List[str]:
    """Scan raw bytes for CTF flag patterns using a printable-char representation."""
    text = "".join(chr(b) if 32 <= b < 127 else " " for b in data)
    raw = list(dict.fromkeys(_FLAG_RE.findall(text)))  # deduplicated
    return [f for f in raw if _is_plausible_flag(f)]


# ---------------------------------------------------------------------------
# WasmAnalyzerTool
# ---------------------------------------------------------------------------


class WasmAnalyzerTool:
    """
    WasmAnalyzerTool: analyze WebAssembly binaries for CTF challenges.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://challenge.com/module.wasm",  # required
          "operation": "analyze",    # optional, default "analyze"
          "key_hex": "f1a7f007ed",  # optional — XOR key for xor_decode
          "headers": {},             # optional request headers
          "timeout": 15              # optional fetch timeout in seconds
        }

    Operations:
      - analyze:     Parse all sections; show exports, globals, and data segment
                     layout with hex+ASCII. Flags in plaintext are highlighted.
      - strings:     Extract all printable strings (4+ chars) from data segments.
                     Suggests xor_decode if no strings are found.
      - xor_decode:  XOR-decode data segments using the 'key' export (auto-detected
                     from global section) or an explicit key_hex. Flag is reported
                     if recovered. Covers SAR-style challenges where the flag is
                     XOR'd with a short repeating key stored in another segment.
      - scan_flags:  Scan the full raw binary for CTF flag patterns.

    Typical workflow for WASM challenges:
      1. http_fetch page → identify external .js file
      2. javascript_source → find WASM module path (e.g. ./JIFxzHyW8W)
      3. wasm_analyzer (analyze) → check for plaintext flag
      4. wasm_analyzer (xor_decode) → recover XOR-encoded flag if needed
    """

    _MAX_OUTPUT: int = 8000

    name: str = "wasm_analyzer"
    description: str = (
        "Analyze a WebAssembly (.wasm) binary for CTF flag extraction. "
        "Input JSON keys: 'url' (required — full URL of the .wasm file to fetch), "
        "'operation' (optional, default 'analyze'): 'analyze' (parse sections, "
        "exports, globals, data layout — flags in plaintext are highlighted), "
        "'strings' (extract printable strings from data; suggests xor_decode if empty), "
        "'xor_decode' (XOR-decode data segments with the exported key global, or "
        "a provided key_hex — recovers the flag for SAR-style XOR challenges), "
        "'scan_flags' (search raw binary bytes for flag patterns). "
        "Optional: 'key_hex' (hex string of XOR key for xor_decode), "
        "'headers' (dict), 'timeout' (int, default 15 seconds). "
        "Use after javascript_source identifies a WASM module URL. "
        "Always try 'analyze' first; if data segments are binary (non-ASCII), "
        "follow up with 'xor_decode' to recover the flag."
    )

    @staticmethod
    def _truncate_output(text: str, max_chars: int) -> str:
        """Truncate output to *max_chars*, preserving head and tail."""
        if len(text) <= max_chars:
            return text
        head_size = int(max_chars * 0.6)
        tail_size = int(max_chars * 0.3)
        omitted = len(text) - head_size - tail_size
        return (
            text[:head_size]
            + f"\n\n... [{omitted} characters truncated] ...\n\n"
            + text[-tail_size:]
        )

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _fetch(self, url: str, headers: Dict, timeout: int) -> bytes:
        """Fetch WASM binary from URL. Returns raw content bytes."""
        resp = self.session.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return resp.content

    def use(self, tool_input: str) -> str:
        """Analyze a WASM binary for CTF flags."""
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[WasmAnalyzerTool] Error: tool_input must be JSON. {exc}"

        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[WasmAnalyzerTool] Error: 'url' (string) is required."

        operation = str(data.get("operation", "analyze")).lower()
        key_hex = data.get("key_hex")
        headers = data.get("headers") or {}
        timeout = data.get("timeout", 15)
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            timeout = 15

        try:
            binary = self._fetch(url, headers, timeout)
        except Exception as exc:
            return f"[WasmAnalyzerTool] Error fetching {url!r}: {exc!r}"

        try:
            sections = _parse_wasm_sections(binary)
        except ValueError as exc:
            return f"[WasmAnalyzerTool] Error: {exc}"

        OPERATIONS = {
            "analyze": self._do_analyze,
            "strings": self._do_strings,
            "xor_decode": self._do_xor_decode,
            "scan_flags": self._do_scan_flags,
        }

        if operation not in OPERATIONS:
            return (
                f"[WasmAnalyzerTool] Unknown operation: {operation!r}. "
                f"Valid operations: {', '.join(OPERATIONS)}"
            )

        if operation == "xor_decode":
            return self._do_xor_decode(binary, sections, key_hex)
        elif operation == "scan_flags":
            return self._do_scan_flags(binary)
        else:
            return OPERATIONS[operation](binary, sections)

    # ------------------------------------------------------------------
    # Operation: analyze
    # ------------------------------------------------------------------

    def _do_analyze(self, binary: bytes, sections: Dict[int, bytes]) -> str:
        lines = [
            "[WasmAnalyzerTool] WASM Analysis",
            f"Binary size: {len(binary)} bytes",
            f"Sections present (IDs): {sorted(sections.keys())}",
            "  (1=Type 2=Import 3=Function 4=Table 5=Memory 6=Global "
            "7=Export 9=Element 10=Code 11=Data)",
        ]

        # Exports
        if 7 in sections:
            try:
                exports = _parse_exports(sections[7])
                kind_names = {0: "func", 1: "table", 2: "memory", 3: "global"}
                lines.append(f"\nExports ({len(exports)}):")
                for name, kind, idx in exports:
                    lines.append(f"  {name}: {kind_names.get(kind, kind)} index={idx}")
            except Exception as exc:
                lines.append(f"  (export parse error: {exc})")

        # Globals (with export name mapping)
        if 6 in sections:
            try:
                globs = _parse_globals(sections[6])
                global_names: Dict[int, str] = {}
                if 7 in sections:
                    for name, kind, idx in _parse_exports(sections[7]):
                        if kind == 3:
                            global_names[idx] = name
                lines.append(f"\nGlobals ({len(globs)}):")
                for i, val in enumerate(globs):
                    label = global_names.get(i, "")
                    tag = f"  <- exported as '{label}'" if label else ""
                    lines.append(f"  [{i}] = {val} (0x{val:x}){tag}")
            except Exception as exc:
                lines.append(f"  (global parse error: {exc})")

        # Data segments
        if 11 in sections:
            try:
                ds = sections[11]
                j = 0
                count, j = _read_uleb128(ds, j)
                lines.append(f"\nData segments ({count}):")
                found_any_flag = False
                for sidx in range(count):
                    _, j = _read_uleb128(ds, j)
                    j += 1  # i32.const
                    offset, j = _read_uleb128(ds, j)
                    j += 1  # end
                    length, j = _read_uleb128(ds, j)
                    seg = ds[j : j + length]
                    j += length
                    ascii_rep = "".join(chr(c) if 32 <= c < 127 else "." for c in seg)
                    lines.append(
                        f"  Segment {sidx}: memory_offset={offset}, length={length}"
                    )
                    seg_hex = seg.hex()
                    if len(seg_hex) > 2000:
                        seg_hex = (
                            seg_hex[:2000]
                            + f"... [{len(seg_hex) - 2000} chars truncated]"
                        )
                    lines.append(f"    hex:   {seg_hex}")
                    if len(ascii_rep) > 2000:
                        ascii_rep = (
                            ascii_rep[:2000]
                            + f"... [{len(ascii_rep) - 2000} chars truncated]"
                        )
                    lines.append(f"    ascii: {ascii_rep}")
                    flags = _scan_bytes_for_flags(seg)
                    if flags:
                        found_any_flag = True
                        for flag in flags:
                            lines.append(f"    *** FLAG FOUND: {flag}")
                if not found_any_flag:
                    lines.append(
                        "\nNo flags in plaintext. Data segments appear binary/encoded."
                    )
                    lines.append(
                        "Suggested next step: use operation='xor_decode' to attempt "
                        "XOR decoding with the 'key' export, or provide key_hex explicitly."
                    )
            except Exception as exc:
                lines.append(f"  (data parse error: {exc})")
        else:
            lines.append("\nNo data section (id=11) found.")

        return self._truncate_output("\n".join(lines), self._MAX_OUTPUT)

    # ------------------------------------------------------------------
    # Operation: strings
    # ------------------------------------------------------------------

    def _do_strings(self, binary: bytes, sections: Dict[int, bytes]) -> str:
        lines = ["[WasmAnalyzerTool] Strings from WASM data segments:"]

        if 11 not in sections:
            return "[WasmAnalyzerTool] No data section (id=11) found."

        try:
            mem = _build_linear_memory(sections[11])
        except Exception as exc:
            return f"[WasmAnalyzerTool] Error building memory: {exc}"

        # Extract runs of 4+ printable characters
        strings: List[str] = []
        current: List[str] = []
        for byte in mem:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= 4:
                    strings.append("".join(current))
                current = []
        if len(current) >= 4:
            strings.append("".join(current))

        if strings:
            flag_found = False
            display_strings = strings[:100]
            if len(strings) > 100:
                lines.append(f"  ({len(strings)} strings found, showing first 100)")
            for s in display_strings:
                lines.append(f"  {s!r}")
                flags = _scan_bytes_for_flags(s.encode())
                if flags:
                    flag_found = True
                    for flag in flags:
                        lines.append(f"    *** FLAG: {flag}")
            if len(strings) > 100:
                # Still scan remaining strings for flags even if not displayed
                for s in strings[100:]:
                    flags = _scan_bytes_for_flags(s.encode())
                    if flags:
                        flag_found = True
                        for flag in flags:
                            lines.append(f"    *** FLAG (in truncated strings): {flag}")
            if not flag_found:
                lines.append(
                    "\nNo flag patterns found in extracted strings. "
                    "Try operation='xor_decode' if data is XOR-encoded."
                )
        else:
            lines.append(
                "  (no printable strings of 4+ characters found in data segments)"
            )
            lines.append(
                "  The flag is likely XOR-encoded. Use operation='xor_decode' to recover it."
            )

        return self._truncate_output("\n".join(lines), self._MAX_OUTPUT)

    # ------------------------------------------------------------------
    # Operation: xor_decode
    # ------------------------------------------------------------------

    def _do_xor_decode(
        self,
        binary: bytes,
        sections: Dict[int, bytes],
        key_hex: Optional[str],
    ) -> str:
        lines = ["[WasmAnalyzerTool] XOR Decode:"]

        if 11 not in sections:
            return "[WasmAnalyzerTool] No data section (id=11) found."

        try:
            mem = _build_linear_memory(sections[11])
        except Exception as exc:
            return f"[WasmAnalyzerTool] Error building memory: {exc}"

        # Resolve key
        key_bytes: Optional[bytes] = None
        if key_hex:
            try:
                key_bytes = bytes.fromhex(key_hex.strip())
                lines.append(f"Using provided key: {key_hex} ({len(key_bytes)} bytes)")
            except ValueError:
                return f"[WasmAnalyzerTool] Error: invalid key_hex {key_hex!r} — must be hex string."
        elif 6 in sections and 7 in sections:
            # Auto-detect from the 'key' exported global
            try:
                globs = _parse_globals(sections[6])
                for name, kind, idx in _parse_exports(sections[7]):
                    if name.lower() == "key" and kind == 3 and idx < len(globs):
                        key_addr = globs[idx]
                        key_bytes = _c_string_at(mem, key_addr)
                        lines.append(
                            f"Auto-detected 'key' export → memory[{key_addr}] = "
                            f"{key_bytes.hex()} ({len(key_bytes)} bytes)"
                        )
                        break
            except Exception as exc:
                lines.append(f"  (key auto-detect error: {exc})")

        if key_bytes is not None and len(key_bytes) == 0:
            key_bytes = None
            lines.append(
                "  Key is empty (null at key address). Falling back to brute-force."
            )

        # Parse and attempt XOR on each data segment
        ds = sections[11]
        j = 0
        count, j = _read_uleb128(ds, j)

        for sidx in range(count):
            _, j = _read_uleb128(ds, j)
            j += 1  # i32.const
            offset, j = _read_uleb128(ds, j)
            j += 1  # end
            length, j = _read_uleb128(ds, j)
            seg = ds[j : j + length]
            j += length

            lines.append(
                f"\nData segment {sidx} (memory_offset={offset}, {length} bytes):"
            )

            if key_bytes:
                kl = len(key_bytes)
                decoded = bytes(seg[i] ^ key_bytes[i % kl] for i in range(len(seg)))
                ascii_rep = "".join(chr(c) if 32 <= c < 127 else "." for c in decoded)
                printable_ratio = sum(32 <= c < 127 for c in decoded) / max(
                    len(decoded), 1
                )
                lines.append(f"  Decoded (XOR with {key_bytes.hex()}): {ascii_rep}")
                flags = _scan_bytes_for_flags(decoded)
                if flags:
                    for flag in flags:
                        lines.append(f"  *** FLAG FOUND: {flag}")
                elif printable_ratio > 0.8:
                    lines.append(
                        "  (mostly printable — likely correct key but no flag pattern)"
                    )
            else:
                # Brute-force: try all single-byte XOR keys first
                lines.append("  No key found. Trying single-byte XOR brute-force...")
                found_bf = False
                for k in range(256):
                    decoded = bytes(b ^ k for b in seg)
                    flags = _scan_bytes_for_flags(decoded)
                    if flags:
                        lines.append(
                            f"  Brute-force key=0x{k:02x} ({chr(k) if 32 <= k < 127 else '.'})"
                        )
                        for flag in flags:
                            lines.append(f"  *** FLAG FOUND: {flag}")
                        found_bf = True
                        break
                if not found_bf:
                    lines.append(
                        "  No flag found with single-byte XOR. "
                        "Try fetching the WASM and analyzing the check_flag function, "
                        "or provide key_hex explicitly."
                    )

        return self._truncate_output("\n".join(lines), self._MAX_OUTPUT)

    # ------------------------------------------------------------------
    # Operation: scan_flags
    # ------------------------------------------------------------------

    def _do_scan_flags(self, binary: bytes) -> str:
        lines = ["[WasmAnalyzerTool] Flag scan on full WASM binary:"]

        flags = _scan_bytes_for_flags(binary)
        if flags:
            display = flags[:10]
            for flag in display:
                lines.append(f"  *** FLAG: {flag}")
            if len(flags) > 10:
                lines.append(f"  ... [{len(flags) - 10} more matches omitted]")
        else:
            lines.append("  No CTF flag patterns found in raw binary.")
            lines.append(
                "  The flag is likely XOR-encoded. "
                "Use operation='analyze' then operation='xor_decode'."
            )

        return self._truncate_output("\n".join(lines), self._MAX_OUTPUT)
