"""
WebAssembly analysis tools for CTF solving.

Two families of operations live on one tool:

* **Static** (``analyze``, ``strings``, ``xor_decode``, ``scan_flags``) —
  pure binary parsing via hand-rolled LEB128 / section readers. No runtime
  required; works against any .wasm byte stream.
* **Runtime oracle** (``probe_exports``, ``memory_diff``,
  ``oracle_brute_force``) — instantiates the module via the ``wasmtime``
  Python binding and runs it. Needed for picoCTF "Some Assembly Required"
  class where the flag is derived from executing ``check_flag`` rather
  than decoding a data segment.

The runtime ops are gated behind ``HAS_WASMTIME`` — if the library isn't
installed, they return a graceful not-installed message instead of
crashing. Mirrors the ``HAS_WEBSOCKET`` gate on ``websocket_probe``.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

import requests

try:
    import wasmtime as _wasmtime  # type: ignore[import-untyped]

    HAS_WASMTIME = True
except ImportError:
    _wasmtime = None  # type: ignore[assignment]
    HAS_WASMTIME = False

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
      5. wasm_analyzer (probe_exports) → if module exports copy_char /
         check_flag, learn argument arity + memory layout
      6. wasm_analyzer (oracle_brute_force) → recover flag via runtime
         oracle when static decoding fails ("Some Assembly Required" class)
      7. wasm_analyzer (oracle_script) → if oracle_brute_force reports
         "identical to data segment", the validator applies an in-place
         transform. Use oracle_script to probe it on a persistent
         instance and build a transition table for manual inversion.
    """

    _MAX_OUTPUT: int = 8000

    name: str = "wasm_analyzer"
    description: str = (
        "Analyze a WebAssembly (.wasm) binary for CTF flag extraction. "
        "Input JSON keys: 'url' (required — full URL of the .wasm file to fetch), "
        "'operation' (optional, default 'analyze'): "
        "'analyze' (parse sections, exports, globals, data layout), "
        "'strings' (extract printable strings from data), "
        "'xor_decode' (XOR-decode data with exported key or provided key_hex), "
        "'scan_flags' (search raw bytes for flag patterns), "
        "'probe_exports' (runtime: instantiate module, list every export "
        "with parameter arity + result type — use to resolve copy_char / "
        "check_flag signatures before oracle work), "
        "'memory_diff' (runtime: snapshot memory, call one export with "
        "given args, report all changed regions — finds the buffer a "
        "transform writes into), "
        "'oracle_brute_force' (runtime: per-position byte search against "
        "check_flag — recovers flag for SAR-style validators), "
        "'oracle_script' (runtime: batch of call/read/reset steps on a "
        "single persistent instance — for building transition tables "
        "when check_flag applies an in-place transform that strcmp_delta "
        "cannot solve). "
        "Runtime ops require 'wasmtime' package; return a graceful error "
        "when missing. Optional: 'key_hex', 'headers', 'timeout' (default 15). "
        "For 'memory_diff': 'function' (export name), 'args' (list of ints), "
        "'scan_range' ([start, end], default [0, 4096]). "
        "For 'oracle_brute_force': 'input_writer' (default 'copy_char'), "
        "'check_fn' (default 'check_flag'), 'input_ptr_export' (default "
        "'input'), 'max_length' (default 64), 'charset' ('printable'|"
        "'ascii'|'alphanumeric'|'hex_digits' or list), 'strategy' "
        "('auto'|'strcmp_delta'|'memory_delta'). "
        "For 'oracle_script': 'script' (list of {call:NAME,args:[...]} / "
        "{read:[start,length]} / {reset:true} steps, max 500)."
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

        STATIC_OPERATIONS = {
            "analyze": self._do_analyze,
            "strings": self._do_strings,
            "xor_decode": self._do_xor_decode,
            "scan_flags": self._do_scan_flags,
        }
        RUNTIME_OPERATIONS = {
            "probe_exports",
            "memory_diff",
            "oracle_brute_force",
            "oracle_script",
        }

        if operation not in STATIC_OPERATIONS and operation not in RUNTIME_OPERATIONS:
            return (
                f"[WasmAnalyzerTool] Unknown operation: {operation!r}. "
                f"Valid operations: "
                f"{', '.join(sorted(set(STATIC_OPERATIONS) | RUNTIME_OPERATIONS))}"
            )

        if operation in RUNTIME_OPERATIONS:
            if operation == "oracle_script":
                # Validate script BEFORE instantiation so cap-over errors
                # don't require wasmtime to be installed.
                script_validation = self._validate_script_arg(data)
                if script_validation is not None:
                    return script_validation
            if not HAS_WASMTIME:
                return (
                    "[WasmAnalyzerTool] Error: 'wasmtime' package not "
                    "installed. Runtime operations (probe_exports, "
                    "memory_diff, oracle_brute_force, oracle_script) "
                    "require it — install with: pip install wasmtime"
                )
            if operation == "probe_exports":
                return self._do_probe_exports(binary)
            if operation == "memory_diff":
                return self._do_memory_diff(binary, data)
            if operation == "oracle_brute_force":
                return self._do_oracle_brute_force(binary, data)
            if operation == "oracle_script":
                return self._do_oracle_script(binary, data)

        if operation == "xor_decode":
            return self._do_xor_decode(binary, sections, key_hex)
        elif operation == "scan_flags":
            return self._do_scan_flags(binary)
        else:
            return STATIC_OPERATIONS[operation](binary, sections)

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

    # ------------------------------------------------------------------
    # Runtime helpers (shared by probe_exports / memory_diff /
    # oracle_brute_force). All three instantiate the module fresh — no
    # shared state between tool calls.
    # ------------------------------------------------------------------

    def _instantiate(self, binary: bytes) -> Tuple[Any, Any, Any]:
        """Compile + instantiate a WASM module. Returns (store, instance,
        exports_dict). Raises on compile/instantiate failure."""
        assert HAS_WASMTIME  # guarded at call site
        engine = _wasmtime.Engine()
        store = _wasmtime.Store(engine)
        module = _wasmtime.Module(engine, binary)
        instance = _wasmtime.Instance(store, module, [])
        exports_obj = instance.exports(store)
        # Build a dict by probing common names + any discoverable via
        # iteration. wasmtime's Exports API isn't dict-like on all
        # versions, so we collect by known names + return the raw object
        # for callers that need __getitem__.
        return store, instance, exports_obj

    def _get_export(self, exports_obj: Any, name: str) -> Optional[Any]:
        """Safe export lookup — returns None when missing."""
        try:
            return exports_obj[name]
        except Exception:
            return None

    def _export_info(self, store: Any, exports_obj: Any, name: str) -> Dict[str, Any]:
        """Return {name, kind, params, results} for a named export.

        ``params``/``results`` are lists of wasmtime value-type names
        (e.g. ``["i32"]``). For non-function exports both are ``[]``.
        """
        try:
            exp = exports_obj[name]
        except Exception:
            return {"name": name, "kind": "missing", "params": [], "results": []}

        info: Dict[str, Any] = {"name": name, "params": [], "results": []}
        # Function: has a .type(store) returning wasmtime.FuncType
        try:
            ty = exp.type(store)
            info["kind"] = "func"
            # wasmtime.FuncType has .params and .results returning lists
            # of wasmtime value-type objects. Stringify each.
            try:
                info["params"] = [
                    str(p).replace("ValType(", "").rstrip(")") for p in ty.params
                ]
                info["results"] = [
                    str(r).replace("ValType(", "").rstrip(")") for r in ty.results
                ]
            except Exception:
                pass
            return info
        except Exception:
            pass
        # Global
        if isinstance(exp, _wasmtime.Global):
            info["kind"] = "global"
            try:
                info["value"] = exp.value(store)
            except Exception:
                pass
            return info
        # Memory
        if isinstance(exp, _wasmtime.Memory):
            info["kind"] = "memory"
            return info
        info["kind"] = "unknown"
        return info

    # ------------------------------------------------------------------
    # Operation: probe_exports
    # ------------------------------------------------------------------

    # Every WASM export name we consider when probing. Covers the
    # "Some Assembly Required" picoCTF series conventions + common C
    # entry points.
    _PROBE_NAMES: Tuple[str, ...] = (
        "memory",
        "input",
        "output",
        "copy_char",
        "check_flag",
        "strcmp",
        "strlen",
        "main",
        "_start",
        "__wasm_call_ctors",
        "__dso_handle",
        "__data_end",
        "__global_base",
        "__heap_base",
        "__memory_base",
        "__table_base",
        "key",
        "encrypted",
        "decrypted",
    )

    def _do_probe_exports(self, binary: bytes) -> str:
        """Instantiate the module and report each probed export's arity."""
        try:
            store, _instance, exports_obj = self._instantiate(binary)
        except Exception as exc:
            return f"[WasmAnalyzerTool] Error instantiating module: {exc!r}"

        lines = ["[WasmAnalyzerTool] Probe Exports (runtime)"]
        found: List[str] = []
        for name in self._PROBE_NAMES:
            info = self._export_info(store, exports_obj, name)
            if info["kind"] == "missing":
                continue
            found.append(name)
            if info["kind"] == "func":
                sig = (
                    f"({', '.join(info['params']) or 'void'}) -> "
                    f"{', '.join(info['results']) or 'void'}"
                )
                lines.append(f"  [func]   {name}: {sig}")
            elif info["kind"] == "global":
                val = info.get("value", "?")
                lines.append(f"  [global] {name} = {val}")
            elif info["kind"] == "memory":
                lines.append(f"  [memory] {name}")
            else:
                lines.append(f"  [{info['kind']}]  {name}")

        if not found:
            lines.append("  (no probe-list exports found)")
            return "\n".join(lines)

        # Opinionated workflow hint — helps the agent pick the next op.
        has_copy = "copy_char" in found
        has_check = "check_flag" in found
        has_strcmp = "strcmp" in found
        lines.append("")
        if has_copy and has_check:
            hint = (
                "  Hint: copy_char + check_flag present — this is a "
                "'Some Assembly Required' validator. Next step: "
                "oracle_brute_force"
            )
            if has_strcmp:
                hint += " (strcmp_delta strategy will be fast)."
            else:
                hint += (
                    " (no strcmp export — memory_delta will diagnose "
                    "the transform regions but direct recovery may need "
                    "manual work)."
                )
            lines.append(hint)
        elif "memory" in found:
            lines.append(
                "  Hint: memory export present but no validator pair — "
                "try memory_diff with the specific function you want to trace."
            )

        return self._truncate_output("\n".join(lines), self._MAX_OUTPUT)

    # ------------------------------------------------------------------
    # Operation: memory_diff
    # ------------------------------------------------------------------

    def _do_memory_diff(self, binary: bytes, data: Dict[str, Any]) -> str:
        """Snapshot memory, call one export, snapshot again. Report all
        changed regions so the caller can find where a transform writes
        its output — including scratch buffers the agent otherwise can't
        see."""
        fn_name = data.get("function")
        if not fn_name or not isinstance(fn_name, str):
            return (
                "[WasmAnalyzerTool] Error: 'function' (string) is required "
                "for operation='memory_diff'."
            )
        args_raw = data.get("args") or []
        if not isinstance(args_raw, list):
            return "[WasmAnalyzerTool] Error: 'args' must be a list of integers."
        try:
            args = [int(a) for a in args_raw]
        except (TypeError, ValueError):
            return "[WasmAnalyzerTool] Error: 'args' must be a list of integers."

        scan_range = data.get("scan_range") or [0, 4096]
        try:
            scan_start = max(0, int(scan_range[0]))
            scan_end = int(scan_range[1])
        except (TypeError, ValueError, IndexError):
            return "[WasmAnalyzerTool] Error: 'scan_range' must be [start, end] ints."
        if scan_end <= scan_start:
            return "[WasmAnalyzerTool] Error: scan_range end must be > start."
        # Cap scan span to keep output bounded.
        scan_end = min(scan_end, scan_start + 65536)

        try:
            store, _instance, exports_obj = self._instantiate(binary)
        except Exception as exc:
            return f"[WasmAnalyzerTool] Error instantiating module: {exc!r}"

        fn = self._get_export(exports_obj, fn_name)
        if fn is None:
            return f"[WasmAnalyzerTool] Error: export {fn_name!r} not found."
        mem = self._get_export(exports_obj, "memory")
        if mem is None:
            return (
                "[WasmAnalyzerTool] Error: module does not export 'memory' "
                "— memory_diff cannot run."
            )

        try:
            before = bytes(mem.read(store, scan_start, scan_end))
        except Exception as exc:
            return f"[WasmAnalyzerTool] Error reading memory (pre-call): {exc!r}"

        try:
            fn(store, *args)
        except Exception as exc:
            return f"[WasmAnalyzerTool] Error calling {fn_name!r}({args}): {exc!r}"

        try:
            after = bytes(mem.read(store, scan_start, scan_end))
        except Exception as exc:
            return f"[WasmAnalyzerTool] Error reading memory (post-call): {exc!r}"

        regions = _group_diff_regions(before, after, scan_start)
        lines = [
            "[WasmAnalyzerTool] Memory Diff",
            f"Call: {fn_name}({', '.join(str(a) for a in args)})",
            f"Scan range: [{scan_start}, {scan_end})",
            f"Changed regions: {len(regions)}",
        ]
        # Cap region count + per-region dump size.
        for offset, old, new in regions[:12]:
            length = len(old)
            lines.append(
                f"  @ 0x{offset:x} ({offset}) "
                f"len={length}: old={old[:32].hex()} -> new={new[:32].hex()}"
            )
        if len(regions) > 12:
            lines.append(f"  ... [{len(regions) - 12} more regions omitted]")

        if not regions:
            lines.append(
                "  (no memory changed — call may be a no-op or wrote outside scan range)"
            )

        return self._truncate_output("\n".join(lines), self._MAX_OUTPUT)

    # ------------------------------------------------------------------
    # Operation: oracle_brute_force
    # ------------------------------------------------------------------

    _CHARSETS: Dict[str, str] = {
        "printable": (
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "_-{}!@#$%^&*()+=[]:;,.?/~<>"
        ),
        "alphanumeric": (
            "abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "0123456789_"
        ),
        "ascii": "".join(chr(c) for c in range(0x20, 0x7F)),
        "hex_digits": "0123456789abcdef",
    }

    def _resolve_charset(self, spec: Any) -> List[int]:
        """Map a charset spec to a list of int byte values."""
        if isinstance(spec, list):
            result: List[int] = []
            for c in spec:
                if isinstance(c, int) and 0 <= c < 256:
                    result.append(c)
                elif isinstance(c, str) and len(c) == 1:
                    result.append(ord(c))
            return result
        if isinstance(spec, str) and spec in self._CHARSETS:
            return [ord(c) for c in self._CHARSETS[spec]]
        # Fall back to printable.
        return [ord(c) for c in self._CHARSETS["printable"]]

    def _do_oracle_brute_force(self, binary: bytes, data: Dict[str, Any]) -> str:
        input_writer = data.get("input_writer", "copy_char")
        check_fn_name = data.get("check_fn", "check_flag")
        input_ptr_export = data.get("input_ptr_export", "input")
        try:
            max_length = int(data.get("max_length", 64))
        except (TypeError, ValueError):
            max_length = 64
        max_length = max(1, min(max_length, 256))
        strategy = str(data.get("strategy", "auto")).lower()
        charset = self._resolve_charset(data.get("charset", "printable"))

        if not charset:
            return "[WasmAnalyzerTool] Error: charset is empty."

        try:
            store, _instance, exports_obj = self._instantiate(binary)
        except Exception as exc:
            return f"[WasmAnalyzerTool] Error instantiating module: {exc!r}"

        writer = self._get_export(exports_obj, input_writer)
        checker = self._get_export(exports_obj, check_fn_name)
        mem = self._get_export(exports_obj, "memory")
        if writer is None or checker is None or mem is None:
            missing = [
                name
                for name, val in (
                    (input_writer, writer),
                    (check_fn_name, checker),
                    ("memory", mem),
                )
                if val is None
            ]
            return (
                "[WasmAnalyzerTool] Error: required exports missing: "
                f"{', '.join(missing)}."
            )

        input_ptr_glob = self._get_export(exports_obj, input_ptr_export)
        input_ptr: Optional[int] = None
        if input_ptr_glob is not None:
            try:
                input_ptr = int(input_ptr_glob.value(store))
            except Exception:
                input_ptr = None

        strcmp = self._get_export(exports_obj, "strcmp")

        # Auto-select strategy.
        if strategy == "auto":
            if strcmp is not None:
                strategy = "strcmp_delta"
            else:
                strategy = "memory_delta"

        def write_prefix(prefix_bytes: bytes) -> None:
            """Write prefix + NUL via input_writer export."""
            for i, b in enumerate(prefix_bytes):
                writer(store, int(b), i)
            # NUL-terminate at end of buffer.
            writer(store, 0, len(prefix_bytes))

        def call_check() -> int:
            try:
                result = checker(store)
                return int(result) if result is not None else 0
            except Exception:
                return 0

        def call_strcmp(input_ptr_val: int, other_ptr: int) -> int:
            try:
                return int(strcmp(store, input_ptr_val, other_ptr))
            except Exception:
                return 0

        # ---- strcmp_delta strategy ----
        # Build flag prefix one byte at a time. At each position p we
        # write candidate[:p+1] into the input buffer and call strcmp
        # against the compare buffer. The correct byte produces the
        # largest "prefix cleared" value (strcmp walking further).
        def run_strcmp_delta() -> Tuple[Optional[bytes], List[str]]:
            log: List[str] = []
            if input_ptr is None:
                log.append("  strcmp_delta: no input_ptr available — skipping")
                return None, log
            # Compare buffer is usually at the module's first data
            # segment offset. We sniff by calling check_flag with an
            # empty input and watching which memory region changes.
            # Simpler: assume compare_ptr = input_ptr - 48 (common) or
            # walk common offsets. Actually the easiest robust approach
            # is: set input to all-zero, call strcmp(input_ptr, x) for
            # x in common data offsets, pick the one that gives a
            # non-zero result (meaning a real comparison).
            candidates_for_compare = [1024, 1028, 1032, 1036, 1040, 1048, 1056, 1064]
            write_prefix(b"\x00")
            compare_ptr: Optional[int] = None
            for c in candidates_for_compare:
                res = call_strcmp(input_ptr, c)
                if res != 0:
                    compare_ptr = c
                    break
            if compare_ptr is None:
                log.append(
                    "  strcmp_delta: could not auto-locate compare buffer; "
                    "falling back"
                )
                return None, log

            # Per-position recovery via strcmp arithmetic. If the
            # prefix already matches, the next call returns
            #     strcmp(prefix+probe+NUL, flag) = probe - flag[pos]
            # for wrong ``probe``. So one probe per position is enough:
            # derived = (probe - strcmp_result) % 256 gives flag[pos]
            # directly, provided probe != flag[pos] (we pick a value
            # unlikely to be a flag char).
            flag_bytes = bytearray()
            # 0x01 is outside the printable charset; picoCTF flags are
            # printable ASCII so this probe can never coincide with
            # flag[pos].
            probe = 0x01
            for pos in range(max_length):
                trial = bytes(flag_bytes) + bytes([probe])
                write_prefix(trial)
                res = call_strcmp(input_ptr, compare_ptr)
                if res == 0:
                    # The probe byte matched flag[pos] (unlikely — we
                    # picked 0x01 to avoid this) OR the flag is exactly
                    # len(prefix) + 1 bytes. Either way, stop.
                    break
                derived = (probe - res) % 256
                if derived == 0:
                    # flag[pos] = 0: we hit the NUL terminator. Done.
                    break
                flag_bytes.append(derived)
                write_prefix(bytes(flag_bytes))
                if call_check() == 1:
                    log.append(
                        f"  strcmp_delta: check_flag=1 at length " f"{len(flag_bytes)}"
                    )
                    return bytes(flag_bytes), log
            if flag_bytes:
                # Fell out of the loop without check_flag==1 (hit NUL or
                # max_length). Still return what we've got — the caller
                # validates via check_flag at the end.
                write_prefix(bytes(flag_bytes))
                if call_check() == 1:
                    return bytes(flag_bytes), log
                log.append(
                    f"  strcmp_delta: recovered {len(flag_bytes)} bytes "
                    "but check_flag still 0 — validator may use a "
                    "custom transform"
                )
                # Distinguish "re-derived the data segment" from genuine
                # transform discovery. If the bytes we recovered match
                # the module's data segment at compare_ptr byte-for-byte,
                # the agent just re-discovered what ``analyze`` already
                # surfaced — the validator applies an in-place transform
                # inside check_flag and strcmp_delta cannot solve it.
                try:
                    compare_content = bytes(
                        mem.read(store, compare_ptr, compare_ptr + len(flag_bytes))
                    )
                except Exception:
                    compare_content = b""
                if compare_content == bytes(flag_bytes):
                    log.append(
                        f"  strcmp_delta: recovered bytes are identical to "
                        f"data segment content at 0x{compare_ptr:x} — this "
                        "validator applies an IN-PLACE TRANSFORM to input "
                        "inside check_flag before comparing. You cannot "
                        "recover the flag by matching input to the data "
                        "segment directly. Next step: use "
                        "operation='oracle_script' to probe the transform "
                        "with controlled inputs on a persistent instance, "
                        "then invert manually."
                    )
            return None, log

        # ---- memory_delta strategy ----
        def run_memory_delta() -> Tuple[Optional[bytes], List[str]]:
            log: List[str] = []
            if input_ptr is None:
                return None, log
            # Snapshot memory before any writes.
            try:
                ref_before = bytes(mem.read(store, 0, 4096))
            except Exception as exc:
                log.append(f"  memory_delta: memory read failed: {exc}")
                return None, log
            # Write all-zero input, run check_flag, snapshot the
            # post-call memory. Any byte positions that differ from
            # before reveal the transform's scratch + compare buffers.
            write_prefix(b"\x00" * 16)
            call_check()
            try:
                ref_after = bytes(mem.read(store, 0, 4096))
            except Exception as exc:
                log.append(f"  memory_delta: memory read failed: {exc}")
                return None, log
            deltas = _group_diff_regions(ref_before, ref_after, 0)
            log.append(f"  memory_delta: {len(deltas)} transform regions")
            # Without deeper analysis of the transform we can't invert
            # reliably; log the finding and fall through.
            return None, log

        log_lines: List[str] = []
        recovered: Optional[bytes] = None
        strategies_tried: List[str] = []

        def try_strategy(name: str) -> bool:
            strategies_tried.append(name)
            nonlocal recovered
            if name == "strcmp_delta":
                res, sublog = run_strcmp_delta()
            elif name == "memory_delta":
                res, sublog = run_memory_delta()
            else:
                return False
            log_lines.extend(sublog)
            if res is not None:
                recovered = res
                return True
            return False

        # Execute selected + fallbacks.
        order: List[str]
        if strategy in ("strcmp_delta", "memory_delta"):
            order = [strategy]
            if strategy == "strcmp_delta":
                order += ["memory_delta"]
        else:
            return (
                "[WasmAnalyzerTool] Error: unknown strategy "
                f"{strategy!r}. Valid: auto, strcmp_delta, memory_delta."
            )

        for s in order:
            if try_strategy(s):
                break

        lines = [
            "[WasmAnalyzerTool] Oracle Brute Force",
            f"Strategy tried: {', '.join(strategies_tried)}",
        ]
        lines.extend(log_lines)
        if recovered is not None:
            try:
                decoded = recovered.decode("ascii", errors="replace").rstrip("\x00")
            except Exception:
                decoded = repr(recovered)
            lines.append(f"Recovered: {decoded}")
            flags_found = _FLAG_RE.findall(decoded)
            if flags_found:
                for flag in flags_found:
                    lines.append(f"  *** FLAG: {flag}")
        else:
            lines.append(
                "No flag recovered. Diagnostic: check whether copy_char's "
                "argument order is (char, idx) or (idx, char) via "
                "operation='memory_diff', and whether the module exports "
                "strcmp for a faster oracle."
            )

        return self._truncate_output("\n".join(lines), self._MAX_OUTPUT)

    # ------------------------------------------------------------------
    # Operation: oracle_script
    # ------------------------------------------------------------------

    # Max script steps per call. Keeps output bounded; agent can chain
    # multiple calls for larger probe sequences.
    _SCRIPT_CAP: int = 500

    def _validate_script_arg(self, data: Dict[str, Any]) -> Optional[str]:
        """Return an error string if ``data['script']`` is missing or
        over-cap; otherwise None. Called pre-instantiation so cap-over
        validation works even without wasmtime installed."""
        script = data.get("script")
        if script is None:
            return (
                "[WasmAnalyzerTool] Error: 'script' (list) is required "
                "for operation='oracle_script'."
            )
        if not isinstance(script, list):
            return (
                "[WasmAnalyzerTool] Error: 'script' must be a list of "
                "{call,args} / {read:[start,length]} / {reset:true} steps."
            )
        if len(script) > self._SCRIPT_CAP:
            return (
                f"[WasmAnalyzerTool] Error: script length {len(script)} "
                f"exceeds cap of {self._SCRIPT_CAP} steps. Split into "
                "multiple oracle_script calls."
            )
        return None

    def _do_oracle_script(self, binary: bytes, data: Dict[str, Any]) -> str:
        """Run a scripted sequence of (call/read/reset) steps on a SINGLE
        persistent wasmtime instance.

        Motivation: building a transition table f(in[i], in[i+1]) -> out[i]
        for an in-place transform requires many controlled probes. Doing
        this via a per-call re-instantiation pattern re-compiles the
        module each time — 5–10 ms × N probes blows the step budget on
        anything non-trivial. This op compiles once and runs every step
        on the same store.
        """
        script = data["script"]  # already validated

        try:
            store, _instance, exports_obj = self._instantiate(binary)
        except Exception as exc:
            return f"[WasmAnalyzerTool] Error instantiating module: {exc!r}"

        # If __wasm_call_ctors exists, run it so static initializers
        # complete before any script step observes memory.
        ctors = self._get_export(exports_obj, "__wasm_call_ctors")
        if ctors is not None:
            try:
                ctors(store)
            except Exception:
                pass

        lines = [
            "[WasmAnalyzerTool] Oracle Script",
            f"Steps: {len(script)}",
        ]

        def _rebuild() -> Tuple[Any, Any, Any]:
            """Fresh instance for a reset step."""
            new_store, new_instance, new_exports = self._instantiate(binary)
            new_ctors = self._get_export(new_exports, "__wasm_call_ctors")
            if new_ctors is not None:
                try:
                    new_ctors(new_store)
                except Exception:
                    pass
            return new_store, new_instance, new_exports

        for idx, step in enumerate(script):
            if not isinstance(step, dict):
                lines.append(f"[step {idx}] Error: step is not a dict")
                break

            # reset: throw away the current store and make a new one.
            if step.get("reset"):
                try:
                    store, _instance, exports_obj = _rebuild()
                    lines.append(f"[step {idx}] reset")
                    continue
                except Exception as exc:
                    lines.append(f"[step {idx}] Error during reset: {exc!r}")
                    break

            # call: invoke an exported function.
            if "call" in step:
                fn_name = step.get("call")
                args = step.get("args", []) or []
                if not isinstance(fn_name, str):
                    lines.append(f"[step {idx}] Error: 'call' must be a string")
                    break
                if not isinstance(args, list):
                    lines.append(f"[step {idx}] Error: 'args' must be a list")
                    break
                fn = self._get_export(exports_obj, fn_name)
                if fn is None:
                    lines.append(f"[step {idx}] Error: export {fn_name!r} not found")
                    break
                try:
                    int_args = [int(a) for a in args]
                except (TypeError, ValueError):
                    lines.append(f"[step {idx}] Error: args must be integers")
                    break
                try:
                    result = fn(store, *int_args)
                except Exception as exc:
                    lines.append(f"[step {idx}] Error calling {fn_name!r}: {exc!r}")
                    break
                if result is None:
                    lines.append(
                        f"[step {idx}] call {fn_name}({', '.join(str(a) for a in int_args)}) = void"
                    )
                else:
                    lines.append(
                        f"[step {idx}] call {fn_name}({', '.join(str(a) for a in int_args)}) = {int(result)}"
                    )
                continue

            # read: dump a memory range as hex.
            if "read" in step:
                r = step.get("read")
                if (
                    not isinstance(r, list)
                    or len(r) != 2
                    or not all(isinstance(x, int) for x in r)
                ):
                    lines.append(
                        f"[step {idx}] Error: 'read' must be [start, length] ints"
                    )
                    break
                start, length = r
                if length < 0 or length > 4096:
                    lines.append(
                        f"[step {idx}] Error: read length must be in [0, 4096]"
                    )
                    break
                mem = self._get_export(exports_obj, "memory")
                if mem is None:
                    lines.append(f"[step {idx}] Error: module does not export 'memory'")
                    break
                try:
                    buf = bytes(mem.read(store, start, start + length))
                except Exception as exc:
                    lines.append(f"[step {idx}] Error reading memory: {exc!r}")
                    break
                # Format as space-separated hex; trim preview to the
                # first 64 bytes to keep output compact.
                preview = buf[:64]
                hex_str = " ".join(f"{b:02x}" for b in preview)
                suffix = f" ... [{length - 64} bytes truncated]" if length > 64 else ""
                lines.append(
                    f"[step {idx}] read 0x{start:x}[{length}] = '{hex_str}'{suffix}"
                )
                continue

            lines.append(
                f"[step {idx}] Error: unknown step shape (need 'call', "
                "'read', or 'reset')"
            )
            break

        return self._truncate_output("\n".join(lines), self._MAX_OUTPUT)


# ---------------------------------------------------------------------------
# Memory-diff helpers (module-level so tests + tool can share)
# ---------------------------------------------------------------------------


def _group_diff_regions(
    before: bytes, after: bytes, base_offset: int
) -> List[Tuple[int, bytes, bytes]]:
    """Group byte-level differences into contiguous regions.

    Returns list of ``(offset, old_bytes, new_bytes)`` tuples. Adjacent
    changed bytes merge into one region; gaps of ≥4 unchanged bytes
    start a new region.
    """
    if len(before) != len(after):
        # Truncate to shortest — caller decides whether that's OK.
        n = min(len(before), len(after))
        before = before[:n]
        after = after[:n]

    regions: List[Tuple[int, bytes, bytes]] = []
    i = 0
    n = len(before)
    GAP = 4
    while i < n:
        if before[i] == after[i]:
            i += 1
            continue
        start = i
        last_change = i
        j = i
        while j < n:
            if before[j] != after[j]:
                last_change = j
                j += 1
            elif j - last_change < GAP:
                j += 1
            else:
                break
        end = last_change + 1
        regions.append(
            (base_offset + start, bytes(before[start:end]), bytes(after[start:end]))
        )
        i = end
    return regions
