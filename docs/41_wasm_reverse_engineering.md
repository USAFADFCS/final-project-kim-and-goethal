# WebAssembly (WASM) Reverse Engineering — CTF Exploitation Reference

> **Document Purpose:** Techniques for extracting CTF flags from WebAssembly modules. Covers plaintext flag extraction, XOR-encoded flag recovery, JavaScript deobfuscation, and the standard WASM binary format.

**Tags:** `wasm, webassembly, reverse engineering, binary, xor, decompile, flag validator, some assembly required, client-side`

---

## 1. WASM CHALLENGE OVERVIEW

> **When to use this section:** The challenge page loads a `.wasm` binary that validates user input. The flag is stored inside the WASM module.

### 1.1 How WASM Flag Validators Work

Typical pattern (picoCTF "Some Assembly Required" series):
1. HTML page loads obfuscated JavaScript (e.g. `G82XCw5CX3.js`)
2. JavaScript fetches a WASM module (e.g. `./JIFxzHyW8W`)
3. WASM exports `copy_char(c, idx)` and `check_flag()` functions
4. JavaScript calls `copy_char` for each keystroke, then `check_flag()` on submit
5. The flag (or an encrypted version) is stored in WASM **data segments**

**Recognition signals:**
- `javascript_source` reveals `WebAssembly.instantiate(...)` and a `fetch('./XXXXXXXX')` call
- Exported functions named `check_flag`, `copy_char`, `strcmp`
- Obfuscated JS using hex string arrays (`_0x402c`, `_0x4e0e`)

---

## 2. EXPLOITATION WORKFLOW

> **Agent Takeaway:** Use `wasm_analyzer` — do NOT try to parse WASM manually with shell commands.

### 2.1 Standard 3-4 Step Chain

```
Step 1: http_fetch page → see <script src="..."> loading obfuscated JS
Step 2: javascript_source → deobfuscate to find WASM module path
Step 3: wasm_analyzer (analyze) → check for plaintext flag in data segments
Step 4: wasm_analyzer (xor_decode) → if data is binary, recover XOR-encoded flag
```

### 2.2 Detailed Steps

**Step 2 — Reading obfuscated JS:**
The JS will contain a string like `./JIFxzHyW8W` — this is the WASM module path.
Also look for: `exports.copy_char`, `exports.check_flag`, `WebAssembly.instantiate`.

**Step 3 — `wasm_analyzer` with `operation: "analyze"`:**
```json
{"url": "http://challenge.com/JIFxzHyW8W", "operation": "analyze"}
```
Returns:
- Section IDs present
- All exports (functions, globals, memory)
- Global values (including key/input memory addresses)
- Data segment contents (hex + ASCII)
- Flag highlighted if plaintext

**Step 4 — `wasm_analyzer` with `operation: "xor_decode"` (if flag is binary):**
```json
{"url": "http://challenge.com/JIFxzHyW8W", "operation": "xor_decode"}
```
- Auto-detects the `key` export global → reads key bytes from linear memory
- XOR-decodes all data segments cyclically with the key
- Reports flag if found

---

## 3. WASM BINARY FORMAT QUICK REFERENCE

> **When to use this section:** Understanding what `wasm_analyzer` is parsing.

### 3.1 Section IDs

| ID | Section | Relevant for CTF |
|----|---------|-----------------|
| 6 | Global | Key/input memory addresses |
| 7 | Export | Named exports (key, input, check_flag) |
| 10 | Code | Validation logic (check_flag, copy_char) |
| 11 | Data | Embedded flag (plaintext or XOR-encoded) |

### 3.2 Export Kinds

| Kind | Type |
|------|------|
| 0 | Function |
| 1 | Table |
| 2 | Memory |
| 3 | Global |

### 3.3 Typical Memory Layout (SAR challenges)

```
Memory[1024]: encoded_flag bytes (43 bytes, non-ASCII if XOR)
Memory[1067]: key bytes (5 bytes, null-terminated)
Memory[1072]: input buffer (user-supplied chars go here)
```

**Encoding:** `stored[i] = flag[i] XOR key[i % key_len]`
**Recovery:** `flag[i] = stored[i] XOR key[i % key_len]`

---

## 4. SAR CHALLENGE VARIANTS

### SAR Level 1 (Easy)
- Flag stored as plaintext string in data section
- `wasm_analyzer (analyze)` or `wasm_analyzer (scan_flags)` finds it immediately
- `http_fetch` with `max_body: 0` may also show it in raw output

### SAR Level 2 (Moderate)
- Flag is a plaintext string but data section is deeper
- `wasm_analyzer (strings)` extracts all printable strings

### SAR Level 3 (Harder — XOR)
- Flag XOR'd with a named key stored in a separate data segment
- `key` export → global pointing to key bytes in linear memory
- `wasm_analyzer (xor_decode)` auto-detects key and recovers flag

### SAR Level 4 (Hardest — XOR + obfuscated key)
- Same as Level 3 but key may not be named `key`
- Try `wasm_analyzer (xor_decode, key_hex=...)` with hex key from `analyze` output
- Data segment hex from `analyze` can be manually XOR'd if key is known

---

## 5. DECISION TREE

```
Challenge loads .wasm binary?
├── YES: Run javascript_source to find WASM URL
│   ├── Got WASM URL → wasm_analyzer (analyze)
│   │   ├── Flag in plaintext ASCII? → Submit flag
│   │   ├── Data is binary (non-ASCII)?
│   │   │   ├── 'key' export exists? → wasm_analyzer (xor_decode) → Submit
│   │   │   └── No key export → wasm_analyzer (xor_decode) brute-forces single-byte XOR
│   │   └── Module exports copy_char + check_flag (validator pattern)?
│   │       ├── wasm_analyzer (probe_exports) → confirm arities + check for strcmp
│   │       ├── strcmp exported? → wasm_analyzer (oracle_brute_force) with
│   │       │                      strategy=strcmp_delta (one probe per position)
│   │       └── No strcmp? → wasm_analyzer (memory_diff) to locate the
│   │                        transform's scratch buffer, then recover manually
│   └── No WASM URL → check for JS validation (javascript_source)
└── NO: Different challenge type → see other docs
```

---

## 5a. RUNTIME ORACLE RECOVERY

When static decoding fails — specifically when the flag is derived by
*executing* a validator function rather than stored in a data segment —
use the runtime oracle operations on `wasm_analyzer`. These require the
`wasmtime` Python package (declared in `requirements.txt`).

**When to pick this path over `xor_decode`:**

- Module exports `copy_char(c, idx)` and `check_flag()` — the picoCTF
  "Some Assembly Required" validator pattern.
- Data segment appears binary but **XOR decoding finds nothing**: the
  transform isn't a simple XOR, it's a per-byte function compiled into
  `check_flag` itself.
- `analyze` shows a `strcmp` export alongside `check_flag` — that's the
  tell for strcmp_delta's one-probe-per-position recovery.

**Ops in order:**

1. `probe_exports` — lists every export with its parameter/result arity,
   so you know whether `copy_char` is `(char, idx)` or `(idx, char)`
   without guessing (the transcript of the wily_courier run shows an
   agent burning two turns on exactly this ambiguity).
2. `memory_diff` — calls one named export and reports every memory
   region that changed. Useful for finding a transform's scratch
   comparison buffer when it isn't at the obvious offset.
3. `oracle_brute_force` — recovers the flag. Auto-selects between:
   - `strcmp_delta`: one `strcmp` probe per position reveals each flag
     byte arithmetically. Near-instant on short flags.
   - `memory_delta`: diagnostic only — reports transform regions so the
     caller can invert them manually when no strcmp is available.

   **Watch the strcmp_delta log.** If it says *"recovered bytes are
   identical to data segment content at 0x…"*, you have discovered a
   **stateful in-place transform** — `check_flag` mutates the input
   buffer before comparing, so matching raw input to the data segment
   cannot possibly succeed. Move to step 4.

4. `oracle_script` — batch of `{call, args}` / `{read:[start,length]}` /
   `{reset:true}` steps executed on a **single persistent** wasmtime
   instance. Use it to build a transition table (e.g. for each `(b0,
   b1)` pair, call `copy_char(b0,0); copy_char(b1,1); copy_char(0,2);
   check_flag(); read [input_ptr, n]` and record `out[0]`), then invert
   manually. Collapses what would otherwise be 100+ re-instantiations
   into one tool call. Script capped at 500 steps per invocation.

   Example — probe pair `(A, A)` at positions 0..1:
   ```json
   {
     "operation": "oracle_script",
     "script": [
       {"call": "copy_char", "args": [65, 0]},
       {"call": "copy_char", "args": [65, 1]},
       {"call": "copy_char", "args": [0, 2]},
       {"call": "check_flag"},
       {"read": [1072, 2]},
       {"reset": true}
     ]
   }
   ```

---

## 6. TOOL USAGE EXAMPLES

### 6.1 Analyze (always first)
```json
{
  "url": "http://challenge.picoctf.net:64268/JIFxzHyW8W",
  "operation": "analyze"
}
```

### 6.2 XOR decode with auto-detected key
```json
{
  "url": "http://challenge.picoctf.net:50987/qCCYI0ajpD",
  "operation": "xor_decode"
}
```

### 6.3 XOR decode with explicit key
```json
{
  "url": "http://challenge.com/module.wasm",
  "operation": "xor_decode",
  "key_hex": "f1a7f007ed"
}
```

### 6.4 Scan raw binary for flags
```json
{
  "url": "http://challenge.com/module.wasm",
  "operation": "scan_flags"
}
```

---

## 7. JAVASCRIPT DEOBFUSCATION TIPS

The JS loader is typically obfuscated with `javascript-obfuscator`. Key patterns:

```javascript
// Array of strings (deobfuscated by rotating/shifting)
const _0x402c = ['value', 'instantiate', 'innerHTML', ...];
// WASM path is usually a plain string like './JIFxzHyW8W'
// Look for: fetch('./...'), WebAssembly.instantiate, arrayBuffer
// Exports: copy_char, check_flag appear as plain strings in the array
```

**Agent Takeaway:** `javascript_source` returns the full obfuscated JS. Scan for:
- `fetch(` — contains the WASM module path
- `copy_char` — confirms it's a WASM flag validator
- `WebAssembly.instantiate` or `WebAssembly.instantiateStreaming`
