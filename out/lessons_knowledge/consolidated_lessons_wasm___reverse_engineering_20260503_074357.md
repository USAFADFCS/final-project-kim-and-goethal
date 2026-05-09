# Consolidated Lessons: WASM / Reverse Engineering

> **Auto-generated:** 2026-05-03 07:43:57 UTC
> **Category:** WASM / Reverse Engineering
> **Type:** consolidated_lessons (2 docs — 2 success, 0 failure)
> **Tags:** `consolidated, wasm___reverse_engineering, lessons, high-priority, wisdom`

> **Agent Note:** This consolidates patterns from multiple runs on this category.
> Use the Quick Exploitation Path as your primary action guide.

---

## Coverage

- **Total atomic rule docs:** 2
- **Success runs:** 2
- **Failure/partial runs:** 0

## Best Exploitation Path (from most recent success)

> **Note:** Replace `<TARGET_URL>` with the current challenge URL.

1. **`http_fetch`**: Fetch the target URL to map the application and identify input forms
2. **`javascript_source`**: Inspect JS for injection points, credentials, or API endpoints — use: `{"url":"<TARGET_URL>","base_url":"http://wily-courier.picoctf.net:62191","max_scripts":10,"max_chars_per_script":8000}`
3. **`wasm_analyzer`**: Parse and reverse-engineer the WASM binary — use: `{"url":"http://wily-courier.picoctf.net:62191/qCCYI0ajpD","operation":"xor_decode","timeout":15}`
4. **`shell_execute`**: Use `shell_execute` — use: `{"command":"node - <<'JS'\nconst fs=require('fs');\nconst wasm=fs.readFileSync('/tmp/mod.wasm');\nWebAssembly.instantiate(wasm,{}).then(({instance})=>{\n  const e=instance.exports;\n  const mem=new Uint8Array(e.memory.buffer);\n  const inputPtr=Number(e.input.valueOf ? e.input.valueOf() : e.input);\n  const keyPtr=Number(e.key.valueOf ? e.key.valueOf() : e.key);\n  console.log('inputPtr',inputPtr,`

> **Next-step strategy:** Deobfuscate the JS loader with `javascript_source` to find the WASM URL, then `wasm_analyzer (analyze)`. If data is binary, follow with `wasm_analyzer (xor_decode)`.

## Key Takeaways (ranked by frequency across runs)

1. Follow this winning tool sequence: http_fetch → javascript_source → wasm_analyzer → shell_execute
2. Continue exploitation after confirming 'recon_complete' — do not stop at reconnaissance

## Confirmed Winning Inputs

These exact requests produced the flag:

- `javascript_source` input: {"url":"http://wily-courier.picoctf.net:62191/index.html","base_url":"http://wily-courier.picoctf.net:62191","max_scripts":10,"max_chars_per_script":8000}
- `wasm_analyzer` input: {"url":"http://wily-courier.picoctf.net:62191/qCCYI0ajpD","operation":"xor_decode","timeout":15}
- `shell_execute` input: {"command":"node - <<'JS'\nconst fs=require('fs');\nconst wasm=fs.readFileSync('/tmp/mod.wasm');\nWebAssembly.instantiate(wasm,{}).then(({instance})=>{\n  const e=instance.exports;\n  const mem=new Uint8Array(e.memory.buffer);\n  const inputPtr=Number(e.input.valueOf ? e.input.valueOf() : e.input);\n  const keyPtr=Number(e.key.valueOf ? e.key.valueOf() : e.key);\n  console.log('inputPtr',inputPtr,
