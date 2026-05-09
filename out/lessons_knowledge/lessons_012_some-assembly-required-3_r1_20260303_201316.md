# WASM / Reverse Engineering: When facing a WASM / Reverse Engineering challenge with these tools av

**Type:** experience_success
**Category:** WASM / Reverse Engineering
**Challenge:** Some Assembly Required 3
**Challenge URL:** http://wily-courier.picoctf.net:62191/index.html
**Auto-generated:** 2026-03-03
**Tags:** wasm_re, success, experience, do
**Confidence:** high

**Applies when:** When facing a WASM / Reverse Engineering challenge with these tools available

**Agent takeaway:** Follow this winning tool sequence: http_fetch → javascript_source → wasm_analyzer → shell_execute

---

## What Happened

In this automated challenge attempt, the analyst successfully navigated a WebAssembly (WASM) exploit using a systematic approach, culminating in the extraction of encoded information. The process commenced with HTTP fetching the webpage, subsequently extracting JavaScript to locate necessary resources. The WASM binary was analyzed, which revealed the presence of an XOR encoded flag. The expert's use of shell commands was critical; they managed to decode the data segment after identifying the correct decode key. Future attempts may benefit from broader scanning for flags in the raw binary earlier in the process, as this could help streamline subsequent decoding efforts.

## Transferable Rule

Do: Follow this winning tool sequence: http_fetch → javascript_source → wasm_analyzer → shell_execute

Reason: Utilizing HTTP fetching to gather initial webpage resources enabled access to JavaScript files containing essential functionalities and references critical for further analysis.

## Tools Involved

- `http_fetch`
- `javascript_source`
- `wasm_analyzer`
- `shell_execute`

**Full sequence:** http_fetch → javascript_source → wasm_analyzer → shell_execute

## Quick Exploitation Path

> **Note:** Replace `<TARGET_URL>` with the current challenge URL.

1. **`http_fetch`**: Fetch the target URL to map the application and identify input forms
2. **`javascript_source`**: Inspect JS for injection points, credentials, or API endpoints — use: `{"url":"<TARGET_URL>","base_url":"http://wily-courier.picoctf.net:62191","max_scripts":10,"max_chars_per_script":8000}`
3. **`wasm_analyzer`**: Parse and reverse-engineer the WASM binary — use: `{"url":"http://wily-courier.picoctf.net:62191/qCCYI0ajpD","operation":"xor_decode","timeout":15}`
4. **`shell_execute`**: Use `shell_execute` — use: `{"command":"node - <<'JS'\nconst fs=require('fs');\nconst wasm=fs.readFileSync('/tmp/mod.wasm');\nWebAssembly.instantiate(wasm,{}).then(({instance})=>{\n  const e=instance.exports;\n  const mem=new Uint8Array(e.memory.buffer);\n  const inputPtr=Number(e.input.valueOf ? e.input.valueOf() : e.input);\n  const keyPtr=Number(e.key.valueOf ? e.key.valueOf() : e.key);\n  console.log('inputPtr',inputPtr,`

> **Next-step strategy:** Deobfuscate the JS loader with `javascript_source` to find the WASM URL, then `wasm_analyzer (analyze)`. If data is binary, follow with `wasm_analyzer (xor_decode)`.

## Key Exploit Inputs

The following request(s) produced the flag:

- `javascript_source` input: {"url":"http://wily-courier.picoctf.net:62191/index.html","base_url":"http://wily-courier.picoctf.net:62191","max_scripts":10,"max_chars_per_script":8000}
- `wasm_analyzer` input: {"url":"http://wily-courier.picoctf.net:62191/qCCYI0ajpD","operation":"xor_decode","timeout":15}
- `shell_execute` input: {"command":"node - <<'JS'\nconst fs=require('fs');\nconst wasm=fs.readFileSync('/tmp/mod.wasm');\nWebAssembly.instantiate(wasm,{}).then(({instance})=>{\n  const e=instance.exports;\n  const mem=new Uint8Array(e.memory.buffer);\n  const inputPtr=Number(e.input.valueOf ? e.input.valueOf() : e.input);\n  const keyPtr=Number(e.key.valueOf ? e.key.valueOf() : e.key);\n  console.log('inputPtr',inputPtr,

**Seq hash:** -6333834211324202080
