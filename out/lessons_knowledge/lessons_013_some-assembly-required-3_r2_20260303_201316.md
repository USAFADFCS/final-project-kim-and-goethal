# WASM / Reverse Engineering: When you achieve 'recon_complete' during a WASM / Reverse Engineering 

**Type:** experience_success
**Category:** WASM / Reverse Engineering
**Challenge:** Some Assembly Required 3
**Challenge URL:** http://wily-courier.picoctf.net:62191/index.html
**Auto-generated:** 2026-03-03
**Tags:** wasm_re, success, experience, do
**Confidence:** medium

**Applies when:** When you achieve 'recon_complete' during a WASM / Reverse Engineering challenge

**Agent takeaway:** Continue exploitation after confirming 'recon_complete' — do not stop at reconnaissance

---

## What Happened

In this automated challenge attempt, the analyst successfully navigated a WebAssembly (WASM) exploit using a systematic approach, culminating in the extraction of encoded information. The process commenced with HTTP fetching the webpage, subsequently extracting JavaScript to locate necessary resources. The WASM binary was analyzed, which revealed the presence of an XOR encoded flag. The expert's use of shell commands was critical; they managed to decode the data segment after identifying the correct decode key. Future attempts may benefit from broader scanning for flags in the raw binary earlier in the process, as this could help streamline subsequent decoding efforts.

## Transferable Rule

Do: Continue exploitation after confirming 'recon_complete' — do not stop at reconnaissance

Reason: Analyzing the WASM binary to identify exports and decode key revelations provided the methodological basis for uncovering the flag, ensuring that subsequent decoding steps were adequately informed.

## Tools Involved

- `http_fetch`
- `javascript_source`
- `wasm_analyzer`

**Full sequence:** http_fetch → javascript_source → wasm_analyzer → shell_execute

## Key Exploit Inputs

The following request(s) produced the flag:

- `javascript_source` input: {"url":"http://wily-courier.picoctf.net:62191/index.html","base_url":"http://wily-courier.picoctf.net:62191","max_scripts":10,"max_chars_per_script":8000}
- `wasm_analyzer` input: {"url":"http://wily-courier.picoctf.net:62191/qCCYI0ajpD","operation":"xor_decode","timeout":15}
- `shell_execute` input: {"command":"node - <<'JS'\nconst fs=require('fs');\nconst wasm=fs.readFileSync('/tmp/mod.wasm');\nWebAssembly.instantiate(wasm,{}).then(({instance})=>{\n  const e=instance.exports;\n  const mem=new Uint8Array(e.memory.buffer);\n  const inputPtr=Number(e.input.valueOf ? e.input.valueOf() : e.input);\n  const keyPtr=Number(e.key.valueOf ? e.key.valueOf() : e.key);\n  console.log('inputPtr',inputPtr,

**Seq hash:** -6333834211324202080
