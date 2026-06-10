# Local model inventory + working/broken status — 2026-05-19

Verified on macOS M5 Max / 128 GB / Ollama 0.24.0.

## Models confirmed working

### `nemotron-3-super:120b-a12b-q4_K_M` (86 GB)
- **Source:** Ollama's official library (`ollama pull nemotron-3-super:120b-a12b-q4_K_M`).
- **Architecture:** Nemotron 3 Super 120B-A12B MoE (12.7B active, 512 experts top-22, hybrid Mamba-2 + MoE + Attention, **LatentMoE**, 1M context).
- **Refusal behavior:** **Not abliterated**, but generates Jinja2 SSTI payloads (`{{ config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read() }}`) cold without permissive system prompt. Stock works fine for web-CTF payloads in practice.
- **Smoke test:** 13.2s first call (Metal JIT), ~30 tok/s decode, valid JSON-ReAct output.
- **Memory footprint:** ~90-95 GB on the 128 GB machine.
- **Wired into UI:** `ctf_solver/ui/core.py:72` — top of the local-Ollama section in `MODEL_OPTIONS`.

### `nemotron3-prism:30b-q6` (33 GB)
- **Source:** `Ex0bit/Elbaz-NVIDIA-Nemotron-3-Nano-30B-A3B-PRISM` Q6_K (wget'd to `~/models/nemotron3-prism/`, then `ollama create`).
- **Architecture:** Nemotron 3 Nano 30B-A3B MoE (3.5B active, plain MoE — NOT LatentMoE).
- **Refusal behavior:** PRISM-abliterated. No refusals.
- **The daily-driver local pick.** Works because plain MoE was supported in Ollama earlier.

### `nemotron-3-nano:latest` (24 GB)
- Stock NVIDIA Nano. Pulled earlier in project; still in store.

## Models that FAIL TO LOAD (architectural compatibility issue)

**Pattern:** Third-party abliterated GGUFs of Nemotron 3 Super hit:
```
ggml.c:3232: GGML_ASSERT(as->ne[0] == b->ne[0]) failed   # in ggml_mul_mat_id
SIGABRT: abort
```

This is the **LatentMoE** layer-shape mismatch. llama.cpp added LatentMoE support
in PR #20411 (merged 2026-03-11), but **third-party abliteration toolchains
have not yet caught up** as of 2026-05-19. Confirmed failures:

| Repo | Quant | Date | Result |
|---|---|---|---|
| `timteh673/Nemotron-3-Super-120B-A12B-Uncensored-GGUF` | Q4_K_M (86 GB) | Author's README admits llama.cpp assertion bugs | FAILED |
| `mradermacher/...heretic-i1-GGUF` | i1-Q4_K_S (76 GB) | "2 months ago" → ~March 2026 | FAILED, identical assertion |

**Lesson:** Do NOT download more third-party abliterated Super GGUFs until
someone reports a working Ollama load. The `ggml_mul_mat_id` shape mismatch
is structural — it doesn't matter how recent the upload is. **Only Ollama's
official `nemotron-3-super:*` tags are guaranteed compatible** with Ollama's
bundled engine.

**If abliteration is truly required**, MLX path with `dealignai/Nemotron-3-Super-120B-A12B-UNCENSORED-JANG_2L` (43-46 GB) is a possibility, but it uses
the proprietary JANG format — needs `jang-tools` package, NOT `mlx-lm`. Would
require non-trivial code changes to integrate with the existing MLX path
(which uses `mlx-lm` + Outlines for grammar constraint).

## Why MLX JANG_2L is so much smaller (43 GB vs 76-87 GB GGUF)

JANG_2L is **mixed-precision sub-4-bit on average**:
- 8-bit attention (the 6 GQA layers)
- 6-bit "important" (routers, embeddings, output proj)
- **2-bit experts** (the bulk — 512 experts × ~870M params each)

GGUF K-quants quantize uniformly at ~4-4.5 bits average, keeping experts at
the same precision as attention. JANG is aware that experts (which are
called rarely — only 22/512 per token) can be more aggressively quantized.

## Reproducible "is this model architecturally compatible?" check

Before pulling another third-party Nemotron 3 Super GGUF:
1. Check the repo for `latent-moe` / `LatentMoE` tags.
2. Look for HF discussion threads reporting *successful Ollama 0.24+ loads*
   on Apple Silicon. **Author claims don't count** — community reports do.
3. Verify file size matches expected GGUF layout (Q4_K_M = ~86 GB, Q4_K_S
   = ~76 GB). Identical sizes across multiple converters suggest same
   tensor layout — so they'll likely all succeed or all fail together.
4. If anything's uncertain, prefer the **official Ollama library tag**
   (`ollama pull nemotron-3-super:...`) — Ollama builds those against their
   own engine, near-100% load rate.

## UI dropdown state (`ctf_solver/ui/core.py:49-79`)

```python
MODEL_OPTIONS = [
    # Hosted: gpt-5.2, gpt-4o, claude-*, gemini-*
    # MLX: mlx-community/gemma-4-26b-a4b-it-4bit
    "nemotron-3-super:120b-a12b-q4_K_M",  # heavyweight local (120B)
    "nemotron3-prism:30b-q6",             # daily-driver local (30B abliterated)
    "gemma4:26b",
    "llama3.1:latest",
    "mistral-small:latest",
    "gpt-oss:20b",
    "edgerunner-medium:latest",
]
```

Both Nemotron entries auto-route to the Ollama provider via the `"nemotron"`
prefix in `_OLLAMA_MODEL_PREFIXES` (`ctf_solver/agent.py:233`).
