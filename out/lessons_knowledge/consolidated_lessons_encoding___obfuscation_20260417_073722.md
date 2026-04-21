# Consolidated Lessons: Encoding / Obfuscation

> **Auto-generated:** 2026-04-17 07:37:22 UTC
> **Category:** Encoding / Obfuscation
> **Type:** consolidated_lessons (2 docs — 2 success, 0 failure)
> **Tags:** `consolidated, encoding___obfuscation, lessons, high-priority, wisdom`

> **Agent Note:** This consolidates patterns from multiple runs on this category.
> Use the Quick Exploitation Path as your primary action guide.

---

## Coverage

- **Total atomic rule docs:** 2
- **Success runs:** 2
- **Failure/partial runs:** 0

## Best Exploitation Path (from most recent success)

> **Note:** Replace `<TARGET_URL>` with the current challenge URL.

1. **`http_fetch`**: Fetch the target URL to map the application and identify input forms — use: `{"url":"<TARGET_URL>/","method":"GET","max_body":4000}`
2. **`javascript_source`**: Inspect JS for injection points, credentials, or API endpoints
3. **`robots_txt`**: Check robots.txt for hidden paths
4. **`encoding`**: Use `encoding` — use: `{"text":"cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzX0M0MzBBRTIwfQ==","operation":"base64_decode"}`

## Key Takeaways (ranked by frequency across runs)

1. Follow this winning tool sequence: http_fetch → javascript_source → robots_txt → encoding
2. Continue exploitation after confirming 'recon_complete' — do not stop at reconnaissance

## Confirmed Winning Inputs

These exact requests produced the flag:

- `http_fetch` input: {"url":"http://verbal-sleep.picoctf.net:50876/","method":"GET","max_body":4000}
- `http_fetch` input: {"url":"http://verbal-sleep.picoctf.net:50876/login.php","method":"GET","max_body":4000}
- `encoding` input: {"text":"cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzX0M0MzBBRTIwfQ==","operation":"base64_decode"}
