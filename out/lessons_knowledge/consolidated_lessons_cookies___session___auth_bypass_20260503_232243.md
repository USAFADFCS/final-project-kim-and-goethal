# Consolidated Lessons: Cookies / Session / Auth Bypass

> **Auto-generated:** 2026-05-03 23:22:43 UTC
> **Category:** Cookies / Session / Auth Bypass
> **Type:** consolidated_lessons (5 docs — 2 success, 3 failure)
> **Tags:** `consolidated, cookies___session___auth_bypass, lessons, high-priority, wisdom`

> **Agent Note:** This consolidates patterns from multiple runs on this category.
> Use the Quick Exploitation Path as your primary action guide.

---

## Coverage

- **Total atomic rule docs:** 5
- **Success runs:** 2
- **Failure/partial runs:** 3

## Best Exploitation Path (from most recent success)

> **Note:** Replace `<TARGET_URL>` with the current challenge URL.

1. **`http_fetch`**: Fetch the target URL to map the application and identify input forms — use: `{"url":"<TARGET_URL>/","method":"GET","max_body":4000}`
2. **`cookie_set`**: Override or forge a session cookie

## Key Takeaways (ranked by frequency across runs)

1. Follow this winning tool sequence: http_fetch → cookie_set
2. Continue exploitation after confirming 'auth_bypassed' — do not stop at reconnaissance
3. Service may be rate-limiting or the challenge URL has changed — reduce request rate, verify URL, and try http_fetch before specialised tools
4. Immediately call cookie_set, form_submit, http_fetch before exploring other vectors — do not miss this signal
5. Pivot to a different attack vector early rather than repeating the same approach with minor variations

## Confirmed Winning Inputs

These exact requests produced the flag:

- `http_fetch` input: {"url":"http://adminportal.chals.mctf.io/","method":"GET","max_body":4000}
- `http_fetch` input: {"url":"http://adminportal.chals.mctf.io/","method":"GET","max_body":0}
