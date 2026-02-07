# Cookies, Sessions, and Authentication Bypass

> **Document Purpose:** Cookie and session manipulation techniques for CTF authentication bypass. Designed for autonomous agent retrieval with exploitation patterns, encoding detection, and tool guidance.

---

## 1. Cookies and Session IDs: How Login State Is Tracked

> **When to use this section:** Understanding cookie-based authentication.

### 1.1 What Is a Cookie?

**Tags:** `cookies, basics, http, state-management`

A cookie is a small piece of data stored by the browser and sent with every request to a particular domain.

**Key properties:**
- Stored as key–value pairs:
  - `sessionid=abcd1234`
  - `isAdmin=false`
- Sent in the Cookie header on subsequent requests:
  - `Cookie: sessionid=abcd1234; theme=dark`

**Cookies are commonly used to:**
- Track sessions (who you are between requests).
- Store user preferences.
- Sometimes hold authentication or authorization info.

---

### 1.2 Session IDs

**Tags:** `session-id, session-management, authentication, tokens`

A session ID is an opaque token that links the browser to server-side state.

**Typical flow in real web apps:**
1. You submit login credentials.
2. Server verifies them.
3. Server creates a session record (e.g., in memory or a database) containing:
   - User ID
   - Role/permissions
   - Other state
4. Server sends a Set-Cookie header:
   - `Set-Cookie: sessionid=abcd1234; HttpOnly; Secure`
5. The browser stores that cookie and sends it on future requests.
6. Server looks up `sessionid=abcd1234` to know which user you are.

**In secure real-world setups:**
- The session ID is random and not guessable.
- Server-side checks determine whether you are "admin" or "user", not the client.

---

### 1.3 Login State in Web Apps

**Tags:** `login-state, authentication, session-tracking`

In a typical design:

**Login state is tracked by:**
- A session cookie (like `sessionid`).
- Server-side session storage that knows whether that session belongs to a logged-in admin or a regular user.
- The browser doesn't decide the role; it just sends the session cookie.

**In many CTF challenges, this is simplified or intentionally misconfigured:**
- Sometimes the cookie itself encodes the role or privileges.
- Sometimes the session ID is structured or guessable.
- Sometimes the server blindly trusts values stored in cookies.

**Agent Takeaway:**
- Real apps use server-side session validation
- CTF apps often trust client-provided cookie values
- Look for role or privilege information in cookies

---

## 2. Common CTF Patterns Related to Cookies

> **When to use this section:** Identifying exploitable cookie patterns.

**Tags:** `ctf-patterns, cookie-exploitation, authentication-bypass`

This section describes patterns that appear frequently in CTF challenges. They are often unrealistic or insecure by design, to teach you how not to build real systems.

### 2.1 "isAdmin=true" Style Cookies

**Tags:** `admin-cookie, role-manipulation, privilege-escalation, ctf-trick`

A very common CTF pattern:
- After login or visiting the site, you receive a cookie like:
  - `isAdmin=false`
  - `role=user`
  - `admin=0`

**Sometimes:**
- The application uses this cookie directly to decide whether to show admin-only content.
- Changing the cookie to `isAdmin=true` or `admin=1` might grant access.

**In these CTFs:**
- There may be no server-side verification beyond reading the cookie.
- The backend may treat whatever cookie you send as truth.

**Example exploitation:**
```
Original:  Cookie: isAdmin=false
Modified:  Cookie: isAdmin=true

Original:  Cookie: role=user
Modified:  Cookie: role=admin

Original:  Cookie: admin=0
Modified:  Cookie: admin=1
```

**Agent Takeaway:**
- If you see a cookie with a name hinting at privileges, try modifying it
- This is not secure in real-world applications, but is a common CTF teaching mechanism

---

### 2.2 Encoded or Serialized Cookies

**Tags:** `base64, json, jwt, encoding, serialization, cookie-tampering`

Another frequent CTF pattern:
- The cookie value is not plain text, but still easily decodable.

**Examples of encodings:**
- Base64 strings (ending with `=` or `==`).
- JSON objects.
- JWT-like tokens without proper signatures.
- Simple serialization formats.

**Example base64 cookie:**
```
Cookie: session=eyJ1c2VybmFtZSI6Imd1ZXN0Iiwicm9sZSI6InVzZXIifQ==
```

Decoded:
```json
{"username":"guest","role":"user"}
```

**Attack:**
1. Decode the cookie.
2. Modify `"role":"user"` to `"role":"admin"`.
3. Re-encode and send.

**In CTF reasoning:**
- If a cookie looks encoded or structured, try decoding it (base64, URL decoding, JSON parsing).
- Inspect for fields like `role`, `admin`, `isAdmin`, `access`.
- Changing `role":"user"` to `role":"admin"` and re-encoding might grant access.

---

### 2.3 Misconfigured or Weak Session Handling

**Tags:** `weak-session, predictable-id, session-manipulation`

Some CTF challenges demonstrate poor session design:

**The session ID might be:**
- Short or predictable.
- Sequential or easily guessable.

**The application may:**
- Create separate session IDs for "user" and "admin" with predictable differences.
- Rely on simple tokens or IDs that can be modified by the client.

**Possible patterns:**
- A cookie like `session=1` for user, `session=2` for admin.
- A URL or cookie parameter like `uid=1` representing the current user.

While truly guessing someone else's session is not usually the goal in beginner CTFs, challenges may use this idea in a simplified form to show why randomness and server-side checks matter.

---

## 3. Step-by-Step Exploitation Examples

> **When to use this section:** Practical cookie manipulation workflows.

**Tags:** `exploitation, workflow, step-by-step, methodology`

The emphasis here is on systematic, logical steps, not brute-force.

### 3.1 Example: Inspect Cookies After Login Attempt

**Tags:** `login-bypass, cookie-inspection, workflow`

**High-level reasoning:**

1. **Start at the main page.**
   - Use `http_fetch` to get the main page.

2. **Identify login form.**
   - Use `html_inspector` to detect `<form>` elements and their action URLs.

3. **Submit credentials.**
   - Use `form_submit` with a test username/password.
   - Even if you do not know the correct values yet, the request may set or change cookies.

4. **Inspect cookies.**
   - Use `cookie_inspector` to list cookies for the domain.
   - Look for fields like:
     - `role`
     - `isAdmin`
     - `user`
     - `auth`
   - If you see `isAdmin=false` or `role=user`:
     - That is a strong hint of a CTF trick.

5. **Try modifying suspicious cookies.**
   - Use `cookie_set` to change `isAdmin=false` to `isAdmin=true`, or `role=user` to `role=admin`.

6. **Fetch a protected page.**
   - Use `http_fetch` on pages that previously showed restricted content (e.g., `/admin`).
   - If the page suddenly becomes accessible, you have bypassed auth through cookie manipulation.

---

### 3.2 Example: Encoded Cookie with Role Information

**Tags:** `base64-cookie, encoded-role, decoding, exploitation`

**Reasoning chain:**

1. **Fetch the main page and/or login.**
   - Use `http_fetch` and `form_submit`.

2. **Inspect cookies.**
   - Use `cookie_inspector`.

3. **Notice a cookie value that looks encoded.**
   - For example, it is long, contains letters, numbers, plus signs, slashes, or ends with `=`.

4. **Try decoding it:**
   - Base64 decode might give something like:
     - `{"user":"guest","role":"user"}`, or
     - `username=guest&role=user`

5. **Modify the decoded value:**
   - Change `role=user` to `role=admin`.
   - Conceptual steps:
     - Modify the string to represent `role=admin`.
     - Re-encode it in the same format (if needed).

6. **Set the modified cookie.**
   - Use `cookie_set` to assign the modified cookie value.

7. **Access pages again.**
   - Use `http_fetch` to test protected endpoints.
   - If previously restricted content becomes accessible, the challenge is using insecure, client-modifiable role information.

**Python example:**
```python
import base64
import json

# Original cookie
cookie = "eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9"

# Decode
decoded = base64.b64decode(cookie)
data = json.loads(decoded)
# {'user': 'guest', 'role': 'user'}

# Modify
data['role'] = 'admin'

# Re-encode
new_cookie = base64.b64encode(json.dumps(data).encode()).decode()
# eyJ1c2VyIjogImd1ZXN0IiwgInJvbGUiOiAiYWRtaW4ifQ==
```

---

### 3.3 Example: Look for Clues About Roles or Levels

**Tags:** `role-discovery, html-clues, systematic-approach`

Sometimes the cookie structure is not obvious at first. Use a broader recon strategy:

1. **Read responses carefully.**
   - Error messages.
   - Debug text.
   - Section headings like "Admin Panel" or "User Dashboard".

2. **Inspect HTML.**
   - Use `html_inspector` to find:
     - Comments referring to roles, like `"TODO: restrict this to admins"`.
     - Hidden fields with role or level information.

3. **Correlate cookies with these hints.**
   - If the HTML shows "Welcome, guest" and cookies mention "guest", consider how that value might become "admin".

4. **Systematically tamper with related fields.**
   - Modify a cookie that says `user=guest` to `user=admin`.
   - Try variations that make sense in context (e.g., `role=staff`, `role=superuser`).

5. **Observe responses after each change.**
   - Use `http_fetch` to see whether the app's behavior changes (new pages appear, flags become visible, etc.).

**Agent Takeaway:**
- Adjust inputs based on observed hints, not random guessing
- Correlate HTML content with cookie values
- Test role-related modifications systematically

---

## 4. Safe, Reasoning-Based Approaches

> **When to use this section:** Methodological guidance for cookie attacks.

### 4.1 Avoid Credential Brute-Forcing

**Tags:** `methodology, reasoning, targeted-approach`

In many web CTFs, the intended solution does not involve:
- Trying thousands of passwords.
- Rapid-fire guessing login credentials.

**Instead, the focus is on:**
- Discovering misconfigurations or logic flaws.
- Exploiting insecure reliance on cookies or client-side data.

**For an LLM agent:**
- Prioritize reading and understanding:
  - Cookie names and values.
  - HTML comments and hints.
  - Response messages about permissions.
- Use this understanding to make a small number of targeted modifications.

---

### 4.2 Work from Evidence, Not Random Changes

**Tags:** `evidence-based, hypothesis, systematic`

Every action should be based on a clear hypothesis:
- "This cookie is named `role`; maybe changing it will change my privileges."
- "The decoded cookie contains `admin:false`; perhaps `admin:true` is accepted."
- "The HTML mentions 'admin-only page at /admin'; I should try visiting `/admin` after modifying cookies."

**This style of reasoning:**
- Is more efficient.
- Aligns with how CTFs are designed to be solved.
- Avoids unnecessary traffic and noise.

---

## 5. Tool Usage Guide for LLM Agents

> **When to use this section:** Mapping tools to cookie exploitation scenarios.

### 5.1 When to Use cookie_inspector

**Tags:** `cookie-inspector, tool-usage, reconnaissance`

Use `cookie_inspector` when:
- You first visit the challenge page.
- You submit any login or form.
- You suspect that login or privileges may be cookie-based.

**Goals:**
- Enumerate existing cookies.
- Identify suspicious names and values.
- Look for encodings or structured data.

---

### 5.2 When to Use cookie_set

**Tags:** `cookie-set, tool-usage, manipulation`

Use `cookie_set` when:
- You have a clear hypothesis about what a cookie might represent.
- You want to test whether changing:
  - `role=user` → `role=admin`
  - `isAdmin=false` → `isAdmin=true`
  - alters behavior.

**Remember:**
- This is a CTF-specific trick; in real-world secure apps, this would normally fail or be blocked by server-side checks.

---

### 5.3 When to Use http_fetch and form_submit

**Tags:** `http-fetch, form-submit, tool-usage, verification`

Use `http_fetch` to:
- Visit pages affected by cookie changes, such as `/admin` or hidden sections.
- Observe differences in response content or status codes before and after modifications.

Use `form_submit` to:
- Log in or send controlled requests that may adjust cookies or sessions.
- Trigger flows where the server sets new cookies or changes existing ones.

---

### 5.4 Combining Cookies with Other Recon

**Tags:** `multi-technique, combined-approach, workflow`

Cookies rarely exist in isolation. Combine cookie analysis with:
- HTML inspection (`html_inspector`) to find references to roles or admin sections.
- Response inspection (and possibly search tools) to identify phrases like "Access denied", "Admin only", or "Debug mode".

**This multi-step process allows an agent to systematically:**
1. Discover how login state is tracked.
2. Infer weak trust in cookies.
3. Tamper with cookies logically.
4. Confirm successful auth bypass by accessing previously forbidden content.

---

## 6. Summary

**Tags:** `summary, cookies, sessions, key-points`

In web CTF challenges, cookies and sessions are often simplified or intentionally misconfigured to create auth bypass puzzles:
- Cookies may directly encode roles or admin status.
- Cookie values may be base64, JSON, or other easy-to-modify formats.
- Session handling may be weak or entirely client-controlled.

**An effective approach is:**
1. Inspect cookies after key actions.
2. Decode or parse structured cookie data.
3. Form hypotheses about how roles or permissions are encoded.
4. Carefully modify cookies and observe resulting behavior.

**Quick Reference - Cookie Manipulation:**

| Original Cookie | Try Changing To |
|-----------------|-----------------|
| `isAdmin=false` | `isAdmin=true` |
| `role=user` | `role=admin` |
| `admin=0` | `admin=1` |
| `level=1` | `level=9` or `level=admin` |
| `auth=guest` | `auth=admin` |

**Quick Reference - Base64 Detection:**
- Ends with `=` or `==`
- Contains only `A-Z`, `a-z`, `0-9`, `+`, `/`
- Length is multiple of 4 (after padding)

**Agent Takeaway:**
- Always check cookies after any form submission
- Look for role/admin/privilege keywords in cookie names
- Base64 and JSON are the most common encodings
- Modify and re-test protected pages
