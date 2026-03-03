# Client-Side Access Control Bypass — CTF Exploitation Reference

> **Document Purpose:** Techniques for bypassing client-side-only access restrictions in web CTF challenges. Covers CSS/DOM paywalls, JavaScript validation bypass, cookie-based access control, and front-end-only authentication.

---

## 1. CSS/DOM PAYWALL BYPASS

> **When to use this section:** A page displays a paywall, subscription wall, or "premium content" overlay, but the actual content is present in the HTML DOM (just hidden by CSS).

**Tags:** `paywall, bypass, client-side, css, dom, overlay, subscription, premium`

### 1.1 How CSS Paywalls Work

Many news sites and CTF challenges use CSS overlays to hide content:
- A `<div>` with `position: fixed; z-index: 99999` covers the page
- The actual article content is fully rendered in the DOM underneath
- No server-side access control exists — the content is already delivered

### 1.2 Detection

**Signs of a CSS-only paywall:**
- Full HTML content is visible in the page source (use `http_fetch`)
- A `position: fixed` or `position: absolute` overlay element exists
- JavaScript only handles the overlay UI (no authentication API calls)
- No `Set-Cookie` headers indicating session-based access control
- `robots.txt` and `cookie_inspector` reveal nothing actionable

**Agent Takeaway:**
- If `http_fetch` returns the full page HTML, the content is already there
- The flag may be beyond the default truncation limit — use `max_body: 0` or a large value
- Use `regex_search` to search the full response for the flag pattern

### 1.3 Bypass Techniques

| Technique | How | Tool |
|-----------|-----|------|
| **Read full HTML source** | Fetch page, search for flag pattern in full response | `http_fetch` with `max_body: 0` |
| **Search for flag pattern** | Regex search on the response body | `regex_search` |
| **Inspect hidden content** | Look at HTML elements after the overlay | `html_inspector` |
| **Disable JavaScript** | Fetch page without executing JS (default for http_fetch) | `http_fetch` |

### 1.4 Common Flag Locations in Paywall Challenges

- Inside `<article>` or `<main>` content, after 2000+ chars of article text
- In HTML comments (`<!-- FLAG{...} -->`)
- In `data-*` attributes on hidden elements
- In JavaScript variables not used for authentication

---

## 2. JAVASCRIPT VALIDATION BYPASS

> **When to use this section:** A login form or access check is implemented entirely in client-side JavaScript, with no server-side validation.

**Tags:** `javascript, validation, bypass, client-side, password, credential, hardcoded`

### 2.1 Common Patterns

**Hardcoded credentials in JavaScript:**
```javascript
const VALID_PASSWORD = 'super-secret-password';
if (input.value === VALID_PASSWORD) { window.location = '/dashboard'; }
```

**Client-side redirect without server auth:**
```javascript
if (j.ok) { window.location = './admin'; }
```

**Token prefix validation only:**
```javascript
const requiredPrefix = 'cur8-';
if (!token.startsWith(requiredPrefix)) { alert('Invalid'); return; }
```

### 2.2 Exploitation Chain

1. **DISCOVER:** Use `javascript_source` to extract all JavaScript (inline + external)
2. **IDENTIFY:** Look for hardcoded passwords, token formats, redirect URLs
3. **EXPLOIT:** Use the discovered credentials to authenticate:
   - POST to the login endpoint with `http_fetch`
   - Set cookies with `cookie_set` if needed
4. **ACCESS:** Visit the protected page (dashboard, admin, etc.) to find the flag

**Agent Takeaway:**
- Finding a credential or token format is NOT the flag — you MUST use it
- Try visiting protected URLs directly first (many CTFs skip server-side checks)
- If JavaScript shows `window.location = './protected'`, try fetching that URL directly

---

## 3. COOKIE-BASED ACCESS CONTROL

> **When to use this section:** Access to content is controlled by cookie values that can be modified client-side.

**Tags:** `cookie, access control, bypass, role, admin, privilege, manipulation`

### 3.1 Common Cookie Patterns

| Cookie | Bypass |
|--------|--------|
| `role=user` | Change to `role=admin` |
| `admin=false` | Change to `admin=true` |
| `is_admin=0` | Change to `is_admin=1` |
| `access_level=1` | Change to `access_level=99` |
| `subscription=free` | Change to `subscription=premium` |

### 3.2 Exploitation Chain

1. **INSPECT:** Use `cookie_inspector` to see current cookies
2. **MODIFY:** Use `cookie_set` to change access-control cookies
3. **RE-FETCH:** Use `http_fetch` to reload the page with modified cookies
4. **EXTRACT:** Find the flag in the now-visible content

---

## 4. FRONT-END ROUTING BYPASS

> **When to use this section:** A single-page application (SPA) uses client-side routing, and protected routes can be accessed directly.

**Tags:** `spa, routing, bypass, direct access, protected page, react, angular, vue`

### 4.1 Detection

- JavaScript contains route definitions (e.g., `/admin`, `/dashboard`, `/flag`)
- Navigation guards exist only in client-side code
- No server-side authentication middleware

### 4.2 Bypass

Simply fetch the protected URL directly with `http_fetch`:
- `/admin`, `/dashboard`, `/flag`, `/secret`, `/protected`
- Check JavaScript for `window.location`, `router.push`, or `navigate()` calls

---

## 5. HIDDEN HTML CONTENT

> **When to use this section:** Content is present in the HTML but hidden via CSS (`display: none`, `visibility: hidden`, `opacity: 0`, etc.).

**Tags:** `hidden, css, display none, visibility, opacity, html, content`

### 5.1 Detection Methods

- Use `http_fetch` to get raw HTML (CSS is not applied)
- Use `html_inspector` to find elements with suspicious classes/IDs
- Search for `display: none`, `visibility: hidden`, `opacity: 0` in CSS
- Check for elements outside the visible viewport (`position: absolute; left: -9999px`)

### 5.2 Common Hiding Techniques

| CSS Property | What to Look For |
|--------------|------------------|
| `display: none` | Hidden elements in DOM |
| `visibility: hidden` | Invisible but space-occupying |
| `opacity: 0` | Fully transparent |
| `position: fixed; inset: 0; z-index: 99999` | Full-page overlay |
| `overflow: hidden; height: 0` | Content clipped to zero height |
| `color: transparent` / `color: #fff` on white bg | Text blended with background |

**Agent Takeaway:**
- Raw HTTP responses include ALL HTML content regardless of CSS styling
- `http_fetch` does not execute CSS — hidden content is fully visible in the response
- If the response is truncated, use `max_body: 0` to get the full body, or use `regex_search` to search for flag patterns

---

## 6. DECISION TREE

```
Page has a paywall/overlay?
├── YES: Is content in the HTML source?
│   ├── YES → Read full HTML (http_fetch with max_body: 0), search for flag
│   └── NO → Check JavaScript for auth logic
│       ├── Hardcoded credentials → Use them to POST to login, then visit protected page
│       ├── Token prefix → Construct valid token, POST to login
│       └── Redirect URL → Try fetching protected URL directly
├── NO: Is access controlled by cookies?
│   ├── YES → Modify cookies with cookie_set, re-fetch page
│   └── NO → Check for other client-side controls
└── Server returns different content for authenticated vs unauthenticated?
    ├── YES → This is server-side auth, try injection or credential attacks
    └── NO → Content is same for all users, search full response for flag
```
