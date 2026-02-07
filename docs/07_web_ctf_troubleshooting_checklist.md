# Web CTF Troubleshooting Checklist

> **Document Purpose:** High-level, fast-reference checklist for web CTF challenges. Designed for autonomous agent retrieval when stuck or needing quick guidance on next steps.

---

## 1. Initial Recon Checklist

> **When to use this section:** Starting a new web CTF challenge.

**Tags:** `initial-recon, checklist, first-steps, reconnaissance`

### Basic URL & Entrypoint
- Note the base URL (host + port).
- Try visiting just `/` and any obvious paths in the challenge text.

### Robots & Common Files
- Check `/robots.txt`.
- Check common "info" endpoints if hinted (e.g., `/admin`, `/backup`, `/old`, `/dev`).

### HTML Source
- View raw HTML, not just rendered page.
- Look for:
  - `<!-- comments -->`
  - Hidden inputs (`type="hidden"`)
  - Unusual IDs/classes that hint at features.

### Links & Resources
- Enumerate:
  - `<a href="...">` links.
  - `<script src="...">` external JS.
  - `<link rel="stylesheet" href="...">` CSS.
- Visit unlinked or odd-looking paths.

### JavaScript
- Collect:
  - Inline `<script>...</script>`.
  - External JS files.
- Skim for:
  - Hardcoded strings (`password`, `secret`, `flag`, `key`).
  - Conditional checks on user input.

### Forms & Parameters
- Identify all forms:
  - Action URL, method (GET/POST).
  - Input field names.
- Note all query parameters in URLs.

### Cookies & Storage
- Record all cookies:
  - Names that look like `session`, `role`, `admin`, `auth`.
  - Encoded-looking values (base64-ish, JSON-like).
- Check if new cookies appear after actions (login, clicking buttons).

---

## 2. "I'm Stuck" Sanity Checklist

> **When to use this section:** No progress after initial attempts.

**Tags:** `troubleshooting, stuck, sanity-check, basics`

**Have I...**

- [ ] Looked at `/robots.txt`?
- [ ] Viewed the full HTML source, not just devtools DOM?
- [ ] Inspected all external JS files referenced in the page?
- [ ] Searched HTML/JS for strings like:
  - `flag`, `picoCTF`, `secret`, `password`, `key`, `admin`?
- [ ] Checked cookies carefully for:
  - Suspicious names (`role`, `isAdmin`, `user`, `debug`).
  - Values that look encoded or serialized?
- [ ] Tried searching the response text for:
  - `sql`, `SELECT`, `FROM`, `WHERE`, `error`, `syntax`, `database`?
- [ ] Considered that the challenge might be about:
  - Client-side validation (JS-only checks)?
  - robots.txt and hidden paths?
  - Simple cookie tampering?
  - Basic SQL injection on a form or parameter?
- [ ] Visited every reasonable link and path I've seen so far?

---

## 3. SQL Injection Troubleshooting Checklist

> **When to use this section:** Suspecting or testing for SQL injection.

**Tags:** `sqli, sql-injection, troubleshooting, detection`

### Suspecting SQLi
**Input fields to test:**
- Login (username/password).
- Search boxes.
- Numeric IDs in URLs (e.g., `?id=1`).

**Errors or behavior changes when:**
- You add `'`, `"`, `)`, `--`, or other special characters.

### Check Responses
**Search for:**
- `SELECT`, `FROM`, `WHERE`.
- "syntax error", "SQL error", "database error".
- "unclosed quotation mark", "near '…'".

### Behavior-Based Clues
**Different behavior for:**
- Normal input vs. input with a quote.
- Inputs that look like `1` vs `1 OR 1=1`.
- "True" vs "false" style responses (content / status / redirect differences).

### Systematic Probes
**Try minimal changes:**
```
test        → Normal response
test'       → Error or different response?
test'--     → Back to normal?
```

**For numeric parameters:**
```
?id=1       → Normal
?id=1-1     → Same as id=0?
?id=1 OR 1=1  → All results?
```

### When to Use Helper Tools
- Use `response_search`:
  - To find lines containing SQL keywords or "error"/"syntax".
- Use `sql_pattern_hint`:
  - To highlight suspected SQL areas in the response.

### If Still Unsure
- Re-check which input actually hits the server (is some validation happening client-side instead?).
- Consult `ctf_knowledge_query` about SQLi patterns and error interpretation.

---

## 4. Client-Side JS / "Don't Trust the Client" Checklist

> **When to use this section:** Challenge involves JavaScript validation.

**Tags:** `client-side, javascript, validation, troubleshooting`

### Clues
**Challenge text mentions:**
- "client-side", "JavaScript", "don't trust the client", "browser checks password".

**Behavioral signs:**
- Form refuses to submit until JS conditions are met.
- Alerts like "Wrong password" without network requests.

### What to Inspect
**Gather:**
- All inline JS in `<script>`.
- All linked JS files.

**Search JS for:**
- Strings that look like passwords/keys/flag pieces.
- Comparisons like `input === "something"` or `=== secret`.
- Functions bound to buttons/onsubmit handlers.

### Reasoning Steps
**Identify:**
- Where user input is read (e.g., `document.getElementById(...)`).
- Where it's compared to constants or processed.

**Reconstruct:**
- "What exact value makes this condition true?"
- "Does the code assemble a secret from pieces?"

### Bypass Strategy
Use the derived correct value to:
- Either satisfy JS (for a quick win), or
- Skip JS and send it directly via an HTTP request.

### When to Use Helper Tools
- `html_inspector`:
  - To list scripts and find JS files.
- `javascript_source`:
  - To pull inline & external JS for analysis.
- `regex_search`:
  - To search JS for `password`, `secret`, `flag`, `key`, etc.

### If Stuck
- Consider simple encodings:
  - Base64-looking strings.
  - Character codes assembled into text.
- Ask `ctf_knowledge_query` about common client-side CTF patterns.

---

## 5. Cookies & Session Handling Checklist

> **When to use this section:** Testing for cookie-based vulnerabilities.

**Tags:** `cookies, sessions, authentication, troubleshooting`

### Initial Checks
**List all cookies. Look for:**
- `session`, `auth`, `token`, `user`, `role`, `admin`, `isAdmin`.
- Values that look base64 / JSON / JWT-ish.

### After Actions
**Submit a login attempt (even with fake creds). Re-inspect cookies:**
- Did any new cookies appear?
- Did any values change?

### Common CTF Patterns
**Plaintext role flags:**
```
isAdmin=false → try true
role=user → try role=admin
admin=0 → try admin=1
```

**Encoded data:**
- Base64-decoded cookie looks like JSON describing user/role.
- Simple serialized structures that can be edited and re-encoded.

### Systematic Steps
1. **Hypothesize:**
   - "This cookie controls my role or access."
2. **Carefully modify:**
   - Toggle booleans like `false` → `true`.
   - Change `user` → `admin` in structured data.
3. **Re-request sensitive endpoints:**
   - `/admin`, `/flag`, `/secret`, etc.

### Tool Usage
- `cookie_inspector`:
  - To see current cookies and values.
- `cookie_set`:
  - To set modified values and persist them across requests.
- `http_fetch` / `form_submit`:
  - To revisit important endpoints under the new cookie state.

### If Unsure
- Re-check HTML/JS for hints about roles or admin areas.
- Consult `ctf_knowledge_query` for common cookie/role tricks.

---

## 6. General "When to Consult External Knowledge" Checklist

> **When to use this section:** Deciding when to use RAG/knowledge queries.

**Tags:** `rag, knowledge-query, external-resources, guidance`

### Call ctf_knowledge_query When...

**You recognize a vulnerability type but forget:**
- Typical payload shapes.
- Recon steps or patterns (e.g., basic SQLi workflow).

**Challenge mentions:**
- Robots.txt / crawlers / user-agents.
- Client-side auth, obfuscation, or JS password check.
- Cookies, sessions, or roles, but you're unsure how to systematically test them.

**You see:**
- SQL errors, but are unsure how to interpret them.
- Encoded/obfuscated strings in JS or cookies that look like base64/hex but you're not certain.

**You've done basic recon (HTML, robots, JS, cookies, forms) and:**
- Need guidance on which attack pattern fits the hints.

### Use ctf_knowledge_query to Get...

**Short explanations of:**
- SQLi patterns, Boolean-based behavior, error interpretation.
- Client-side JS abuse and common obfuscation tricks.
- Cookie tampering and role-escalation patterns in CTFs.
- Generic examples and strategies—not specific solutions or flags.

---

## 7. Quick One-Liner Checklist (Ultra-Short)

> **When to use this section:** Fastest reference when completely stuck.

**Tags:** `quick-reference, one-liner, ultra-short, emergency`

**Before giving up, ask:**

- [ ] Checked `/robots.txt`?
- [ ] Viewed HTML source and comments?
- [ ] Inspected all JS (inline + external)?
- [ ] Extracted and reviewed all cookies?
- [ ] Tested key inputs with simple special characters (`'`, `"`, `<`, `>`)?
- [ ] Searched responses for `sql`, `error`, `flag`, `secret`, `admin`?
- [ ] Considered that the real logic might be in JS, cookies, or SQL?
- [ ] Called `ctf_knowledge_query` when the pattern is recognizable but details are fuzzy?

---

## 8. Summary: Decision Tree

**Tags:** `summary, decision-tree, workflow, quick-reference`

```
START: New web challenge
│
├─ Step 1: Initial Recon
│  ├─ Fetch main page
│  ├─ Check /robots.txt
│  ├─ View HTML source
│  └─ List cookies
│
├─ Step 2: Identify Challenge Type
│  ├─ Hidden paths → robots.txt + enumeration
│  ├─ View source hints → HTML/JS inspection
│  ├─ Login form → SQLi or cookie manipulation
│  ├─ Client-side → JS analysis
│  └─ Old/backup hints → path enumeration
│
├─ Step 3: Targeted Testing
│  ├─ SQLi: Add quotes, check for errors
│  ├─ Cookies: Modify role/admin values
│  ├─ JS: Find hardcoded credentials
│  └─ Paths: Visit discovered endpoints
│
├─ Step 4: Stuck?
│  ├─ Run sanity checklist
│  ├─ Try missed recon steps
│  └─ Consult knowledge base
│
└─ Step 5: Flag Retrieved!
```

**Agent Takeaway:**
- Use checklists to avoid missing simple steps
- Most CTFs are solved with basic recon, not complex exploits
- When stuck, return to fundamentals: source, robots, cookies, JS
- Pattern recognition drives efficient solving
