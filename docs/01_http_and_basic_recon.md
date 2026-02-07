# HTTP and Basic Recon for Web CTF Challenges

> **Document Purpose:** Comprehensive HTTP fundamentals and reconnaissance techniques for CTF challenges. Designed for autonomous agent retrieval with structured workflows and tool guidance.

---

## 1. HTTP Basics Refresher

> **When to use this section:** Understanding HTTP communication in web challenges.

### 1.1 Request–Response Model

**Tags:** `http, request-response, basics, protocol, communication`

Web applications in CTFs typically communicate over HTTP:
- The client (browser or script) sends a request.
- The server replies with a response.

Understanding what is in each part of the request and response is essential for reasoning about vulnerabilities.

**Agent Takeaway:**
- Every web interaction is a request-response pair
- Both parts contain valuable information for exploitation
- Tools should capture and analyze both directions

---

### 1.2 HTTP Methods

**Tags:** `http, methods, get, post, request-types`

Common methods encountered in web CTF challenges:

| Method | Purpose | Parameter Location |
|--------|---------|-------------------|
| GET | Retrieves a resource | URL query string (`?id=1`) |
| POST | Sends data to server | Request body |
| HEAD | Headers only (no body) | URL query string |
| PUT | Update resource | Request body |
| DELETE | Remove resource | URL or body |
| OPTIONS | Check allowed methods | N/A |

**GET:**
- Parameters usually appear in the URL query string (e.g., `?id=1`).
- Often used for simple pages and read-only actions.

**POST:**
- Sends data in the request body (e.g., form submissions, JSON).
- Frequently used for login forms, search forms, and data updates.

**HEAD:**
- Same as GET but requests headers only (no body).
- Useful for quickly checking existence/metadata without loading full content.

**Less common but sometimes relevant:**
- PUT, DELETE, OPTIONS, TRACE
- Their presence can hint at a richer API surface.

**Agent Takeaway:**
- The method affects where parameters are placed
- Check if the server accepts methods other than GET/POST
- Some vulnerabilities only work with specific methods

---

### 1.3 Status Codes

**Tags:** `http, status-codes, response-codes, indicators`

HTTP status codes summarize the outcome:

**2xx – Success:**
- 200 OK – Normal success. Indicates that the request was understood and processed.

**3xx – Redirection:**
- 301 Moved Permanently, 302 Found – Redirect to another location.
- In CTFs, redirects after login can be important; the redirect target can indicate success or failure.

**4xx – Client Errors:**
- 400 Bad Request – Malformed request.
- 401 Unauthorized, 403 Forbidden – Access denied or requires authentication.
- 404 Not Found – Missing resource; sometimes used to hide content or as a hint.

**5xx – Server Errors:**
- 500 Internal Server Error – The server encountered an error.
- In CTFs, 500 responses triggered by crafted input can indicate unsafe handling of user data (e.g., potential SQL injection or other bugs).

**Agent Takeaway:**
- The combination of method, URL, and status code gives strong clues about server behavior
- 500 errors after special input = likely injection point
- 302 after login attempt = check where it redirects

---

### 1.4 Headers

**Tags:** `http, headers, cookies, metadata, request-headers, response-headers`

HTTP headers are key–value pairs that provide metadata.

**Important Request Headers:**

| Header | Purpose | CTF Relevance |
|--------|---------|---------------|
| Host | Target hostname | May influence routing |
| User-Agent | Client identifier | Sometimes used as input |
| Referer | Referring page | Occasionally checked in filters |
| Cookie | Session/state data | Critical for auth bypass |
| X-Forwarded-For | Original client IP | IP-based access bypass |
| Authorization | Auth credentials | Basic/Bearer token attacks |

**Important Response Headers:**

| Header | Purpose | CTF Relevance |
|--------|---------|---------------|
| Set-Cookie | Store cookies | Sessions, roles, tokens |
| Location | Redirect target | Post-login behavior |
| Content-Type | Body format | HTML, JSON, text |
| Server | Server software | Technology fingerprinting |
| X-Powered-By | Framework info | Technology fingerprinting |

**Agent Takeaway:**
- Headers are useful for discovering cookies and roles
- Understanding redirects helps trace authentication flow
- Security headers provide insight into mitigations

---

### 1.5 URL Query Parameters and Body Parameters

**Tags:** `http, parameters, query-string, form-data, json, input`

User input reaches the server through:

**Query parameters (GET):**
```
/page?param=value&search=keyword
```
Each parameter can influence server-side logic (search queries, record IDs, filters).

**Form fields (POST):**
```
Content-Type: application/x-www-form-urlencoded
username=admin&password=secret
```

**JSON body:**
```json
Content-Type: application/json
{"username": "admin", "password": "secret"}
```

**Agent Takeaway:**
- Treat each parameter as a potential attack surface
- Observe how changing each parameter affects responses
- Test with special characters: `'`, `"`, `<`, `>`, `{`, `}`

---

### 1.6 Response Body

**Tags:** `http, response-body, html, json, content`

The response body usually contains:
- **HTML** – Rendered page content.
- **JSON** – Data API responses.
- **Plain text** – Debug output, error messages, or hints.

**In many challenges, important clues are found in:**
- Comments inside HTML.
- Hidden elements.
- Text that looks like stack traces, SQL, or configuration information.

---

## 2. HTTP Tooling Mindset

> **When to use this section:** Choosing appropriate tools for web testing.

### 2.1 Browser as a Primary Tool

**Tags:** `browser, devtools, manual-testing, recon`

The browser is usually the first view of the challenge:
- Navigate to the URL.
- Interact naturally with forms and buttons.
- Open developer tools to inspect network requests and the DOM.

The browser gives a high-level picture of how the app is intended to work.

---

### 2.2 Programmatic HTTP Clients

**Tags:** `http-client, automation, scripting, curl, requests`

CTF players often also use:
- Command-line HTTP clients (curl, wget, httpie).
- Scripted HTTP requests in languages like Python.
- Browser-like tools that show raw requests and responses.

**These tools let you:**
- Precisely control headers, methods, and bodies.
- Repeat modified requests quickly.
- Automate tests for a variety of inputs.

**Example curl commands:**
```bash
# Basic GET request
curl -v http://target.com/

# POST with form data
curl -X POST -d "username=admin&password=test" http://target.com/login

# Custom headers
curl -H "Cookie: session=abc123" http://target.com/admin

# Follow redirects
curl -L http://target.com/login
```

---

### 2.3 Developer Tools

**Tags:** `devtools, network-tab, elements, storage, debugging`

Common uses of browser dev tools:

**Network tab:**
- See every request and response.
- Inspect headers, bodies, and timing.
- Discover API endpoints that are not visible in page links.

**Elements / DOM inspector:**
- View the structure of HTML.
- See hidden inputs or dynamically created content.

**Storage / Application:**
- Inspect cookies, localStorage, and sessionStorage.
- See what values are persisted across requests.

**Agent Takeaway:**
- Treat the browser as both a normal user interface and a protocol analyzer
- The Network tab reveals hidden API calls
- Storage shows all client-side state

---

### 2.4 Custom Scripts and Automation

**Tags:** `automation, scripting, python, requests-library`

Custom scripts (for example, in Python) are often used to:
- Repeat specific request patterns.
- Modify parameters programmatically.
- Extract specific values from responses.

**Example Python script:**
```python
import requests

# Test multiple payloads
payloads = ["'", "\"", "<script>", "{{7*7}}"]
for payload in payloads:
    r = requests.get(f"http://target.com/search?q={payload}")
    if "error" in r.text.lower():
        print(f"Potential injection with: {payload}")
```

---

## 3. Typical Recon Steps

> **When to use this section:** Systematic reconnaissance workflow.

### 3.1 Fetch the Main Page and Inspect HTML

**Tags:** `recon, html-inspection, initial-fetch, source-code`

Initial recon often follows this pattern:

1. **Fetch the base URL.**
   - Observe the status code and main page content.

2. **Inspect the HTML.**
   - Look for:
     - Links (`<a href=...>`) to other paths.
     - Forms (login, search, upload).
     - Scripts and styles (`<script>`, `<link>`) that load additional resources.
     - Comments (`<!-- ... -->`) containing hints or notes.

**Agent Takeaway:**
- First action: fetch main page
- Follow-up: summarize HTML structure and extract links/scripts/comments

---

### 3.2 Enumerate Links, Forms, and Parameters

**Tags:** `enumeration, links, forms, parameters, mapping`

After the initial page:

**Links:**
- Visit each discovered path.
- Note unusual directories or filenames (e.g., `/admin`, `/backup`, `/secret`).

**Forms:**
- Record:
  - Action URL.
  - Method (GET/POST).
  - Field names (username, password, search, etc.).

**Parameters:**
- Experiment with changing parameter values.
- Note how responses differ with different inputs.

**Agent Takeaway:**
- Build a map of the application
- Track what pages exist and how data moves
- Identify where user input is processed

---

### 3.3 Check robots.txt and Other Common Endpoints

**Tags:** `robots-txt, common-paths, enumeration, hidden-endpoints`

As part of basic recon, many CTF players:
- Request `/robots.txt`.
- Check for `Disallow:` lines suggesting hidden or sensitive paths.
- Try simple variations of known paths:

**Common paths to check:**
```
/robots.txt
/admin
/admin/
/backup
/old
/secret
/dev
/test
/debug
/.git/
/.env
/config
```

These paths often contain further clues or the final flag.

---

### 3.4 Inspect HTTP Response Headers

**Tags:** `response-headers, cookies, redirects, server-info`

For each response, it can be useful to look at:

**Set-Cookie headers:**
- Identify new cookies or changed values (e.g., role changes after login).

**Location header:**
- Understand redirect targets, especially after forms.

**Content-Type:**
- Confirm whether the response is HTML, JSON, or something else.

**Headers may reveal:**
- Session identifiers.
- Debug or framework information.
- Redirection logic after authentication attempts.

---

### 3.5 Explore Error Behavior

**Tags:** `error-testing, fuzzing, special-characters, injection-detection`

Intentionally trying "unusual" input can trigger errors:
- Special characters (`'`, `"`, `%`, `;`, etc.).
- Very long values.
- Missing or malformed parameters.

**When these cause:**
- 500 errors,
- Full stack traces, or
- Raw SQL or server-side messages in responses,

This suggests areas where input may be handled unsafely.

**Quick injection test characters:**
```
'
"
;
--
<
>
{{
${
```

---

## 4. Recording Observations

> **When to use this section:** Organizing findings during recon.

### 4.1 Track Endpoints and Methods

**Tags:** `documentation, tracking, endpoints, methods`

Keep a structured list of:
- Each URL visited.
- Method used (GET/POST).
- Observed status codes.
- Presence of forms and parameters.

This helps avoid repeating the same tests and reveals which areas remain unexplored.

---

### 4.2 Track Parameters and Their Effects

**Tags:** `parameter-tracking, input-output, behavior-analysis`

For each parameter:

**Note:**
- Name (id, user, search, password, etc.).
- Typical values seen in normal use.

**Test:**
- Slight variations.
- Special characters.
- Empty or missing values.

**Record:**
- How the page responds.
- Whether responses differ based on input.
- Any new errors or messages.

---

### 4.3 Track Cookies and Session Changes

**Tags:** `cookie-tracking, session-analysis, state-changes`

As you interact with the site:
- Observe cookies before and after:
  - Visiting new pages.
  - Submitting forms.
  - Logging in or out.

**Record:**
- Which cookies change.
- Whether new cookies appear.
- Any clearly meaningful names (`admin`, `role`, `session`, etc.).

Changes in cookies often signal:
- Transitions in authentication or authorization state.
- Potential points where manipulation could yield higher privileges.

---

### 4.4 Note Suspicious Strings and Patterns

**Tags:** `pattern-recognition, keywords, suspicious-content, clues`

While reading responses:
- Highlight lines or fragments that mention:
  - SQL keywords (`SELECT`, `FROM`, `WHERE`).
  - File paths or system errors.
  - `"admin"`, `"flag"`, `"secret"`, `"debug"`, `"test"`.

**These may be partial disclosures of:**
- Database queries.
- File system structure.
- Internal logic.

---

## 5. Common "Red Flags" in Responses

> **When to use this section:** Identifying exploitation opportunities.

### 5.1 Debug Messages and Stack Traces

**Tags:** `debug-info, stack-traces, information-disclosure`

If a response contains:
- Detailed error messages.
- Stack traces with function names and file paths.
- References to specific frameworks or database drivers.

**This suggests:**
- The server is returning internal information.
- Invalid input is reaching deeper into the application than intended.

These messages can guide which inputs to refine and which components may be vulnerable.

---

### 5.2 SQL-Related Text

**Tags:** `sql-errors, database-errors, injection-indicators`

Lines that contain:
- `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `FROM`, `WHERE`
- Phrases like "syntax error in SQL statement" or "database error"
- Clearly interpolated user input in a query-like string

**Often indicate:**
- Potential or actual SQL injection behavior.
- Mis-handling of input in constructing queries.

Such output is a strong cue to focus on parameters and form fields related to that request.

---

### 5.3 "Admin" or Role-Based Language

**Tags:** `admin, roles, privileges, access-control`

Words such as:
- `"admin"`, `"administrator"`, `"moderator"`
- `"role"`, `"privilege"`, `"access level"`

May appear in:
- HTML content.
- Comments.
- Responses from login endpoints.

**These can hint at:**
- Role-based behavior that might be influenced by cookies or parameters.
- Hidden admin pages or functions.

---

### 5.4 Configuration or Path Leaks

**Tags:** `path-disclosure, config-leaks, information-disclosure`

Responses that show:
- File paths (e.g., `/var/www/html/app.php`).
- Configuration keys or environment variable names.
- Framework-specific warnings.

**Indicate that:**
- Error handling is exposing internal details.
- There may be misconfigurations that can be abused.

Even if not directly exploitable, these details can guide further reasoning about the stack and likely vulnerabilities.

---

### 5.5 Suspicious Comments and Leftover Artifacts

**Tags:** `html-comments, debug-artifacts, todo-notes, hints`

HTML comments or leftover code might contain:
- TODO notes.
- Debug statements.
- References to old endpoints or test pages.
- Mentions of flags or secrets.

These are often intentional hints in CTF design and should be examined closely.

---

## 6. Summary: Agent Tool Usage Guide

**Tags:** `summary, tool-usage, workflow, agent-guidance`

For an AI agent equipped with tools, this reference guides when and why to call them:

**When first given a base URL:**
- Call an HTTP fetch tool on the main page.
- Then call an HTML inspection tool to summarize links, forms, scripts, and comments.

**After discovering parameters or forms:**
- Use HTTP/form submission tools to test variations of input.
- Use search tools to scan responses for keywords (`sql`, `error`, `admin`, `flag`).

**When seeing errors or unusual output:**
- Use focused search tools to pull out surrounding lines.
- Adjust further requests based on error content and context.

**When cookies change:**
- Inspect cookies systematically and reason about their meaning.
- Consider whether cookie manipulation could affect access level or behavior.

**Agent Takeaway:**
- Always start with basic recon: main page, robots.txt, source inspection
- Track all discovered endpoints, parameters, and cookies
- Use error behavior to identify injection points
- Combine multiple observations to form exploitation hypotheses
