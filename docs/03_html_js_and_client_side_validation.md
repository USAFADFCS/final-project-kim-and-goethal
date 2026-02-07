# HTML and JavaScript Inspection for CTF Challenges

> **Document Purpose:** Techniques for inspecting HTML and reasoning about client-side JavaScript in CTF challenges. Designed for autonomous agent retrieval with static analysis patterns and bypass strategies.

---

## 1. "View Source" Basics

> **When to use this section:** Inspecting raw HTML for hidden content.

### 1.1 How to View Source

**Tags:** `view-source, html-inspection, raw-html, basics`

When you open a challenge URL, the rendered page is only part of the story. The raw HTML often contains crucial hints.

In a browser (or using an HTTP tool), you can view the raw HTML returned by the server.

**For an agent:**
- Use an HTTP fetch tool on the page.
- Pass the response body to an HTML inspection tool.

---

### 1.2 HTML Elements of Interest

**Tags:** `html-elements, comments, hidden-inputs, scripts, links`

When scanning HTML, focus on:

**Comments:**
```html
<!-- TODO: remove debug login -->
<!-- Hint: password is not what it seems -->
<!-- Flag is in /secret/flag.txt -->
```
These may contain hints, old notes, or references to hidden URLs or features.

**Hidden inputs:**
```html
<input type="hidden" name="role" value="user">
<input type="hidden" name="debug" value="false">
<input type="hidden" name="admin" value="0">
```
Hidden inputs can leak default roles, tokens, or configuration data. Sometimes the challenge expects you to change or replay these values directly via HTTP.

**Links:**
```html
<a href="/admin">Admin Panel</a>
<a href="/static/app.js">App JS</a>
<script src="/js/validation.js"></script>
```
Links can reveal admin pages, backup pages, or important script files.

**Inline scripts:**
```html
<script>
  const secret = "supersecret";
  const flag = "picoCTF{...}";
</script>
```
Inline JavaScript may hold keys, flag fragments, or credential checks.

**Agent Takeaway:**
- Always inspect raw HTML, not just rendered content
- Search for comments, hidden inputs, and script tags
- Follow all links to JS files and other resources

---

### 1.3 Using Tools

**Tags:** `html-tools, regex-search, automation, inspection`

For an LLM-based agent:
- Call `html_inspector` after fetching HTML to:
  - Extract links, scripts, styles, and comments.
  - Summarize what to explore next.
- Use `regex_search` on HTML if you want to:
  - Search for patterns like `secret`, `password`, `flag`, or `picoCTF{`.

**Useful search patterns:**
```
flag
picoCTF{
password
secret
admin
key
token
TODO
FIXME
```

---

## 2. Common Client-Side Patterns in CTF Challenges

> **When to use this section:** Identifying exploitable client-side logic.

**Tags:** `client-side, javascript, patterns, vulnerabilities`

Many web CTF challenges teach that client-side checks are not security. They often implement logic in JavaScript that can be inspected and bypassed.

### 2.1 Hardcoded Passwords or Keys in JS

**Tags:** `hardcoded-credentials, javascript, password-disclosure`

A classic beginner pattern:
```javascript
const correctPassword = "supersecret";
if (userInput === correctPassword) {
    // Grant access
}
```

**Key observations:**
- The password or key is hardcoded in the script.
- There may be no server-side verification; the browser just compares strings.

**In a CTF:**
- You can read the JS to recover the password directly.
- You might also choose to skip the UI and send the correct value via a direct HTTP request.

---

### 2.2 Simple if (input === secret) Checks

**Tags:** `string-comparison, validation-logic, bypass`

Variations of the same idea:
```javascript
function checkLogin() {
    var user = document.getElementById('username').value;
    var pass = document.getElementById('password').value;
    if (user === "admin" && pass === "supersecret") {
        window.location = "/success.html";
    }
}
```

The logic is straightforward: string equality comparisons. Sometimes the "secret" is split into pieces in variables, but the structure remains simple.

---

### 2.3 Obfuscated or Minified JavaScript

**Tags:** `obfuscation, minification, deobfuscation, encoding`

More advanced client-side challenges try to hide the logic:
- **Minified JS:** code all on one line, very short variable names.
- **Obfuscated JS:** strange variable names, extra operations, scrambled strings.

**Common patterns:**
- Concatenating multiple string fragments into a final password or flag.
- Using ASCII codes: arrays of numbers that are turned into characters.
- Encoding/decoding functions: base64, simple ciphers, or character shifts.

**The JS might:**
```javascript
// Concatenation
var a = "pi" + "co" + "CTF{" + "fl4g}";

// From char codes
var flag = String.fromCharCode(112, 105, 99, 111);

// Base64 decode
var secret = atob("cGljb0NURns...}");

// Reverse string
var pass = "terces".split("").reverse().join("");
```

The challenge is to reverse this logic by reading the code, not just running it blindly.

---

### 2.4 How an Agent Detects These Patterns

**Tags:** `pattern-detection, static-analysis, automation`

An LLM agent can:
- Use `javascript_source` to fetch all inline and external scripts from a page.
- Scan the JS using `regex_search` for clues like `password`, `secret`, `flag`, `picoCTF`, or `key`.
- Reason about assignments and conditions, especially patterns resembling:
  - Equality checks of user input.
  - String concatenations that look like they form a secret.
  - Encodings or decodings applied to constant data.

---

## 3. Reasoning About JavaScript Without Running It

> **When to use this section:** Static analysis of JavaScript code.

**Tags:** `static-analysis, code-reading, javascript-reasoning`

You do not need to execute JavaScript to understand many challenges. You can treat JS just like source code in any other language.

### 3.1 Read Conditions and Branches

**Tags:** `conditionals, if-statements, logic-analysis`

Look for:
- If-statements that compare user input to constants or computed values.
  ```javascript
  if (passwordInput === "supersecret") { ... }
  ```
- Logical operators combining conditions, such as checks on both username and password.

**Questions to ask:**
- What input would make this condition true?
- When the condition is true, what does the code do (redirect, display flag, call an API, etc.)?

---

### 3.2 Examine String Operations

**Tags:** `string-operations, concatenation, array-manipulation`

Many secrets are assembled from small parts:
- Multiple string variables added together to form a password or flag.
- Arrays of character codes converted with functions that build up a string.
- Operations like `split`, `join`, `reverse` applied to strings or arrays.

**Example analysis:**
```javascript
var a = "pic";
var b = "oCT";
var c = "F{s";
var d = "ecr";
var e = "et}";
var flag = a + b + c + d + e;
// Result: "picoCTF{secret}"
```

When you see string manipulation and character code functions, consider:
- What the final string value is after all operations.
- Whether that final value is compared against user input or displayed somewhere.

---

### 3.3 Recognize Simple Encodings

**Tags:** `encoding, base64, hex, decoding`

Common encodings in client-side CTF JS include:

**Base64:**
```javascript
var secret = atob("cGljb0NURntmbGFnfQ==");
// Decodes to: "picoCTF{flag}"
```

**Hex encoding:**
```javascript
var hex = "70696373";
// Convert: "pics"
```

**Simple character shifts (Caesar cipher):**
```javascript
// ROT13 or similar
```

**Agent Takeaway:**
- Identify common decoding patterns by variable names or operations
- `atob()` = base64 decode, `btoa()` = base64 encode
- Look for arrays of numbers (char codes) being converted to strings

---

### 3.4 Ignore UI Boilerplate

**Tags:** `code-filtering, relevance, focus`

Many JS files contain extra code that does not matter to security, such as:
- Event listeners for mouse clicks.
- CSS-related manipulations.
- Animations or visual effects.

**Focus instead on code that:**
- Reads values from form fields.
- Performs comparisons or validations.
- Constructs or reveals secrets.

---

## 4. "Don't Trust the Client" Challenges

> **When to use this section:** Bypassing client-side-only security.

### 4.1 Why Client-Side Validation Is Insecure

**Tags:** `client-side-security, bypass, insecure-validation`

Client-side validation runs in the user's environment:
- Users can edit JavaScript, skip running code, or intercept and modify network requests.
- Any secrets written into client-side JS are visible to anyone who inspects the source.
- Any restrictions enforced only by JS can be bypassed.

**Because of this:**
- Real security checks (authentication, access control, flag delivery) should be enforced on the server.
- CTF challenges intentionally violate this rule so you can exploit the weakness.

---

### 4.2 Strategy: Bypass JS Checks or Send Correct Values Manually

**Tags:** `bypass-strategy, direct-request, http-submission`

**Typical workflow:**

1. **View the HTML and JS code.**
   - Understand what the client-side code is checking.

2. **Derive the expected "correct" input.**
   - For example, the correct password, token, or code based on JS logic.

3. **Send that value directly in an HTTP request.**
   - Use a form submission tool or raw HTTP request.
   - Ignore any UI restrictions or JS validation that prevents form submission.

**Even if the JS tries to block you from submitting the form until the input is correct:**
- You can craft your own HTTP request with the correct data.
- You do not have to obey the browser-side checks.

**Example bypass:**
```bash
# JS validates password client-side, but we send directly
curl -X POST -d "password=supersecret" http://target.com/login
```

---

### 4.3 An Agent's Approach

**Tags:** `agent-workflow, client-side-bypass, systematic`

For an LLM agent solving such a challenge:

1. Use `html_inspector` to identify external and inline scripts.
2. Use `javascript_source` to retrieve the complete JS code.
3. Analyze the JS to:
   - Identify the correct password, token, or flag location.
   - Determine which fields are sent to the server and in what format.
4. Use `form_submit` or an HTTP tool to send the derived values directly, ignoring JavaScript limitations in the UI.

---

## 5. Tips for Spotting the "Real Check" in JS

> **When to use this section:** Finding the core validation logic.

### 5.1 Look for Key Functions and Event Handlers

**Tags:** `event-handlers, functions, entry-points`

Focus on:
- Functions hooked to button clicks or form submissions.

**Example patterns:**
```javascript
// Button click handler
document.getElementById('login-btn').onclick = checkLogin;

// Form submission
<form onsubmit="return validateForm()">

// Event listener
document.getElementById('submit').addEventListener('click', verify);
```

These clues point to the entry points of the validation logic.

---

### 5.2 Search for Comparison Patterns

**Tags:** `comparison, equality-check, validation`

Within those functions, look for:

**Equality checks involving user input:**
```javascript
if (userInput === "someValue") { ... }
```

**Conditions involving multiple inputs:**
```javascript
if (user === "admin" && pass === "supersecret") { ... }
```

**Checks on decoded or transformed values:**
```javascript
if (atob(input) === "knownValue") { ... }
```

These patterns indicate where the code decides "success" versus "failure."

---

### 5.3 Identify Where Success Is Handled

**Tags:** `success-handler, redirect, flag-display`

Find what happens on successful checks:

**Redirects or navigation:**
```javascript
window.location = "/success.html";
window.location.href = "/flag";
```

**DOM updates:**
```javascript
document.getElementById('result').innerText = flag;
```

**Calls to backend endpoints:**
```javascript
fetch('/api/getFlag', { method: 'POST', body: ... });
```

This reveals whether:
- The flag or secret is purely client-side (hidden in the HTML/JS).
- Or whether you must send correct data to the server to obtain it.

---

### 5.4 Use Search Strategically

**Tags:** `search-strategy, keywords, automation`

In larger JS files, manual scanning is inefficient. Instead:
- Use search tools for keywords:
  - `password`, `pass`, `secret`, `flag`, `key`, `admin`.
- Search for common functions related to encoding or character operations.
- Search for patterns around `if (` and strict equality comparisons (`===`).

**For an LLM agent:**
1. First, call `javascript_source` to gather all JS code.
2. Second, call `regex_search` over the JS to highlight potential validation or secret-handling code.
3. Third, reason over the extracted snippets.

---

## 6. Tool Usage Guide for Agents

> **When to use this section:** Mapping tools to client-side challenge patterns.

**Tags:** `agent-tools, workflow, tool-selection`

This document helps an agent choose which tools to call and when:

**When a challenge mentions "view source", "client-side", "JavaScript", or "don't trust the client":**
- Call `html_inspector` on the main page to list scripts and interesting HTML elements.
- Follow up with `javascript_source` to collect inline and external JS.

**When scripts are retrieved:**
- Use `regex_search` over the JS to find:
  - Hardcoded strings that look like secrets or flags.
  - Equality checks involving input values.
  - Encodings and decodings that manipulate constant strings.

**When the expected input is identified:**
- Call `form_submit` or an HTTP fetch tool to send the correct values directly, bypassing any front-end restrictions.

**When JS seems obfuscated:**
- Focus on data flow:
  - Where user input is read.
  - Where it is transformed or checked.
  - Where success or failure is determined.
- Optionally use RAG to recall common obfuscation and encoding patterns.

---

## 7. Summary

**Tags:** `summary, client-side, javascript, key-points`

Client-side HTML and JavaScript in web CTF challenges often:
- Disclose secrets via hardcoded values or simple encodings.
- Enforce weak validation logic that can be bypassed.
- Implement obfuscation that is more about misdirection than actual security.

**"View source" and JS inspection are therefore central techniques:**

Humans and LLM agents should routinely:
- Inspect HTML, comments, hidden inputs, and scripts.
- Read JavaScript statically to understand validation and secret reconstruction.
- Bypass or emulate client-side checks via direct HTTP requests.

**Quick Reference - Things to Search For:**
```
flag
picoCTF{
password
secret
admin
key
token
===
atob(
btoa(
fromCharCode
eval(
```

**Agent Takeaway:**
- Client-side security = no security
- Always read the JavaScript source
- Hardcoded credentials are extremely common in CTFs
- Send derived values directly via HTTP to bypass UI restrictions
