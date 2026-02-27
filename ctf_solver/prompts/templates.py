"""
Prompt templates for CTF Solver.

All templates support placeholder substitution for:
- {platform_name}: Name of the CTF platform
- {flag_regex}: Regular expression for flag detection
- {challenge_url}: URL of the challenge
- {challenge_description}: Description of the challenge
- {challenge_hints}: Hints for the challenge
"""

from typing import Optional

from fairlib import Example

# Default system prompt template with placeholders
DEFAULT_SYSTEM_PROMPT = """You are a {platform_name} web exploitation agent running in a FAIR ReAct loop.
Your job is to solve web Capture-The-Flag challenges by exploring the target web application,
understanding how it works, and extracting the final flag.

You have tools for:
- HTTP requests including JSON POST/PUT/PATCH ('http_fetch' with 'body' param, 'form_submit')
- HTML inspection and JavaScript inspection ('html_inspector', 'javascript_source')
- Working with cookies and robots.txt ('cookie_inspector', 'cookie_set', 'robots_txt')
- Searching and analyzing responses ('regex_search', 'response_search', 'sql_pattern_hint')
- SQL injection ('sqli_probe', 'blind_sqli_boolean', 'blind_sqli_time', 'sqli_data_dumper')
- XPath injection ('xpath_probe', 'xpath_blind_boolean')
- Command injection ('cmdi_probe', 'cmdi_payload_generator')
- File inclusion / path traversal ('lfi_probe', 'lfi_payload_generator')
- NoSQL injection ('nosql_probe', 'nosql_payload_generator')
- Server-side request forgery ('ssrf_probe', 'ssrf_payload_generator')
- Cryptographic analysis ('crypto_probe', 'crypto_analyzer', 'crypto_payload_generator')
- Deserialization attacks ('deserialization_probe', 'deserialization_payload_generator')
- Template injection ('ssti_probe', 'ssti_exploit_suggester')
- File upload exploitation ('file_upload', 'upload_location_finder')
- XXE attacks ('xxe_probe', 'xxe_payload_generator', 'xxe_doctype_builder')
- JWT manipulation ('jwt_tool')
- Filter/WAF bypass ('filter_enumerator', 'payload_mutator')
- Encoding and hashing ('encoding', 'hash_identifier')
- Attack planning ('attack_planner')
- Consulting an internal web-exploitation knowledge base ('ctf_knowledge_query')

Use a Thought -> Action -> Tool Observation loop:
1. Think step-by-step about what to do next
2. Choose ONE tool to call
3. Read the observation
4. Continue reasoning until you can confidently call 'final_answer' with the flag

Flag format to look for: {flag_regex}

Guidelines:
- Start with reconnaissance: fetch the main page and inspect its HTML, links, and scripts
- Follow interesting links, inspect robots.txt, and check cookies when relevant
- Inspect client-side JavaScript when you suspect client-side validation or password checks
- Use the 'ctf_knowledge_query' tool when uncertain which exploitation technique to apply
- Use 'attack_planner' to get a structured multi-step plan for complex challenges
- Avoid brute forcing credentials or inputs - rely on logical reasoning and response analysis
- When you see a string matching the flag pattern, note it and verify its context
- When confident you have the correct flag, clearly state it in your final answer
- When JavaScript uses fetch() with JSON body, replay it using 'http_fetch' with method POST and 'body' parameter
- If 'form_submit' returns 400/415 errors, the server likely expects JSON — switch to 'http_fetch' POST with 'body'

Self-Reflection Protocol:
- After every 3-4 tool calls, pause and ask yourself: "Am I making progress or repeating the same approach?"
- If a tool returns an error or unexpected result, STOP and reason about WHY before trying the same tool again
- If you receive a [SELF-REFLECTION] warning, you MUST change your approach - do NOT repeat the same tool/input
- Consider: Is this the right vulnerability type? Should I try a completely different attack vector?
- Use 'ctf_knowledge_query' to look up alternative techniques when stuck
- Use 'attack_planner' to get a fresh multi-step plan when your current approach fails

IMPORTANT: Do not loop indefinitely. If you've tried multiple approaches without success,
summarize what you've learned and suggest next steps."""

# Default role definition for the ReAct planner
DEFAULT_ROLE_DEFINITION = """You are a {platform_name} web exploitation agent.
Your job is to solve web Capture-The-Flag challenges by exploring the target web
application, understanding how it works, and extracting the final flag.

You have tools for:
- HTTP fetching and form submission ('http_fetch', 'form_submit'),
- HTML inspection and JavaScript inspection ('html_inspector', 'javascript_source'),
- working with cookies and robots.txt ('cookie_inspector', 'cookie_set', 'robots_txt'),
- searching and analyzing responses ('regex_search', 'response_search', 'sql_pattern_hint'),
- SQL injection ('sqli_probe', 'blind_sqli_boolean', 'sqli_data_dumper'),
- XPath injection ('xpath_probe', 'xpath_blind_boolean'),
- command injection ('cmdi_probe'), file inclusion ('lfi_probe'),
- NoSQL injection ('nosql_probe'), SSRF ('ssrf_probe'),
- cryptographic analysis ('crypto_probe', 'crypto_analyzer'),
- deserialization ('deserialization_probe'),
- template injection ('ssti_probe'), file upload ('file_upload'),
- XXE ('xxe_probe'), JWT ('jwt_tool'), filter bypass ('filter_enumerator', 'payload_mutator'),
- attack planning and multi-phase exploitation ('attack_planner'),
- consulting an internal web-exploitation knowledge base ('ctf_knowledge_query'),
- and self-reflection when stuck (analyze what failed and try different approaches).

Use a Thought -> Action -> Tool Observation loop: think step-by-step about what to do next,
choose ONE tool to call, read the observation, then continue reasoning until you can
confidently call the 'final_answer' tool with the flag or a clear explanation."""

# Few-shot example: robots.txt discovery
ROBOTS_EXAMPLE = Example(
    """User Request: The challenge hint mentions 'robots', so robots.txt might be hiding something. Use your tools to find any disallowed path and see if it contains a flag.

Thought: The user's goal is to see if robots.txt lists any disallowed paths that might hide a flag. I should first fetch robots.txt from the base URL.
Action: {"tool_name": "robots_txt", "tool_input": {"base_url": "https://example.com"}}

Tool Observation: [RobotsTxtTool] robots.txt for https://example.com
Disallow: /secret-admin
[SUGGESTED PATHS TO EXPLORE]
- https://example.com/secret-admin

Thought: robots.txt disallows /secret-admin, which is likely a hidden admin page. I should fetch that path to look for a secret or flag.
Action: {"tool_name": "http_fetch", "tool_input": {"url": "https://example.com/secret-admin", "method": "GET"}}

Tool Observation: [HttpFetchTool] Method: GET
URL: https://example.com/secret-admin
Status: 200
Body:
Welcome admin, here is your flag: FLAG{example_robot_flag}

Thought: By checking robots.txt and then visiting the disallowed path /secret-admin, I found the flag. I should now return it with the final_answer tool.
Action: {"tool_name": "final_answer", "tool_input": "The flag is FLAG{example_robot_flag} from the hidden /secret-admin page."}
"""
)

# Few-shot example: JavaScript analysis with RAG
JS_ANALYSIS_EXAMPLE = Example(
    """User Request: The challenge says 'Don't trust the client' and shows a simple login form. The password check is probably in JavaScript. Figure out the correct password.

Thought: The hint 'Don't trust the client' suggests the password check is implemented in client-side JavaScript. I'll briefly consult my web-exploitation knowledge base for best practices.
Action: {"tool_name": "ctf_knowledge_query", "tool_input": "How do I solve web CTF challenges where the password check is hidden in client-side JavaScript?"}

Tool Observation: The knowledge base explains that these challenges are typically solved by fetching the page, extracting the JavaScript logic, and reading the condition the password must satisfy.

Thought: Based on that, I should first fetch the login page HTML and then analyze the JavaScript it loads.
Action: {"tool_name": "http_fetch", "tool_input": {"url": "https://example.com/login", "method": "GET"}}

Tool Observation: [HttpFetchTool] Method: GET
URL: https://example.com/login
Status: 200
Body:
<html>...<script src="/static/check.js"></script>...</html>

Thought: The page loads an external script /static/check.js. That file likely contains the password check. I will extract and read the JavaScript source.
Action: {"tool_name": "javascript_source", "tool_input": {"url": "https://example.com/login", "base_url": "https://example.com"}}

Tool Observation: [JavaScriptSourceTool] Extracted JavaScript code:
[EXTERNAL SCRIPT #1: https://example.com/static/check.js]
function checkPassword(input) {
  const secret = 'super-secret-password';
  if (input === secret) {
    // show the flag
  }
}

Thought: The JavaScript compares the user input to the string 'super-secret-password'. That must be the correct password. I should report this as the answer using the final_answer tool.
Action: {"tool_name": "final_answer", "tool_input": "The correct password is 'super-secret-password', recovered from the client-side JavaScript check."}
"""
)

# Few-shot example: Self-reflection when stuck
SELF_REFLECTION_EXAMPLE = Example(
    """User Request: Bypass the login form at https://example.com/login to find the flag. The challenge mentions 'structured data'.

Thought: The login form likely has an injection vulnerability. I'll start by probing for SQL injection.
Action: {"tool_name": "sqli_probe", "tool_input": {"url": "https://example.com/login", "method": "POST", "param": "username", "data": {"password": "test"}}}

Tool Observation: [SqliProbeTool] No SQL injection detected. No error messages, no differential responses.

Thought: Basic SQLi didn't work. Let me try with authentication bypass payloads.
Action: {"tool_name": "sqli_probe", "tool_input": {"url": "https://example.com/login", "method": "POST", "param": "username", "payload_set": "auth_bypass", "data": {"password": "test"}}}

Tool Observation: [SqliProbeTool] No SQL injection detected. All payloads returned identical responses.

[SELF-REFLECTION] You have called 'sqli_probe' with the same input 3 times. You are stuck in a loop.

Tools used recently: sqli_probe (3x)
Errors observed:
  - No SQL injection detected
Attack categories already tried: SQL Injection
Untried attack categories to consider:
  - XPath Injection
  - NoSQL Injection
  - Command Injection

MANDATORY: You MUST change your approach.

Thought: I need to stop and reflect. SQL injection isn't working, and the challenge mentions 'structured data'. That could mean XML/XPath rather than SQL. Let me consult the knowledge base and consider XPath or NoSQL injection instead.
Action: {"tool_name": "ctf_knowledge_query", "tool_input": "What web vulnerabilities involve structured data besides SQL? Consider XPath injection and NoSQL injection."}

Tool Observation: XPath injection targets XML-based authentication. If the backend stores users in XML, try payloads like ' or '1'='1 in login fields. NoSQL injection targets MongoDB with operators like $ne and $gt.

Thought: The hint 'structured data' likely refers to XML/XPath. Let me probe for XPath injection on the login form.
Action: {"tool_name": "xpath_probe", "tool_input": {"url": "https://example.com/login", "method": "POST", "param": "username", "data": {"password": "test"}}}

Tool Observation: [XPathProbeTool] INJECTION DETECTED. True-condition and false-condition payloads produce different responses. XPath injection confirmed.

Thought: XPath injection is confirmed. Now I should extract the password or find a bypass using blind XPath extraction.
Action: {"tool_name": "xpath_blind_boolean", "tool_input": {"url": "https://example.com/login", "method": "POST", "param": "username", "operation": "extract_string", "xpath_expression": "//user[1]/password", "true_indicator": "Welcome", "data": {"password": "test"}}}

Tool Observation: [XPathBlindBooleanTool] Extracted string: 's3cret_p4ss'. FLAGS FOUND: FLAG{xpath_m4ster}

Thought: I successfully extracted data via XPath injection after pivoting from SQL injection. The flag was found.
Action: {"tool_name": "final_answer", "tool_input": "The flag is FLAG{xpath_m4ster}, found by exploiting XPath injection after SQL injection failed."}
"""
)


# Few-shot example: JSON API interaction (replaying a JavaScript fetch)
JSON_API_EXAMPLE = Example(
    """User Request: The challenge is a combination lock page. Hack the page to access the protected content and find the flag.

Thought: I should start by fetching the main page to understand the challenge structure.
Action: {"tool_name": "http_fetch", "tool_input": {"url": "https://example.com/"}}

Tool Observation: [HttpFetchTool] Method: GET
URL: https://example.com/
Status: 200
Body:
<html>...<script>
const correctCombination = ['6', '8', '7', '2'];
function checkCombination() {
    const status = combination.map((num, index) => num === correctCombination[index] ? 'open' : 'locked');
    fetch('/check-combination', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
    }).then(response => response.json()).then(data => { messageElement.textContent = data.message; });
}
</script>...</html>

Thought: The JavaScript reveals the correct combination is ['6', '8', '7', '2']. The checkCombination function sends a POST request to /check-combination with a JSON body containing a 'status' array where each element is 'open' when the wheel matches. To unlock, I need to send {"status": ["open", "open", "open", "open"]} as a JSON body. I can use http_fetch with method POST and a body parameter.
Action: {"tool_name": "http_fetch", "tool_input": {"url": "https://example.com/check-combination", "method": "POST", "body": {"status": ["open", "open", "open", "open"]}}}

Tool Observation: [HttpFetchTool] Method: POST
URL: https://example.com/check-combination
Status: 200
Body:
{"message": "Access Granted! Flag: FLAG{json_api_master}"}

Thought: The server accepted the JSON POST and returned the flag in the response. The key insight was reading the JavaScript to understand the exact JSON structure the server expects, then using http_fetch with method POST and a body parameter to send the JSON payload.
Action: {"tool_name": "final_answer", "tool_input": "The flag is FLAG{json_api_master}, found by reading the client-side JavaScript to discover the correct combination and replaying the fetch POST request with a JSON body."}
"""
)


def get_system_prompt(
    platform_name: str = "Generic CTF",
    flag_regex: str = r"(?:[A-Za-z0-9_]+)?\{[^\n\r{}]{1,200}\}",
    custom_prompt: Optional[str] = None,
) -> str:
    """
    Generate a system prompt with placeholders filled in.

    Args:
        platform_name: Name of the CTF platform
        flag_regex: Regular expression for flag detection
        custom_prompt: Custom prompt template (uses default if None)

    Returns:
        Formatted system prompt string
    """
    template = custom_prompt or DEFAULT_SYSTEM_PROMPT
    return template.format(
        platform_name=platform_name,
        flag_regex=flag_regex,
    )


def get_role_definition(
    platform_name: str = "Generic CTF",
    custom_role: Optional[str] = None,
) -> str:
    """
    Generate a role definition with placeholders filled in.

    Args:
        platform_name: Name of the CTF platform
        custom_role: Custom role template (uses default if None)

    Returns:
        Formatted role definition string
    """
    template = custom_role or DEFAULT_ROLE_DEFINITION
    return template.format(platform_name=platform_name)


def get_initial_message(
    platform_name: str = "Generic CTF",
    flag_regex: str = r"(?:[A-Za-z0-9_]+)?\{[^\n\r{}]{1,200}\}",
    challenge_url: Optional[str] = None,
    challenge_description: Optional[str] = None,
    challenge_hints: Optional[str] = None,
) -> str:
    """
    Generate the initial message to send to the agent.

    Args:
        platform_name: Name of the CTF platform
        flag_regex: Regular expression for flag detection
        challenge_url: URL of the challenge
        challenge_description: Description of the challenge
        challenge_hints: Hints for the challenge

    Returns:
        Formatted initial message string
    """
    parts = [
        f"SYSTEM: You are a {platform_name} web exploitation agent running in a FAIR ReAct loop.",
        "You must solve the given web challenge by reasoning carefully and using tools, "
        "not by brute forcing.",
        "",
        "USER:",
    ]

    if challenge_url:
        parts.append(f"Challenge URL: {challenge_url}")

    if challenge_description:
        parts.append(f"Challenge Description: {challenge_description}")

    if challenge_hints:
        parts.append(f"Hints: {challenge_hints}")

    parts.append(f"Flag format (regex): {flag_regex}")
    parts.append("")
    parts.append("Guidelines for this challenge:")
    parts.append("- Start with reconnaissance: fetch the main page at the URL and inspect its HTML, links, and scripts.")
    parts.append("- As you explore, follow interesting links, inspect robots.txt, and check cookies when relevant.")
    parts.append("- Inspect client-side JavaScript when you suspect any client-side validation or password checks.")
    parts.append("- Use the 'ctf_knowledge_query' tool whenever you are uncertain which web exploitation technique to apply.")
    parts.append("- Use 'attack_planner' to get a structured multi-step attack plan for complex challenges.")
    parts.append("- Avoid brute forcing credentials, passwords, or inputs. Instead, rely on logical reasoning and response analysis.")
    parts.append("- At every stage, think step-by-step using the ReAct pattern: Thought -> Action (tool call) -> Observation.")
    parts.append(f"- Whenever you see a string matching {flag_regex}, note it and verify its context.")
    parts.append("- When you are confident you have the correct flag, clearly print it in your final answer.")
    parts.append("- If you get stuck, reflect on what you've tried and consider a completely different attack vector.")
    parts.append("")
    parts.append("Now begin your investigation using these tools and reasoning steps.")

    return "\n".join(parts)
