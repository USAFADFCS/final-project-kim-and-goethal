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
- HTTP fetching and form submission ('http_fetch', 'form_submit')
- HTML inspection and JavaScript inspection ('html_inspector', 'javascript_source')
- Working with cookies and robots.txt ('cookie_inspector', 'cookie_set', 'robots_txt')
- Searching and analyzing responses ('regex_search', 'response_search', 'sql_pattern_hint')
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
- Avoid brute forcing credentials or inputs - rely on logical reasoning and response analysis
- When you see a string matching the flag pattern, note it and verify its context
- When confident you have the correct flag, clearly state it in your final answer

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
- and consulting an internal web-exploitation knowledge base ('ctf_knowledge_query').

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
    parts.append("- Avoid brute forcing credentials, passwords, or inputs. Instead, rely on logical reasoning and response analysis.")
    parts.append("- At every stage, think step-by-step using the ReAct pattern: Thought -> Action (tool call) -> Observation.")
    parts.append(f"- Whenever you see a string matching {flag_regex}, note it and verify its context.")
    parts.append("- When you are confident you have the correct flag, clearly print it in your final answer.")
    parts.append("")
    parts.append("Now begin your investigation using these tools and reasoning steps.")

    return "\n".join(parts)
