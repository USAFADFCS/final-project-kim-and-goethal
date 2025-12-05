High-level, fast-reference checklist for web CTF challenges.
Designed so an LLM agent can quickly decide “what to try next.”

⸻

1. Initial Recon Checklist
	•	Basic URL & entrypoint
	•	Note the base URL (host + port).
	•	Try visiting just / and any obvious paths in the challenge text.
	•	Robots & common files
	•	Check /robots.txt.
	•	Check common “info” endpoints if hinted (e.g., /admin, /backup, /old, /dev).
	•	HTML source
	•	View raw HTML, not just rendered page.
	•	Look for:
	•	<!-- comments -->
	•	Hidden inputs (type="hidden")
	•	Unusual IDs/classes that hint at features.
	•	Links & resources
	•	Enumerate:
	•	<a href="..."> links.
	•	<script src="..."> external JS.
	•	<link rel="stylesheet" href="..."> CSS.
	•	Visit unlinked or odd-looking paths.
	•	JavaScript
	•	Collect:
	•	Inline <script>...</script>.
	•	External JS files.
	•	Skim for:
	•	Hardcoded strings (password, secret, flag, key).
	•	Conditional checks on user input.
	•	Forms & parameters
	•	Identify all forms:
	•	Action URL, method (GET/POST).
	•	Input field names.
	•	Note all query parameters in URLs.
	•	Cookies & storage
	•	Record all cookies:
	•	Names that look like session, role, admin, auth.
	•	Encoded-looking values (base64-ish, JSON-like).
	•	Check if new cookies appear after actions (login, clicking buttons).

⸻

2. “I’m Stuck” Sanity Checklist
	•	Have I…
	•	Looked at /robots.txt?
	•	Viewed the full HTML source, not just devtools DOM?
	•	Inspected all external JS files referenced in the page?
	•	Searched HTML/JS for strings like:
	•	flag, picoCTF, secret, password, key, admin?
	•	Checked cookies carefully for:
	•	Suspicious names (role, isAdmin, user, debug).
	•	Values that look encoded or serialized?
	•	Tried searching the response text for:
	•	sql, SELECT, FROM, WHERE, error, syntax, database?
	•	Considered that the challenge might be about:
	•	Client-side validation (JS-only checks)?
	•	robots.txt and hidden paths?
	•	Simple cookie tampering?
	•	Basic SQL injection on a form or parameter?
	•	Visited every reasonable link and path I’ve seen so far?

⸻

3. SQL Injection Troubleshooting Checklist
	•	Suspecting SQLi
	•	Input fields for:
	•	Login (username/password).
	•	Search boxes.
	•	Numeric IDs in URLs (e.g., ?id=1).
	•	Errors or behavior changes when:
	•	You add ', ", ), --, or other special characters.
	•	Check responses
	•	Search for:
	•	SELECT, FROM, WHERE.
	•	“syntax error”, “SQL error”, “database error”.
	•	“unclosed quotation mark”, “near ‘…’”.
	•	Behavior-based clues
	•	Different behavior for:
	•	Normal input vs. input with a quote.
	•	Inputs that look like 1 vs. 1 OR 1=1.
	•	“True” vs “false” style responses (content / status / redirect differences).
	•	Systematic probes
	•	Try minimal changes:
	•	Append a single ' and see if it breaks.
	•	Try test' vs test'-- and compare.
	•	For numeric parameters:
	•	Try 1 vs 1-1 vs 1 OR 1=1.
	•	When to use helper tools (for an agent)
	•	Use response-search:
	•	To find lines containing SQL keywords or “error”/“syntax”.
	•	Use sql-pattern-hint:
	•	To highlight suspected SQL areas in the response.
	•	If still unsure
	•	Re-check which input actually hits the server (is some validation happening client-side instead?).
	•	Consult ctf_knowledge_query about SQLi patterns and error interpretation.

⸻

4. Client-Side JS / “Don’t Trust the Client” Checklist
	•	Clues
	•	Challenge text mentions:
	•	“client-side”, “JavaScript”, “don’t trust the client”, “browser checks password”.
	•	Form refuses to submit until JS conditions are met.
	•	Alerts like “Wrong password” without network requests.
	•	What to inspect
	•	Gather:
	•	All inline JS in <script>.
	•	All linked JS files.
	•	Search JS for:
	•	Strings that look like passwords/keys/flag pieces.
	•	Comparisons like input === "something" or === secret.
	•	Functions bound to buttons/onsubmit handlers.
	•	Reasoning steps
	•	Identify:
	•	Where user input is read (e.g., document.getElementById(...)).
	•	Where it’s compared to constants or processed.
	•	Reconstruct:
	•	“What exact value makes this condition true?”
	•	“Does the code assemble a secret from pieces?”
	•	Bypass strategy
	•	Use the derived correct value to:
	•	Either satisfy JS (for a quick win), or
	•	Skip JS and send it directly via an HTTP request.
	•	When to use helper tools
	•	html_inspector:
	•	To list scripts and find JS files.
	•	javascript_source:
	•	To pull inline & external JS for analysis.
	•	regex_search:
	•	To search JS for password, secret, flag, key, etc.
	•	If stuck
	•	Consider simple encodings:
	•	Base64-looking strings.
	•	Character codes assembled into text.
	•	Ask ctf_knowledge_query about common client-side CTF patterns.

⸻

5. Cookies & Session Handling Checklist
	•	Initial checks
	•	List all cookies.
	•	Look for:
	•	session, auth, token, user, role, admin, isAdmin.
	•	Values that look base64 / JSON / JWT-ish.
	•	After actions
	•	Submit a login attempt (even with fake creds).
	•	Re-inspect cookies:
	•	Did any new cookies appear?
	•	Did any values change?
	•	Common CTF patterns
	•	Plaintext role flags:
	•	isAdmin=false → try true.
	•	role=user → try role=admin.
	•	Encoded data:
	•	Base64-decoded cookie looks like JSON describing user/role.
	•	Simple serialized structures that can be edited and re-encoded.
	•	Systematic steps
	•	Hypothesize:
	•	“This cookie controls my role or access.”
	•	Carefully modify:
	•	Toggle booleans like false → true.
	•	Change user → admin in structured data.
	•	Re-request sensitive endpoints:
	•	/admin, /flag, /secret, etc.
	•	Tool usage for an agent
	•	cookie_inspector:
	•	To see current cookies and values.
	•	cookie_set:
	•	To set modified values and persist them across requests.
	•	http_fetch / form_submit:
	•	To revisit important endpoints under the new cookie state.
	•	If unsure
	•	Re-check HTML/JS for hints about roles or admin areas.
	•	Consult ctf_knowledge_query for common cookie/role tricks.

⸻

6. General “When to Consult External Knowledge” Checklist

(For an agent: when to call ctf_knowledge_query)
	•	Call ctf_knowledge_query when…
	•	You recognize a vulnerability type but forget:
	•	Typical payload shapes.
	•	Recon steps or patterns (e.g., basic SQLi workflow).
	•	Challenge mentions:
	•	Robots.txt / crawlers / user-agents.
	•	Client-side auth, obfuscation, or JS password check.
	•	Cookies, sessions, or roles, but you’re unsure how to systematically test them.
	•	You see:
	•	SQL errors, but are unsure how to interpret them.
	•	Encoded/obfuscated strings in JS or cookies that look like base64/hex but you’re not certain.
	•	You’ve done basic recon (HTML, robots, JS, cookies, forms) and:
	•	Need guidance on which attack pattern fits the hints.
	•	Use ctf_knowledge_query to get…
	•	Short explanations of:
	•	SQLi patterns, Boolean-based behavior, error interpretation.
	•	Client-side JS abuse and common obfuscation tricks.
	•	Cookie tampering and role-escalation patterns in CTFs.
	•	Generic examples and strategies—not specific solutions or flags.

⸻

7. Quick One-Liner Checklist (Ultra-Short)

Before giving up, ask:
	•	Have I:
	•	Checked /robots.txt?
	•	Viewed HTML source and comments?
	•	Inspected all JS (inline + external)?
	•	Extracted and reviewed all cookies?
	•	Tested key inputs with simple special characters?
	•	Searched responses for sql, error, flag, secret, admin?
	•	Considered that the real logic might be in JS, cookies, or SQL?
	•	Called ctf_knowledge_query when the pattern is recognizable but details are fuzzy?