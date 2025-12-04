This document explains how cookies and sessions work in typical web applications, and how CTF challenges often simplify or misuse them to create authentication bypass puzzles. It is written for readers with basic web knowledge and is designed so an LLM can decide when to use tools like cookie_inspector, cookie_set, http_fetch, and form_submit.

Throughout, “common CTF trick” means something that appears frequently in CTF challenges, not necessarily in real-world secure applications.

⸻

1. Cookies and Session IDs: How Login State Is Typically Tracked

1.1 What Is a Cookie?

A cookie is a small piece of data stored by the browser and sent with every request to a particular domain.

Key properties:
	•	Stored as key–value pairs, e.g.:
	•	sessionid=abcd1234
	•	isAdmin=false
	•	Sent in the Cookie header on subsequent requests:
	•	Cookie: sessionid=abcd1234; theme=dark

Cookies are commonly used to:
	•	Track sessions (who you are between requests).
	•	Store user preferences.
	•	Sometimes hold authentication or authorization info.

1.2 Session IDs

A session ID is an opaque token that links the browser to server-side state.

Typical flow in real web apps:
	1.	You submit login credentials.
	2.	Server verifies them.
	3.	Server creates a session record (e.g., in memory or a database) containing:
	•	User ID
	•	Role/permissions
	•	Other state
	4.	Server sends a Set-Cookie header:
	•	Set-Cookie: sessionid=abcd1234; HttpOnly; Secure
	5.	The browser stores that cookie and sends it on future requests.
	6.	Server looks up sessionid=abcd1234 to know which user you are.

In secure real-world setups:
	•	The session ID is random and not guessable.
	•	Server-side checks determine whether you are “admin” or “user”, not the client.

1.3 Login State in Web Apps

In a typical design:
	•	Login state is tracked by:
	•	A session cookie (like sessionid).
	•	Server-side session storage that knows whether that session belongs to a logged-in admin or a regular user.
	•	The browser doesn’t decide the role; it just sends the session cookie.

In many CTF challenges, this is simplified or intentionally misconfigured:
	•	Sometimes the cookie itself encodes the role or privileges.
	•	Sometimes the session ID is structured or guessable.
	•	Sometimes the server blindly trusts values stored in cookies.

⸻

2. Common CTF Patterns Related to Cookies

This section describes patterns that appear frequently in CTF challenges. They are often unrealistic or insecure by design, to teach you how not to build real systems.

2.1 “isAdmin=true” Style Cookies (CTF Trick)

A very common CTF pattern:
	•	After login or visiting the site, you receive a cookie like:
	•	isAdmin=false
	•	role=user
	•	admin=0

Sometimes:
	•	The application uses this cookie directly to decide whether to show admin-only content.
	•	Changing the cookie to isAdmin=true or admin=1 might grant access.

In these CTFs:
	•	There may be no server-side verification beyond reading the cookie.
	•	The backend may treat whatever cookie you send as truth.

From a reasoning perspective:
	•	If you see a cookie with a name hinting at privileges (e.g., admin, role, userType), it is often worth trying a modified value.
	•	This is not considered secure in real-world applications, but is a common teaching mechanism in CTFs.

2.2 Encoded or Serialized Cookies (Base64, JSON, JWT-like)

Another frequent CTF pattern:
	•	The cookie value is not plain text, but still easily decodable. Examples:
	•	Base64 strings.
	•	JSON objects.
	•	JWT-like tokens without proper signatures.
	•	Simple serialization formats.

Examples of conceptual patterns (not specific to any challenge):
	•	A cookie that looks like random text but ends with == may be base64.
	•	Decoding base64 might give:
	•	{"username":"guest","role":"user"}
	•	A simple JSON cookie might be:
	•	{"role":"user","expires":"..."}
	•	A fake JWT-like structure (header.payload.signature) may be present where the signature is not actually validated in the challenge.

In CTF reasoning:
	•	If a cookie looks encoded or structured:
	•	Try decoding it (base64, URL decoding, JSON parsing).
	•	Inspect for fields like role, admin, isAdmin, access.
	•	If the challenge is intentionally weakened:
	•	Changing role":"user" to role":"admin" and re-encoding the cookie might grant access.
	•	Always remember: this is a common CTF trick, not secure real-world behavior.

2.3 Misconfigured or Weak Session Handling

Some CTF challenges demonstrate poor session design:
	•	The session ID might be:
	•	Short or predictable.
	•	Sequential or easily guessable.
	•	The application may:
	•	Create separate session IDs for “user” and “admin” with predictable differences.
	•	Rely on simple tokens or IDs that can be modified by the client.

Possible patterns:
	•	A cookie like session=1 for user, session=2 for admin.
	•	A URL or cookie parameter like uid=1 representing the current user.

While truly guessing someone else’s session is not usually the goal in beginner CTFs, challenges may use this idea in a simplified form to show why randomness and server-side checks matter.

⸻

3. Step-by-Step Reasoning Examples

The emphasis here is on systematic, logical steps, not brute-force.

3.1 Example: Inspect Cookies After Login Attempt

High-level reasoning:
	1.	Start at the main page.
	•	Use http_fetch to get the main page.
	2.	Identify login form.
	•	Use html_inspector to detect <form> elements and their action URLs.
	3.	Submit credentials.
	•	Use form_submit with a test username/password:
	•	Even if you do not know the correct values yet, the request may set or change cookies.
	4.	Inspect cookies.
	•	Use cookie_inspector to list cookies for the domain.
	•	Look for fields like:
	•	role
	•	isAdmin
	•	user
	•	auth
	•	If you see isAdmin=false or role=user:
	•	That is a strong hint of a CTF trick.
	5.	Try modifying suspicious cookies.
	•	Use cookie_set to change isAdmin=false to isAdmin=true, or role=user to role=admin.
	6.	Fetch a protected page.
	•	Use http_fetch on pages that previously showed restricted content (e.g., /admin).
	•	If the page suddenly becomes accessible, you have bypassed auth through cookie manipulation.

This pattern is a common CTF trick where the server trusts the cookie value too much.

3.2 Example: Encoded Cookie with Role Information

Reasoning chain:
	1.	Fetch the main page and/or login.
	•	Use http_fetch and form_submit.
	2.	Inspect cookies.
	•	Use cookie_inspector.
	3.	Notice a cookie value that looks encoded.
	•	For example, it is long, contains letters, numbers, plus signs, slashes, or ends with =.
	4.	Try decoding it conceptually:
	•	If base64-decoded form gives something like:
	•	{"user":"guest","role":"user"}, or
	•	username=guest&role=user
	5.	Ask: “What if I change role=user to role=admin?”
	•	Conceptual steps:
	•	Modify the string to represent role=admin.
	•	Re-encode it in the same format (if needed).
	6.	Use cookie_set to assign the modified cookie value.
	7.	Access pages again with http_fetch.
	•	If previously restricted content becomes accessible, the challenge is using insecure, client-modifiable role information.

Again, this is a CTF teaching pattern, not best practice.

3.3 Example: Look for Clues About Roles or Levels

Sometimes the cookie structure is not obvious at first. Use a broader recon strategy:
	1.	Read responses carefully.
	•	Error messages.
	•	Debug text.
	•	Section headings like “Admin Panel” or “User Dashboard”.
	2.	Inspect HTML.
	•	Use html_inspector to find:
	•	Comments referring to roles, like “TODO: restrict this to admins”.
	•	Hidden fields with role or level information.
	3.	Correlate cookies with these hints.
	•	If the HTML shows “Welcome, guest” and cookies mention “guest”, consider how that value might become “admin”.
	4.	Systematically tamper with related fields.
	•	Modify a cookie that says user=guest to user=admin.
	•	Try variations that make sense in context (e.g., role=staff, role=superuser).
	5.	Observe responses after each change.
	•	Use http_fetch to see whether the app’s behavior changes (new pages appear, flags become visible, etc.).

The key is to adjust inputs based on observed hints, not random guessing.

⸻

4. Emphasizing Safe, Reasoning-Based Approaches (Not Brute Force)

4.1 Avoid Credential Brute-Forcing

In many web CTFs, the intended solution does not involve:
	•	Trying thousands of passwords.
	•	Rapid-fire guessing login credentials.

Instead, the focus is on:
	•	Discovering misconfigurations or logic flaws.
	•	Exploiting insecure reliance on cookies or client-side data.

For an LLM agent:
	•	Prioritize reading and understanding:
	•	Cookie names and values.
	•	HTML comments and hints.
	•	Response messages about permissions.
	•	Use this understanding to make a small number of targeted modifications.

4.2 Work from Evidence, Not Random Changes

Every action should be based on a clear hypothesis:
	•	“This cookie is named role; maybe changing it will change my privileges.”
	•	“The decoded cookie contains admin:false; perhaps admin:true is accepted.”
	•	“The HTML mentions ‘admin-only page at /admin’; I should try visiting /admin after modifying cookies.”

This style of reasoning:
	•	Is more efficient.
	•	Aligns with how CTFs are designed to be solved.
	•	Avoids unnecessary traffic and noise.

⸻

5. How This Guides Tool Usage for an LLM Agent

This document is intended to help an LLM choose appropriate tools at the right time.

5.1 When to Use cookie_inspector

Use cookie_inspector when:
	•	You first visit the challenge page.
	•	You submit any login or form.
	•	You suspect that login or privileges may be cookie-based.

Goals:
	•	Enumerate existing cookies.
	•	Identify suspicious names and values.
	•	Look for encodings or structured data.

5.2 When to Use cookie_set

Use cookie_set when:
	•	You have a clear hypothesis about what a cookie might represent.
	•	You want to test whether changing:
	•	role=user ⇒ role=admin
	•	isAdmin=false ⇒ isAdmin=true
alters behavior.

Remember:
	•	This is a CTF-specific trick; in real-world secure apps, this would normally fail or be blocked by server-side checks.

5.3 When to Use http_fetch and form_submit

Use http_fetch to:
	•	Visit pages affected by cookie changes, such as /admin or hidden sections.
	•	Observe differences in response content or status codes before and after modifications.

Use form_submit to:
	•	Log in or send controlled requests that may adjust cookies or sessions.
	•	Trigger flows where the server sets new cookies or changes existing ones.

5.4 Combining Cookies with Other Recon

Cookies rarely exist in isolation. Combine cookie analysis with:
	•	HTML inspection (html_inspector) to find references to roles or admin sections.
	•	Response inspection (and possibly search tools) to identify phrases like “Access denied”, “Admin only”, or “Debug mode”.

This multi-step process allows an agent to systematically:
	1.	Discover how login state is tracked.
	2.	Infer weak trust in cookies.
	3.	Tamper with cookies logically.
	4.	Confirm successful auth bypass by accessing previously forbidden content.

⸻

6. Summary

In web CTF challenges, cookies and sessions are often simplified or intentionally misconfigured to create auth bypass puzzles:
	•	Cookies may directly encode roles or admin status.
	•	Cookie values may be base64, JSON, or other easy-to-modify formats.
	•	Session handling may be weak or entirely client-controlled.

An effective approach is:
	•	Inspect cookies after key actions.
	•	Decode or parse structured cookie data.
	•	Form hypotheses about how roles or permissions are encoded.
	•	Carefully modify cookies and observe resulting behavior, using tools like cookie_inspector, cookie_set, http_fetch, and form_submit.