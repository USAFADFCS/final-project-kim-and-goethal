This document explains how to inspect HTML and reason about client-side JavaScript logic in CTF-style web challenges. It is aimed at readers comfortable with basic programming but not necessarily experts in JavaScript.

The goal is to help both humans and LLM agents decide when and how to use tools like html_inspector, javascript_source, and regex_search while solving web challenges.

⸻

1. “View Source” Basics: What to Look For in HTML

When you open a challenge URL, the rendered page is only part of the story. The raw HTML often contains crucial hints.

1.1 How to “View Source”

In a browser (or using an HTTP tool), you can view the raw HTML returned by the server. For an agent:
	•	Use an HTTP fetch tool on the page.
	•	Pass the response body to an HTML inspection tool.

1.2 HTML Elements of Interest

When scanning HTML, focus on:
	•	Comments
Examples (conceptually):
	•	<!-- TODO: remove debug login -->
	•	<!-- Hint: password is not what it seems -->
These may contain hints, old notes, or references to hidden URLs or features.
	•	Hidden inputs
Example idea:
	•	<input type="hidden" name="role" value="user">
Hidden inputs can leak default roles, tokens, or configuration data. Sometimes the challenge expects you to change or replay these values directly via HTTP.
	•	Links
Example idea:
	•	<a href="/admin">Admin Panel</a>
	•	<a href="/static/app.js">App JS</a>
Links can reveal admin pages, backup pages, or important script files.
	•	Inline scripts
Example idea:
	•	<script> const secret = "supersecret"; /* validation logic */ </script>
Inline JavaScript may hold keys, flag fragments, or credential checks.

1.3 Using Tools

For an LLM-based agent:
	•	Call html_inspector after fetching HTML to:
	•	Extract links, scripts, styles, and comments.
	•	Summarize what to explore next.
	•	Use regex_search on HTML if you want to:
	•	Search for patterns like secret, password, flag, or picoCTF{.

⸻

2. Common Client-Side Patterns in CTF Challenges

Many web CTF challenges teach that client-side checks are not security. They often implement logic in JavaScript that can be inspected and bypassed.

2.1 Hardcoded Passwords or Keys in JS

A classic beginner pattern:
	•	The script defines something like
const correctPassword = "supersecret";
and then checks user input against it.

Key observations:
	•	The password or key is hardcoded in the script.
	•	There may be no server-side verification; the browser just compares strings.

In a CTF:
	•	You can read the JS to recover the password directly.
	•	You might also choose to skip the UI and send the correct value via a direct HTTP request.

2.2 Simple if (input === secret) Checks

Variations of the same idea:
	•	A function reads values such as user and pass.
	•	Then it does something logically equivalent to:
if (user === "admin" && pass === "supersecret") { /* success */ }

The logic is straightforward: string equality comparisons. Sometimes the “secret” is split into pieces in variables, but the structure remains simple.

2.3 Obfuscated or Minified JavaScript That Reconstructs a Flag

More advanced client-side challenges try to hide the logic:
	•	Minified JS: code all on one line, very short variable names.
	•	Obfuscated JS: strange variable names, extra operations, scrambled strings.

Common patterns:
	•	Concatenating multiple string fragments into a final password or flag.
	•	Using ASCII codes: arrays of numbers that are turned into characters.
	•	Encoding/decoding functions: base64, simple ciphers, or character shifts.

The JS might:
	•	Concatenate strings like "pi" + "co" + "CTF" plus some extra part.
	•	Decode a base64 string into a readable secret.
	•	Use simple transformations like reversing a string.

The challenge is to reverse this logic by reading the code, not just running it blindly.

2.4 How an Agent Detects These Patterns

An LLM agent can:
	•	Use javascript_source to fetch all inline and external scripts from a page.
	•	Scan the JS using regex_search for clues like password, secret, flag, picoCTF, or key.
	•	Reason about assignments and conditions, especially patterns resembling:
	•	Equality checks of user input.
	•	String concatenations that look like they form a secret.
	•	Encodings or decodings applied to constant data.

⸻

3. Reasoning About JavaScript Without Running It

You do not need to execute JavaScript to understand many challenges. You can treat JS just like source code in any other language.

3.1 Read Conditions and Branches

Look for:
	•	If-statements that compare user input to constants or computed values.
Example pattern: if (passwordInput === "supersecret") { ... }
	•	Logical operators combining conditions, such as checks on both username and password.

Questions to ask:
	•	What input would make this condition true?
	•	When the condition is true, what does the code do (redirect, display flag, call an API, etc.)?

3.2 Examine String Operations

Many secrets are assembled from small parts:
	•	Multiple string variables added together to form a password or flag.
	•	Arrays of character codes converted with functions that build up a string.
	•	Operations like split, join, reverse applied to strings or arrays.

When you see string manipulation and character code functions, consider:
	•	What the final string value is after all operations.
	•	Whether that final value is compared against user input or displayed somewhere.

3.3 Recognize Simple Encodings

Common encodings in client-side CTF JS include:
	•	Base64: constant looking like random characters, decoded with a base64 decoder.
	•	Hex encoding: long strings of hexadecimal digits that can be converted into text.
	•	Simple substitution ciphers or letter rotations.

An LLM (or a human) can:
	•	Identify common decoding patterns by variable names or operations (for example, functions that decode base64 or operate on character codes).
	•	Conceptually reverse the transformation to recover the underlying text.

3.4 Ignore UI Boilerplate

Many JS files contain extra code that does not matter to security, such as:
	•	Event listeners for mouse clicks.
	•	CSS-related manipulations.
	•	Animations or visual effects.

Focus instead on code that:
	•	Reads values from form fields.
	•	Performs comparisons or validations.
	•	Constructs or reveals secrets.

⸻

4. “Don’t Trust the Client” / “Don’t Use Client Side” Challenges

These challenges explicitly highlight the mistake of trusting client-side checks.

4.1 Why Client-Side Validation Is Insecure

Client-side validation runs in the user’s environment:
	•	Users can edit JavaScript, skip running code, or intercept and modify network requests.
	•	Any secrets written into client-side JS are visible to anyone who inspects the source.
	•	Any restrictions enforced only by JS can be bypassed.

Because of this:
	•	Real security checks (authentication, access control, flag delivery) should be enforced on the server.
	•	CTF challenges intentionally violate this rule so you can exploit the weakness.

4.2 Strategy: Bypass JS Checks or Send Correct Values Manually

Typical workflow:
	1.	View the HTML and JS code.
	•	Understand what the client-side code is checking.
	2.	Derive the expected “correct” input.
	•	For example, the correct password, token, or code based on JS logic.
	3.	Send that value directly in an HTTP request.
	•	Use a form submission tool or raw HTTP request.
	•	Ignore any UI restrictions or JS validation that prevents form submission.

Even if the JS tries to block you from submitting the form until the input is correct:
	•	You can craft your own HTTP request with the correct data.
	•	You do not have to obey the browser-side checks.

4.3 An Agent’s Approach

For an LLM agent solving such a challenge:
	•	Use html_inspector to identify external and inline scripts.
	•	Use javascript_source to retrieve the complete JS code.
	•	Analyze the JS to:
	•	Identify the correct password, token, or flag location.
	•	Determine which fields are sent to the server and in what format.
	•	Use form_submit or an HTTP tool to send the derived values directly, ignoring JavaScript limitations in the UI.

⸻

5. Tips for Spotting Where the “Real Check” Happens in JS

The key is to find the core logic that decides whether access is granted.

5.1 Look for Key Functions and Event Handlers

Focus on:
	•	Functions hooked to button clicks or form submissions.
Example patterns:
	•	A login button that calls a function like checkLogin().
	•	A form tag with an onsubmit attribute calling validateForm().

These clues point to the entry points of the validation logic.

5.2 Search for Comparison Patterns

Within those functions, look for:
	•	Equality checks involving user input, such as:
	•	if (userInput === "someValue") { ... }
	•	Conditions involving multiple inputs:
	•	if (user === "admin" && pass === "supersecret") { ... }
	•	Checks on decoded or transformed values:
	•	if (decode(input) === "knownValue") { ... }

These patterns indicate where the code decides “success” versus “failure.”

5.3 Identify Where Success Is Handled

Find what happens on successful checks:
	•	Redirects or navigation:
	•	For example, assigning a new URL to window.location or similar behavior.
	•	DOM updates:
	•	Setting inner text of an element that might hold a flag.
	•	Calls to backend endpoints:
	•	Making an HTTP request to a “check” or “flag” endpoint when validation passes.

This reveals whether:
	•	The flag or secret is purely client-side (hidden in the HTML/JS).
	•	Or whether you must send correct data to the server to obtain it.

5.4 Use Search Strategically

In larger JS files, manual scanning is inefficient. Instead:
	•	Use search tools (or regex_search) for keywords:
	•	password, pass, secret, flag, key, admin.
	•	Search for common functions related to encoding or character operations.
	•	Search for patterns around if ( and strict equality comparisons.

For an LLM agent:
	•	First, call javascript_source to gather all JS code.
	•	Second, call regex_search over the JS to highlight potential validation or secret-handling code.
	•	Third, reason over the extracted snippets.

⸻

6. How This Guides Tool Usage in an LLM Agent

This document is meant to help an agent choose which tools to call and when:
	•	When a challenge description mentions “view source”, “client-side”, “JavaScript”, or “don’t trust the client”:
	•	Call html_inspector on the main page to list scripts and interesting HTML elements.
	•	Follow up with javascript_source to collect inline and external JS.
	•	When scripts are retrieved:
	•	Use regex_search over the JS to find:
	•	Hardcoded strings that look like secrets or flags.
	•	Equality checks involving input values.
	•	Encodings and decodings that manipulate constant strings.
	•	When the expected input is identified:
	•	Call form_submit or an HTTP fetch tool to send the correct values directly, bypassing any front-end restrictions.
	•	When JS seems obfuscated:
	•	Focus on data flow:
	•	Where user input is read.
	•	Where it is transformed or checked.
	•	Where success or failure is determined.
	•	Optionally use RAG to recall common obfuscation and encoding patterns.

⸻

7. Summary

Client-side HTML and JavaScript in web CTF challenges often:
	•	Disclose secrets via hardcoded values or simple encodings.
	•	Enforce weak validation logic that can be bypassed.
	•	Implement obfuscation that is more about misdirection than actual security.

“View source” and JS inspection are therefore central techniques:
	•	Humans and LLM agents should routinely:
	•	Inspect HTML, comments, hidden inputs, and scripts.
	•	Read JavaScript statically to understand validation and secret reconstruction.
	•	Bypass or emulate client-side checks via direct HTTP requests.