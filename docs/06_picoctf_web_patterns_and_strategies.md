This document describes common patterns and strategies that often appear in PicoCTF-style web challenges. It assumes you already know what PicoCTF is, but not the internals of any specific challenge.

The goal is to help a human or LLM agent recognize patterns from the challenge description and early recon, and then choose which technique to try next (robots.txt, view-source, JS inspection, cookies, SQLi, etc.).

⸻

1. General Style of PicoCTF Web Challenges

PicoCTF web challenges are:
	•	Educational – designed to teach core web security ideas.
	•	Progressive – early problems are straightforward; later ones combine multiple concepts.
	•	Hint-driven – titles, descriptions, and flavor text often hint at the intended technique.

Common concepts they aim to teach:
	•	Checking robots.txt and hidden paths.
	•	Viewing HTML source and client-side JS.
	•	Understanding cookies and basic session handling.
	•	Spotting and exploiting simple SQL injection.
	•	Recognizing that client-side checks are not real security.

A good mental model:

“When I see certain keywords or behaviors, they often map to typical web-exploitation patterns.”

⸻

2. “Robots / Crawlers / User-Agents” Pattern

2.1 How to Recognize It

Clues in titles or descriptions:
	•	References to:
	•	“robots”, “robot.txt”, “crawlers”, “spiders”, “indexing”.
	•	“Search engines should not find this.”
	•	“Only bots can see it” or “hidden from crawlers.”

Behavioral hints:
	•	The main page is minimal and unhelpful.
	•	There’s mention of “disallowed areas” or similar wording.

2.2 Typical Recon Steps
	1.	Fetch the main page
	•	Get initial HTML; read any visible text and comments.
	2.	Check /robots.txt
	•	Visit <base_url>/robots.txt.
	•	Look for Disallow: lines.
	3.	Construct and visit disallowed paths
	•	For each Disallow: /path, try <base_url>/path.
	4.	Inspect the content behind those paths
	•	View HTML.
	•	Look for links, comments, or further hints.

2.3 Example Reasoning Path
	•	Challenge mention: “crawlers” and “hidden from search engines.”
	•	Reasoning:
	1.	“If robots are mentioned, the site might have an informative robots.txt.”
	2.	Fetch /robots.txt.
	3.	Note Disallow: /secret/.
	4.	Visit /secret/ and inspect HTML for comments, links, or scripts.
	5.	Continue recon on any newly discovered paths or resources.

Technique choice:
When you see “robots” or crawlers mentioned, prioritize:
	•	http_fetch → /robots.txt
	•	robots_txt-style analysis
	•	html_inspector on any disallowed paths found

⸻

3. “View Source” / “Look Closer at the Page” Pattern

3.1 How to Recognize It

Clues in text:
	•	Phrases like:
	•	“Maybe you should look closer…”
	•	“Everything you need is already in front of you.”
	•	“Don’t just trust what you see in the browser.”
	•	“Try viewing the source.”

Often the page itself looks simple or empty, but:
	•	The flag or important hints are in HTML comments, hidden inputs, or a linked resource.

3.2 Typical Recon Steps
	1.	View raw HTML
	•	Fetch the main URL and inspect the HTML directly.
	2.	Search for hints in HTML
	•	Comments: <!-- like this -->
	•	Hidden inputs: <input type="hidden" ...>
	•	Suspicious strings or TODO notes.
	3.	Follow all links and static resources
	•	JS files, CSS, images, odd directories.
	4.	Repeat inspection
	•	For each new page or file, inspect the content and comments.

3.3 Example Reasoning Path
	•	Challenge text: “The page looks boring, but maybe there’s more than meets the eye.”
	•	Reasoning:
	1.	“This sounds like a ‘view source’ scenario.”
	2.	Fetch HTML and inspect comments and hidden fields.
	3.	Find a comment referencing /hidden.html.
	4.	Visit /hidden.html and repeat inspection until flag or next hint emerges.

Technique choice:
When hint text suggests “look closer” or “view-source,” prioritize:
	•	http_fetch of HTML.
	•	html_inspector to extract comments, links, scripts.
	•	regex_search for keywords like flag, picoCTF, secret, admin.

⸻

4. “Don’t Trust the Client” / Client-Side JS Logic Pattern

4.1 How to Recognize It

Clues in title/description:
	•	Keywords:
	•	“don’t trust the client”
	•	“client-side”
	•	“JavaScript validation”
	•	“the browser enforces the rules”

Behavioral hints:
	•	A form that refuses submission until input passes some JS check.
	•	A “Check password” button that pops alerts like “Wrong!” without contacting the server.

4.2 Typical Recon Steps
	1.	Inspect HTML and JS
	•	Use HTML tools to find <script> tags and linked .js files.
	2.	Retrieve JS source
	•	Get all inline and external JavaScript code.
	3.	Locate validation logic
	•	Search for:
	•	Conditionals around user input.
	•	Hardcoded strings (passwords, keys, or flag components).
	•	Functions triggered by button clicks or form submissions.
	4.	Reconstruct the correct input or bypass logic
	•	Deduce the expected password, code, or sequence.
	•	Plan to send the correct values directly in an HTTP request.

4.3 Example Reasoning Path
	•	Challenge text: “The login system relies on client-side checks. That can’t go wrong… right?”
	•	Reasoning:
	1.	“This is likely teaching that client-side validation is insecure.”
	2.	Use html_inspector to find scripts.
	3.	Use javascript_source to fetch JS.
	4.	Find a condition like if (password === "supersecret").
	5.	Either:
	•	Use that password in the UI, or
	•	Directly send it in an HTTP request with form_submit.

Technique choice:
For client-side hints:
	•	html_inspector → list scripts
	•	javascript_source → get JS
	•	regex_search → find password, secret, flag, etc.
	•	form_submit / http_fetch → send the final “correct” value to the server

⸻

5. “Weird Login Form” / SQL Injection or Cookie Tampering Pattern

5.1 How to Recognize It

Clues in description:
	•	Mentions of:
	•	“SQL”, “database”, “query”, “login not working right”.
	•	“The login acts strangely for certain inputs.”
	•	“Can you log in without knowing the password?”

Observed behavior:
	•	Different error messages for different input styles.
	•	Application behaves strangely when you add quotes or special characters.
	•	Cookies or roles appear to change after login attempts.

5.2 Typical Recon Steps
	1.	Try normal login attempts
	•	Observe standard error messages and responses.
	2.	Experiment with small, deliberate variations
	•	Single quotes, double quotes, or simple patterns in username/search fields.
	•	Watch for SQL-like errors or different behavior.
	3.	Inspect responses for SQL clues
	•	Use response_search and sql_pattern_hint to find:
	•	SELECT, FROM, WHERE.
	•	“syntax error”, “SQL error”, or similar.
	4.	Inspect cookies after login attempts
	•	Use cookie_inspector.
	•	Look for fields like role, isAdmin, user, auth.
	5.	Form a hypothesis
	•	If errors mention SQL or queries → SQL injection path.
	•	If cookies include roles or admin flags → cookie tampering path.

5.3 Example Reasoning Path (SQLi Flavor)
	•	Challenge flavor: “Can you bypass the login without the password?”
	•	Reasoning:
	1.	Try a username like test and see normal “invalid” message.
	2.	Try username with a single quote, like test'.
	3.	Observe an error referencing SQL syntax.
	4.	Use sql_pattern_hint to focus on SQL-related lines.
	5.	Conclude the input is being inserted into a query.
	6.	Attempt carefully crafted input to manipulate the logic (e.g., closing quotes and adding OR conditions), observing differences in responses.

5.4 Example Reasoning Path (Cookie Tampering Flavor)
	•	Challenge flavor: “It looks like you’re not an admin yet…”
	•	Reasoning:
	1.	Log in or access the page as a default user.
	2.	Use cookie_inspector to list cookies.
	3.	Notice role=user or isAdmin=false.
	4.	Change cookie with cookie_set to role=admin or isAdmin=true.
	5.	Revisit protected endpoint (/admin, /flag, etc.) with http_fetch.

Technique choice:
When a login form behaves oddly or hints at SQL / roles:
	•	For SQLi:
	•	form_submit with controlled test inputs.
	•	response_search / sql_pattern_hint.
	•	For cookie-based:
	•	cookie_inspector → inspect roles.
	•	cookie_set → modify.
	•	http_fetch → re-test protected endpoints.

⸻

6. “Hidden Files / Old Versions / Backups” Pattern

6.1 How to Recognize It

Hints in text:
	•	References to:
	•	“Old version of the site.”
	•	“Backups lying around.”
	•	“Deployed in a hurry.”
	•	Comments like “TODO: remove backup before production.”

Technical clues:
	•	robots.txt listing disallowed paths like /backup/, /old/.
	•	HTML comments mentioning old endpoints.

6.2 Typical Recon Steps
	1.	Check robots.txt
	•	Look for Disallow: /old/ or Disallow: /backup.
	2.	Enumerate likely paths
	•	Try /old, /old/, /backup, /backup/.
	•	Look for .bak, .old, .zip, .tar, etc., if hinted.
	3.	Inspect discovered resources
	•	If you find an old admin panel, login form, or config file:
	•	View source.
	•	Check for hardcoded credentials, secrets, or debug info.

6.3 Example Reasoning Path
	•	Challenge text: “The developers left something old lying around.”
	•	Reasoning:
	1.	Check robots.txt and HTML comments.
	2.	Discover Disallow: /old/.
	3.	Visit /old/ and inspect HTML and JS.
	4.	Find simpler or less protected functionality (e.g., easily bypassed login).

Technique choice:
For “old/backup” style hints:
	•	http_fetch → /robots.txt
	•	html_inspector → find hints to backup paths
	•	Systematically test a small set of likely backup paths and inspect them

⸻

7. “When You’re Stuck” Checklist Pattern

7.1 Recognizing Being Stuck

Signs you might be missing a standard trick:
	•	You’ve only clicked around the UI without:
	•	Viewing source.
	•	Checking robots.txt.
	•	Inspecting JS or cookies.
	•	The challenge is low/medium difficulty but you’re trying complex exploits.

PicoCTF web problems are rarely about:
	•	Heavy brute force.
	•	Exotic 0-day exploits.
	•	Deep framework-specific tricks.

They are usually about missing a standard recon step.

7.2 Quick Mental Checklist

When stuck, ask:
	•	Have I:
	•	Viewed the HTML source and comments?
	•	Checked robots.txt?
	•	Inspected cookies for roles or encodings?
	•	Located and read all JS files (inline and external)?
	•	Tried very simple variations of input (quotes, odd characters, etc.)?
	•	Looked for SQL-like error messages?

7.3 Example Reasoning Path Out of a Dead-End
	•	You’ve tried random guesses on a login page with no success.
	•	Apply checklist:
	1.	View HTML source.
	2.	Find script reference static/check.js.
	3.	Fetch static/check.js.
	4.	Discover hardcoded check or clue that redirects you to a hidden page.

Technique choice:
When stuck, cycle through:
	•	html_inspector (source, links, comments)
	•	javascript_source (JS logic)
	•	cookie_inspector (roles/state)
	•	http_fetch on robots.txt and obvious endpoints

⸻

8. Pattern → Technique Mapping for an LLM Agent

To make this document directly useful for an agent, here’s a compact mapping:
	•	Mentions of “robots”, “crawlers”, “hidden from search engines”
→ Check /robots.txt, then visit disallowed paths.
	•	Hints like “view source”, “look closer”, or a very plain page
→ Fetch HTML, inspect comments, hidden inputs, and linked files.
	•	Talk of “client-side”, “JavaScript”, “browser checks password”
→ Inspect scripts, reverse the validation logic, and send correct value directly.
	•	Strange login behavior, references to databases or queries
→ Test for SQLi, inspect responses for SQL errors, and/or check cookies for roles.
	•	References to old versions, backups, or forgotten files
→ Check robots.txt, then try likely backup/old paths and examine contents.
	•	Feeling stuck without clear direction
→ Run the mental checklist and systematically revisit:
	•	HTML source
	•	robots.txt
	•	JS logic
	•	Cookies
	•	Simple parameter variations

⸻

9. Summary

PicoCTF web challenges are designed around recognizable patterns:
	•	Robots.txt secrets.
	•	View-source and HTML clues.
	•	Client-side JS logic that can be read and bypassed.
	•	Cookie-based role manipulation.
	•	Simplified SQL injection scenarios.
	•	Hidden or old resources.

By linking hints in the description to typical web-exploitation techniques, a human or LLM agent can:
	•	Choose the right next step.
	•	Avoid random guessing.
	•	Follow a structured recon and reasoning path toward the flag.