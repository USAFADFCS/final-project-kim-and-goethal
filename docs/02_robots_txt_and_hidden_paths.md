Using robots.txt and Hidden Paths in Web CTF Challenges

This document (02_robots_txt_and_hidden_paths.md) explains how to use robots.txt and related techniques to discover hidden content in web CTF challenges, and how an LLM agent should reason about it.

⸻

1. What robots.txt Is (Normal Web Usage)

In normal web usage:
	•	robots.txt is a plain-text file located at the root of a website:
	•	Example: https://example.com/robots.txt
	•	It follows the Robots Exclusion Protocol, which is a voluntary standard telling web crawlers (like search engines) which paths they should or should not crawl.
	•	Typical fields:
	•	User-agent: – which crawler the rule applies to (e.g., * for all).
	•	Disallow: – path(s) the crawler should avoid.
	•	Allow: – path(s) explicitly allowed, often overriding broader Disallow rules.

Important points:
	•	robots.txt is a hint, not an access control mechanism.
	•	Browsers and HTTP clients are not prevented from visiting disallowed paths.
	•	In normal sites, it helps search engines avoid private or duplicate content.

⸻

2. Why CTFs Often Hide Interesting Endpoints in Disallow: Rules

In many CTFs, robots.txt is intentionally misused as a treasure map:
	•	Because:
	•	The file is public and easy to fetch.
	•	It is expected that players will inspect it during recon.
	•	Challenge authors often:
	•	Put “secret” or “admin” paths in Disallow: lines.
	•	Hint at where the flag or admin functionality might be.

From an LLM agent’s perspective:
	•	Seeing a Disallow: /something line is not a prohibition in this context; it’s a strong hint to visit /something.
	•	When the challenge mentions “robots” or crawling in its description or title, checking robots.txt becomes even more important.

⸻

3. Interpreting Allow: vs Disallow: Lines

3.1 Basic Structure

A simple robots.txt might look like:
User-agent: *
Disallow: /admin
Disallow: /backup
Allow: /public

Key ideas:
	•	User-agent: * – rules apply to all crawlers.
	•	Disallow: /admin – crawlers are asked not to fetch /admin.
	•	Allow: /public – crawlers are allowed to fetch /public.

3.2 What These Mean in CTF Reasoning

In a CTF context:
	•	Disallow: /admin
	•	Often suggests /admin is interesting:
	•	Could be a hidden admin panel.
	•	Might contain debug information or the flag.
	•	Disallow: /backup
	•	Suggests there might be backup files or old versions:
	•	/backup/
	•	/backup/index.php
	•	Compressed archives like /backup.zip are common patterns (but not guaranteed).
	•	Allow: lines are usually less interesting but still:
	•	Help you understand what the “intended” public area is.
	•	Sometimes help with overrides in more complex files.

3.3 Multiple User-Agent Blocks

You may see multiple sections, e.g.:
User-agent: Googlebot
Disallow: /private

User-agent: *
Disallow: /tmp
Disallow: /old

CTF reasoning:
	•	Any path listed under any user agent can be worth visiting.
	•	If one crawler is told not to visit /private, that might be a hint even if User-agent: * does not mention it.

⸻

4. Turning Disallow: /secret-path into URLs to Visit

4.1 Basic Conversion

Given a base URL like:
	•	https://ctf.example.org

and a robots rule:
Disallow: /secret-path

You can construct the concrete URL:
	•	https://ctf.example.org/secret-path

If the challenge uses a nonstandard port or path, keep those:
	•	Base: http://challenge.example.org:12345
	•	Disallow: /hidden ⇒ http://challenge.example.org:12345/hidden

4.2 Paths with Trailing Slashes

For rules like:
Disallow: /private/

Common URLs to try:
	•	/private/
	•	/private/index.html
	•	/private/index.php
	•	/private/admin, /private/backup (if other hints suggest these).

4.3 Paths with Wildcards (Informal)

Some robots.txt files use patterns (not universally standardized):
Disallow: /tmp/*
Disallow: /*.bak

In CTF-style reasoning:
	•	/tmp/* suggests:
	•	Files under /tmp/ like /tmp/test, /tmp/logs, /tmp/debug.txt.
	•	/*.bak suggests:
	•	Possible backup files in the root, e.g., /index.php.bak.

Even if the wildcard syntax is not strictly enforced by all crawlers, it’s a clue that similar paths might exist.

⸻

5. Common “Hidden” Paths in CTFs (Patterns, Not Guarantees)

CTF authors often reuse certain “secret-y” path names. These are common patterns, not rules:
	•	Admin-related
	•	/admin
	•	/administrator
	•	/adminpanel
	•	/secret-admin
	•	Backups / Old Versions
	•	/backup
	•	/backups
	•	/old
	•	/old-site
	•	/archive
	•	/dev
	•	/development
	•	User or home-like directories
	•	/~user
	•	/~admin
	•	/~test
	•	Test / Debug
	•	/test
	•	/debug
	•	/staging
	•	/beta

These may appear:
	•	In Disallow: lines of robots.txt.
	•	As actual links in HTML.
	•	Only in comments or as clues in the description.

An LLM agent should:
	•	Treat each of these as a candidate path to explore.
	•	Always confirm by fetching the URL and inspecting the result, rather than assuming it exists.

⸻

6. Combining robots.txt Findings with Other Recon Techniques

6.1 Pairing with Directory Guesses

After reading robots.txt, the agent can:
	•	Use the paths listed as starting points for further guesses.
	•	Example:
	•	Disallow: /old/
	•	Try:
	•	/old/
	•	/old/index.php
	•	/old/admin
	•	/old/backup

These guesses are more focused than random brute-forcing, because they build on explicit hints.

6.2 Pairing with Link Enumeration

Links in HTML might confirm or extend robots.txt clues.

Example:
	1.	robots.txt contains:
        Disallow: /admin
        Disallow: /old

2.	HTML page contains links to:
	•	/old/login.php
	•	/static/admin.js

Reasoning:
	•	/old/login.php might be an outdated or weaker login page.
	•	/static/admin.js might contain client-side logic or secrets for admin access.

An LLM agent should:
	•	Fetch pages linked from these paths.
	•	Inspect their HTML, scripts, and behavior.

6.3 Pairing with Comments in HTML

HTML comments sometimes refer to paths that match or reinforce what robots.txt says.

Example:
<!-- TODO: Remove /backup/ before production deployment -->

and in robots.txt:
User-agent: *
Disallow: /backup

Reasoning:
	•	/backup is likely a directory with old or sensitive files.
	•	This double signal (comment + Disallow) makes it a high-priority path.

6.4 Using RAG/Knowledge to Interpret Patterns

When the agent finds:
	•	A Disallow rule for something like /secret-admin.
	•	A comment referencing “don’t let search engines find the admin page”.
	•	Unusual cookie or parameter names.

It can then:
	•	Consult web-exploitation knowledge (via RAG) to:
	•	Recall typical admin-panel tricks.
	•	Consider whether cookies, parameters, or client-side checks are involved.
	•	Decide:
	•	To call tools that inspect HTML, JS, cookies, or run targeted parameter tests.

⸻

7. What an LLM Agent Should Look For in robots.txt

When an LLM agent fetches robots.txt, it should:
	•	Parse and list all Disallow: and Allow: lines, including associated paths.
	•	Normalize paths:
	•	Ensure they start with /.
	•	Combine with the base URL (including port).
	•	Prioritize:
	•	Disallowed paths with names suggesting admin, backups, secrets, or testing.
	•	Plan follow-up actions:
	•	Fetch each high-priority path and inspect its response.
	•	Use HTML/JS inspection tools on the fetched pages.
	•	Note any new links, forms, or comments discovered there.
	•	Log observations:
	•	Which paths exist (status 200, 301/302).
	•	Which paths return errors (403, 404, 500).
	•	Any new hints, such as mention of “flag”, “admin”, SQL-like text, or debug info.

⸻

8. Summary

For web CTF challenges, robots.txt is often:
	•	A deliberate hint mechanism, not just a crawler configuration file.
	•	A way to point players (and agents) toward sensitive or hidden paths.

An effective agent will:
	1.	Fetch robots.txt.
	2.	Extract all Disallow: (and relevant Allow:) paths.
	3.	Convert them into concrete URLs relative to the challenge base.
	4.	Visit and analyze these URLs.
	5.	Use additional signals (comments, link structure, cookies, errors) to decide next steps.