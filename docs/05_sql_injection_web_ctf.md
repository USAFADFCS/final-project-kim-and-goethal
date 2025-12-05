This document gives a focused overview of SQL injection (SQLi).


1. What Is SQL Injection and Why Does It Happen?

SQL injection occurs when a web application builds an SQL query by directly concatenating unsanitized user input into the query string.

Conceptually:
	•	The application expects user input to be just data (e.g., a username).
	•	Instead, the input also contains SQL syntax (quotes, operators, comments).
	•	The final query sent to the database ends up doing more than intended.

Example idea (not tied to a specific DB):
	•	Intended query pattern:
SELECT * FROM users WHERE username = '<user_input>' AND password = '<pass_input>';
	•	If the programmer simply inserts user input into the string, malicious input can alter the query structure.

SQL injection happens when:
	•	User input is directly embedded in SQL strings.
	•	There is no proper escaping, validation, or use of parameterized queries.

In real-world secure systems, parameterized queries and proper input handling are used to prevent this. In CTFs, applications are often intentionally written in an unsafe way to illustrate the concept.

⸻

2. Typical Places SQLi Appears in Web CTFs

In many web CTF challenges, SQLi shows up in predictable places:
	•	Login forms
	•	Fields like username and password that get checked against a database.
	•	Search boxes
	•	Search terms may be used in WHERE or LIKE clauses.
	•	URL parameters
	•	IDs in query strings: ?id=1 or ?user=guest.
	•	Hidden or less obvious inputs
	•	Form fields that aren’t visible.
	•	Parameters in POST requests.
	•	API endpoints that accept JSON bodies translated into queries.

When you see a feature that looks like it is reading from a database based on user input (e.g., “look up user”, “view record”, “search”), SQL injection is sometimes the intended vulnerability in CTFs.

⸻

3. Basic SQL Syntax & Concepts Relevant to SQLi

You do not need to be a full SQL expert to understand basic SQLi challenges, but you should recognize some common elements.

3.1 SELECT, FROM, WHERE

A very common pattern:
	•	SELECT <columns> FROM <table> WHERE <condition>;

Examples of conceptual queries:
	•	SELECT * FROM users WHERE username = 'alice';
	•	SELECT * FROM products WHERE id = 1;

The WHERE clause is often where user input is inserted and where injection occurs.

3.2 AND / OR

Logical operators connect conditions:
	•	... WHERE username = 'alice' AND password = 'password123';
	•	... WHERE id = 1 OR 1 = 1;

If user input can introduce additional OR or AND clauses, it can change which rows are selected.

3.3 Quotes

String literals in many SQL dialects are surrounded by single quotes:
	•	'alice'
	•	'admin'

Injections often involve closing an existing quote and adding new SQL:
	•	If the query is:
... WHERE username = '<user_input>' ...
	•	And the input is: admin' OR '1'='1
	•	The final query might become:
... WHERE username = 'admin' OR '1'='1' ...

3.4 Comments

Comments allow the rest of a query line to be ignored:
	•	-- (double dash followed by a space) — comment until end of line.
	•	# — used in some SQL dialects.
	•	/* ... */ — block comment.

In SQL injection, comments can be used to neutralize the remainder of the original query:
	•	When the application adds AND password = '<pass>' after your input, you might end the injected condition with -- so that part is ignored.

⸻

4. High-Level Examples of SQLi Payload “Types”

This section focuses on what payloads try to accomplish, not on a huge list of exact strings.

4.1 Authentication Bypass

Goal: Log in as a particular user (often admin) without knowing the real password.

Example pattern (conceptual):
	•	User input for username:
	•	admin' OR '1'='1
	•	Password field can be anything.

If the application builds a query like:
	•	SELECT * FROM users WHERE username = '<user_input>' AND password = '<pass_input>';

The injected query might become logically equivalent to:
	•	SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = 'whatever';

Depending on operator precedence and DB behavior, this can result in the WHERE condition always being true, causing the application to treat you as logged in.

4.2 Extracting or “Dumping” Data

More advanced CTF challenges may let you:
	•	Use UNION SELECT to combine results from multiple queries.
	•	Grab data from other tables, like user lists.

High-level idea:
	•	A vulnerable input that normally does:
	•	SELECT name FROM products WHERE id = <input>;
	•	With injection, you might turn it into:
	•	SELECT name FROM products WHERE id = 1 UNION SELECT username FROM users;

In beginner challenges, you might only need to extract a single extra column or a flag; advanced versions can be more complex.

4.3 Detecting SQLi Through Behavior (Boolean-based)

Even if errors are hidden, you can sometimes tell if injection is possible by:
	•	Using inputs that cause different responses depending on a condition.

For example:
	•	Input that leads to a true condition:
	•	1' OR '1'='1
	•	Input that leads to a false condition:
	•	1' AND '1'='2

If:
	•	The first input returns a normal or “success” page.
	•	The second input returns an error or “no results” page.

Then the application behavior suggests that your input is controlling a Boolean condition inside an SQL query.

⸻

5. Interpreting SQL Error Messages and Echoed Queries

5.1 SQL Error Messages as Hints

Many CTF challenges intentionally display detailed error messages, such as:
	•	“You have an error in your SQL syntax near ‘…’”
	•	“Unknown column ‘blah’ in ‘where clause’”
	•	“Unclosed quotation mark after the character string ‘…’”

These can reveal:
	•	Where your input appears in the query (inside quotes, after WHERE, etc.).
	•	Whether the query uses single quotes, double quotes, or none.
	•	The database type (MySQL, PostgreSQL, SQLite, etc.).

If an error appears only when you include certain characters (like ', ", or --), that suggests your input is being interpolated into an SQL statement.

5.2 Echoed Queries

Some challenges (for teaching purposes) show the constructed query back to you:
	•	For example:
	•	“Executing query: SELECT * FROM users WHERE name = ‘test’;”

This is an extremely strong hint:
	•	You can see exactly how user input is embedded.
	•	You can design injection payloads that correctly balance quotes and syntax.

In real-world apps, showing raw queries like this is considered a serious security issue, but in CTFs it is common for demonstration.

5.3 Using Tools to Highlight Interesting Lines

Two tools are especially helpful for an AI agent:
	•	response_search
	•	Given a response body and some keywords (e.g., sql, error, SELECT, FROM), it can pull out lines around those keywords.
	•	This helps focus on important parts of verbose HTML or error output.
	•	sql_pattern_hint
	•	Scans response text for common SQL keywords and patterns.
	•	Returns lines that likely indicate query construction or database-related errors.

Together, these tools help the agent quickly identify:
	•	Whether SQL-related text appears in responses.
	•	Where errors and query fragments are located.
	•	Which inputs might be causing the errors.

⸻

6. Common CTF-Specific SQLi Patterns

These patterns show up frequently in CTFs and are worth recognizing. They are simplified to make learning easier.

6.1 Classic ' OR 1=1 -- Logic Bypass (CTF Trick)

This is one of the most iconic teaching examples.

Scenario (conceptual):
	•	Application expects:
SELECT * FROM users WHERE username = '<user>' AND password = '<pass>';
	•	Input for username:
' OR 1=1 --
	•	Input for password: anything.

The resulting query might look like:
	•	SELECT * FROM users WHERE username = '' OR 1=1 -- ' AND password = 'whatever';

Effects:
	•	OR 1=1 always evaluates to true, so the WHERE clause may match all rows.
	•	-- comments out the rest of the line, effectively removing the password check.

In CTFs, this pattern is often used to illustrate the concept of authentication bypass. Actual payloads may differ depending on the specific query structure and DB dialect.

6.2 Boolean-Based Behavior

Sometimes the challenge hides error messages but still gives different responses:
	•	“Welcome, user!” vs. “Invalid login.”
	•	Showing slightly different content depending on the result.

You can probe with inputs that cause a condition to be true or false:
	•	One input that, if interpreted as SQL, makes the WHERE clause always true.
	•	Another input that makes it always false.

If:
	•	True-style input produces a “positive” response.
	•	False-style input produces a “negative” response.

Then the difference suggests SQL injection is affecting the query’s logic.

6.3 Brief Mention of Blind and Time-Based SQLi

Some challenges briefly touch on more advanced concepts:
	•	Blind SQLi
	•	The application does not show SQL errors or output directly.
	•	You infer information from different responses (e.g., page content, length, status code).
	•	Time-based SQLi
	•	The application’s response time changes based on the injected condition (e.g., using functions that introduce a delay if a condition is true).
	•	By measuring delays, an attacker can learn about the database state.

In beginner CTFs, these are usually simplified and may only be referenced conceptually.

⸻

7. CTF-Only Learning and Ethical Use

It is important to emphasize:
	•	These techniques are presented in the context of legal, ethical CTF challenges.
	•	CTF platforms provide isolated, intentionally vulnerable targets for learning.
	•	Attempting SQL injection on systems you do not own or have permission to test is unethical and often illegal.

Use these concepts to:
	•	Understand how SQL injection works.
	•	Learn how developers should avoid such vulnerabilities.
	•	Solve educational CTF tasks designed for this purpose.

⸻

8. How This Guides Tool Usage for an LLM Agent

An AI agent solving a suspected SQLi challenge can follow a reasoning process informed by this document:
	1.	Initial suspicion of SQLi
	•	Challenge description mentions databases or “login bypass”.
	•	Unusual error messages appear when quotes or special characters are used.
	2.	Use response_search and sql_pattern_hint
	•	Scan responses for:
	•	SELECT, FROM, WHERE.
	•	Error text like “syntax error”, “SQL”, “database”.
	•	Focus attention on lines where SQL syntax appears.
	3.	Refine hypothesis
	•	If adding ' or " breaks the page with a DB error, user input is likely part of a query.
	•	If different logical inputs produce distinct responses (true/false style), boolean-based SQLi may be present.
	4.	Carefully craft inputs
	•	Try simple patterns (e.g., closing quotes and adding OR 1=1).
	•	Observe whether behavior changes in a way that suggests injection.
	5.	Confirm and extract
	•	Once injection is confirmed, reason about:
	•	Whether the goal is to bypass a login.
	•	Whether the goal is to retrieve additional data or just the flag.
	•	Use http_fetch or form_submit to send appropriate requests based on the inferred vulnerable parameter.