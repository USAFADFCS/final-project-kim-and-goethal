# Cookies / Session / Auth Bypass: When facing a Cookies / Session / Auth Bypass challenge with these too

**Type:** experience_success
**Category:** Cookies / Session / Auth Bypass
**Challenge:** Admin Portal
**Challenge URL:** http://adminportal.chals.mctf.io
**Auto-generated:** 2026-03-03
**Tags:** cookies_auth, success, experience, do
**Confidence:** high
**Site fingerprint:** title:Admin Portal|h1:Welcome to the Admin Portal

**Applies when:** When facing a Cookies / Session / Auth Bypass challenge with these tools available

**Agent takeaway:** Follow this winning tool sequence: http_fetch → cookie_set

---

## What Happened

In tackling the Admin Portal challenge, the initial steps involved fetching the site using the GET method, which returned a 200 status and set a user role cookie. Leveraging the cookie manipulation tool, the participant set the user role to 'admin', which granted access to the admin functionalities. This success highlights the vulnerability of relying solely on client-side cookie validation for authorization. For future attempts, analyzing more intermediary responses and headers could unveil additional weaknesses, while considering security measures like HttpOnly flags and proper server-side checks to avoid similar bypasses.

## Transferable Rule

Do: Follow this winning tool sequence: http_fetch → cookie_set

Reason: HttpFetch was used to retrieve the site, revealing the behavior around how cookies were managed in the response.

## Tools Involved

- `http_fetch`
- `cookie_set`

**Full sequence:** http_fetch → cookie_set

## Quick Exploitation Path

> **Note:** Replace `<TARGET_URL>` with the current challenge URL.

1. **`http_fetch`**: Fetch the target URL to map the application and identify input forms — use: `{"url":"<TARGET_URL>/","method":"GET","max_body":4000}`
2. **`cookie_set`**: Override or forge a session cookie

## Key Exploit Inputs

The following request(s) produced the flag:

- `http_fetch` input: {"url":"http://adminportal.chals.mctf.io/","method":"GET","max_body":4000}
- `http_fetch` input: {"url":"http://adminportal.chals.mctf.io/","method":"GET","max_body":0}

**Seq hash:** -3538274449773584783
