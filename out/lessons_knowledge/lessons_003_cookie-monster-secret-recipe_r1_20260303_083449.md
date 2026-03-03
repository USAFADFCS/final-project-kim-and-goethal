# Client-Side (HTML/JS) Analysis: When facing a Client-Side (HTML/JS) Analysis (engine: Thymeleaf) chall

**Type:** experience_success
**Category:** Client-Side (HTML/JS) Analysis
**Challenge:** Cookie Monster Secret Recipe
**Challenge URL:** http://verbal-sleep.picoctf.net:54516/
**Auto-generated:** 2026-03-03
**Tags:** client_side, success, experience, do
**Confidence:** medium
**Template engine:** Thymeleaf
**Site fingerprint:** title:Cookie Monster's Secret Recipe|h1:Cookie Monster's Secret Recipe|form:login.php

**Applies when:** When facing a Client-Side (HTML/JS) Analysis (engine: Thymeleaf) challenge with these tools available

**Agent takeaway:** Follow this winning tool sequence: http_fetch → javascript_source → robots_txt → encoding

---

## What Happened

In this challenge, a successful retrieval of a secret recipe hidden in a cookie was accomplished through a series of steps. The first tool, http_fetch, was used to request the main page and login page, revealing a cookie containing encoded data. By inspecting the JavaScript source, no additional insights were gained, indicating there were no further client-side scripts to exploit. The absence of a robots.txt file suggested no restrictions on crawling. Using the encoding tool facilitated decoding of the cookie data from URL and base64 formats, ultimately revealing the flag. Next time, one could experiment with different decoding methods or analyze HTTP responses more rigorously for further hidden data.

## Transferable Rule

Do: Follow this winning tool sequence: http_fetch → javascript_source → robots_txt → encoding

Reason: Using the http_fetch tool allowed for quick data retrieval from the web server, identifying key URLs and associated cookies.

## Tools Involved

- `http_fetch`
- `javascript_source`
- `robots_txt`
- `encoding`

**Full sequence:** http_fetch → javascript_source → robots_txt → encoding

## Quick Exploitation Path

1. **`http_fetch`**: Fetch the target URL to map the application and identify input forms — use: `{"url":"http://verbal-sleep.picoctf.net:54516/","method":"GET"}`
2. **`javascript_source`**: Inspect JS for injection points, credentials, or API endpoints
3. **`robots_txt`**: Check robots.txt for hidden paths
4. **`encoding`**: Use `encoding` — use: `{"text":"cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzX0M0MzBBRTIwfQ==","operation":"base64_decode"}`

> **Next-step strategy:** Run `javascript_source` on every JS file linked from the page. Credentials and tokens are often hard-coded or in local storage.

## Key Exploit Inputs

The following request(s) produced the flag:

- `http_fetch` input: {"url":"http://verbal-sleep.picoctf.net:54516/","method":"GET"}
- `http_fetch` input: {"url":"http://verbal-sleep.picoctf.net:54516/login.php","method":"GET"}
- `encoding` input: {"text":"cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzX0M0MzBBRTIwfQ==","operation":"base64_decode"}

**Seq hash:** 744940742784729376
