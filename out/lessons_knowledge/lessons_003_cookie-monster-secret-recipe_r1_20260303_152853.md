# Encoding / Obfuscation: When facing a Encoding / Obfuscation challenge with these tools availa

**Type:** experience_success
**Category:** Encoding / Obfuscation
**Challenge:** Cookie Monster Secret Recipe
**Challenge URL:** http://verbal-sleep.picoctf.net:50876
**Auto-generated:** 2026-03-03
**Tags:** encoding_obfuscation, success, experience, do
**Confidence:** medium
**Site fingerprint:** title:Cookie Monster's Secret Recipe|h1:Cookie Monster's Secret Recipe|form:login.php

**Applies when:** When facing a Encoding / Obfuscation challenge with these tools available

**Agent takeaway:** Follow this winning tool sequence: http_fetch → javascript_source → robots_txt → encoding

---

## What Happened

The automated challenge attempt successfully retrieved a flag after systematically utilizing various tools. The process began by performing HTTP GET requests to the main page and login endpoint, confirming the presence of a set-cookie header containing an encoded string. The encoding tool was then applied to decode the cookie value, first through URL decoding and subsequently through base64 decoding. Notably, the approach capitalized on the absence of explicit crawling rules in the robots.txt file, allowing for unhindered exploration. For future attempts, one should always check for additional encoded data or other potential endpoints that may yield more information or shortcuts to the flag.

## Transferable Rule

Do: Follow this winning tool sequence: http_fetch → javascript_source → robots_txt → encoding

Reason: Using the HttpFetch tool to make GET requests allowed the retrieval of web content and important headers, revealing encoded information.

## Tools Involved

- `http_fetch`
- `javascript_source`
- `robots_txt`
- `encoding`

**Full sequence:** http_fetch → javascript_source → robots_txt → encoding

## Quick Exploitation Path

> **Note:** Replace `<TARGET_URL>` with the current challenge URL.

1. **`http_fetch`**: Fetch the target URL to map the application and identify input forms — use: `{"url":"<TARGET_URL>/","method":"GET","max_body":4000}`
2. **`javascript_source`**: Inspect JS for injection points, credentials, or API endpoints
3. **`robots_txt`**: Check robots.txt for hidden paths
4. **`encoding`**: Use `encoding` — use: `{"text":"cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzX0M0MzBBRTIwfQ==","operation":"base64_decode"}`

## Key Exploit Inputs

The following request(s) produced the flag:

- `http_fetch` input: {"url":"http://verbal-sleep.picoctf.net:50876/","method":"GET","max_body":4000}
- `http_fetch` input: {"url":"http://verbal-sleep.picoctf.net:50876/login.php","method":"GET","max_body":4000}
- `encoding` input: {"text":"cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzX0M0MzBBRTIwfQ==","operation":"base64_decode"}

**Seq hash:** 7044095527235326300
