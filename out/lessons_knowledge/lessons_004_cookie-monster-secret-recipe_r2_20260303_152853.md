# Encoding / Obfuscation: When you achieve 'recon_complete' during a Encoding / Obfuscation chal

**Type:** experience_success
**Category:** Encoding / Obfuscation
**Challenge:** Cookie Monster Secret Recipe
**Challenge URL:** http://verbal-sleep.picoctf.net:50876
**Auto-generated:** 2026-03-03
**Tags:** encoding_obfuscation, success, experience, do
**Confidence:** medium
**Site fingerprint:** title:Cookie Monster's Secret Recipe|h1:Cookie Monster's Secret Recipe|form:login.php

**Applies when:** When you achieve 'recon_complete' during a Encoding / Obfuscation challenge

**Agent takeaway:** Continue exploitation after confirming 'recon_complete' — do not stop at reconnaissance

---

## What Happened

The automated challenge attempt successfully retrieved a flag after systematically utilizing various tools. The process began by performing HTTP GET requests to the main page and login endpoint, confirming the presence of a set-cookie header containing an encoded string. The encoding tool was then applied to decode the cookie value, first through URL decoding and subsequently through base64 decoding. Notably, the approach capitalized on the absence of explicit crawling rules in the robots.txt file, allowing for unhindered exploration. For future attempts, one should always check for additional encoded data or other potential endpoints that may yield more information or shortcuts to the flag.

## Transferable Rule

Do: Continue exploitation after confirming 'recon_complete' — do not stop at reconnaissance

Reason: By decoding the cookie through both URL and base64 processes, the hidden flag was accurately extracted from an otherwise obfuscated format.

## Tools Involved

- `http_fetch`
- `javascript_source`
- `robots_txt`

**Full sequence:** http_fetch → javascript_source → robots_txt → encoding

## Key Exploit Inputs

The following request(s) produced the flag:

- `http_fetch` input: {"url":"http://verbal-sleep.picoctf.net:50876/","method":"GET","max_body":4000}
- `http_fetch` input: {"url":"http://verbal-sleep.picoctf.net:50876/login.php","method":"GET","max_body":4000}
- `encoding` input: {"text":"cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzX0M0MzBBRTIwfQ==","operation":"base64_decode"}

**Seq hash:** 7044095527235326300
