# Client-Side (HTML/JS) Analysis: When you achieve 'recon_complete' during a Client-Side (HTML/JS) Analy

**Type:** experience_success
**Category:** Client-Side (HTML/JS) Analysis
**Challenge:** Cookie Monster Secret Recipe
**Challenge URL:** http://verbal-sleep.picoctf.net:54516/
**Auto-generated:** 2026-03-03
**Tags:** client_side, success, experience, do
**Confidence:** medium
**Template engine:** Thymeleaf
**Site fingerprint:** title:Cookie Monster's Secret Recipe|h1:Cookie Monster's Secret Recipe|form:login.php

**Applies when:** When you achieve 'recon_complete' during a Client-Side (HTML/JS) Analysis challenge

**Agent takeaway:** Continue exploitation after confirming 'recon_complete' — do not stop at reconnaissance

---

## What Happened

In this challenge, a successful retrieval of a secret recipe hidden in a cookie was accomplished through a series of steps. The first tool, http_fetch, was used to request the main page and login page, revealing a cookie containing encoded data. By inspecting the JavaScript source, no additional insights were gained, indicating there were no further client-side scripts to exploit. The absence of a robots.txt file suggested no restrictions on crawling. Using the encoding tool facilitated decoding of the cookie data from URL and base64 formats, ultimately revealing the flag. Next time, one could experiment with different decoding methods or analyze HTTP responses more rigorously for further hidden data.

## Transferable Rule

Do: Continue exploitation after confirming 'recon_complete' — do not stop at reconnaissance

Reason: The encoding tool was critical in decoding the base64 encoded value from the cookie, directly leading to the successful flag extraction.

## Tools Involved

- `http_fetch`
- `javascript_source`
- `robots_txt`

**Full sequence:** http_fetch → javascript_source → robots_txt → encoding

## Key Exploit Inputs

The following request(s) produced the flag:

- `http_fetch` input: {"url":"http://verbal-sleep.picoctf.net:54516/","method":"GET"}
- `http_fetch` input: {"url":"http://verbal-sleep.picoctf.net:54516/login.php","method":"GET"}
- `encoding` input: {"text":"cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzX0M0MzBBRTIwfQ==","operation":"base64_decode"}

**Seq hash:** 744940742784729376
