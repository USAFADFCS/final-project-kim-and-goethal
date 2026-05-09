# Cookies / Session / Auth Bypass: When the server returns 400 for payloads containing quote characters

**Type:** experience_partial
**Category:** Cookies / Session / Auth Bypass
**Challenge:** Trading Places
**Challenge URL:** https://host5.metaproblems.com:7606
**Auto-generated:** 2026-05-04
**Tags:** cookies_auth, partial, experience, do_not
**Confidence:** low
**Site fingerprint:** title:System Login|h1:Trading Platform Login

**Applies when:** When the server returns 400 for payloads containing quote characters

**Agent takeaway:** WAF or strict input validation blocks special chars — use filter_enumerator with bypass_waf:true or try URL/hex/unicode encoding

---

## What Happened

The automated challenge attempt successfully bypassed authentication using the `http_fetch` tool to log in with guest credentials. However, despite the `jwt_tool` and `cookie_set` identifying a valid JWT token, there was no subsequent exploitation attempt with these tokens after they were found, leading to only a partial success. Future attempts should prioritize utilizing found JWT tokens immediately after discovery, leveraging them to access restricted areas or perform actions on behalf of the admin user. Additionally, better selection of wordlists for path enumeration might yield more interesting endpoints to explore, and conducting follow-up actions on identified tokens could provide a complete solution.

## Transferable Rule

Avoid this: WAF or strict input validation blocks special chars — use filter_enumerator with bypass_waf:true or try URL/hex/unicode encoding

Reason: The initial use of `http_fetch` successfully retrieved content from the target URL, indicating the target was responsive.

## Tools Involved

- `robots_txt`
- `path_enumerator`
- `deep_recon`

**Seq hash:** 5468384819372760048
