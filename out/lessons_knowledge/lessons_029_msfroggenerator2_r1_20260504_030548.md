# Reconnaissance & Hidden Paths: When the server returns 400 for payloads containing quote characters

**Type:** experience_partial
**Category:** Reconnaissance & Hidden Paths
**Challenge:** msfroggenerator2
**Challenge URL:** http://saturn.picoctf.net:51585
**Auto-generated:** 2026-05-04
**Tags:** recon, partial, experience, do_not
**Confidence:** low

**Applies when:** When the server returns 400 for payloads containing quote characters

**Agent takeaway:** WAF or strict input validation blocks special chars — use filter_enumerator with bypass_waf:true or try URL/hex/unicode encoding

---

## What Happened

In this challenge, the analyst utilized various reconnaissance tools to explore the target application at http://saturn.picoctf.net:51585/. Initial attempts using common wordlists yielded no interesting paths, but deeper exploration into API endpoints revealed accessible paths. Some HTTP requests returned 200 statuses without meaningful responses. The analyst effectively extracted JavaScript, confirming potential server-side template injection points (SSTI). However, no valid flags were acquired due to incomplete enumeration. In the future, expanding the wordlists and employing targeted exploration of discovered endpoints may lead to more successful outcomes, especially focusing on crafting inputs that exploit weak API implementations.

## Transferable Rule

Avoid this: WAF or strict input validation blocks special chars — use filter_enumerator with bypass_waf:true or try URL/hex/unicode encoding

Reason: Using common wordlists was ineffective due to the lack of interesting paths, suggesting a need to customize or diversify wordlists for better results.

## Tools Involved

- `robots_txt`
- `path_enumerator`
- `deep_recon`

**Seq hash:** 1683255459103089682
