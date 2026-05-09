# Reconnaissance & Hidden Paths: When a Reconnaissance & Hidden Paths challenge resists standard payloa

**Type:** experience_partial
**Category:** Reconnaissance & Hidden Paths
**Challenge:** Dot-Matrix Destruction
**Challenge URL:** http://w4tfqdk1.chals.mctf.io/
**Auto-generated:** 2026-05-03
**Tags:** recon, partial, experience, do_not
**Confidence:** low
**Site fingerprint:** title:500 Internal Server Error|h1:Internal Server Error

**Applies when:** When a Reconnaissance & Hidden Paths challenge resists standard payloads

**Agent takeaway:** Pivot to a different attack vector early rather than repeating the same approach with minor variations

---

## What Happened

The automated challenge attempt utilized multiple tools to gather information and test for vulnerabilities in the target application. It confirmed server-side template injection (SSTI) and achieved a complete reconnaissance of the target. However, despite the reconnaissance phase revealing no interesting paths or files through the robots.txt or path enumeration, the HTTP fetch to the static file successfully returned data, indicating the application was operational. Future attempts should consider customizing wordlists for path enumeration and other types of probes to enhance the discovery of potentially interesting files and endpoints.

## Transferable Rule

Avoid this: Pivot to a different attack vector early rather than repeating the same approach with minor variations

Reason: Using default wordlists for path enumeration can limit discovery; customized lists can yield better results.

## Tools Involved

- `http_fetch`
- `path_enumerator`
- `robots_txt`

**Seq hash:** -394168359515419477
