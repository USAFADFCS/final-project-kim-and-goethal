# Reconnaissance & Hidden Paths: When tools repeatedly encounter connection errors

**Type:** experience_partial
**Category:** Reconnaissance & Hidden Paths
**Challenge:** msfroggenerator2
**Challenge URL:** http://saturn.picoctf.net:53552
**Auto-generated:** 2026-03-03
**Tags:** recon, partial, experience, do_not
**Confidence:** medium
**Site fingerprint:** title:msfroggenerator2

**Applies when:** When tools repeatedly encounter connection errors

**Agent takeaway:** Service may be rate-limiting or the challenge URL has changed — reduce request rate, verify URL, and try http_fetch before specialised tools

---

## What Happened

The automated challenge attempt effectively utilized various tools to gather information on the target application. A successful HTTP GET request to the root URL confirmed that the service was running. The enumeration of paths revealed endpoints that could be tested further, and using a request repeater enabled parameter fuzzing to explore the API. The detection of server-side template injection (SSTI) suggests vulnerabilities in the application. However, the attempts to access certain API resources yielded `403 Unauthorized` responses, indicating restricted access. In the future, expanding the parameter values tested and perhaps leveraging discovered API routes more creatively could yield additional insights.

## Transferable Rule

Avoid this: Service may be rate-limiting or the challenge URL has changed — reduce request rate, verify URL, and try http_fetch before specialised tools

Reason: Utilizing path enumeration can effectively identify interesting endpoints within a web application that may be susceptible to further testing.

## Tools Involved

- `http_fetch`
- `javascript_source`
- `path_enumerator`

**Seq hash:** 876904008982970011
