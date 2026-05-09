# Server-Side Template Injection: When a Server-Side Template Injection challenge resists standard paylo

**Type:** experience_partial
**Category:** Server-Side Template Injection
**Challenge:** Super Quick Logic Invitational
**Challenge URL:** http://14amlyf9.chals.mctf.io/
**Auto-generated:** 2026-05-03
**Tags:** ssti, partial, experience, do_not
**Confidence:** high
**Site fingerprint:** title:Super Quick Logic Invitational|h1:Super Quick Logic Invitational

**Applies when:** When a Server-Side Template Injection challenge resists standard payloads

**Agent takeaway:** Pivot to a different attack vector early rather than repeating the same approach with minor variations

---

## What Happened

In a prior attempt on a Server-Side Template Injection challenge, the agent failed after 31 steps. Primary tools used: `http_fetch`, `blind_sqli_boolean`, `path_enumerator`. Partial progress confirmed: ssti_confirmed, schema_extracted. Key lesson: Pivot to a different attack vector early rather than repeating the same approach with minor variations.

## Transferable Rule

Avoid this: Pivot to a different attack vector early rather than repeating the same approach with minor variations

Reason: Run exhausted 31 steps without progress

## Tools Involved

- `http_fetch`
- `blind_sqli_boolean`
- `path_enumerator`

**Seq hash:** 4886379210129269344
