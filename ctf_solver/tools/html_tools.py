"""
HTML and JavaScript inspection tools for CTF solving.

Provides HTML structure analysis and JavaScript source extraction.
"""

from typing import List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup, Comment

from ctf_solver.tools.core import parse_json_input

# Optional JS beautifier (if installed)
try:
    import jsbeautifier  # type: ignore

    HAS_JSBEAUTIFIER = True
except Exception:
    HAS_JSBEAUTIFIER = False


class HtmlInspectorTool:
    """
    HtmlInspectorTool: inspect and summarize the structure of an HTML page.

    Inputs (JSON via `.use`):

        {
          "url": "https://example.com/path",  # optional
          "html": "<html>...</html>",        # optional
          "max_items": 50                    # optional, maximum items per section
        }

    Behavior:
      - If 'html' is provided, parse that directly.
      - Else if 'url' is provided, fetch the page using the shared session.
      - Extract:
          * <a href=...> links (href + text)
          * <script src=...> external script URLs
          * <link rel="stylesheet" href=...> CSS URLs
          * HTML comments
      - Return a readable text summary grouping LINKS / SCRIPTS / STYLESHEETS / COMMENTS.
    """

    name: str = "html_inspector"
    description: str = (
        "Inspect and summarize the structure of HTML. Input JSON keys: "
        "'url' (optional) or 'html' (optional), and 'max_items' (optional int). "
        "If 'url' is given, fetches that page; otherwise uses the provided 'html'. "
        "Extracts links, external scripts, inline script previews, stylesheets, "
        "comments, forms, meta tags, and hidden inputs. NOTE: For full inline "
        "JavaScript code, use 'javascript_source' — this tool only shows previews."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Page to fetch and inspect"},
            "html": {
                "type": "string",
                "description": "Raw HTML to inspect (use instead of url)",
            },
            "max_items": {"type": "integer", "default": 30},
        },
        "additionalProperties": False,
    }
    samples = [{"url": "http://example.com/"}]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _fetch_html(self, url: str) -> str:
        try:
            resp = self.session.get(url, timeout=10)
        except Exception as exc:
            return f"[HtmlInspectorTool] Error fetching URL {url!r}: {exc!r}"
        return resp.text or ""

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "HtmlInspectorTool")
        if err:
            return err
        url = data.get("url")
        html = data.get("html")
        max_items = data.get("max_items", 50)

        if html and not isinstance(html, str):
            return "[HtmlInspectorTool] Error: 'html' must be a string if provided."
        if url and not isinstance(url, str):
            return "[HtmlInspectorTool] Error: 'url' must be a string if provided."

        if not html and not url:
            return (
                "[HtmlInspectorTool] Error: You must provide either 'url' or 'html' "
                "in the JSON input."
            )

        if not html and url:
            html = self._fetch_html(url)

        if html.startswith("[HtmlInspectorTool] Error"):
            # Propagate error from _fetch_html
            return html

        soup = BeautifulSoup(html, "html.parser")

        # Extract links
        links: List[str] = []
        for a in soup.find_all("a", href=True):
            text = (a.get_text() or "").strip()
            href = a["href"]
            if url:
                href = urljoin(url, href)
            if text:
                links.append(f"- text={text!r}, href={href!r}")
            else:
                links.append(f"- href={href!r}")

        # Extract external scripts
        scripts: List[str] = []
        for script in soup.find_all("script", src=True):
            src = script["src"]
            scripts.append(f"- src={src!r}")

        # Extract inline scripts (preview only — use javascript_source for full code)
        inline_scripts: List[str] = []
        for idx, script in enumerate(soup.find_all("script"), start=1):
            if script.get("src"):
                continue  # already captured above
            js_code = (script.string or script.get_text() or "").strip()
            if not js_code:
                continue
            preview = js_code[:200].replace("\n", " ").strip()
            if len(js_code) > 200:
                preview += " ...[truncated]"
            inline_scripts.append(
                f"- [INLINE #{idx}] ({len(js_code)} chars): {preview}"
            )

        # Extract stylesheets
        stylesheets: List[str] = []
        for link in soup.find_all("link", rel=True, href=True):
            rel = " ".join(link.get("rel", []))
            if "stylesheet" in rel.lower():
                href = link["href"]
                stylesheets.append(f"- rel={rel!r}, href={href!r}")

        # Extract comments
        comments: List[str] = []
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            c_text = str(comment).strip()
            if len(c_text) > 200:
                c_text = c_text[:200] + " ...[truncated]..."
            comments.append(f"- {c_text!r}")

        def truncate_list(items: List[str], max_n: int) -> List[str]:
            if len(items) <= max_n:
                return items
            return items[:max_n] + [
                f"...[truncated, {len(items) - max_n} more items]..."
            ]

        try:
            max_items_int = int(max_items)
        except Exception:
            max_items_int = 50

        links = truncate_list(links, max_items_int)
        scripts = truncate_list(scripts, max_items_int)
        stylesheets = truncate_list(stylesheets, max_items_int)
        comments = truncate_list(comments, max_items_int)

        summary_parts = [
            "[HtmlInspectorTool] HTML structure summary:",
            "",
        ]
        if url:
            summary_parts.append(f"Source URL: {url}")
            summary_parts.append("")

        summary_parts.append("[LINKS]")
        summary_parts.extend(links or ["- (none found)"])
        summary_parts.append("")

        summary_parts.append("[SCRIPTS - external src]")
        summary_parts.extend(scripts or ["- (none found)"])
        summary_parts.append("")

        inline_scripts = truncate_list(inline_scripts, max_items_int)
        summary_parts.append("[SCRIPTS - inline]")
        if inline_scripts:
            summary_parts.extend(inline_scripts)
            summary_parts.append(
                ">>> Use 'javascript_source' tool to read full inline JavaScript code."
            )
        else:
            summary_parts.append("- (none found)")
        summary_parts.append("")

        summary_parts.append("[STYLESHEETS]")
        summary_parts.extend(stylesheets or ["- (none found)"])
        summary_parts.append("")

        summary_parts.append("[COMMENTS]")
        summary_parts.extend(comments or ["- (none found)"])
        summary_parts.append("")

        # Extract forms
        forms: List[str] = []
        for form in soup.find_all("form"):
            action = form.get("action", "(none)")
            if url and action != "(none)":
                action = urljoin(url, action)
            method = form.get("method", "GET").upper()
            enctype = form.get("enctype", "")
            form_id = form.get("id", "")
            form_desc = f"- action={action!r}, method={method!r}"
            if enctype:
                form_desc += f", enctype={enctype!r}"
            if form_id:
                form_desc += f", id={form_id!r}"

            # Extract inputs within this form
            inputs = []
            for inp in form.find_all(["input", "select", "textarea"]):
                inp_type = inp.get("type", "text")
                inp_name = inp.get("name", "(unnamed)")
                inp_value = inp.get("value", "")
                inp_id = inp.get("id", "")
                inp_desc = f"    * {inp.name}: name={inp_name!r}, type={inp_type!r}"
                if inp_value:
                    inp_desc += f", value={inp_value!r}"
                if inp_id:
                    inp_desc += f", id={inp_id!r}"
                if inp_type == "hidden":
                    inp_desc += " [HIDDEN]"
                inputs.append(inp_desc)

            forms.append(form_desc)
            forms.extend(inputs)

        forms = truncate_list(forms, max_items_int * 2)  # More items for forms

        summary_parts.append("[FORMS]")
        summary_parts.extend(forms or ["- (none found)"])
        summary_parts.append("")

        # Extract meta tags
        meta_tags: List[str] = []
        for meta in soup.find_all("meta"):
            attrs = dict(meta.attrs)
            parts_list = []
            for k, v in attrs.items():
                if isinstance(v, list):
                    v = " ".join(v)
                parts_list.append(f"{k}={v!r}")
            if parts_list:
                meta_tags.append(f"- {', '.join(parts_list)}")

        meta_tags = truncate_list(meta_tags, max_items_int)

        summary_parts.append("[META TAGS]")
        summary_parts.extend(meta_tags or ["- (none found)"])
        summary_parts.append("")

        # Extract all hidden inputs (including those outside forms)
        hidden_inputs: List[str] = []
        for inp in soup.find_all("input", attrs={"type": "hidden"}):
            name = inp.get("name", "(unnamed)")
            value = inp.get("value", "")
            hidden_inputs.append(f"- name={name!r}, value={value!r}")

        hidden_inputs = truncate_list(hidden_inputs, max_items_int)

        summary_parts.append("[HIDDEN INPUTS]")
        summary_parts.extend(hidden_inputs or ["- (none found)"])
        summary_parts.append("")

        return "\n".join(summary_parts)


class JavaScriptSourceTool:
    """
    JavaScriptSourceTool: extract and (optionally) pretty-print JS from a page.

    Inputs (JSON via `.use`):

        {
          "url": "https://example.com/page",   # optional
          "html": "<html>...</html>",          # optional
          "base_url": "https://example.com",   # optional, for resolving relative src
          "max_scripts": 20,                   # optional
          "max_chars_per_script": 4000         # optional
        }

    Behavior:
      - If 'html' is provided, parse that directly.
      - Else if 'url' is provided, fetch the HTML using the shared session.
      - Parse HTML, locate <script> tags.
      - For each script:
          * If it has a 'src', resolve it against base_url or page URL and fetch JS.
          * If inline, capture its text content.
      - If jsbeautifier is available, pretty-print each script.
      - Return a readable text summary with sections like:
          [INLINE SCRIPT #1]
          ...
          [EXTERNAL SCRIPT: https://example.com/static/app.js]
          ...
    """

    name: str = "javascript_source"
    description: str = (
        "Extract JavaScript code from an HTML page. Input JSON keys: 'url' "
        "(optional), 'html' (optional), 'base_url' (optional), 'max_scripts' "
        "(optional int), and 'max_chars_per_script' (optional int). If 'url' is "
        "provided, fetches the page. Then parses <script> tags: for each tag, "
        "either fetches external JS from 'src' or captures inline JS. Returns a "
        "readable summary labeling each script block. Use this tool to analyze "
        "client-side validation, password checks, or hidden logic in JavaScript."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "html": {"type": "string"},
            "base_url": {
                "type": "string",
                "description": "Resolves relative <script src=…> URLs",
            },
            "max_scripts": {"type": "integer", "default": 20},
            "max_chars_per_script": {"type": "integer", "default": 5000},
        },
        "additionalProperties": False,
    }
    samples = [{"url": "http://example.com/", "base_url": "http://example.com"}]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _fetch_html(self, url: str) -> str:
        try:
            resp = self.session.get(url, timeout=10)
        except Exception as exc:
            return f"[JavaScriptSourceTool] Error fetching URL {url!r}: {exc!r}"
        return resp.text or ""

    def _beautify_js(self, code: str) -> str:
        if HAS_JSBEAUTIFIER:
            try:
                return jsbeautifier.beautify(code)  # type: ignore
            except Exception:
                return code
        return code

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "JavaScriptSourceTool")
        if err:
            return err
        url = data.get("url")
        html = data.get("html")
        base_url = data.get("base_url")
        max_scripts = data.get("max_scripts", 20)
        max_chars_per_script = data.get("max_chars_per_script", 4000)

        if url and not isinstance(url, str):
            return "[JavaScriptSourceTool] Error: 'url' must be a string if provided."
        if html and not isinstance(html, str):
            return "[JavaScriptSourceTool] Error: 'html' must be a string if provided."
        if base_url and not isinstance(base_url, str):
            return (
                "[JavaScriptSourceTool] Error: 'base_url' must be a string if provided."
            )

        if not html and not url:
            return (
                "[JavaScriptSourceTool] Error: You must provide either 'url' or "
                "'html' in the JSON input."
            )

        if not html and url:
            html = self._fetch_html(url)
        page_url = url

        if html.startswith("[JavaScriptSourceTool] Error"):
            return html

        try:
            max_scripts_int = int(max_scripts)
        except Exception:
            max_scripts_int = 20

        try:
            max_chars_int = int(max_chars_per_script)
        except Exception:
            max_chars_int = 4000

        soup = BeautifulSoup(html, "html.parser")
        script_tags = soup.find_all("script")

        blocks: List[str] = ["[JavaScriptSourceTool] Extracted JavaScript code:"]
        if url:
            blocks.append(f"Source page URL: {url}")
        if base_url:
            blocks.append(f"Base URL for resolving src: {base_url}")
        blocks.append("")

        count = 0
        for idx, script in enumerate(script_tags, start=1):
            if count >= max_scripts_int:
                blocks.append(
                    f"...[truncated: more than {max_scripts_int} <script> tags found]"
                )
                break

            src = script.get("src")
            if src:
                # External script
                if base_url:
                    full_src = urljoin(base_url, src)
                elif page_url:
                    full_src = urljoin(page_url, src)
                else:
                    full_src = src

                blocks.append(f"[EXTERNAL SCRIPT #{idx}: {full_src}]")

                try:
                    resp = self.session.get(full_src, timeout=10)
                    js_code = resp.text or ""
                except Exception as exc:
                    blocks.append(
                        f"Error fetching external script {full_src!r}: {exc!r}\n"
                    )
                    count += 1
                    continue

                js_code = self._beautify_js(js_code)

                if max_chars_int > 0 and len(js_code) > max_chars_int:
                    js_code = js_code[:max_chars_int] + "\n...[truncated]..."

                blocks.append(js_code)
                blocks.append("")  # blank line
            else:
                # Inline script
                js_code = script.string or script.get_text() or ""
                js_code = js_code.strip()
                if not js_code:
                    continue

                blocks.append(f"[INLINE SCRIPT #{idx}]")

                js_code = self._beautify_js(js_code)

                if max_chars_int > 0 and len(js_code) > max_chars_int:
                    js_code = js_code[:max_chars_int] + "\n...[truncated]..."

                blocks.append(js_code)
                blocks.append("")

            count += 1

        if count == 0:
            blocks.append("- (no <script> tags with content or src found)")

        return "\n".join(blocks)
