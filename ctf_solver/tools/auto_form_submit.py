"""
Auto-form-submit tool (v3.8 P2).

Models — especially 26B local — frequently misconstruct ``form_submit``
inputs: they drop CSRF/hidden fields, miss the right HTTP method, mis-
resolve the action URL.  ``AutoFormSubmitTool`` does the boilerplate:
fetches the page, parses forms with BeautifulSoup, picks one by index or
by id/action substring, fills hidden inputs from the page, applies
caller-supplied overrides, and forwards to ``FormSubmitTool``.

The model only has to say "submit form 0 of <url> with username=admin
password=admin" — the tool handles the rest.

The tool is registered alongside ``form_submit``, not in place of it; the
model can still hand-craft a request when needed.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from ctf_solver.tools.core import parse_json_input
from ctf_solver.tools.http_tools import FormSubmitTool


class AutoFormSubmitTool:
    """Fetch a page, locate a form, fill it, submit it.

    Inputs (JSON):

      - ``url`` (required): page containing the form to submit.
      - ``form_index`` (optional int, default 0): which form on the page.
      - ``form_match`` (optional string): substring match on a form's
        ``id`` or ``action``; takes precedence over ``form_index``.
      - ``overrides`` (optional dict): values to set on input fields.
        Hidden fields are preserved automatically; explicit overrides
        win over the page defaults.
      - ``extra_headers`` (optional dict).
      - ``max_body`` (optional int, forwarded to ``form_submit``).
      - ``dry_run`` (optional bool): if True, return the resolved
        FormSubmitTool input JSON without submitting. Useful for the
        model to inspect what it's about to send.
    """

    name: str = "auto_form_submit"
    description: str = (
        "Fetch a page, locate a form, fill in hidden/default fields, apply "
        "overrides, and submit it. Input JSON keys: 'url' (string, required), "
        "'form_index' (optional int, default 0), 'form_match' (optional "
        "substring matched against form id/action; wins over form_index), "
        "'overrides' (optional dict of field_name → value), 'extra_headers' "
        "(optional dict), 'max_body' (optional int), 'dry_run' (optional bool, "
        "True returns the resolved request without submitting). Use this "
        "instead of 'form_submit' when you've inspected a page and just want "
        "to send the form with sensible defaults."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "form_index": {"type": "integer", "default": 0},
            "form_match": {"type": "string"},
            "overrides": {"type": "object"},
            "extra_headers": {"type": "object"},
            "max_body": {"type": "integer", "default": 4000},
            "dry_run": {"type": "boolean", "default": False},
        },
        "required": ["url"],
        "additionalProperties": False,
    }
    samples = [
        {
            "url": "http://example.com/login",
            "overrides": {"username": "admin", "password": "admin"},
        },
        {
            "url": "http://example.com/page",
            "form_match": "csrf",
            "overrides": {"comment": "test"},
        },
        {
            "url": "http://example.com/page",
            "form_index": 1,
            "dry_run": True,
        },
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()
        self._submitter = FormSubmitTool(session=self.session)

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "AutoFormSubmitTool")
        if err:
            return err
        url = data.get("url")
        if not isinstance(url, str) or not url:
            return "[AutoFormSubmitTool] Error: 'url' (string) is required."

        try:
            resp = self.session.get(url, timeout=10)
        except Exception as exc:
            return (
                f"[AutoFormSubmitTool] Error fetching {url!r}: {exc!r}. "
                "Cannot inspect form."
            )

        soup = BeautifulSoup(resp.text or "", "html.parser")
        forms = soup.find_all("form")
        if not forms:
            return f"[AutoFormSubmitTool] No <form> elements found at {url!r}."

        form_match = data.get("form_match")
        form_index = data.get("form_index", 0)
        try:
            form_index = int(form_index)
        except (TypeError, ValueError):
            return "[AutoFormSubmitTool] Error: 'form_index' must be an integer."

        target = None
        if isinstance(form_match, str) and form_match:
            for f in forms:
                form_id = f.get("id", "") or ""
                action = f.get("action", "") or ""
                if form_match in form_id or form_match in action:
                    target = f
                    break
            if target is None:
                return (
                    f"[AutoFormSubmitTool] No form matched 'form_match'="
                    f"{form_match!r} (id/action). {len(forms)} form(s) "
                    "available; try a different substring or use 'form_index'."
                )
        else:
            if form_index < 0 or form_index >= len(forms):
                return (
                    f"[AutoFormSubmitTool] form_index={form_index} out of "
                    f"range; page has {len(forms)} form(s)."
                )
            target = forms[form_index]

        action = target.get("action") or url
        action = urljoin(url, action)
        method = (target.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "POST"
        enctype = (target.get("enctype") or "").lower()

        # Collect default field values from the form.
        fields: Dict[str, Any] = {}
        for inp in target.find_all(["input", "select", "textarea"]):
            name = inp.get("name")
            if not name:
                continue
            if inp.name == "select":
                # First selected <option>, else first option.
                opts = inp.find_all("option")
                chosen = ""
                for opt in opts:
                    if opt.has_attr("selected"):
                        chosen = opt.get("value", opt.get_text() or "")
                        break
                else:
                    if opts:
                        chosen = opts[0].get("value", opts[0].get_text() or "")
                fields[name] = chosen
                continue
            if inp.name == "textarea":
                fields[name] = inp.get_text() or ""
                continue
            inp_type = (inp.get("type") or "text").lower()
            if inp_type in ("submit", "button", "image", "reset"):
                # Skip — submit buttons don't need to be in the form data
                # unless explicitly overridden. Including them by default
                # would force the model to know the right button name.
                continue
            if inp_type in ("checkbox", "radio"):
                if inp.has_attr("checked"):
                    fields[name] = inp.get("value", "on")
                else:
                    # Leave unset — only checked controls submit a value.
                    continue
            else:
                fields[name] = inp.get("value", "")

        overrides = data.get("overrides") or {}
        if not isinstance(overrides, dict):
            return "[AutoFormSubmitTool] Error: 'overrides' must be an object."
        for k, v in overrides.items():
            fields[str(k)] = v

        extra_headers = data.get("extra_headers") or {}
        if not isinstance(extra_headers, dict):
            return "[AutoFormSubmitTool] Error: 'extra_headers' must be an object."
        max_body = data.get("max_body", 4000)
        dry_run = bool(data.get("dry_run", False))

        # Build FormSubmitTool input.
        sub_input: Dict[str, Any] = {
            "url": action,
            "method": method,
            "data": fields,
            "max_body": max_body,
        }
        if extra_headers:
            sub_input["headers"] = extra_headers
        if "multipart" in enctype:
            sub_input["multipart"] = True

        if dry_run:
            preview = {
                "[AutoFormSubmitTool] dry_run": True,
                "form_index": form_index,
                "form_match": form_match,
                "resolved_request": sub_input,
            }
            return json.dumps(preview, indent=2)

        # Forward to FormSubmitTool.
        return self._submitter.use(json.dumps(sub_input))
