"""
v3.8 P2: AutoFormSubmitTool tests.

The tool fetches a page, finds a form (by index or substring match),
fills hidden/default inputs, applies overrides, and forwards to
``FormSubmitTool``.  These tests verify the form-extraction logic with
mocked HTTP — no real network.
"""

import json
from unittest.mock import MagicMock

from ctf_solver.tools.auto_form_submit import AutoFormSubmitTool


def _make_tool_with_html(html: str) -> AutoFormSubmitTool:
    tool = AutoFormSubmitTool()
    fake_resp = MagicMock()
    fake_resp.text = html
    fake_session = MagicMock()
    fake_session.get = MagicMock(return_value=fake_resp)
    tool.session = fake_session
    return tool


class TestSchema:
    def test_name_and_required(self):
        tool = AutoFormSubmitTool()
        assert tool.name == "auto_form_submit"
        ps = tool.parameters_schema
        assert "url" in ps["required"]


class TestErrorHandling:
    def test_missing_url(self):
        tool = AutoFormSubmitTool()
        out = tool.use(json.dumps({}))
        assert "Error" in out
        assert "url" in out

    def test_invalid_json(self):
        tool = AutoFormSubmitTool()
        out = tool.use("not json")
        assert "tool_input must be JSON" in out

    def test_no_forms(self):
        tool = _make_tool_with_html("<html><body><p>nothing here</p></body></html>")
        out = tool.use(json.dumps({"url": "http://example.com/"}))
        assert "No <form>" in out

    def test_form_index_out_of_range(self):
        tool = _make_tool_with_html(
            '<html><body><form action="/a"><input name="x"></form></body></html>'
        )
        out = tool.use(json.dumps({"url": "http://example.com/", "form_index": 5}))
        assert "out of range" in out

    def test_form_match_no_match(self):
        tool = _make_tool_with_html(
            '<html><body><form id="login" action="/a"></form></body></html>'
        )
        out = tool.use(
            json.dumps({"url": "http://example.com/", "form_match": "register"})
        )
        assert "No form matched" in out

    def test_overrides_must_be_object(self):
        tool = _make_tool_with_html(
            '<html><body><form action="/a"></form></body></html>'
        )
        out = tool.use(
            json.dumps(
                {
                    "url": "http://example.com/",
                    "overrides": "not-a-dict",
                    "dry_run": True,
                }
            )
        )
        assert "Error" in out
        assert "overrides" in out


class TestDryRun:
    """The model often wants to *see* what it's about to submit before
    actually sending. ``dry_run=True`` returns the resolved payload."""

    def test_basic_form_default_values(self):
        html = """
        <html><body>
          <form action="/login" method="POST">
            <input name="csrf" type="hidden" value="abc123">
            <input name="username" type="text" value="">
            <input name="password" type="password" value="">
            <button type="submit">go</button>
          </form>
        </body></html>
        """
        tool = _make_tool_with_html(html)
        out = tool.use(
            json.dumps(
                {
                    "url": "http://example.com/login",
                    "overrides": {"username": "admin", "password": "admin"},
                    "dry_run": True,
                }
            )
        )
        payload = json.loads(out)
        req = payload["resolved_request"]
        assert req["method"] == "POST"
        assert req["url"] == "http://example.com/login"
        assert req["data"]["csrf"] == "abc123"  # hidden preserved
        assert req["data"]["username"] == "admin"  # override won
        assert req["data"]["password"] == "admin"

    def test_action_resolved_relative_to_page_url(self):
        html = """
        <html><body><form action="login" method="POST"></form></body></html>
        """
        tool = _make_tool_with_html(html)
        out = tool.use(json.dumps({"url": "http://example.com/auth/", "dry_run": True}))
        payload = json.loads(out)
        assert payload["resolved_request"]["url"] == "http://example.com/auth/login"

    def test_form_match_picks_form_by_id(self):
        html = """
        <html><body>
          <form id="search" action="/q"><input name="q" value=""></form>
          <form id="login" action="/login" method="POST">
            <input name="username" value="default">
          </form>
        </body></html>
        """
        tool = _make_tool_with_html(html)
        out = tool.use(
            json.dumps(
                {
                    "url": "http://example.com/",
                    "form_match": "login",
                    "dry_run": True,
                }
            )
        )
        payload = json.loads(out)
        req = payload["resolved_request"]
        assert req["url"] == "http://example.com/login"
        assert req["method"] == "POST"
        assert "username" in req["data"]

    def test_skips_submit_buttons(self):
        html = """
        <html><body><form action="/x" method="POST">
          <input name="real" value="yes">
          <input type="submit" name="btn" value="Send">
        </form></body></html>
        """
        tool = _make_tool_with_html(html)
        out = tool.use(json.dumps({"url": "http://example.com/", "dry_run": True}))
        payload = json.loads(out)
        # Real field captured, submit button skipped (model can override
        # if it actually needs that name).
        assert "real" in payload["resolved_request"]["data"]
        assert "btn" not in payload["resolved_request"]["data"]

    def test_select_uses_selected_option(self):
        html = """
        <html><body><form action="/x" method="POST">
          <select name="role">
            <option value="user">user</option>
            <option value="admin" selected>admin</option>
          </select>
        </form></body></html>
        """
        tool = _make_tool_with_html(html)
        out = tool.use(json.dumps({"url": "http://example.com/", "dry_run": True}))
        payload = json.loads(out)
        assert payload["resolved_request"]["data"]["role"] == "admin"

    def test_textarea_default_text(self):
        html = """
        <html><body><form action="/x" method="POST">
          <textarea name="comment">hello world</textarea>
        </form></body></html>
        """
        tool = _make_tool_with_html(html)
        out = tool.use(json.dumps({"url": "http://example.com/", "dry_run": True}))
        payload = json.loads(out)
        assert payload["resolved_request"]["data"]["comment"] == "hello world"

    def test_unchecked_checkbox_omitted(self):
        html = """
        <html><body><form action="/x" method="POST">
          <input type="checkbox" name="agree" value="yes">
          <input type="checkbox" name="news" value="yes" checked>
        </form></body></html>
        """
        tool = _make_tool_with_html(html)
        out = tool.use(json.dumps({"url": "http://example.com/", "dry_run": True}))
        payload = json.loads(out)
        data = payload["resolved_request"]["data"]
        assert "agree" not in data
        assert data["news"] == "yes"

    def test_multipart_enctype_propagated(self):
        html = """
        <html><body><form action="/upload" method="POST"
                          enctype="multipart/form-data">
          <input name="file" type="file">
        </form></body></html>
        """
        tool = _make_tool_with_html(html)
        out = tool.use(json.dumps({"url": "http://example.com/", "dry_run": True}))
        payload = json.loads(out)
        assert payload["resolved_request"]["multipart"] is True


class TestForwardsToFormSubmit:
    def test_non_dry_run_calls_submitter(self):
        html = """
        <html><body><form action="/login" method="POST">
          <input name="user" value="">
        </form></body></html>
        """
        tool = _make_tool_with_html(html)
        tool._submitter = MagicMock()
        tool._submitter.use.return_value = "[FormSubmitTool] Status: 200..."
        out = tool.use(
            json.dumps(
                {
                    "url": "http://example.com/",
                    "overrides": {"user": "admin"},
                }
            )
        )
        assert "[FormSubmitTool]" in out
        forwarded = json.loads(tool._submitter.use.call_args[0][0])
        assert forwarded["url"] == "http://example.com/login"
        assert forwarded["method"] == "POST"
        assert forwarded["data"]["user"] == "admin"
