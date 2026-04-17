"""
Tests for CookieSetTool delete feature and HtmlInspectorTool enhancements.

Covers:
- CookieSetTool: delete existing cookie, delete nonexistent cookie, validation
- HtmlInspectorTool: forms extraction, hidden inputs, meta tags, select/textarea,
  form attributes, empty forms
"""

import json
import pytest
import requests

from ctf_solver.tools.web_tools import CookieSetTool
from ctf_solver.tools.html_tools import HtmlInspectorTool

# ==============================================================================
# CookieSetTool delete tests
# ==============================================================================


class TestCookieSetToolDelete:
    """Tests for the CookieSetTool delete feature."""

    def setup_method(self):
        self.session = requests.Session()
        self.tool = CookieSetTool(session=self.session)

    def test_delete_existing_cookie(self):
        """Set a cookie, then delete it with delete=true, verify it's removed."""
        # First, set a cookie
        result = self.tool.use(
            json.dumps(
                {
                    "domain": "example.com",
                    "name": "session_id",
                    "value": "abc123",
                    "path": "/",
                }
            )
        )
        assert "Set cookie" in result
        assert (
            self.session.cookies.get("session_id", domain="example.com", path="/")
            == "abc123"
        )

        # Now delete it
        result = self.tool.use(
            json.dumps(
                {
                    "domain": "example.com",
                    "name": "session_id",
                    "path": "/",
                    "delete": True,
                }
            )
        )
        assert "Deleted cookie" in result
        assert "session_id" in result
        assert (
            self.session.cookies.get("session_id", domain="example.com", path="/")
            is None
        )

    def test_delete_nonexistent_cookie(self):
        """Try deleting a cookie that doesn't exist; should return 'not found' message."""
        result = self.tool.use(
            json.dumps(
                {
                    "domain": "example.com",
                    "name": "no_such_cookie",
                    "path": "/",
                    "delete": True,
                }
            )
        )
        assert "not found" in result.lower()

    def test_delete_requires_domain(self):
        """Missing domain returns error."""
        result = self.tool.use(
            json.dumps(
                {
                    "name": "session_id",
                    "delete": True,
                }
            )
        )
        assert "Error" in result
        assert "domain" in result.lower()

    def test_delete_requires_name(self):
        """Missing name returns error."""
        result = self.tool.use(
            json.dumps(
                {
                    "domain": "example.com",
                    "delete": True,
                }
            )
        )
        assert "Error" in result
        assert "name" in result.lower()

    def test_delete_ignores_value(self):
        """Value can be missing when delete=true; the delete still works."""
        # Set a cookie first
        self.tool.use(
            json.dumps(
                {
                    "domain": "example.com",
                    "name": "token",
                    "value": "xyz",
                    "path": "/",
                }
            )
        )
        assert (
            self.session.cookies.get("token", domain="example.com", path="/") == "xyz"
        )

        # Delete without providing value
        result = self.tool.use(
            json.dumps(
                {
                    "domain": "example.com",
                    "name": "token",
                    "path": "/",
                    "delete": True,
                }
            )
        )
        assert "Deleted cookie" in result
        assert self.session.cookies.get("token", domain="example.com", path="/") is None

    def test_set_still_requires_value(self):
        """Without delete flag, value is still required for set operation."""
        result = self.tool.use(
            json.dumps(
                {
                    "domain": "example.com",
                    "name": "admin",
                }
            )
        )
        assert "Error" in result
        assert "value" in result.lower()


# ==============================================================================
# HtmlInspectorTool enhancement tests
# ==============================================================================


class TestHtmlInspectorEnhancements:
    """Tests for HtmlInspectorTool enhancements (forms, meta tags, hidden inputs)."""

    def setup_method(self):
        self.tool = HtmlInspectorTool()

    def test_forms_extraction(self):
        """HTML with a form containing inputs; verify [FORMS] section appears."""
        html = """
        <html>
        <body>
            <form action="/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <input type="submit" value="Login" />
            </form>
        </body>
        </html>
        """
        result = self.tool.use(json.dumps({"html": html}))
        assert "[FORMS]" in result
        assert "action='/login'" in result
        assert "method='POST'" in result
        assert "name='username'" in result
        assert "name='password'" in result

    def test_form_hidden_inputs_marked(self):
        """Hidden inputs within forms are marked with [HIDDEN]."""
        html = """
        <html>
        <body>
            <form action="/submit" method="POST">
                <input type="hidden" name="csrf_token" value="abc123" />
                <input type="text" name="query" />
            </form>
        </body>
        </html>
        """
        result = self.tool.use(json.dumps({"html": html}))
        assert "[FORMS]" in result
        assert "[HIDDEN]" in result
        assert "name='csrf_token'" in result

    def test_meta_tags_extraction(self):
        """HTML with meta tags; verify [META TAGS] section."""
        html = """
        <html>
        <head>
            <meta charset="utf-8" />
            <meta name="description" content="A test page" />
            <meta name="author" content="Test Author" />
        </head>
        <body></body>
        </html>
        """
        result = self.tool.use(json.dumps({"html": html}))
        assert "[META TAGS]" in result
        assert "charset='utf-8'" in result
        assert "name='description'" in result
        assert "content='A test page'" in result
        assert "name='author'" in result

    def test_hidden_inputs_section(self):
        """Hidden inputs outside forms appear in [HIDDEN INPUTS] section."""
        html = """
        <html>
        <body>
            <input type="hidden" name="secret_flag" value="FLAG{hidden}" />
            <input type="hidden" name="api_key" value="key123" />
            <p>Some text</p>
        </body>
        </html>
        """
        result = self.tool.use(json.dumps({"html": html}))
        assert "[HIDDEN INPUTS]" in result
        assert "name='secret_flag'" in result
        assert "value='FLAG{hidden}'" in result
        assert "name='api_key'" in result
        assert "value='key123'" in result

    def test_form_with_select_and_textarea(self):
        """Forms with select and textarea elements are extracted."""
        html = """
        <html>
        <body>
            <form action="/feedback" method="POST">
                <select name="rating">
                    <option value="1">1</option>
                    <option value="5">5</option>
                </select>
                <textarea name="comments"></textarea>
                <input type="submit" value="Send" />
            </form>
        </body>
        </html>
        """
        result = self.tool.use(json.dumps({"html": html}))
        assert "[FORMS]" in result
        assert "action='/feedback'" in result
        assert "name='rating'" in result
        assert "select:" in result
        assert "name='comments'" in result
        assert "textarea:" in result

    def test_form_enctype_and_id(self):
        """Form attributes like enctype and id are extracted."""
        html = """
        <html>
        <body>
            <form action="/upload" method="POST" enctype="multipart/form-data" id="upload-form">
                <input type="file" name="document" />
                <input type="submit" value="Upload" />
            </form>
        </body>
        </html>
        """
        result = self.tool.use(json.dumps({"html": html}))
        assert "[FORMS]" in result
        assert "enctype='multipart/form-data'" in result
        assert "id='upload-form'" in result
        assert "action='/upload'" in result

    def test_empty_forms(self):
        """HTML with no forms shows '(none found)'."""
        html = """
        <html>
        <body>
            <h1>No forms here</h1>
            <p>Just text.</p>
        </body>
        </html>
        """
        result = self.tool.use(json.dumps({"html": html}))
        assert "[FORMS]" in result
        assert "(none found)" in result
