"""
Tests for file upload testing tools.
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock

from ctf_solver.tools.upload_tools import FileUploadTool, UploadLocationFinder


class TestFileUploadToolBasics:
    """Test basic FileUploadTool functionality."""

    def test_has_required_attributes(self):
        """Test that FileUploadTool has name and description."""
        tool = FileUploadTool()
        assert hasattr(tool, "name")
        assert hasattr(tool, "description")
        assert tool.name == "file_upload"
        assert "upload" in tool.description.lower()

    def test_invalid_json_input(self):
        """Test handling of invalid JSON."""
        tool = FileUploadTool()
        result = tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_operation(self):
        """Test that operation is required."""
        tool = FileUploadTool()
        result = tool.use(json.dumps({"url": "http://test.com"}))
        assert "Error" in result
        assert "operation" in result.lower()

    def test_invalid_operation(self):
        """Test handling of unknown operation."""
        tool = FileUploadTool()
        result = tool.use(json.dumps({"operation": "invalid_op"}))
        assert "Error" in result
        assert "Unknown operation" in result

    def test_accepts_session(self):
        """Test that tool accepts a requests session."""
        mock_session = Mock()
        tool = FileUploadTool(session=mock_session)
        assert tool.session == mock_session


class TestFileUploadExtensionBypass:
    """Test extension bypass functionality."""

    def test_test_extensions_missing_url(self):
        """Test that url is required for test_extensions."""
        tool = FileUploadTool()
        result = tool.use(json.dumps({"operation": "test_extensions"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_test_extensions_default_language(self):
        """Test extension testing with default PHP language."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "File uploaded successfully"
        mock_response.content = b"success"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_extensions",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        assert "Extension Bypass Test" in result
        # Should have tested multiple extensions
        assert mock_session.post.call_count > 1

    def test_test_extensions_detects_success(self):
        """Test that successful uploads are detected."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "File uploaded successfully"
        mock_response.content = b"success"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_extensions",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                    "language": "php",
                }
            )
        )

        assert "SUCCESS" in result

    def test_test_extensions_detects_failure(self):
        """Test that failed uploads are detected."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "File type not allowed"
        mock_response.content = b"error"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_extensions",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        # Should report failures or no successes
        assert "Extension Bypass Test" in result


class TestFileUploadMimeBypass:
    """Test MIME type bypass functionality."""

    def test_test_mime_requires_url(self):
        """Test that url is required for test_mime."""
        tool = FileUploadTool()
        result = tool.use(json.dumps({"operation": "test_mime"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_test_mime_tests_multiple_types(self):
        """Test that multiple MIME types are tested."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "success"
        mock_response.content = b"success"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_mime",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        assert "MIME Type Bypass Test" in result
        # Should test image MIME types
        assert mock_session.post.call_count >= 1


class TestFileUploadContentGeneration:
    """Test content generation functionality."""

    def test_test_content_default_values(self):
        """Test content generation with default values."""
        tool = FileUploadTool()
        result = tool.use(json.dumps({"operation": "test_content"}))

        assert "Test Content Generator" in result
        assert "GIF" in result.upper() or "gif" in result
        assert "php" in result.lower()

    def test_test_content_custom_magic(self):
        """Test content generation with custom magic bytes."""
        tool = FileUploadTool()
        result = tool.use(
            json.dumps({"operation": "test_content", "magic": "png", "language": "php"})
        )

        assert "png" in result.lower()
        assert "php" in result.lower()

    def test_test_content_generates_hex(self):
        """Test that hex representation is generated."""
        tool = FileUploadTool()
        result = tool.use(
            json.dumps({"operation": "test_content", "magic": "gif", "language": "php"})
        )

        assert "hex" in result.lower()
        # GIF magic bytes start with 474946 (GIF)
        assert "474946" in result


class TestFileUploadWebshellGeneration:
    """Test webshell generation functionality."""

    def test_generate_webshell_default(self):
        """Test webshell generation with defaults."""
        tool = FileUploadTool()
        result = tool.use(json.dumps({"operation": "generate_webshell"}))

        assert "Webshell Generator" in result
        assert "php" in result.lower()
        assert "system" in result or "shell_exec" in result

    def test_generate_webshell_php(self):
        """Test PHP webshell generation."""
        tool = FileUploadTool()
        result = tool.use(
            json.dumps({"operation": "generate_webshell", "language": "php"})
        )

        assert "<?php" in result
        assert "system" in result or "exec" in result

    def test_generate_webshell_asp(self):
        """Test ASP webshell generation."""
        tool = FileUploadTool()
        result = tool.use(
            json.dumps({"operation": "generate_webshell", "language": "asp"})
        )

        assert "<%eval" in result.lower() or "<%execute" in result.lower()

    def test_generate_webshell_jsp(self):
        """Test JSP webshell generation."""
        tool = FileUploadTool()
        result = tool.use(
            json.dumps({"operation": "generate_webshell", "language": "jsp"})
        )

        assert "Runtime" in result
        assert "getRuntime" in result

    def test_generate_webshell_unknown_language(self):
        """Test handling of unknown language."""
        tool = FileUploadTool()
        result = tool.use(
            json.dumps({"operation": "generate_webshell", "language": "unknown_lang"})
        )

        assert "Error" in result
        assert "Unknown language" in result

    def test_generate_webshell_custom_command(self):
        """Test webshell with custom command parameter."""
        tool = FileUploadTool()
        result = tool.use(
            json.dumps(
                {"operation": "generate_webshell", "language": "php", "command": "x"}
            )
        )

        assert "x" in result

    def test_generate_webshell_includes_polyglot(self):
        """Test that polyglot examples are included."""
        tool = FileUploadTool()
        result = tool.use(
            json.dumps({"operation": "generate_webshell", "language": "php"})
        )

        assert "Polyglot" in result or "GIF89a" in result


class TestFileUploadFullTest:
    """Test comprehensive upload testing."""

    def test_full_test_requires_url(self):
        """Test that url is required for full_test."""
        tool = FileUploadTool()
        result = tool.use(json.dumps({"operation": "full_test"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_full_test_runs_multiple_phases(self):
        """Test that full_test runs multiple test phases."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "success"
        mock_response.content = b"success"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "full_test",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        assert "Phase 1" in result
        assert "Phase 2" in result
        assert "Phase 3" in result
        assert "SUMMARY" in result

    def test_full_test_provides_next_steps(self):
        """Test that next steps are provided."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "uploaded"
        mock_response.content = b"success"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "full_test",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        assert "Next Steps" in result or "Successful" in result


class TestUploadLocationFinderBasics:
    """Test basic UploadLocationFinder functionality."""

    def test_has_required_attributes(self):
        """Test that UploadLocationFinder has name and description."""
        tool = UploadLocationFinder()
        assert hasattr(tool, "name")
        assert hasattr(tool, "description")
        assert tool.name == "upload_location_finder"

    def test_invalid_json_input(self):
        """Test handling of invalid JSON."""
        tool = UploadLocationFinder()
        result = tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_base_url(self):
        """Test that base_url is required."""
        tool = UploadLocationFinder()
        result = tool.use(json.dumps({"filename": "shell.php"}))
        assert "Error" in result
        assert "base_url" in result.lower()

    def test_missing_filename(self):
        """Test that filename is required."""
        tool = UploadLocationFinder()
        result = tool.use(json.dumps({"base_url": "http://test.com"}))
        assert "Error" in result
        assert "filename" in result.lower()


class TestUploadLocationFinderSearch:
    """Test file location search functionality."""

    def test_finds_file_in_common_path(self):
        """Test finding file in common upload path."""
        mock_session = Mock()

        def mock_head(url, **kwargs):
            resp = Mock()
            if "/uploads/shell.php" in url:
                resp.status_code = 200
            else:
                resp.status_code = 404
            return resp

        mock_session.head.side_effect = mock_head

        tool = UploadLocationFinder(session=mock_session)
        result = tool.use(
            json.dumps({"base_url": "http://test.com", "filename": "shell.php"})
        )

        assert "FOUND" in result
        assert "/uploads/shell.php" in result

    def test_no_file_found(self):
        """Test when file is not found."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.head.return_value = mock_response

        tool = UploadLocationFinder(session=mock_session)
        result = tool.use(
            json.dumps({"base_url": "http://test.com", "filename": "shell.php"})
        )

        assert "not found" in result.lower() or "Suggestions" in result

    def test_handles_redirects(self):
        """Test handling of redirects."""
        mock_session = Mock()

        def mock_head(url, **kwargs):
            resp = Mock()
            if "/uploads/" in url:
                resp.status_code = 302
                resp.headers = {"Location": "/login"}
            else:
                resp.status_code = 404
            return resp

        mock_session.head.side_effect = mock_head

        tool = UploadLocationFinder(session=mock_session)
        result = tool.use(
            json.dumps({"base_url": "http://test.com", "filename": "shell.php"})
        )

        assert "Redirect" in result or "not found" in result.lower()

    def test_custom_paths(self):
        """Test searching with custom paths."""
        mock_session = Mock()

        def mock_head(url, **kwargs):
            resp = Mock()
            if "/custom/uploads/" in url:
                resp.status_code = 200
            else:
                resp.status_code = 404
            return resp

        mock_session.head.side_effect = mock_head

        tool = UploadLocationFinder(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "base_url": "http://test.com",
                    "filename": "shell.php",
                    "custom_paths": ["/custom/uploads/"],
                }
            )
        )

        assert "FOUND" in result
        assert "/custom/uploads/" in result


class TestFileUploadToolCTFScenarios:
    """Test realistic CTF scenarios."""

    def test_php_extension_bypass_scenario(self):
        """Test PHP extension bypass scenario."""
        mock_session = Mock()

        def mock_post(url, **kwargs):
            files = kwargs.get("files", {})
            file_tuple = files.get("file", ("", b"", ""))
            filename = file_tuple[0] if file_tuple else ""

            resp = Mock()
            resp.content = b"response"

            if filename.endswith(".php"):
                resp.status_code = 403
                resp.text = "File type not allowed"
            elif filename.endswith(".phtml"):
                resp.status_code = 200
                resp.text = "File uploaded successfully"
            else:
                resp.status_code = 200
                resp.text = "OK"
            return resp

        mock_session.post.side_effect = mock_post

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_extensions",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                    "language": "php",
                }
            )
        )

        # Should detect .phtml as successful
        assert "SUCCESS" in result
        assert ".phtml" in result

    def test_mime_type_bypass_scenario(self):
        """Test MIME type bypass scenario."""
        mock_session = Mock()

        def mock_post(url, **kwargs):
            files = kwargs.get("files", {})
            file_tuple = files.get("file", ("", b"", ""))
            content_type = file_tuple[2] if len(file_tuple) > 2 else ""

            resp = Mock()
            resp.content = b"response"

            if content_type.startswith("image/"):
                resp.status_code = 200
                resp.text = "File uploaded successfully"
            else:
                resp.status_code = 403
                resp.text = "Invalid content type"
            return resp

        mock_session.post.side_effect = mock_post

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_mime",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        assert "SUCCESS" in result
        assert "image/" in result


class TestFileUploadToolEdgeCases:
    """Test edge cases and error handling."""

    def test_network_error(self):
        """Test handling of network errors."""
        mock_session = Mock()
        mock_session.post.side_effect = Exception("Connection refused")

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_extensions",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        assert "Error" in result or "Connection" in result

    def test_empty_response(self):
        """Test handling of empty response."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = ""
        mock_response.content = b""
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_extensions",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        # Should handle gracefully
        assert "Extension Bypass Test" in result


class TestUploadCustomOperation:
    """Test upload_custom operation for exact filename uploads."""

    def test_upload_custom_requires_filename(self):
        """Test that filename is required for upload_custom."""
        tool = FileUploadTool()
        result = tool.use(
            json.dumps(
                {
                    "operation": "upload_custom",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                    "content": "test content",
                }
            )
        )
        assert "Error" in result
        assert "filename" in result.lower()

    def test_upload_custom_with_exact_filename(self):
        """Test uploading with exact filename like .htaccess."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "File uploaded"
        mock_response.content = b"success"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "upload_custom",
                    "url": "http://test.com/upload",
                    "file_param": "image",
                    "filename": ".htaccess",
                    "content": "AddType application/x-httpd-php .jpg",
                }
            )
        )

        # Verify the file was uploaded with exact filename
        call_args = mock_session.post.call_args
        files = call_args.kwargs.get("files") or call_args[1].get("files")
        assert files is not None
        assert "image" in files
        assert files["image"][0] == ".htaccess"
        assert "Custom File Upload" in result

    def test_upload_custom_extracts_path(self):
        """Test that upload path is extracted from response."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"path": "/uploads/shell.jpg", "status": "success"}'
        mock_response.content = b"success"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "upload_custom",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                    "filename": "shell.jpg",
                    "content": "<?php system($_GET['cmd']); ?>",
                }
            )
        )

        assert "Detected upload path" in result or "/uploads/shell.jpg" in result


class TestUploadHtaccessOperation:
    """Test upload_htaccess operation for Apache attacks."""

    def test_upload_htaccess_default(self):
        """Test .htaccess upload with default settings."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "File uploaded"
        mock_response.content = b"success"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "upload_htaccess",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        assert ".htaccess Upload Attack" in result
        assert "SUCCESS" in result or "payload" in result.lower()

    def test_upload_htaccess_exact_filename(self):
        """Test that .htaccess is uploaded with exact filename."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "uploaded"
        mock_response.content = b"ok"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "operation": "upload_htaccess",
                    "url": "http://test.com/upload",
                    "file_param": "image",
                    "target_ext": ".gif",
                }
            )
        )

        # Check that filename is exactly ".htaccess"
        for call in mock_session.post.call_args_list:
            files = call.kwargs.get("files") or call[1].get("files", {})
            if files:
                file_tuple = files.get("image")
                if file_tuple:
                    assert file_tuple[0] == ".htaccess"

    def test_upload_htaccess_custom_extension(self):
        """Test .htaccess upload with custom target extension."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "uploaded"
        mock_response.content = b"ok"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "upload_htaccess",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                    "target_ext": ".png",
                }
            )
        )

        assert ".png" in result


class TestUploadUseriniOperation:
    """Test upload_userini operation for PHP-FPM attacks."""

    def test_upload_userini_default(self):
        """Test .user.ini upload with default settings."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "File uploaded"
        mock_response.content = b"success"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "upload_userini",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        assert ".user.ini Upload Attack" in result
        assert "PHP-FPM" in result

    def test_upload_userini_exact_filename(self):
        """Test that .user.ini is uploaded with exact filename."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "uploaded"
        mock_response.content = b"ok"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "operation": "upload_userini",
                    "url": "http://test.com/upload",
                    "file_param": "image",
                }
            )
        )

        # Check that filename is exactly ".user.ini"
        for call in mock_session.post.call_args_list:
            files = call.kwargs.get("files") or call[1].get("files", {})
            if files:
                file_tuple = files.get("image")
                if file_tuple:
                    assert file_tuple[0] == ".user.ini"

    def test_upload_userini_custom_shell_file(self):
        """Test .user.ini with custom shell filename."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "uploaded"
        mock_response.content = b"ok"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "upload_userini",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                    "shell_file": "backdoor.gif",
                }
            )
        )

        assert "backdoor.gif" in result


class TestTraversalOperation:
    """Test test_traversal operation for path traversal attacks."""

    def test_traversal_basic(self):
        """Test basic path traversal testing."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "File uploaded"
        mock_response.content = b"success"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_traversal",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        assert "Path Traversal Test" in result
        # Should test multiple payloads
        assert mock_session.post.call_count > 5

    def test_traversal_detects_accepted(self):
        """Test that accepted traversal payloads are detected."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "File saved"  # No "traversal" warning
        mock_response.content = b"ok"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_traversal",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        assert "ACCEPTED" in result

    def test_traversal_detects_blocked(self):
        """Test that blocked traversal payloads are detected."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Path traversal detected"
        mock_response.content = b"error"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_traversal",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        assert "BLOCKED" in result


class TestGenerateHtaccessOperation:
    """Test generate_htaccess operation for payload generation."""

    def test_generate_htaccess_default(self):
        """Test .htaccess payload generation with defaults."""
        tool = FileUploadTool()
        result = tool.use(json.dumps({"operation": "generate_htaccess"}))

        assert ".htaccess Payload Generator" in result
        assert "AddType" in result
        assert "SetHandler" in result

    def test_generate_htaccess_custom_extension(self):
        """Test .htaccess generation with custom extension."""
        tool = FileUploadTool()
        result = tool.use(
            json.dumps({"operation": "generate_htaccess", "target_ext": ".gif"})
        )

        assert ".gif" in result
        assert "AddType application/x-httpd-php .gif" in result

    def test_generate_htaccess_includes_userini(self):
        """Test that .user.ini alternative is included."""
        tool = FileUploadTool()
        result = tool.use(json.dumps({"operation": "generate_htaccess"}))

        assert ".user.ini" in result
        assert "auto_prepend_file" in result


class TestExtractUploadPath:
    """Test the _extract_upload_path helper method."""

    def test_extract_json_path(self):
        """Test extracting path from JSON response."""
        tool = FileUploadTool()
        response = '{"path": "/uploads/shell.php", "status": "ok"}'
        result = tool._extract_upload_path(response)
        assert result == "/uploads/shell.php"

    def test_extract_text_path(self):
        """Test extracting path from text response."""
        tool = FileUploadTool()
        response = "File uploaded to: /images/test.jpg successfully"
        result = tool._extract_upload_path(response)
        assert result is not None
        assert ".jpg" in result

    def test_extract_html_path(self):
        """Test extracting path from HTML response."""
        tool = FileUploadTool()
        response = '<img src="/uploads/image.png" alt="uploaded">'
        result = tool._extract_upload_path(response)
        assert result is not None
        assert "/uploads/image.png" in result

    def test_no_path_found(self):
        """Test when no path is found."""
        tool = FileUploadTool()
        response = "Upload complete!"
        result = tool._extract_upload_path(response)
        assert result is None


class TestExtensionPathDiscovery:
    """Test that test_extensions now extracts and displays upload paths and response bodies."""

    def test_test_extensions_shows_first_success_response(self):
        """test_extensions should show the first successful response body."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"status":"ok","path":"/uploads/shell.php"}'
        mock_response.content = mock_response.text.encode()
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_extensions",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        assert "First Successful Response" in result
        assert "/uploads/shell.php" in result

    def test_test_extensions_extracts_paths_from_json_response(self):
        """test_extensions should extract paths from JSON responses."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"path": "/files/shell.php", "message": "uploaded"}'
        mock_response.content = mock_response.text.encode()
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_extensions",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        assert "Discovered Upload Paths" in result
        assert "/files/shell.php" in result

    def test_test_extensions_extracts_paths_from_baseline(self):
        """test_extensions should also extract paths from baseline (.txt) response."""
        call_count = [0]
        mock_session = Mock()

        def make_response(*args, **kwargs):
            resp = Mock()
            resp.status_code = 200
            call_count[0] += 1
            if call_count[0] == 1:
                # Baseline response
                resp.text = "File saved to /data/uploads/test.txt"
            else:
                resp.text = "Upload complete"
            resp.content = resp.text.encode()
            return resp

        mock_session.post.side_effect = make_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_extensions",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        assert "Discovered Upload Paths" in result
        assert "baseline" in result

    def test_test_extensions_no_paths_when_response_empty(self):
        """test_extensions should not show paths section when no paths found."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_response.content = b"OK"
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_extensions",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        assert "Discovered Upload Paths" not in result
        # But should still show first success response
        assert "First Successful Response" in result
        assert "OK" in result

    def test_test_extensions_deduplicates_paths(self):
        """test_extensions should not show duplicate paths in the Discovered section."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"path": "/uploads/shell.php"}'
        mock_response.content = mock_response.text.encode()
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_extensions",
                    "url": "http://test.com/upload",
                    "file_param": "file",
                }
            )
        )

        # Discovered Upload Paths section should have the path only once
        # (even though many extensions all return the same path)
        disc_start = result.find("Discovered Upload Paths")
        disc_end = result.find("First Successful Response")
        discovered_section = result[disc_start:disc_end]
        count = discovered_section.count("/uploads/shell.php")
        assert count == 1

    def test_test_extensions_shows_response_body_for_path_discovery(self):
        """test_extensions response body snippet helps agent find upload location."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '<p>Your CV has been uploaded to <a href="/cv_uploads/shell.php">here</a></p>'
        mock_response.content = mock_response.text.encode()
        mock_session.post.return_value = mock_response

        tool = FileUploadTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "operation": "test_extensions",
                    "url": "http://test.com/upload",
                    "file_param": "cv",
                }
            )
        )

        # Agent should see the response body that reveals the path
        assert "cv_uploads" in result
        assert "First Successful Response" in result


class TestFileUploadToolIntegration:
    """Test integration with CTF solver."""

    def test_import_from_tools(self):
        """Test that upload tools are importable from tools package."""
        from ctf_solver.tools import FileUploadTool, UploadLocationFinder

        upload = FileUploadTool()
        finder = UploadLocationFinder()
        assert upload.name == "file_upload"
        assert finder.name == "upload_location_finder"

    def test_tools_follow_fair_pattern(self):
        """Test that tools follow FAIR pattern."""
        for Tool in [FileUploadTool, UploadLocationFinder]:
            tool = Tool()

            # Has required attributes
            assert hasattr(tool, "name")
            assert hasattr(tool, "description")
            assert hasattr(tool, "use")

            # Types are correct
            assert isinstance(tool.name, str)
            assert isinstance(tool.description, str)

            # use returns string
            result = tool.use("{}")
            assert isinstance(result, str)

    def test_tools_share_session(self):
        """Test that tools use shared session."""
        import requests

        session = requests.Session()
        session.headers["X-Custom"] = "test"

        upload = FileUploadTool(session=session)
        finder = UploadLocationFinder(session=session)

        assert upload.session.headers.get("X-Custom") == "test"
        assert finder.session.headers.get("X-Custom") == "test"


class TestCheckUploadSuccessRegression:
    """Regression tests for the substring-match false positive seen on the
    MetaCTF 'Open Application' run — response body literally said
    'Sorry, PHP files ... not allowed.Sorry, your file was not uploaded.'
    and the tool still reported SUCCESSFUL because 'uploaded' is a substring
    of 'not uploaded' and the success check used to run before the failure
    check."""

    def setup_method(self):
        self.tool = FileUploadTool()

    def test_not_uploaded_phrase_rejects_success(self):
        """'was not uploaded' must not be treated as success."""
        assert (
            self.tool._check_upload_success(200, "File was not uploaded.", 200) is False
        )

    def test_not_allowed_phrase_rejects_success_even_when_uploaded_present(self):
        """Exact observed MetaCTF response body — the bug."""
        body = (
            "Sorry, PHP files and its variations are not allowed."
            "Sorry, your file was not uploaded."
        )
        assert self.tool._check_upload_success(200, body, 200) is False

    def test_genuine_upload_success_still_detected(self):
        """The good path must still be recognised."""
        body = "The file test.txt has been uploaded. File path: uploads/test.txt"
        assert self.tool._check_upload_success(200, body, 200) is True

    def test_unsuccessful_phrase_rejects_word_boundary_match(self):
        """'unsuccessful' currently substring-matches 'success' → bug."""
        assert self.tool._check_upload_success(200, "Upload unsuccessful", 200) is False

    def test_error_phrase_anywhere_rejects_success(self):
        """A clear error marker anywhere in body rejects even with
        ambiguous success-ish words elsewhere."""
        body = "Upload error: extension blocked. The file was not uploaded."
        assert self.tool._check_upload_success(200, body, 200) is False

    def test_status_500_still_rejected(self):
        """Pre-existing contract: 5xx is never success."""
        assert (
            self.tool._check_upload_success(500, "The file was uploaded", 200) is False
        )
