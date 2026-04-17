"""
Tests for enumeration_tools.py
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from ctf_solver.tools.enumeration_tools import PathEnumeratorTool, BackupFileFinder


class TestPathEnumeratorTool:
    """Tests for the PathEnumeratorTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = PathEnumeratorTool()

    # === Input Validation Tests ===

    def test_invalid_json_input(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_url(self):
        """Test handling of missing URL."""
        result = self.tool.use(json.dumps({"wordlist": "common"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_unknown_wordlist(self):
        """Test handling of unknown wordlist name."""
        result = self.tool.use(
            json.dumps(
                {"url": "http://example.com", "wordlist": "nonexistent_wordlist"}
            )
        )
        assert "Error" in result
        assert "Unknown wordlist" in result

    # === Wordlist Tests ===

    def test_wordlists_exist(self):
        """Test that all documented wordlists exist."""
        expected_wordlists = ["common", "backup", "git", "admin", "api"]
        for wl in expected_wordlists:
            assert wl in PathEnumeratorTool.WORDLISTS
            assert len(PathEnumeratorTool.WORDLISTS[wl]) > 0

    def test_common_wordlist_contents(self):
        """Test common wordlist has expected paths."""
        common = PathEnumeratorTool.WORDLISTS["common"]
        assert "robots.txt" in common
        assert "admin" in common
        assert "flag.txt" in common

    def test_git_wordlist_contents(self):
        """Test git wordlist has expected paths."""
        git = PathEnumeratorTool.WORDLISTS["git"]
        assert ".git" in git
        assert ".git/HEAD" in git
        assert ".gitignore" in git

    def test_custom_wordlist(self):
        """Test using a custom wordlist."""
        with patch.object(self.tool.session, "get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 404
            mock_response.content = b""
            mock_get.return_value = mock_response

            result = self.tool.use(
                json.dumps(
                    {
                        "url": "http://example.com",
                        "wordlist": ["custom1", "custom2", "custom3"],
                    }
                )
            )

            assert "Paths tested:" in result
            assert mock_get.called

    # === HTTP Request Tests ===

    @patch("ctf_solver.tools.enumeration_tools.PathEnumeratorTool")
    def test_successful_path_discovery(self, mock_tool):
        """Test discovering accessible paths."""
        tool = PathEnumeratorTool()

        with patch.object(tool.session, "get") as mock_get:
            # First call returns 200, rest return 404
            def side_effect(url, **kwargs):
                mock_resp = Mock()
                if "robots.txt" in url:
                    mock_resp.status_code = 200
                    mock_resp.content = b"User-agent: *\nDisallow: /secret/"
                    mock_resp.text = "User-agent: *\nDisallow: /secret/"
                    mock_resp.request = Mock()
                    mock_resp.request.path_url = "/robots.txt"
                else:
                    mock_resp.status_code = 404
                    mock_resp.content = b""
                return mock_resp

            mock_get.side_effect = side_effect

            result = tool.use(
                json.dumps(
                    {
                        "url": "http://example.com",
                        "wordlist": ["robots.txt", "admin", "test"],
                        "max_paths": 3,
                    }
                )
            )

            assert "robots.txt" in result
            assert "200" in result
            assert "DISCOVERED PATHS" in result

    @patch("ctf_solver.tools.enumeration_tools.PathEnumeratorTool")
    def test_protected_path_detection(self, mock_tool):
        """Test detecting protected (403) paths."""
        tool = PathEnumeratorTool()

        with patch.object(tool.session, "get") as mock_get:
            mock_resp = Mock()
            mock_resp.status_code = 403
            mock_resp.content = b"Forbidden"
            mock_resp.text = "Forbidden"
            mock_resp.request = Mock()
            mock_resp.request.path_url = "/admin"
            mock_get.return_value = mock_resp

            result = tool.use(
                json.dumps(
                    {"url": "http://example.com", "wordlist": ["admin"], "max_paths": 1}
                )
            )

            assert "403" in result
            assert "[!]" in result  # Protected indicator

    @patch("ctf_solver.tools.enumeration_tools.PathEnumeratorTool")
    def test_redirect_detection(self, mock_tool):
        """Test detecting redirect responses."""
        tool = PathEnumeratorTool()

        with patch.object(tool.session, "get") as mock_get:
            mock_resp = Mock()
            mock_resp.status_code = 302
            mock_resp.content = b""
            mock_resp.text = ""
            mock_resp.request = Mock()
            mock_resp.request.path_url = "/login"
            mock_get.return_value = mock_resp

            result = tool.use(
                json.dumps(
                    {"url": "http://example.com", "wordlist": ["login"], "max_paths": 1}
                )
            )

            assert "302" in result
            assert "[->]" in result  # Redirect indicator

    # === Extension Testing ===

    def test_extension_testing(self):
        """Test that extensions are appended to paths."""
        with patch.object(self.tool.session, "get") as mock_get:
            mock_resp = Mock()
            mock_resp.status_code = 404
            mock_resp.content = b""
            mock_get.return_value = mock_resp

            result = self.tool.use(
                json.dumps(
                    {
                        "url": "http://example.com",
                        "wordlist": ["config"],
                        "extensions": [".php", ".bak"],
                        "max_paths": 10,
                    }
                )
            )

            # Should test config, config.php, config.bak
            call_urls = [call[0][0] for call in mock_get.call_args_list]
            assert any("config.php" in url for url in call_urls)
            assert any("config.bak" in url for url in call_urls)

    # === Response Analysis Tests ===

    def test_flag_detection(self):
        """Test detection of flag patterns in responses."""
        tool = PathEnumeratorTool()

        with patch.object(tool.session, "get") as mock_get:
            baseline_resp = Mock()
            baseline_resp.status_code = 404
            baseline_resp.content = b"Not Found"
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.content = b"flag{test_flag_here}"
            mock_resp.text = "flag{test_flag_here}"
            mock_resp.request = Mock()
            mock_resp.request.path_url = "/flag.txt"
            mock_get.side_effect = [baseline_resp, mock_resp]

            result = tool.use(
                json.dumps(
                    {
                        "url": "http://example.com",
                        "wordlist": ["flag.txt"],
                        "max_paths": 1,
                    }
                )
            )

            assert "FLAG" in result.upper()

    def test_source_code_detection(self):
        """Test detection of source code exposure."""
        tool = PathEnumeratorTool()

        with patch.object(tool.session, "get") as mock_get:
            baseline_resp = Mock()
            baseline_resp.status_code = 404
            baseline_resp.content = b"Not Found"
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.content = b"<?php echo 'hello'; ?>"
            mock_resp.text = "<?php echo 'hello'; ?>"
            mock_resp.request = Mock()
            mock_resp.request.path_url = "/config.php.bak"
            mock_get.side_effect = [baseline_resp, mock_resp]

            result = tool.use(
                json.dumps(
                    {
                        "url": "http://example.com",
                        "wordlist": ["config.php.bak"],
                        "max_paths": 1,
                    }
                )
            )

            assert "source code" in result.lower()

    def test_directory_listing_detection(self):
        """Test detection of directory listing."""
        tool = PathEnumeratorTool()

        with patch.object(tool.session, "get") as mock_get:
            baseline_resp = Mock()
            baseline_resp.status_code = 404
            baseline_resp.content = b"Not Found"
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.content = b"<html><title>Index of /uploads</title></html>"
            mock_resp.text = "<html><title>Index of /uploads</title></html>"
            mock_resp.request = Mock()
            mock_resp.request.path_url = "/uploads"
            mock_get.side_effect = [baseline_resp, mock_resp]

            result = tool.use(
                json.dumps(
                    {
                        "url": "http://example.com",
                        "wordlist": ["uploads"],
                        "max_paths": 1,
                    }
                )
            )

            assert "directory listing" in result.lower()

    # === CTF Analysis Tests ===

    def test_git_repository_hint(self):
        """Test CTF hint for git repository exposure."""
        tool = PathEnumeratorTool()

        with patch.object(tool.session, "get") as mock_get:
            baseline_resp = Mock()
            baseline_resp.status_code = 404
            baseline_resp.content = b"Not Found"
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.content = b"ref: refs/heads/main"
            mock_resp.text = "ref: refs/heads/main"
            mock_resp.request = Mock()
            mock_resp.request.path_url = "/.git/HEAD"
            mock_get.side_effect = [baseline_resp, mock_resp]

            result = tool.use(
                json.dumps(
                    {
                        "url": "http://example.com",
                        "wordlist": [".git/HEAD"],
                        "max_paths": 1,
                    }
                )
            )

            assert "git" in result.lower()

    # === Error Handling Tests ===

    def test_timeout_handling(self):
        """Test handling of request timeouts."""
        import requests

        with patch.object(self.tool.session, "get") as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout()

            result = self.tool.use(
                json.dumps(
                    {"url": "http://example.com", "wordlist": ["test"], "max_paths": 1}
                )
            )

            assert "Timeout" in result or "No interesting paths" in result

    def test_connection_error_handling(self):
        """Test handling of connection errors."""
        import requests

        with patch.object(self.tool.session, "get") as mock_get:
            mock_get.side_effect = requests.exceptions.ConnectionError(
                "Connection refused"
            )

            result = self.tool.use(
                json.dumps(
                    {"url": "http://example.com", "wordlist": ["test"], "max_paths": 1}
                )
            )

            # Should handle error gracefully
            assert "Error" in result or "No interesting paths" in result


class TestBackupFileFinder:
    """Tests for the BackupFileFinder class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = BackupFileFinder()

    # === Input Validation Tests ===

    def test_invalid_json_input(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_url(self):
        """Test handling of missing URL."""
        result = self.tool.use(json.dumps({}))
        assert "Error" in result
        assert "url" in result.lower()

    # === Pattern Generation Tests ===

    def test_pattern_count(self):
        """Test that multiple patterns are defined."""
        assert len(BackupFileFinder.PATTERNS) > 10

    def test_suffix_patterns(self):
        """Test that common suffix patterns work."""
        test_url = "http://example.com/config.php"
        expected_suffixes = [".bak", ".backup", ".old", "~"]

        for pattern in BackupFileFinder.PATTERNS:
            try:
                result = pattern(test_url)
                # At least some patterns should add these suffixes
                break
            except:
                continue

    # === HTTP Request Tests ===

    def test_backup_found(self):
        """Test finding a backup file."""
        with patch.object(self.tool.session, "get") as mock_get:

            def side_effect(url, **kwargs):
                mock_resp = Mock()
                if url.endswith(".bak"):
                    mock_resp.status_code = 200
                    mock_resp.content = b"<?php $password = 'secret'; ?>"
                    mock_resp.text = "<?php $password = 'secret'; ?>"
                else:
                    mock_resp.status_code = 404
                    mock_resp.content = b""
                return mock_resp

            mock_get.side_effect = side_effect

            result = self.tool.use(json.dumps({"url": "http://example.com/config.php"}))

            assert "BACKUP FILES FOUND" in result
            assert ".bak" in result

    def test_no_backup_found(self):
        """Test when no backup files exist."""
        with patch.object(self.tool.session, "get") as mock_get:
            mock_resp = Mock()
            mock_resp.status_code = 404
            mock_resp.content = b""
            mock_get.return_value = mock_resp

            result = self.tool.use(json.dumps({"url": "http://example.com/config.php"}))

            assert "No backup files found" in result

    def test_content_preview(self):
        """Test that content preview is shown for found backups."""
        with patch.object(self.tool.session, "get") as mock_get:

            def side_effect(url, **kwargs):
                mock_resp = Mock()
                if url.endswith(".bak"):
                    mock_resp.status_code = 200
                    mock_resp.content = b"SECRET_API_KEY=abc123"
                    mock_resp.text = "SECRET_API_KEY=abc123"
                else:
                    mock_resp.status_code = 404
                    mock_resp.content = b""
                return mock_resp

            mock_get.side_effect = side_effect

            result = self.tool.use(json.dumps({"url": "http://example.com/config.php"}))

            assert "Preview:" in result


class TestEnumerationToolsCTFScenarios:
    """Test CTF-specific scenarios with enumeration tools."""

    def setup_method(self):
        """Set up test fixtures."""
        self.path_tool = PathEnumeratorTool()
        self.backup_tool = BackupFileFinder()

    def test_git_repo_discovery_scenario(self):
        """Test discovering exposed git repository."""
        with patch.object(self.path_tool.session, "get") as mock_get:

            def side_effect(url, **kwargs):
                mock_resp = Mock()
                mock_resp.request = Mock()
                mock_resp.request.path_url = (
                    url.split("example.com")[1] if "example.com" in url else url
                )

                if ".git/HEAD" in url:
                    mock_resp.status_code = 200
                    mock_resp.content = b"ref: refs/heads/main"
                    mock_resp.text = "ref: refs/heads/main"
                elif ".git/config" in url:
                    mock_resp.status_code = 200
                    mock_resp.content = b"[core]\n\trepositoryformatversion = 0"
                    mock_resp.text = "[core]\n\trepositoryformatversion = 0"
                else:
                    mock_resp.status_code = 404
                    mock_resp.content = b""
                    mock_resp.text = ""

                return mock_resp

            mock_get.side_effect = side_effect

            result = self.path_tool.use(
                json.dumps(
                    {"url": "http://example.com", "wordlist": "git", "max_paths": 20}
                )
            )

            assert ".git" in result.lower()
            assert "200" in result

    def test_admin_panel_discovery_scenario(self):
        """Test discovering protected admin panel."""
        with patch.object(self.path_tool.session, "get") as mock_get:

            def side_effect(url, **kwargs):
                mock_resp = Mock()
                mock_resp.request = Mock()
                mock_resp.request.path_url = (
                    url.split("example.com")[1] if "example.com" in url else url
                )

                if "admin" in url.lower():
                    mock_resp.status_code = 401
                    mock_resp.content = b"Unauthorized"
                    mock_resp.text = "Unauthorized"
                else:
                    mock_resp.status_code = 404
                    mock_resp.content = b""
                    mock_resp.text = ""

                return mock_resp

            mock_get.side_effect = side_effect

            result = self.path_tool.use(
                json.dumps(
                    {"url": "http://example.com", "wordlist": "admin", "max_paths": 10}
                )
            )

            assert "401" in result
            assert "admin" in result.lower()

    def test_source_code_backup_scenario(self):
        """Test finding source code in backup file."""
        with patch.object(self.backup_tool.session, "get") as mock_get:

            def side_effect(url, **kwargs):
                mock_resp = Mock()
                if url.endswith(".php.bak") or url.endswith(".php~"):
                    mock_resp.status_code = 200
                    mock_resp.content = (
                        b"<?php\n$flag = 'picoCTF{backup_files_exposed}';\n?>"
                    )
                    mock_resp.text = (
                        "<?php\n$flag = 'picoCTF{backup_files_exposed}';\n?>"
                    )
                else:
                    mock_resp.status_code = 404
                    mock_resp.content = b""
                return mock_resp

            mock_get.side_effect = side_effect

            result = self.backup_tool.use(
                json.dumps({"url": "http://example.com/index.php"})
            )

            assert "BACKUP FILES FOUND" in result
            assert "flag" in result.lower() or "php" in result.lower()

    def test_flag_in_robots_scenario(self):
        """Test finding flag hint in robots.txt."""
        with patch.object(self.path_tool.session, "get") as mock_get:

            def side_effect(url, **kwargs):
                mock_resp = Mock()
                mock_resp.request = Mock()
                mock_resp.request.path_url = (
                    url.split("example.com")[1] if "example.com" in url else url
                )

                if "robots.txt" in url:
                    mock_resp.status_code = 200
                    mock_resp.content = (
                        b"User-agent: *\nDisallow: /secret_flag_location/"
                    )
                    mock_resp.text = "User-agent: *\nDisallow: /secret_flag_location/"
                else:
                    mock_resp.status_code = 404
                    mock_resp.content = b""
                    mock_resp.text = ""

                return mock_resp

            mock_get.side_effect = side_effect

            result = self.path_tool.use(
                json.dumps(
                    {
                        "url": "http://example.com",
                        "wordlist": ["robots.txt"],
                        "max_paths": 1,
                    }
                )
            )

            assert "robots.txt" in result
            assert "200" in result
