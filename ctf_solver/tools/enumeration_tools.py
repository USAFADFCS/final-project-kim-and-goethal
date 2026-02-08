"""
Path enumeration tools for CTF solving.

Provides utilities for discovering hidden files, directories, and interesting paths.
"""

import json
from typing import Dict, List, Optional, Set

import requests


class PathEnumeratorTool:
    """
    PathEnumeratorTool: enumerate common paths and files on a web server.

    Useful for discovering:
    - Hidden directories and files
    - Backup files and source code
    - Git/SVN repositories
    - Admin panels and sensitive endpoints
    - API endpoints

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://example.com",
          "wordlist": "common",  # "common", "backup", "git", "admin", "api", or custom list
          "extensions": [".php", ".bak"],  # optional: test with these extensions
          "timeout": 5,  # optional: request timeout in seconds
          "max_paths": 50  # optional: limit number of paths to test
        }
    """

    name: str = "path_enumerator"
    description: str = (
        "Enumerate common paths and files on a web server. Input must be JSON with keys: "
        "'url' (base URL to enumerate), 'wordlist' (one of 'common', 'backup', 'git', 'admin', 'api', "
        "or a list of custom paths), optional 'extensions' (list of extensions to append), "
        "optional 'timeout' (request timeout, default 5), optional 'max_paths' (limit paths tested, default 50). "
        "Returns list of discovered paths with status codes. Use for CTF recon to find hidden files."
    )

    # Built-in wordlists for different scenarios
    WORDLISTS: Dict[str, List[str]] = {
        "common": [
            "robots.txt", "sitemap.xml", ".htaccess", ".htpasswd",
            "admin", "login", "dashboard", "panel", "console",
            "backup", "old", "test", "dev", "staging",
            "config", "configuration", "settings", "setup",
            "upload", "uploads", "files", "images", "media",
            "api", "v1", "v2", "graphql", "rest",
            "user", "users", "account", "profile",
            "flag", "flag.txt", "secret", "secrets",
            "debug", "trace", "status", "health", "info",
            "index", "home", "main", "default",
            "js", "css", "static", "assets", "public",
            "include", "includes", "lib", "libs", "vendor",
            "tmp", "temp", "cache", "logs", "log",
        ],
        "backup": [
            "backup.zip", "backup.tar.gz", "backup.sql", "backup.bak",
            "site.zip", "site.tar.gz", "www.zip", "www.tar.gz",
            "db.sql", "database.sql", "dump.sql", "mysql.sql",
            "config.bak", "config.old", "config.php.bak", "config.php~",
            ".backup", "~backup", "backup~",
            "index.php.bak", "index.php~", "index.bak",
            "web.config.bak", "web.config.old",
            ".old", ".bak", ".backup", ".save", ".swp",
            "1", "2", "old", "new", "test", "copy",
        ],
        "git": [
            ".git", ".git/HEAD", ".git/config", ".git/index",
            ".git/logs/HEAD", ".git/refs/heads/master", ".git/refs/heads/main",
            ".git/objects/", ".git/COMMIT_EDITMSG",
            ".gitignore", ".gitattributes", ".gitmodules",
            ".svn", ".svn/entries", ".svn/wc.db",
            ".hg", ".hg/hgrc", ".hg/store",
            ".bzr", "CVS", "CVS/Root", "CVS/Entries",
        ],
        "admin": [
            "admin", "administrator", "admin.php", "admin.html",
            "admin/login", "admin/index", "admin/dashboard",
            "adminpanel", "admin-panel", "admin_panel",
            "cpanel", "wp-admin", "wp-login.php",
            "phpmyadmin", "pma", "myadmin", "mysql",
            "manager", "management", "control", "controlpanel",
            "backend", "backoffice", "staff", "internal",
            "root", "superuser", "superadmin", "sysadmin",
            "moderator", "mod", "editor",
            "login", "signin", "sign-in", "auth", "authenticate",
        ],
        "api": [
            "api", "api/v1", "api/v2", "api/v3",
            "rest", "rest/v1", "restapi",
            "graphql", "graphiql", "playground",
            "swagger", "swagger.json", "swagger.yaml", "api-docs",
            "openapi", "openapi.json", "openapi.yaml",
            "endpoints", "routes", "services",
            "users", "user", "accounts", "account",
            "auth", "authenticate", "login", "token", "tokens",
            "data", "fetch", "query", "search",
            "admin", "debug", "test", "health", "status", "ping",
            "export", "import", "upload", "download",
            "webhook", "webhooks", "callback", "callbacks",
        ],
    }

    # Common file extensions for backup/source detection
    BACKUP_EXTENSIONS = [".bak", ".backup", ".old", ".orig", ".save", ".swp", "~", ".copy"]
    SOURCE_EXTENSIONS = [".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".pl"]

    # Status codes that indicate interesting finds
    INTERESTING_CODES = {200, 201, 301, 302, 303, 307, 308, 401, 403}

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[PathEnumeratorTool] Error: tool_input must be JSON: {exc}"

        url = data.get("url", "").rstrip("/")
        wordlist_input = data.get("wordlist", "common")
        extensions = data.get("extensions", [])
        timeout = data.get("timeout", 5)
        max_paths = data.get("max_paths", 50)

        if not url:
            return "[PathEnumeratorTool] Error: 'url' is required."

        # Determine paths to test
        if isinstance(wordlist_input, list):
            paths = wordlist_input[:max_paths]
        elif wordlist_input in self.WORDLISTS:
            paths = self.WORDLISTS[wordlist_input][:max_paths]
        else:
            return f"[PathEnumeratorTool] Error: Unknown wordlist '{wordlist_input}'. Use one of: {list(self.WORDLISTS.keys())} or provide a custom list."

        # Build full list of URLs to test
        urls_to_test = []
        for path in paths:
            # Test base path
            full_url = f"{url}/{path}"
            urls_to_test.append((full_url, path))

            # Test with extensions if provided
            if extensions and not any(path.endswith(ext) for ext in [".txt", ".xml", ".html", ".php", ".json"]):
                for ext in extensions:
                    ext_url = f"{url}/{path}{ext}"
                    urls_to_test.append((ext_url, f"{path}{ext}"))

        # Limit total tests
        urls_to_test = urls_to_test[:max_paths * 2]

        # Results storage
        found: List[Dict] = []
        errors: List[str] = []
        tested = 0

        for test_url, path in urls_to_test:
            try:
                resp = self.session.get(
                    test_url,
                    timeout=timeout,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 (CTF Enumeration)"}
                )
                tested += 1

                if resp.status_code in self.INTERESTING_CODES:
                    result = {
                        "path": path,
                        "url": test_url,
                        "status": resp.status_code,
                        "size": len(resp.content),
                        "interesting": self._analyze_response(resp),
                    }
                    found.append(result)

            except requests.exceptions.Timeout:
                errors.append(f"Timeout: {path}")
            except requests.exceptions.RequestException as e:
                errors.append(f"{path}: {str(e)[:50]}")

        # Build output
        output_lines = [
            "[PathEnumeratorTool] Enumeration Results",
            "",
            f"Base URL: {url}",
            f"Wordlist: {wordlist_input if isinstance(wordlist_input, str) else 'custom'}",
            f"Paths tested: {tested}",
            f"Interesting finds: {len(found)}",
            "",
        ]

        if found:
            output_lines.append("=== DISCOVERED PATHS ===")
            for item in found:
                status_emoji = self._status_emoji(item["status"])
                output_lines.append(f"{status_emoji} [{item['status']}] {item['path']} ({item['size']} bytes)")
                if item["interesting"]:
                    for note in item["interesting"]:
                        output_lines.append(f"    [!] {note}")
            output_lines.append("")

        # Categorize findings
        accessible = [f for f in found if f["status"] == 200]
        redirects = [f for f in found if f["status"] in {301, 302, 303, 307, 308}]
        protected = [f for f in found if f["status"] in {401, 403}]

        if accessible or redirects or protected:
            output_lines.append("=== SUMMARY ===")
            if accessible:
                output_lines.append(f"Accessible (200): {[f['path'] for f in accessible]}")
            if redirects:
                output_lines.append(f"Redirects (3xx): {[f['path'] for f in redirects]}")
            if protected:
                output_lines.append(f"Protected (401/403): {[f['path'] for f in protected]}")
            output_lines.append("")

        # Highlight CTF-relevant findings
        ctf_hints = self._ctf_analysis(found)
        if ctf_hints:
            output_lines.append("=== CTF HINTS ===")
            output_lines.extend(ctf_hints)
            output_lines.append("")

        if errors and len(errors) <= 5:
            output_lines.append("=== ERRORS ===")
            output_lines.extend(errors[:5])

        if not found:
            output_lines.append("No interesting paths found with this wordlist.")
            output_lines.append("Try a different wordlist or custom paths.")

        return "\n".join(output_lines)

    def _status_emoji(self, status: int) -> str:
        """Get emoji for status code."""
        if status == 200:
            return "[+]"
        elif status in {301, 302, 303, 307, 308}:
            return "[->]"
        elif status in {401, 403}:
            return "[!]"
        else:
            return "[-]"

    def _analyze_response(self, resp: requests.Response) -> List[str]:
        """Analyze response for interesting content."""
        notes = []
        content = resp.text.lower()

        # Check for flags
        if "flag{" in content or "ctf{" in content or "picoctf{" in content:
            notes.append("POSSIBLE FLAG DETECTED!")

        # Check for source code indicators
        if "<?php" in content or "<%@" in content:
            notes.append("Source code exposure")

        # Check for directory listing
        if "index of" in content or "directory listing" in content:
            notes.append("Directory listing enabled")

        # Check for git exposure
        if resp.request.path_url and ".git" in resp.request.path_url:
            if resp.status_code == 200:
                notes.append("Git repository exposed!")

        # Check for backup file
        if any(ext in resp.request.path_url for ext in self.BACKUP_EXTENSIONS):
            if resp.status_code == 200:
                notes.append("Backup file accessible")

        # Check for sensitive data
        sensitive_patterns = ["password", "secret", "api_key", "apikey", "token", "credential"]
        for pattern in sensitive_patterns:
            if pattern in content:
                notes.append(f"Contains '{pattern}'")
                break

        # Check for admin/login
        if resp.status_code in {401, 403}:
            if any(kw in resp.request.path_url.lower() for kw in ["admin", "login", "dashboard"]):
                notes.append("Protected admin area")

        return notes

    def _ctf_analysis(self, found: List[Dict]) -> List[str]:
        """Generate CTF-specific analysis and hints."""
        hints = []

        paths_found = {f["path"].lower() for f in found}

        # Git repository detection
        git_paths = {".git", ".git/head", ".git/config"}
        if git_paths & paths_found:
            hints.append("[*] Git repository detected! Try: git-dumper or manually fetch .git/objects")

        # robots.txt detection
        if "robots.txt" in paths_found:
            hints.append("[*] robots.txt found - check for disallowed paths")

        # Backup files
        backup_found = [f for f in found if any(ext in f["path"] for ext in self.BACKUP_EXTENSIONS)]
        if backup_found:
            hints.append(f"[*] Backup files found: {[b['path'] for b in backup_found]}")

        # Admin panels
        admin_found = [f for f in found if any(kw in f["path"].lower() for kw in ["admin", "login", "dashboard"])]
        if admin_found:
            hints.append(f"[*] Admin/login pages found: {[a['path'] for a in admin_found]}")

        # API endpoints
        api_found = [f for f in found if any(kw in f["path"].lower() for kw in ["api", "graphql", "rest"])]
        if api_found:
            hints.append(f"[*] API endpoints found: {[a['path'] for a in api_found]}")

        # Flags detected
        flag_found = [f for f in found if any("flag" in note.lower() for note in f.get("interesting", []))]
        if flag_found:
            hints.append(f"[!!!] POSSIBLE FLAGS at: {[f['path'] for f in flag_found]}")

        return hints


class BackupFileFinder:
    """
    BackupFileFinder: generate and test backup file variations for a known file.

    Given a known file path, tests common backup naming patterns.
    """

    name: str = "backup_finder"
    description: str = (
        "Find backup versions of a known file. Input must be JSON with keys: "
        "'url' (full URL to the known file, e.g. 'http://example.com/config.php'), "
        "optional 'timeout' (request timeout, default 5). "
        "Tests common backup patterns like .bak, .old, ~, .swp, etc. "
        "Returns any accessible backup files found."
    )

    # Backup patterns to test
    PATTERNS = [
        # Suffix patterns
        lambda f: f + ".bak",
        lambda f: f + ".backup",
        lambda f: f + ".old",
        lambda f: f + ".orig",
        lambda f: f + ".save",
        lambda f: f + ".swp",
        lambda f: f + "~",
        lambda f: f + ".copy",
        lambda f: f + ".tmp",
        lambda f: f + ".temp",
        lambda f: f + "_backup",
        lambda f: f + "_old",
        lambda f: f + "_bak",
        lambda f: f + ".1",
        lambda f: f + ".2",
        # Prefix patterns
        lambda f: f.rsplit("/", 1)[0] + "/." + f.rsplit("/", 1)[1],  # hidden file
        lambda f: f.rsplit("/", 1)[0] + "/~" + f.rsplit("/", 1)[1],
        lambda f: f.rsplit("/", 1)[0] + "/_" + f.rsplit("/", 1)[1],
        lambda f: f.rsplit("/", 1)[0] + "/backup_" + f.rsplit("/", 1)[1],
        lambda f: f.rsplit("/", 1)[0] + "/old_" + f.rsplit("/", 1)[1],
        # Vim swap files
        lambda f: f.rsplit("/", 1)[0] + "/." + f.rsplit("/", 1)[1] + ".swp",
        lambda f: f.rsplit("/", 1)[0] + "/." + f.rsplit("/", 1)[1] + ".swo",
        # Editor backups
        lambda f: f + ".kate-swp",
        lambda f: f + ".gedit-save",
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[BackupFileFinder] Error: tool_input must be JSON: {exc}"

        url = data.get("url", "")
        timeout = data.get("timeout", 5)

        if not url:
            return "[BackupFileFinder] Error: 'url' is required."

        # Generate backup URLs
        backup_urls = []
        for pattern in self.PATTERNS:
            try:
                backup_url = pattern(url)
                if backup_url != url:
                    backup_urls.append(backup_url)
            except (IndexError, ValueError):
                continue

        # Remove duplicates while preserving order
        seen: Set[str] = set()
        unique_urls = []
        for u in backup_urls:
            if u not in seen:
                seen.add(u)
                unique_urls.append(u)

        # Test each URL
        found = []
        tested = 0

        for backup_url in unique_urls:
            try:
                resp = self.session.get(
                    backup_url,
                    timeout=timeout,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                tested += 1

                if resp.status_code == 200:
                    found.append({
                        "url": backup_url,
                        "size": len(resp.content),
                        "content_preview": resp.text[:200] if resp.text else "(binary)",
                    })

            except requests.exceptions.RequestException:
                continue

        # Build output
        output_lines = [
            "[BackupFileFinder] Backup Search Results",
            "",
            f"Original file: {url}",
            f"Patterns tested: {tested}",
            f"Backups found: {len(found)}",
            "",
        ]

        if found:
            output_lines.append("=== BACKUP FILES FOUND ===")
            for item in found:
                output_lines.append(f"[+] {item['url']} ({item['size']} bytes)")
                if item["content_preview"]:
                    preview = item["content_preview"].replace("\n", " ")[:100]
                    output_lines.append(f"    Preview: {preview}...")
            output_lines.append("")
            output_lines.append("[!] IMPORTANT: Backup files may contain source code or credentials!")
        else:
            output_lines.append("No backup files found.")

        return "\n".join(output_lines)
