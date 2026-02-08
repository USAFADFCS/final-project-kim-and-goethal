# Changelog

All notable changes to CTF Solver are documented in this file.

## [1.1.1] - 2026-02-07

### Fixed

#### RAG Documentation - Extension Mismatch Guidance
- Added **Mistake 5** to common mistakes: Extension mismatch between .htaccess and shell
- Added **Section 1.4**: Adaptive Workflow for when uploads are blocked
- Updated **Decision Tree** to check extension mismatch as FIRST troubleshooting step

**Problem solved:** Agent was uploading .htaccess targeting `.txt`, then when `.txt` was blocked,
switching to `.gif` without re-uploading .htaccess. The documentation now explicitly warns:
"If shell extension changes, RE-UPLOAD .htaccess with new target_ext!"

---

## [1.1.0] - 2026-02-07

### Added

#### FileUploadTool Enhancements
- **upload_custom**: Upload files with exact filenames (e.g., `.htaccess`, `.user.ini`)
- **upload_htaccess**: Automated Apache .htaccess attack with multiple payloads
  - AddType, SetHandler, AddHandler, php_value payload variants
  - Targets image extensions to enable PHP execution
- **upload_userini**: PHP-FPM .user.ini attack for auto_prepend_file injection
- **test_traversal**: Path traversal testing in uploaded filenames
  - 15+ traversal payloads including URL encoding variants
- **generate_htaccess**: Payload generator for .htaccess attacks
- **_extract_upload_path()**: Helper to extract uploaded file paths from responses

#### New Constants
- `HTACCESS_PAYLOADS`: 10 Apache configuration payloads
- `USERINI_PAYLOADS`: 5 PHP-FPM configuration payloads
- `TRAVERSAL_PAYLOADS`: 15 path traversal filename variants

#### Documentation
- **docs/20_apache_htaccess_attacks.md**: Comprehensive RAG document covering:
  - Apache .htaccess attack techniques
  - PHP-FPM .user.ini exploitation
  - CTF playbook with decision trees
  - Common mistakes to avoid (exact filename requirement)

### Fixed
- Agent now uploads `.htaccess` with exact filename (previously uploaded `shell.htaccess` incorrectly)
- Proper multipart file upload with filename control

### Technical Details
- FileUploadTool now supports 10 operations (was 5)
- RAG knowledge base expanded to 21 documents
- Test suite expanded to 685+ tests

---

## [1.0.0] - 2026-02-07

### Added

#### Core Utilities (Phase 1)
- **EncodingTool**: Base64, URL, hex, HTML entity, ROT13, binary, JWT decode, Unicode normalize
- **HashIdentifierTool**: MD5, SHA-1, SHA-256, SHA-512, bcrypt identification
- **ResponseDiffTool**: Compare HTTP responses to detect meaningful differences
- **TimingCompareTool**: Measure response time differences for timing attacks
- **ResponseFingerprinter**: Fingerprint web applications by response characteristics
- **PathEnumeratorTool**: Directory enumeration with common wordlists
- **BackupFileFinder**: Find backup files (.bak, .old, .backup, .swp, etc.)

#### Active Exploitation (Phase 2)
- **SqliProbeTool**: Automated SQL injection vulnerability detection
- **SqliColumnCounter**: Determine column count for UNION-based attacks
- **BlindSqliBooleanTool**: Boolean-based blind SQL injection data extraction
- **BlindSqliTimeTool**: Time-based blind SQL injection with configurable delays
- **SqliDataDumper**: Automated data extraction from vulnerable endpoints
- **JwtTool**: JWT decode, analyze, forge (none algorithm, key confusion attacks)

#### Advanced Detection (Phase 3)
- **SstiProbeTool**: Server-side template injection detection with multiple engines
- **SstiExploitSuggester**: Engine-specific exploitation technique suggestions
- **FileUploadTool**: File upload testing with bypass techniques
- **UploadLocationFinder**: Locate where uploaded files are accessible
- **XxeProbeTool**: XML External Entity vulnerability detection
- **XxePayloadGenerator**: Generate XXE payloads for various scenarios
- **XxeDocTypeBuilder**: Build malicious DOCTYPE declarations

#### Infrastructure (Phase 4)
- **AsyncToolExecutor**: Parallel tool execution with configurable workers
- **ProgressTracker**: Real-time progress tracking for batch operations
- **ChallengeClassifier**: Automatic challenge categorization (15 categories)
- **Multi-LLM Adapters**: Support for OpenAI, Anthropic, Ollama, and Hybrid configurations
- **AnthropicAdapter**: Claude model integration
- **OllamaAdapter**: Local model support via Ollama
- **HybridAdapter**: Multi-model strategy for enhanced performance

#### Documentation (Phase 5A)
- 20 reference documents covering common CTF techniques:
  - SQL Injection (basic, advanced, blind techniques)
  - XSS (reflected, stored, DOM-based)
  - JWT vulnerabilities and attacks
  - SSTI for multiple template engines
  - File upload bypass techniques
  - XXE attacks and exploitation
  - Deserialization vulnerabilities
  - Race conditions and TOCTOU
  - GraphQL security testing
  - WebSocket vulnerabilities

#### RAG Optimization (Phase 5B)
- **QueryExpander**: Automatic query expansion for better retrieval
- **SimpleReranker**: Document reranking for improved relevance
- **HybridSearcher**: Combined BM25 + vector search
- **BM25Index**: Fast keyword-based search indexing

#### Testing (Phase 6A)
- Comprehensive test suite with 627 tests
- Shared fixtures in conftest.py
- Integration tests for cross-component verification
- Tool-specific unit tests for all 29 tools

### Changed
- Upgraded to FAIR-LLM framework architecture
- Improved tool registration with LoggingToolWrapper
- Enhanced error handling across all tools
- Standardized JSON input parsing

### Technical Details
- All tools follow FAIR pattern: `name`, `description`, `.use(tool_input: str) -> str`
- Shared `requests.Session` for HTTP tools
- Global caching for RAG components
- Weighted scoring in classifier (0.15 regular, 0.4 strong indicators)

## [0.1.0] - Initial Release

### Added
- Basic HTTP fetching and form submission
- HTML and JavaScript inspection
- Cookie and robots.txt handling
- Response search and regex patterns
- Initial RAG knowledge base
