"""
CTF Solver Tools - HTTP, HTML, and web exploitation tools for CTF solving.

All tools follow the FAIR framework interface with `.use(tool_input: str) -> str`.
"""

from ctf_solver.tools.attack_planner import AttackPlannerTool
from ctf_solver.tools.blind_sqli_tools import (
    BlindSqliBooleanTool,
    BlindSqliTimeTool,
    SqliDataDumper,
)
from ctf_solver.tools.cmdi_tools import (
    CommandInjectionPayloadGenerator,
    CommandInjectionProbeTool,
)
from ctf_solver.tools.crypto_tools import (
    CryptoAnalyzerTool,
    CryptoPayloadGenerator,
    CryptoProbeTool,
)
from ctf_solver.tools.css_tools import (
    CssExfiltrationBuilder,
    CssInjectionPayloadGenerator,
)
from ctf_solver.tools.deserialization_tools import (
    DeserializationPayloadGenerator,
    DeserializationProbeTool,
)
from ctf_solver.tools.diff_tools import (
    ResponseDiffTool,
    ResponseFingerprinter,
    TimingCompareTool,
)
from ctf_solver.tools.encoding_tools import EncodingTool, HashIdentifierTool
from ctf_solver.tools.enumeration_tools import BackupFileFinder, PathEnumeratorTool
from ctf_solver.tools.filter_bypass_tools import (
    FilterEnumeratorTool,
    PayloadMutatorTool,
)
from ctf_solver.tools.fuzzer_tools import RequestRepeaterTool
from ctf_solver.tools.graphql_tools import GraphqlIntrospectionTool, GraphqlQueryTool
from ctf_solver.tools.html_tools import HtmlInspectorTool, JavaScriptSourceTool
from ctf_solver.tools.http_tools import FormSubmitTool, HttpFetchTool
from ctf_solver.tools.jwt_tools import JwtTool
from ctf_solver.tools.lfi_tools import LfiPayloadGenerator, LfiProbeTool
from ctf_solver.tools.logging_wrapper import LoggingToolWrapper
from ctf_solver.tools.misc_probe_tools import (
    CrlfProbeTool,
    IdorEnumeratorTool,
    OpenRedirectProbeTool,
    PhpTypeJugglingTool,
    PrototypePollutionTool,
)
from ctf_solver.tools.nosql_tools import NosqlPayloadGenerator, NosqlProbeTool
from ctf_solver.tools.oauth_tools import OAuthPayloadGenerator, OAuthProbeTool
from ctf_solver.tools.parser_diff_tools import ParserDifferentialProbeTool
from ctf_solver.tools.php_filter_tools import PhpFilterChainTool
from ctf_solver.tools.race_tools import RaceConditionTool
from ctf_solver.tools.recon_tools import DeepReconTool, SecurityHeaderAnalyzerTool
from ctf_solver.tools.search_tools import (
    RegexSearchTool,
    ResponseSearchTool,
    SqlPatternHintTool,
)
from ctf_solver.tools.session_forgery_tools import (
    DomClobberingPayloadGenerator,
    FlaskSessionForgeryTool,
)
from ctf_solver.tools.shell_tools import ShellExecuteTool
from ctf_solver.tools.smuggling_tools import HttpSmugglingProbeTool
from ctf_solver.tools.sqli_tools import SqliColumnCounter, SqliProbeTool
from ctf_solver.tools.ssrf_tools import SsrfPayloadGenerator, SsrfProbeTool
from ctf_solver.tools.ssti_tools import SstiExploitSuggester, SstiProbeTool
from ctf_solver.tools.upload_tools import FileUploadTool, UploadLocationFinder
from ctf_solver.tools.wasm_tools import WasmAnalyzerTool
from ctf_solver.tools.web_tools import CookieInspectorTool, CookieSetTool, RobotsTxtTool
from ctf_solver.tools.websocket_tools import WebSocketProbeTool
from ctf_solver.tools.xpath_tools import (
    XPathBlindBooleanTool,
    XPathPayloadGenerator,
    XPathProbeTool,
)
from ctf_solver.tools.xss_tools import (
    CspAnalyzerTool,
    XssPayloadGenerator,
    XssProbeTool,
)
from ctf_solver.tools.xxe_tools import (
    XxeDocTypeBuilder,
    XxePayloadGenerator,
    XxeProbeTool,
)

__all__ = [
    "HttpFetchTool",
    "FormSubmitTool",
    "HtmlInspectorTool",
    "JavaScriptSourceTool",
    "RegexSearchTool",
    "ResponseSearchTool",
    "SqlPatternHintTool",
    "RobotsTxtTool",
    "CookieInspectorTool",
    "CookieSetTool",
    "LoggingToolWrapper",
    # Encoding tools
    "EncodingTool",
    "HashIdentifierTool",
    # Diff/comparison tools
    "ResponseDiffTool",
    "TimingCompareTool",
    "ResponseFingerprinter",
    # Enumeration tools
    "PathEnumeratorTool",
    "BackupFileFinder",
    # SQL Injection tools
    "SqliProbeTool",
    "SqliColumnCounter",
    # Blind SQL Injection tools
    "BlindSqliBooleanTool",
    "BlindSqliTimeTool",
    "SqliDataDumper",
    # JWT tools
    "JwtTool",
    # SSTI tools
    "SstiProbeTool",
    "SstiExploitSuggester",
    # File upload tools
    "FileUploadTool",
    "UploadLocationFinder",
    # XXE tools
    "XxeProbeTool",
    "XxePayloadGenerator",
    "XxeDocTypeBuilder",
    # Shell execution tools
    "ShellExecuteTool",
    # XPath injection tools
    "XPathProbeTool",
    "XPathBlindBooleanTool",
    "XPathPayloadGenerator",
    # Filter bypass tools
    "FilterEnumeratorTool",
    "PayloadMutatorTool",
    # SSRF tools
    "SsrfProbeTool",
    "SsrfPayloadGenerator",
    # Attack planner
    "AttackPlannerTool",
    # LFI/RFI tools
    "LfiProbeTool",
    "LfiPayloadGenerator",
    # NoSQL injection tools
    "NosqlProbeTool",
    "NosqlPayloadGenerator",
    # Command injection tools
    "CommandInjectionProbeTool",
    "CommandInjectionPayloadGenerator",
    # Crypto tools
    "CryptoProbeTool",
    "CryptoAnalyzerTool",
    "CryptoPayloadGenerator",
    # Deserialization tools
    "DeserializationProbeTool",
    "DeserializationPayloadGenerator",
    # XSS tools
    "XssProbeTool",
    "XssPayloadGenerator",
    "CspAnalyzerTool",
    # GraphQL tools
    "GraphqlIntrospectionTool",
    "GraphqlQueryTool",
    # Race condition tools
    "RaceConditionTool",
    # Fuzzer tools
    "RequestRepeaterTool",
    # Misc probe tools
    "CrlfProbeTool",
    "PhpTypeJugglingTool",
    "PrototypePollutionTool",
    "IdorEnumeratorTool",
    "OpenRedirectProbeTool",
    # CSS injection tools
    "CssInjectionPayloadGenerator",
    "CssExfiltrationBuilder",
    # HTTP smuggling tools
    "HttpSmugglingProbeTool",
    # Session forgery tools
    "FlaskSessionForgeryTool",
    "DomClobberingPayloadGenerator",
    # OAuth/OIDC tools
    "OAuthProbeTool",
    "OAuthPayloadGenerator",
    # PHP filter chain tools
    "PhpFilterChainTool",
    # Parser differential tools
    "ParserDifferentialProbeTool",
    # WebSocket tools
    "WebSocketProbeTool",
    # WASM / Reverse Engineering tools
    "WasmAnalyzerTool",
    # Recon meta-tools
    "SecurityHeaderAnalyzerTool",
    "DeepReconTool",
]
