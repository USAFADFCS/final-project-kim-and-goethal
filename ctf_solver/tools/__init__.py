"""
CTF Solver Tools - HTTP, HTML, and web exploitation tools for CTF solving.

All tools follow the FAIR framework interface with `.use(tool_input: str) -> str`.
"""

from ctf_solver.tools.http_tools import HttpFetchTool, FormSubmitTool
from ctf_solver.tools.html_tools import HtmlInspectorTool, JavaScriptSourceTool
from ctf_solver.tools.search_tools import RegexSearchTool, ResponseSearchTool, SqlPatternHintTool
from ctf_solver.tools.web_tools import RobotsTxtTool, CookieInspectorTool, CookieSetTool
from ctf_solver.tools.logging_wrapper import LoggingToolWrapper
from ctf_solver.tools.encoding_tools import EncodingTool, HashIdentifierTool
from ctf_solver.tools.diff_tools import ResponseDiffTool, TimingCompareTool, ResponseFingerprinter
from ctf_solver.tools.enumeration_tools import PathEnumeratorTool, BackupFileFinder
from ctf_solver.tools.sqli_tools import SqliProbeTool, SqliColumnCounter
from ctf_solver.tools.blind_sqli_tools import (
    BlindSqliBooleanTool,
    BlindSqliTimeTool,
    SqliDataDumper,
)
from ctf_solver.tools.jwt_tools import JwtTool
from ctf_solver.tools.ssti_tools import SstiProbeTool, SstiExploitSuggester
from ctf_solver.tools.upload_tools import FileUploadTool, UploadLocationFinder
from ctf_solver.tools.xxe_tools import XxeProbeTool, XxePayloadGenerator, XxeDocTypeBuilder
from ctf_solver.tools.shell_tools import ShellExecuteTool
from ctf_solver.tools.xpath_tools import XPathProbeTool, XPathBlindBooleanTool, XPathPayloadGenerator
from ctf_solver.tools.filter_bypass_tools import FilterEnumeratorTool, PayloadMutatorTool
from ctf_solver.tools.ssrf_tools import SsrfProbeTool, SsrfPayloadGenerator
from ctf_solver.tools.attack_planner import AttackPlannerTool
from ctf_solver.tools.lfi_tools import LfiProbeTool, LfiPayloadGenerator
from ctf_solver.tools.nosql_tools import NosqlProbeTool, NosqlPayloadGenerator
from ctf_solver.tools.cmdi_tools import CommandInjectionProbeTool, CommandInjectionPayloadGenerator
from ctf_solver.tools.crypto_tools import CryptoProbeTool, CryptoAnalyzerTool, CryptoPayloadGenerator
from ctf_solver.tools.deserialization_tools import DeserializationProbeTool, DeserializationPayloadGenerator
from ctf_solver.tools.xss_tools import XssProbeTool, XssPayloadGenerator, CspAnalyzerTool
from ctf_solver.tools.graphql_tools import GraphqlIntrospectionTool, GraphqlQueryTool
from ctf_solver.tools.race_tools import RaceConditionTool
from ctf_solver.tools.fuzzer_tools import RequestRepeaterTool
from ctf_solver.tools.misc_probe_tools import (
    CrlfProbeTool,
    PhpTypeJugglingTool,
    PrototypePollutionTool,
    IdorEnumeratorTool,
    OpenRedirectProbeTool,
)
from ctf_solver.tools.css_tools import CssInjectionPayloadGenerator, CssExfiltrationBuilder
from ctf_solver.tools.smuggling_tools import HttpSmugglingProbeTool
from ctf_solver.tools.session_forgery_tools import FlaskSessionForgeryTool, DomClobberingPayloadGenerator

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
]
