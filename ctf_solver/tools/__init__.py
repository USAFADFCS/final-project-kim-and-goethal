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
]
