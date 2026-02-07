"""
CTF Solver Tools - HTTP, HTML, and web exploitation tools for CTF solving.

All tools follow the FAIR framework interface with `.use(tool_input: str) -> str`.
"""

from ctf_solver.tools.http_tools import HttpFetchTool, FormSubmitTool
from ctf_solver.tools.html_tools import HtmlInspectorTool, JavaScriptSourceTool
from ctf_solver.tools.search_tools import RegexSearchTool, ResponseSearchTool, SqlPatternHintTool
from ctf_solver.tools.web_tools import RobotsTxtTool, CookieInspectorTool, CookieSetTool
from ctf_solver.tools.logging_wrapper import LoggingToolWrapper

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
]
