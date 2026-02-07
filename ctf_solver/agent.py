"""
Agent construction for CTF Solver.

Builds a FAIR SimpleAgent with all necessary tools, RAG, and configuration.
"""

import logging
import os
from typing import Callable, Optional

# Prevent multiprocessing crashes on Apple Silicon
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("OMP_NUM_THREADS", "1")

import requests

from fairlib import (
    settings,
    OpenAIAdapter,
    SimpleAgent,
    ToolRegistry,
    ToolExecutor,
    ReActPlanner,
    WorkingMemory,
    RoleDefinition,
)

from ctf_solver.config import SolverConfig
from ctf_solver.tools import (
    HttpFetchTool,
    FormSubmitTool,
    HtmlInspectorTool,
    JavaScriptSourceTool,
    RegexSearchTool,
    ResponseSearchTool,
    SqlPatternHintTool,
    RobotsTxtTool,
    CookieInspectorTool,
    CookieSetTool,
    LoggingToolWrapper,
)
from ctf_solver.rag import initialize_knowledge_base, build_knowledge_tool
from ctf_solver.prompts import (
    get_role_definition,
    ROBOTS_EXAMPLE,
    JS_ANALYSIS_EXAMPLE,
)

logger = logging.getLogger(__name__)


def build_agent(
    config: SolverConfig,
    log_callback: Optional[Callable[[str], None]] = None,
) -> SimpleAgent:
    """
    Construct and return a SimpleAgent wired up with:

      - OpenAI LLM (OpenAIAdapter)
      - ReActPlanner + custom PromptBuilder role + examples
      - ToolRegistry with HTTP / HTML / regex / cookies / robots / form / JS / search / SQL / RAG tools
      - LoggingToolWrapper around all tools (for tool-call + flag logging)
      - ToolExecutor
      - WorkingMemory

    Args:
        config: Solver configuration
        log_callback: Optional callback for log messages (defaults to print)

    Returns:
        Configured SimpleAgent instance
    """
    log_fn = log_callback or print

    # Validate API key
    if not config.openai_api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not set. Set it in your environment, .env file, or config."
        )
    settings.api_keys.openai_api_key = config.openai_api_key

    llm = OpenAIAdapter(api_key=settings.api_keys.openai_api_key)

    # Single shared HTTP session for ALL HTTP-related tools
    shared_session = requests.Session()

    tool_registry = ToolRegistry()

    # Instantiate actual tools
    http_tool = HttpFetchTool(session=shared_session)
    html_tool = HtmlInspectorTool(session=shared_session)
    regex_tool = RegexSearchTool()
    robots_tool = RobotsTxtTool(session=shared_session)
    cookie_inspector_tool = CookieInspectorTool(session=shared_session)
    cookie_set_tool = CookieSetTool(session=shared_session)
    form_submit_tool = FormSubmitTool(session=shared_session)
    js_source_tool = JavaScriptSourceTool(session=shared_session)
    response_search_tool = ResponseSearchTool()
    sql_pattern_hint_tool = SqlPatternHintTool()

    # All tools to register
    tools = [
        http_tool,
        html_tool,
        regex_tool,
        robots_tool,
        cookie_inspector_tool,
        cookie_set_tool,
        form_submit_tool,
        js_source_tool,
        response_search_tool,
        sql_pattern_hint_tool,
    ]

    # Wrap them with LoggingToolWrapper and register
    for tool in tools:
        wrapped = LoggingToolWrapper(
            tool,
            flag_regex=config.flag_regex,
            log_callback=log_fn,
        )
        tool_registry.register_tool(wrapped)

    # ---- RAG: CTF knowledge base ----
    rag_retriever = initialize_knowledge_base(config, log_callback=log_fn)
    ctf_knowledge_tool = build_knowledge_tool(rag_retriever, config.platform_name)

    if ctf_knowledge_tool is not None:
        wrapped_rag = LoggingToolWrapper(
            ctf_knowledge_tool,
            flag_regex=config.flag_regex,
            log_callback=log_fn,
        )
        tool_registry.register_tool(wrapped_rag)
        log_fn("[Agent] Registered 'ctf_knowledge_query' RAG tool")
    else:
        log_fn("[Agent] WARNING: RAG knowledge base not available; 'ctf_knowledge_query' tool disabled")

    # Planner (ReAct) with PromptBuilder customization
    planner = ReActPlanner(llm, tool_registry)

    # === PromptBuilder Tuning: Role + Few-Shot Examples ===
    pb = planner.prompt_builder

    # 1. Custom RoleDefinition using configurable template
    role_text = get_role_definition(
        platform_name=config.platform_name,
        custom_role=config.agent_system_prompt,
    )
    pb.role_definition = RoleDefinition(role_text)

    # 2. Few-shot ReAct-style examples (generic CTF scenarios)
    pb.examples.clear()
    pb.examples.append(ROBOTS_EXAMPLE)
    pb.examples.append(JS_ANALYSIS_EXAMPLE)

    # === Tool executor, memory, and agent ===
    executor = ToolExecutor(tool_registry)
    memory = WorkingMemory()

    agent = SimpleAgent(
        llm=llm,
        planner=planner,
        tool_executor=executor,
        memory=memory,
        max_steps=config.max_steps,
    )

    # Short, high-level role description
    agent.role_description = (
        f"You are a {config.platform_name} web exploitation agent that uses tools to explore "
        "web challenges, reason about HTTP, HTML/JS, cookies, robots.txt, and SQL "
        "behavior, consults an internal CTF knowledge base when needed, and finally "
        "returns the discovered flag using the 'final_answer' tool."
    )

    log_fn(f"[Agent] Built successfully with {len(tools) + (1 if ctf_knowledge_tool else 0)} tools")

    return agent
