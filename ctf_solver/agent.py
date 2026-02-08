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
    EncodingTool,
    HashIdentifierTool,
    ResponseDiffTool,
    TimingCompareTool,
    ResponseFingerprinter,
    PathEnumeratorTool,
    BackupFileFinder,
    SqliProbeTool,
    SqliColumnCounter,
    BlindSqliBooleanTool,
    BlindSqliTimeTool,
    SqliDataDumper,
    JwtTool,
    SstiProbeTool,
    SstiExploitSuggester,
    FileUploadTool,
    UploadLocationFinder,
    XxeProbeTool,
    XxePayloadGenerator,
    XxeDocTypeBuilder,
)
from ctf_solver.rag import initialize_knowledge_base, build_knowledge_tool
from ctf_solver.prompts import (
    get_role_definition,
    ROBOTS_EXAMPLE,
    JS_ANALYSIS_EXAMPLE,
)
from ctf_solver.classifier import (
    ChallengeClassifier,
    ClassificationResult,
    ChallengeCategory,
    create_classifier,
)
from ctf_solver.llm import (
    LLMProvider,
    create_adapter,
    create_adapter_from_config,
    check_provider_available,
)
from ctf_solver.config import LLMProviderType

logger = logging.getLogger(__name__)


def classify_challenge(
    config: SolverConfig,
    response_content: Optional[str] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> ClassificationResult:
    """
    Classify a challenge based on configuration and optional response content.

    Args:
        config: Solver configuration with challenge_url, description, hints
        response_content: Optional initial response content for analysis
        log_callback: Optional callback for logging

    Returns:
        ClassificationResult with category, confidence, and suggestions
    """
    log_fn = log_callback or print
    classifier = create_classifier()

    result = classifier.classify_from_config(config, response_content)

    log_fn(f"[Classifier] Challenge classified as: {result.primary_category.value}")
    log_fn(f"[Classifier] Confidence: {result.confidence:.2f}")

    if result.secondary_categories:
        secondary = ", ".join(
            f"{cat.value}({conf:.2f})"
            for cat, conf in result.secondary_categories[:3]
        )
        log_fn(f"[Classifier] Also possible: {secondary}")

    if result.suggested_tools:
        tools = ", ".join(result.suggested_tools[:5])
        log_fn(f"[Classifier] Recommended tools: {tools}")

    return result


def get_classification_context(result: ClassificationResult) -> str:
    """
    Generate context text for the agent based on classification result.

    Args:
        result: ClassificationResult from classify_challenge

    Returns:
        Context string to include in agent prompt
    """
    lines = [
        f"Challenge Classification: {result.primary_category.value.upper()}",
        f"Confidence: {result.confidence:.0%}",
    ]

    if result.secondary_categories:
        secondary = [cat.value for cat, _ in result.secondary_categories[:2]]
        lines.append(f"Also consider: {', '.join(secondary)}")

    lines.append("")
    lines.append("Suggested Approach:")
    lines.append(result.suggested_approach)

    lines.append("")
    lines.append(f"Priority Tools: {', '.join(result.suggested_tools[:5])}")

    return "\n".join(lines)


def build_agent(
    config: SolverConfig,
    log_callback: Optional[Callable[[str], None]] = None,
) -> SimpleAgent:
    """
    Construct and return a SimpleAgent wired up with:

      - LLM adapter (OpenAI, Anthropic, Ollama, or Hybrid)
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

    # Get the LLM provider from config
    provider = getattr(config, "llm_provider", LLMProviderType.OPENAI)

    # Check if provider is available
    if isinstance(provider, str):
        try:
            provider = LLMProviderType(provider.lower())
        except ValueError:
            pass  # Keep as string, will be handled by adapter factory

    # Create the LLM adapter based on provider
    if provider == LLMProviderType.OPENAI or provider == "openai":
        # OpenAI path (original behavior for backward compatibility)
        if not config.openai_api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Set it in your environment, .env file, or config."
            )
        settings.api_keys.openai_api_key = config.openai_api_key
        llm = OpenAIAdapter(
            api_key=settings.api_keys.openai_api_key,
            model_name=config.model_name,
        )
        log_fn(f"[Agent] Using OpenAI adapter with model: {config.model_name}")
    else:
        # Use the adapter factory for other providers
        try:
            llm = create_adapter_from_config(config)
            caps = llm.get_model_capabilities()
            log_fn(f"[Agent] Using {caps.get('provider', 'unknown')} adapter with model: {caps.get('model', 'unknown')}")
        except ImportError as e:
            # Fall back to OpenAI if the requested provider is not available
            log_fn(f"[Agent] Warning: {e}. Falling back to OpenAI.")
            if not config.openai_api_key:
                raise RuntimeError(
                    "OPENAI_API_KEY is not set and fallback is required. "
                    "Set it in your environment, .env file, or config."
                )
            settings.api_keys.openai_api_key = config.openai_api_key
            llm = OpenAIAdapter(
                api_key=settings.api_keys.openai_api_key,
                model_name=config.model_name,
            )
            log_fn(f"[Agent] Using OpenAI adapter with model: {config.model_name}")

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

    # Encoding/utility tools (no session needed)
    encoding_tool = EncodingTool()
    hash_identifier_tool = HashIdentifierTool()

    # Diff/comparison tools
    response_diff_tool = ResponseDiffTool()
    timing_compare_tool = TimingCompareTool(session=shared_session)
    response_fingerprint_tool = ResponseFingerprinter()

    # Enumeration tools
    path_enumerator_tool = PathEnumeratorTool(session=shared_session)
    backup_finder_tool = BackupFileFinder(session=shared_session)

    # SQL Injection tools
    sqli_probe_tool = SqliProbeTool(session=shared_session)
    sqli_column_counter_tool = SqliColumnCounter(session=shared_session)

    # Blind SQL Injection tools
    blind_sqli_boolean_tool = BlindSqliBooleanTool(session=shared_session)
    blind_sqli_time_tool = BlindSqliTimeTool(session=shared_session)
    sqli_data_dumper_tool = SqliDataDumper(session=shared_session)

    # JWT tools (no session needed)
    jwt_tool = JwtTool()

    # SSTI tools
    ssti_probe_tool = SstiProbeTool(session=shared_session)
    ssti_exploit_suggester = SstiExploitSuggester()

    # File upload tools
    file_upload_tool = FileUploadTool(session=shared_session)
    upload_location_finder = UploadLocationFinder(session=shared_session)

    # XXE tools
    xxe_probe_tool = XxeProbeTool(session=shared_session)
    xxe_payload_generator = XxePayloadGenerator()
    xxe_doctype_builder = XxeDocTypeBuilder()

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
        encoding_tool,
        hash_identifier_tool,
        response_diff_tool,
        timing_compare_tool,
        response_fingerprint_tool,
        path_enumerator_tool,
        backup_finder_tool,
        sqli_probe_tool,
        sqli_column_counter_tool,
        blind_sqli_boolean_tool,
        blind_sqli_time_tool,
        sqli_data_dumper_tool,
        jwt_tool,
        ssti_probe_tool,
        ssti_exploit_suggester,
        file_upload_tool,
        upload_location_finder,
        xxe_probe_tool,
        xxe_payload_generator,
        xxe_doctype_builder,
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
