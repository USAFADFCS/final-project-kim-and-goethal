"""
Agent construction for CTF Solver.

Builds a FAIR SimpleAgent with all necessary tools, RAG, and configuration.
"""

import json
import logging
import os
import re
from typing import Callable, List, Optional

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
from fairlib.core.message import FinalAnswer, Message
from fairlib.modules.planning.react_planner import SimpleReActPlanner

from ctf_solver.config import SolverConfig, RAGMode
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
    ShellExecuteTool,
    XPathProbeTool,
    XPathBlindBooleanTool,
    XPathPayloadGenerator,
    FilterEnumeratorTool,
    PayloadMutatorTool,
    SsrfProbeTool,
    SsrfPayloadGenerator,
    AttackPlannerTool,
    LfiProbeTool,
    LfiPayloadGenerator,
    NosqlProbeTool,
    NosqlPayloadGenerator,
    CommandInjectionProbeTool,
    CommandInjectionPayloadGenerator,
    CryptoProbeTool,
    CryptoAnalyzerTool,
    CryptoPayloadGenerator,
    DeserializationProbeTool,
    DeserializationPayloadGenerator,
    XssProbeTool,
    XssPayloadGenerator,
    CspAnalyzerTool,
    GraphqlIntrospectionTool,
    GraphqlQueryTool,
    RaceConditionTool,
    RequestRepeaterTool,
    CrlfProbeTool,
    PhpTypeJugglingTool,
    PrototypePollutionTool,
    IdorEnumeratorTool,
    OpenRedirectProbeTool,
    CssInjectionPayloadGenerator,
    CssExfiltrationBuilder,
    HttpSmugglingProbeTool,
    FlaskSessionForgeryTool,
    DomClobberingPayloadGenerator,
)
from ctf_solver.rag import initialize_knowledge_base, build_knowledge_tool, clear_cache
from ctf_solver.prompts import (
    get_role_definition,
    ROBOTS_EXAMPLE,
    JS_ANALYSIS_EXAMPLE,
    SELF_REFLECTION_EXAMPLE,
    JSON_API_EXAMPLE,
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
from ctf_solver.run_tracker import RunTracker, TokenTrackingAdapter

logger = logging.getLogger(__name__)

# ── Markdown code-block stripping regex (compiled once) ──
_MD_FENCE_OPEN = re.compile(r"^```(?:json|JSON)?\s*\n?")
_MD_FENCE_CLOSE = re.compile(r"\n?```\s*$")


class CTFAgent(SimpleAgent):
    """
    CTF-specific agent that extends SimpleAgent with two guards:

    1. **Markdown stripping** — If the LLM wraps its JSON response in a
       markdown code block (```json ... ```), the parser would fail and
       treat the entire response as a FinalAnswer.  We monkey-patch the
       planner's ``_parse_json_response`` to strip these fences first.

    2. **Premature FinalAnswer prevention** — If the planner returns a
       FinalAnswer but no flag matching ``flag_regex`` has been seen
       (neither in the answer text nor in the tracker's candidate list),
       we inject a continuation system message and keep the loop running
       instead of stopping.
    """

    MAX_PREMATURE_RETRIES = 3

    def __init__(
        self,
        *args,
        tracker=None,
        flag_regex: str = r"(?:[A-Za-z0-9_]+)?\{[^\n\r{}]{1,200}\}",
        log_callback: Optional[Callable[[str], None]] = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._tracker = tracker
        self._flag_regex = flag_regex
        self._log_fn = log_callback or print
        self._premature_fa_count = 0
        self._patch_planner_parsing()

    # ── Planner monkey-patch ────────────────────────────────────────
    def _patch_planner_parsing(self):
        """Strip markdown code-block fences before JSON parsing."""
        if not hasattr(self.planner, "_parse_json_response"):
            return
        original_parse = self.planner._parse_json_response

        def _strip_and_parse(response_text: str):
            text = response_text.strip()
            if text.startswith("```"):
                text = _MD_FENCE_OPEN.sub("", text)
                text = _MD_FENCE_CLOSE.sub("", text)
                text = text.strip()
            return original_parse(text)

        self.planner._parse_json_response = _strip_and_parse

    # ── Flag detection ──────────────────────────────────────────────
    def _has_flag(self, text: str = "") -> bool:
        """Return True if a flag has been found anywhere."""
        if self._tracker and self._tracker.candidate_flags_found:
            return True
        if text and re.search(self._flag_regex, text):
            return True
        return False

    # ── Overridden run loop ─────────────────────────────────────────
    async def arun(self, user_input: str) -> str:  # noqa: C901
        """ReAct loop with premature-FinalAnswer guard."""
        if self.stateless:
            self.memory.clear()

        turn_messages: List[Message] = [Message(role="user", content=user_input)]
        current_request = user_input

        for step in range(self.max_steps):
            print(f"--- Step {step + 1}/{self.max_steps} ---")

            history = self.memory.get_history()
            plan_result = await self.planner.aplan(history, current_request)

            # ── FinalAnswer handling with guard ──
            if isinstance(plan_result, FinalAnswer):
                final_answer_text = plan_result.text

                if (
                    not self._has_flag(final_answer_text)
                    and self._premature_fa_count < self.MAX_PREMATURE_RETRIES
                ):
                    self._premature_fa_count += 1
                    self._log_fn(
                        f"[Guard] Blocked premature Final Answer "
                        f"(attempt {self._premature_fa_count}/{self.MAX_PREMATURE_RETRIES}). "
                        "No flag found yet — injecting continuation."
                    )
                    continuation = Message(
                        role="system",
                        content=(
                            "Observation: [GUARD] You attempted to give a final answer, "
                            "but NO FLAG has been found yet. "
                            f"The flag must match the pattern: {self._flag_regex}\n"
                            "You MUST continue investigating. Try a different approach:\n"
                            "- Check cookies, robots.txt, hidden fields, JavaScript source\n"
                            "- Try attack tools: sqli_probe, ssti_probe, lfi_probe, xpath_probe, nosql_probe, cmdi_probe\n"
                            "- Use 'attack_planner' for a structured plan\n"
                            "- Use 'ctf_knowledge_query' for technique suggestions\n"
                            "Do NOT repeat what you already tried."
                        ),
                    )
                    turn_messages.append(continuation)
                    for msg in turn_messages:
                        self.memory.add_message(msg)
                    turn_messages = []
                    current_request = ""
                    continue

                # Genuine final answer (flag found or retries exhausted)
                print(f"Thought: {final_answer_text}")
                print("Action: Final Answer")
                turn_messages.append(
                    Message(role="assistant", content=final_answer_text)
                )
                for msg in turn_messages:
                    self.memory.add_message(msg)
                return final_answer_text

            # ── Normal thought + action ──
            try:
                thought, action = plan_result
                print(f"Thought: {thought.text}")
                print(
                    f"Action: Using tool '{action.tool_name}' with input '{action.tool_input}'"
                )
            except (ValueError, TypeError):
                error_message = (
                    "Error: The planner returned a malformed response. Ending task."
                )
                print(error_message)
                return error_message

            # Build history message in the format expected by the planner
            if isinstance(self.planner, SimpleReActPlanner):
                assistant_content = (
                    f"Thought: {thought.text}\n"
                    f"Action:\n"
                    f"tool_name: {action.tool_name}\n"
                    f"tool_input: {action.tool_input}"
                )
            else:
                assistant_content = json.dumps(
                    {
                        "thought": thought.text,
                        "action": {
                            "tool_name": action.tool_name,
                            "tool_input": action.tool_input,
                        },
                    },
                    indent=4,
                )

            turn_messages.append(
                Message(role="assistant", content=assistant_content)
            )

            try:
                observation_output = self.tool_executor.execute(
                    action.tool_name, action.tool_input
                )
                print(f"Observation: {observation_output}")
            except Exception as e:
                observation_output = f"Error: {e}"
                print(observation_output)

            turn_messages.append(
                Message(
                    role="system",
                    content=f"Observation: {str(observation_output)}",
                )
            )

            for msg in turn_messages:
                self.memory.add_message(msg)

            turn_messages = []
            current_request = ""

        final_response = "Agent stopped after reaching max steps."
        self.memory.add_message(
            Message(role="assistant", content=final_response)
        )
        return final_response


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


def _build_rag_config(config: SolverConfig, mode: RAGMode) -> SolverConfig:
    """
    Create a modified config for RAG initialization based on the selected mode.

    - ORIGINAL: uses config.docs_dirs and config.vector_store_dir (default behavior)
    - AUGMENTED: adds failure_docs_dir to docs_dirs and uses a separate vector store
    """
    if mode == RAGMode.ORIGINAL:
        return config

    # AUGMENTED mode: include failure knowledge docs
    augmented_docs_dirs = list(config.docs_dirs)
    failure_dir = config.failure_docs_dir
    if failure_dir not in augmented_docs_dirs:
        augmented_docs_dirs.append(failure_dir)

    # Use a separate vector store to avoid cross-contamination
    augmented_vector_store = config.vector_store_dir + "_augmented"

    return config.merge_with_args(
        docs_dirs=augmented_docs_dirs,
        vector_store_dir=augmented_vector_store,
    )


def build_agent(
    config: SolverConfig,
    log_callback: Optional[Callable[[str], None]] = None,
    tracker: Optional[RunTracker] = None,
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

    # Wrap the LLM adapter for token tracking when a tracker is provided
    if tracker is not None:
        llm = TokenTrackingAdapter(llm, tracker)

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

    # Shell execution tool (general-purpose command runner)
    shell_tool = ShellExecuteTool()

    # XPath injection tools
    xpath_probe_tool = XPathProbeTool(session=shared_session)
    xpath_blind_boolean_tool = XPathBlindBooleanTool(session=shared_session)
    xpath_payload_generator = XPathPayloadGenerator()

    # Filter bypass tools
    filter_enumerator_tool = FilterEnumeratorTool(session=shared_session)
    payload_mutator_tool = PayloadMutatorTool()

    # SSRF tools
    ssrf_probe_tool = SsrfProbeTool(session=shared_session)
    ssrf_payload_generator = SsrfPayloadGenerator()

    # Attack planner (pure logic, no session)
    attack_planner_tool = AttackPlannerTool()

    # LFI/RFI tools
    lfi_probe_tool = LfiProbeTool(session=shared_session)
    lfi_payload_generator = LfiPayloadGenerator()

    # NoSQL injection tools
    nosql_probe_tool = NosqlProbeTool(session=shared_session)
    nosql_payload_generator = NosqlPayloadGenerator()

    # Command injection tools
    cmdi_probe_tool = CommandInjectionProbeTool(session=shared_session)
    cmdi_payload_generator = CommandInjectionPayloadGenerator()

    # Crypto tools
    crypto_probe_tool = CryptoProbeTool(session=shared_session)
    crypto_analyzer_tool = CryptoAnalyzerTool()
    crypto_payload_generator = CryptoPayloadGenerator()

    # Deserialization tools
    deserialization_probe_tool = DeserializationProbeTool(session=shared_session)
    deserialization_payload_generator = DeserializationPayloadGenerator()

    # XSS tools
    xss_probe_tool = XssProbeTool(session=shared_session)
    xss_payload_generator = XssPayloadGenerator()
    csp_analyzer_tool = CspAnalyzerTool(session=shared_session)

    # GraphQL tools
    graphql_introspection_tool = GraphqlIntrospectionTool(session=shared_session)
    graphql_query_tool = GraphqlQueryTool(session=shared_session)

    # Race condition tools
    race_condition_tool = RaceConditionTool(session=shared_session)

    # Fuzzer tools
    request_repeater_tool = RequestRepeaterTool(session=shared_session)

    # Misc probe tools
    crlf_probe_tool = CrlfProbeTool(session=shared_session)
    php_type_juggling_tool = PhpTypeJugglingTool()
    prototype_pollution_tool = PrototypePollutionTool(session=shared_session)
    idor_enumerator_tool = IdorEnumeratorTool(session=shared_session)
    open_redirect_probe_tool = OpenRedirectProbeTool(session=shared_session)

    # CSS injection tools (pure logic, no session)
    css_injection_payload_generator = CssInjectionPayloadGenerator()
    css_exfiltration_builder = CssExfiltrationBuilder()

    # HTTP smuggling tools
    http_smuggling_probe_tool = HttpSmugglingProbeTool(session=shared_session)

    # Session forgery tools
    flask_session_forgery_tool = FlaskSessionForgeryTool()
    dom_clobbering_payload_generator = DomClobberingPayloadGenerator()

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
        shell_tool,
        xpath_probe_tool,
        xpath_blind_boolean_tool,
        xpath_payload_generator,
        filter_enumerator_tool,
        payload_mutator_tool,
        ssrf_probe_tool,
        ssrf_payload_generator,
        attack_planner_tool,
        lfi_probe_tool,
        lfi_payload_generator,
        nosql_probe_tool,
        nosql_payload_generator,
        cmdi_probe_tool,
        cmdi_payload_generator,
        crypto_probe_tool,
        crypto_analyzer_tool,
        crypto_payload_generator,
        deserialization_probe_tool,
        deserialization_payload_generator,
        xss_probe_tool,
        xss_payload_generator,
        csp_analyzer_tool,
        graphql_introspection_tool,
        graphql_query_tool,
        race_condition_tool,
        request_repeater_tool,
        crlf_probe_tool,
        php_type_juggling_tool,
        prototype_pollution_tool,
        idor_enumerator_tool,
        open_redirect_probe_tool,
        css_injection_payload_generator,
        css_exfiltration_builder,
        http_smuggling_probe_tool,
        flask_session_forgery_tool,
        dom_clobbering_payload_generator,
    ]

    # Wrap them with LoggingToolWrapper and register
    for tool in tools:
        wrapped = LoggingToolWrapper(
            tool,
            flag_regex=config.flag_regex,
            log_callback=log_fn,
            tracker=tracker,
        )
        tool_registry.register_tool(wrapped)

    # ---- RAG: Mode-aware knowledge base ----
    rag_mode = config.rag_mode
    if isinstance(rag_mode, str):
        try:
            rag_mode = RAGMode(rag_mode.lower())
        except ValueError:
            rag_mode = RAGMode.ORIGINAL

    # Record RAG mode in tracker
    if tracker is not None:
        tracker.rag_mode = rag_mode.value

    ctf_knowledge_tool = None

    if rag_mode == RAGMode.NONE:
        log_fn("[Agent] RAG mode: NONE — knowledge base disabled")
    else:
        # Build a mode-specific config for RAG initialization
        rag_config = _build_rag_config(config, rag_mode)
        # Clear cache to ensure mode switch takes effect
        clear_cache()
        rag_retriever = initialize_knowledge_base(rag_config, log_callback=log_fn)
        ctf_knowledge_tool = build_knowledge_tool(rag_retriever, config.platform_name)

        if ctf_knowledge_tool is not None:
            wrapped_rag = LoggingToolWrapper(
                ctf_knowledge_tool,
                flag_regex=config.flag_regex,
                log_callback=log_fn,
                tracker=tracker,
            )
            tool_registry.register_tool(wrapped_rag)
            log_fn(f"[Agent] Registered 'ctf_knowledge_query' RAG tool (mode: {rag_mode.value})")
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
    pb.examples.append(SELF_REFLECTION_EXAMPLE)
    pb.examples.append(JSON_API_EXAMPLE)

    # === Tool executor, memory, and agent ===
    executor = ToolExecutor(tool_registry)
    memory = WorkingMemory()

    agent = CTFAgent(
        llm=llm,
        planner=planner,
        tool_executor=executor,
        memory=memory,
        max_steps=config.max_steps,
        tracker=tracker,
        flag_regex=config.flag_regex,
        log_callback=log_fn,
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
