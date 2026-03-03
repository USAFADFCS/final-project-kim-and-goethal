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
    OAuthProbeTool,
    OAuthPayloadGenerator,
    PhpFilterChainTool,
    ParserDifferentialProbeTool,
    WebSocketProbeTool,
    WasmAnalyzerTool,
)
from ctf_solver.rag import initialize_knowledge_base, build_knowledge_tool, clear_cache
from ctf_solver.prompts import (
    get_role_definition,
    ROBOTS_EXAMPLE,
    JS_ANALYSIS_EXAMPLE,
    SELF_REFLECTION_EXAMPLE,
    JSON_API_EXAMPLE,
    COOKIE_BYPASS_EXAMPLE,
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

# Keywords that suggest the agent found something exploitable but hasn't used it
_EXPLOITABLE_KEYWORDS = re.compile(
    r"\b(password|credential|token|secret|api.?key|prefix|hardcoded|found.+in.+javascript"
    r"|found.+in.+JS|logged in|injection.+detected|vulnerability.+found"
    r"|bypass|endpoint|admin|protected.+page)\b",
    re.IGNORECASE,
)

# Recon-only tools (agent hasn't started exploitation yet)
_RECON_TOOLS = frozenset(
    {
        "http_fetch",
        "html_inspector",
        "javascript_source",
        "robots_txt",
        "cookie_inspector",
        "response_search",
        "regex_search",
        "path_enumerator",
        "backup_file_finder",
        "ctf_knowledge_query",
        "attack_planner",
    }
)


def _extract_json_object(text: str) -> Optional[str]:
    """
    Extract the first balanced JSON object ``{...}`` from mixed text.

    Handles cases where the LLM prepends/appends conversational text around
    valid JSON, e.g. "Sure, here's my response:\n{...}\nI chose this because..."
    """
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape_next = False

    for i in range(start, len(text)):
        ch = text[i]
        if escape_next:
            escape_next = False
            continue
        if ch == "\\":
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start : i + 1]
                # Quick sanity check: must parse as JSON
                try:
                    json.loads(candidate)
                    return candidate
                except json.JSONDecodeError:
                    return None
    return None


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
        """
        Override the planner's JSON parser to:
        1. Strip markdown code-block fences
        2. Extract embedded JSON from conversational responses
        3. Signal format errors instead of silently treating non-JSON as FinalAnswer

        The original fairlib parser treats *any* non-JSON response as a
        FinalAnswer, which causes premature termination when the LLM returns
        a conversational response (e.g. "I found the password, let me try
        logging in...").  This patch intercepts that fallback path.
        """
        if not hasattr(self.planner, "_parse_json_response"):
            return
        original_parse = self.planner._parse_json_response
        agent = self  # capture reference for the closure

        def _robust_parse(response_text: str):
            from fairlib.core.message import FinalAnswer as FA, Thought, Action

            text = response_text.strip()

            # Step 1: Strip markdown fences
            if text.startswith("```"):
                text = _MD_FENCE_OPEN.sub("", text)
                text = _MD_FENCE_CLOSE.sub("", text)
                text = text.strip()

            # Step 2: Check if text is valid JSON before calling original_parse.
            # We do our own check because original_parse catches JSONDecodeError
            # internally and returns FinalAnswer (the problem we're fixing).
            is_valid_json = False
            try:
                json.loads(text)
                is_valid_json = True
            except (json.JSONDecodeError, ValueError):
                pass

            if is_valid_json:
                # Valid JSON — use original parser directly (happy path)
                return original_parse(text)

            # Step 3: Not valid JSON — try to extract embedded JSON from text
            # (handles "Sure, here's my response: {...}" patterns)
            json_obj = _extract_json_object(text)
            if json_obj is not None:
                result = original_parse(json_obj)
                # Accept if it parsed into a Thought+Action tuple
                if not isinstance(result, FA):
                    return result
                # Also accept if it's an intentional final_answer tool call
                try:
                    data = json.loads(json_obj)
                    if data.get("action", {}).get("tool_name") == "final_answer":
                        return result
                except (json.JSONDecodeError, AttributeError):
                    pass

            # Step 4: No valid JSON found anywhere. Instead of silently returning
            # FinalAnswer (which the original parser would do), inject a format
            # error so the agent loop can re-prompt the LLM.
            agent._format_error_count = getattr(agent, "_format_error_count", 0) + 1
            agent._log_fn(
                f"[Parser] LLM returned non-JSON response "
                f"(format error #{agent._format_error_count}). "
                "Injecting format-error continuation instead of treating as FinalAnswer."
            )

            # After 3 format errors, fall back to original parser's behavior
            # (FinalAnswer) to avoid infinite loops
            if agent._format_error_count > 3:
                agent._log_fn(
                    "[Parser] Too many format errors. Falling back to original parser."
                )
                return original_parse(text)

            # Return a thought + action that triggers a tool-not-found error,
            # which naturally re-enters the loop with a corrective observation
            return (
                Thought(
                    text=(
                        "[FORMAT RECOVERY] My previous response was not valid JSON. "
                        "I must respond with ONLY a JSON object containing 'thought' and 'action' keys."
                    )
                ),
                Action(
                    tool_name="__format_error__",
                    tool_input=(
                        "YOUR RESPONSE WAS NOT VALID JSON. "
                        "You MUST respond with a raw JSON object like: "
                        '{"thought": "...", "action": {"tool_name": "...", "tool_input": "..."}}. '
                        "Do NOT include any text outside the JSON. "
                        "Do NOT use markdown code blocks. "
                        "Continue solving the challenge."
                    ),
                ),
            )

        self.planner._parse_json_response = _robust_parse

    # ── Flag detection ──────────────────────────────────────────────
    def _has_flag(self, text: str = "") -> bool:
        """Return True if a flag has been found anywhere."""
        if self._tracker and self._tracker.candidate_flags_found:
            return True
        if text and re.search(self._flag_regex, text):
            return True
        return False

    # ── Exploitable-finding detection ──────────────────────────────
    def _has_unexploited_findings(self, text: str) -> bool:
        """
        Detect when a FinalAnswer describes exploitable findings
        (credentials, vulnerabilities, endpoints) without a flag.

        This catches the common failure mode where the agent says
        "I found the password in the JS" but never actually used it.
        """
        return bool(_EXPLOITABLE_KEYWORDS.search(text))

    def _get_tools_used(self) -> List[str]:
        """Return the list of tool names used so far from the tracker."""
        if self._tracker and hasattr(self._tracker, "tool_call_log"):
            return [entry.get("tool_name", "") for entry in self._tracker.tool_call_log]
        return []

    def _only_recon_so_far(self) -> bool:
        """Return True if the agent has only used recon tools (no exploitation)."""
        tools_used = set(self._get_tools_used())
        return tools_used.issubset(_RECON_TOOLS) and len(tools_used) > 0

    def _build_guard_message(self, attempt: int, final_text: str) -> str:
        """
        Build an escalating continuation message based on the attempt number.

        Each retry is more specific about what to do next, based on what the
        agent has tried so far and what its attempted final answer contained.
        """
        base = (
            "Observation: [GUARD] You attempted to give a final answer, "
            "but NO FLAG has been found yet. "
            f"The flag must match the pattern: {self._flag_regex}\n\n"
        )

        tools_used = self._get_tools_used()
        tools_summary = ", ".join(set(tools_used[-10:])) if tools_used else "none"

        if attempt == 1:
            # First block: general guidance
            specific = (
                "REMEMBER: Finding information is NOT the same as solving the challenge.\n"
                "- If you found credentials/tokens in JavaScript, you MUST USE them to authenticate\n"
                "- If you found a protected URL, you MUST VISIT it\n"
                "- If you found a vulnerability, you MUST EXPLOIT it to extract data\n"
                f"\nTools you've used so far: {tools_summary}\n"
                "Continue investigating — the flag is at the END of the exploitation chain."
            )
        elif attempt == 2:
            # Second block: more urgent, include what was attempted
            has_findings = self._has_unexploited_findings(final_text)
            if has_findings:
                specific = (
                    "URGENT: Your answer mentions findings (credentials, endpoints, or vulnerabilities) "
                    "but you have NOT actually exploited them yet.\n"
                    f'Your attempted answer was: "{final_text[:300]}..."\n\n'
                    "You MUST:\n"
                    "1. If you found a credential/token → POST to the login endpoint with http_fetch\n"
                    "2. If login succeeds → visit the protected page to find the flag\n"
                    "3. If you found a vuln → use the appropriate exploit tool to extract data\n"
                    "Do NOT report findings as your answer. EXPLOIT them."
                )
            else:
                specific = (
                    "Your previous approach did not yield a flag. Try a COMPLETELY different approach:\n"
                    "- Check cookies, robots.txt, hidden fields, JavaScript source\n"
                    "- Try attack tools: sqli_probe, ssti_probe, lfi_probe, xpath_probe, nosql_probe, cmdi_probe\n"
                    "- Use 'attack_planner' for a structured plan\n"
                    "- Use 'ctf_knowledge_query' for technique suggestions\n"
                    f"\nTools already tried: {tools_summary}\n"
                    "Do NOT repeat what you already tried."
                )
        else:
            # Third+ block: last chance, very directive
            specific = (
                "FINAL WARNING: This is your last chance before the agent stops.\n"
                f'Your attempted answer was: "{final_text[:200]}..."\n'
                f"Tools used so far: {tools_summary}\n\n"
                "You MUST take a concrete exploitation action NOW:\n"
                "1. Use http_fetch to POST credentials you found to a login endpoint\n"
                "2. Use http_fetch to visit any protected URLs you discovered\n"
                "3. Use cookie_set to modify access-control cookies and re-fetch\n"
                "4. Use an injection tool to extract data from a confirmed vulnerability\n"
                "Pick ONE of these and do it immediately."
            )

        return base + specific

    # ── Overridden run loop ─────────────────────────────────────────
    async def arun(self, user_input: str) -> str:  # noqa: C901
        """ReAct loop with premature-FinalAnswer guard and progress checks."""
        if self.stateless:
            self.memory.clear()

        turn_messages: List[Message] = [Message(role="user", content=user_input)]
        current_request = user_input

        for step in range(self.max_steps):
            print(f"--- Step {step + 1}/{self.max_steps} ---")

            # ── Periodic progress check (every 5 steps) ──
            if step > 0 and step % 5 == 0 and not self._has_flag():
                tools_used = self._get_tools_used()
                tools_summary = (
                    ", ".join(set(tools_used[-10:])) if tools_used else "none"
                )
                progress_msg = Message(
                    role="system",
                    content=(
                        f"[PROGRESS CHECK — Step {step + 1}/{self.max_steps}]\n"
                        f"Tools used recently: {tools_summary}\n"
                        f"Flag found: NO\n"
                        "ASK YOURSELF:\n"
                        "  1. Am I making progress toward finding the flag?\n"
                        "  2. Have I followed up on ALL discoveries (credentials, endpoints, vulnerabilities)?\n"
                        "  3. Did I find something useful but forget to USE it?\n"
                        "  4. Should I try a completely different approach?\n"
                        "Remember: finding information ≠ solving the challenge. "
                        "You must EXPLOIT findings to get the flag."
                    ),
                )
                turn_messages.append(progress_msg)

            history = self.memory.get_history()
            plan_result = await self.planner.aplan(history, current_request)

            # ── FinalAnswer handling with escalating guard ──
            if isinstance(plan_result, FinalAnswer):
                final_answer_text = plan_result.text

                # Dynamic retry cap: allow more retries if early in the run
                budget_ratio = (step + 1) / self.max_steps
                max_retries = self.MAX_PREMATURE_RETRIES
                if budget_ratio < 0.4:
                    max_retries = self.MAX_PREMATURE_RETRIES + 2  # 5 retries if early
                elif budget_ratio > 0.8:
                    max_retries = max(
                        1, self.MAX_PREMATURE_RETRIES - 1
                    )  # 2 retries if late

                if (
                    not self._has_flag(final_answer_text)
                    and self._premature_fa_count < max_retries
                ):
                    self._premature_fa_count += 1
                    self._log_fn(
                        f"[Guard] Blocked premature Final Answer "
                        f"(attempt {self._premature_fa_count}/{max_retries}, "
                        f"step {step + 1}/{self.max_steps}). "
                        "No flag found yet — injecting continuation."
                    )
                    guard_text = self._build_guard_message(
                        self._premature_fa_count, final_answer_text
                    )
                    continuation = Message(role="system", content=guard_text)
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

            turn_messages.append(Message(role="assistant", content=assistant_content))

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
        self.memory.add_message(Message(role="assistant", content=final_response))
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
            f"{cat.value}({conf:.2f})" for cat, conf in result.secondary_categories[:3]
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
    - AUGMENTED_READONLY: same index as AUGMENTED (reads experience DB) but never writes
    """
    if mode == RAGMode.ORIGINAL:
        return config

    # AUGMENTED / AUGMENTED_READONLY: include experience knowledge docs
    augmented_docs_dirs = list(config.docs_dirs)
    failure_dir = config.failure_docs_dir
    if failure_dir not in augmented_docs_dirs:
        augmented_docs_dirs.append(failure_dir)

    # Use a separate vector store to avoid cross-contamination with original
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
            log_fn(
                f"[Agent] Using {caps.get('provider', 'unknown')} adapter with model: {caps.get('model', 'unknown')}"
            )
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

    # OAuth/OIDC tools
    oauth_probe_tool = OAuthProbeTool(session=shared_session)
    oauth_payload_generator = OAuthPayloadGenerator()

    # PHP filter chain tools (pure logic, no session)
    php_filter_chain_tool = PhpFilterChainTool()

    # Parser differential tools
    parser_differential_probe_tool = ParserDifferentialProbeTool(session=shared_session)

    # WebSocket tools (no session — uses websocket-client library)
    websocket_probe_tool = WebSocketProbeTool()

    # WASM / Reverse Engineering tools (session-based for fetch)
    wasm_analyzer_tool = WasmAnalyzerTool(session=shared_session)

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
        oauth_probe_tool,
        oauth_payload_generator,
        php_filter_chain_tool,
        parser_differential_probe_tool,
        websocket_probe_tool,
        wasm_analyzer_tool,
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
            log_fn(
                f"[Agent] Registered 'ctf_knowledge_query' RAG tool (mode: {rag_mode.value})"
            )
        else:
            log_fn(
                "[Agent] WARNING: RAG knowledge base not available; 'ctf_knowledge_query' tool disabled"
            )

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
    # Order: self-reflection first (primary failure mode), exploitation chains in middle,
    # most common success pattern last (primacy/recency bias)
    pb.examples.clear()
    pb.examples.append(SELF_REFLECTION_EXAMPLE)
    pb.examples.append(ROBOTS_EXAMPLE)
    pb.examples.append(JS_ANALYSIS_EXAMPLE)
    pb.examples.append(JSON_API_EXAMPLE)
    pb.examples.append(COOKIE_BYPASS_EXAMPLE)

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

    log_fn(
        f"[Agent] Built successfully with {len(tools) + (1 if ctf_knowledge_tool else 0)} tools"
    )

    return agent
