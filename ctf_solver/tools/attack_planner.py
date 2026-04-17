"""
Multi-phase attack planning tool for CTF solving.

Provides intelligent attack plan generation based on challenge type,
current findings, and tools already tried.
"""

import json
from typing import Dict, List


class AttackPlannerTool:
    """
    AttackPlannerTool: generate multi-phase attack plans for CTF challenges.

    A pure-logic tool that suggests structured attack plans based on challenge
    type, incorporating knowledge of available tools and common attack patterns.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Supported operations:
      - suggest_plan: Generate a full multi-step attack plan
      - suggest_next_step: Suggest the single best next action

    Expected JSON tool_input format:

        {
          "operation": "suggest_plan",
          "challenge_type": "sql_injection",
          "current_findings": "found login form with username/password fields",
          "tools_tried": ["http_fetch"]
        }
    """

    name: str = "attack_planner"
    description: str = (
        "Generate multi-phase attack plans for CTF challenges. Input must be JSON with keys: "
        "'operation' ('suggest_plan' or 'suggest_next_step'), 'challenge_type' (e.g. "
        "'sql_injection', 'xpath_injection', 'file_inclusion', 'command_injection', 'ssrf', "
        "'nosql_injection', 'crypto', 'deserialization', 'file_upload', 'filter_bypass', "
        "'ssti', 'xxe', 'jwt', 'unknown'). Optional keys: 'current_findings' (string describing "
        "what you know so far), 'tools_tried' (list of tool names already used), "
        "'steps_completed' (list of completed step descriptions), 'last_result' (string with "
        "last tool output). Use this tool to get a structured attack plan or determine the "
        "next best action."
    )

    # Predefined attack plans keyed by challenge type.
    # Each plan is a list of (step_description, tool_name) tuples.
    ATTACK_PLANS: Dict[str, List[tuple]] = {
        "sql_injection": [
            (
                "Probe for SQL injection vulnerabilities using common payloads",
                "sqli_probe",
            ),
            ("Check for input filters and blocked keywords", "filter_enumerator"),
            ("Determine the number of columns in the query", "sqli_column_counter"),
            (
                "Extract data using blind boolean-based SQL injection",
                "blind_sqli_boolean",
            ),
            (
                "Dump database contents with UNION or error-based techniques",
                "sqli_data_dumper",
            ),
        ],
        "xpath_injection": [
            ("Probe for XPath injection points", "xpath_probe"),
            (
                "Detect oracle inversion and extract boolean responses",
                "xpath_blind_boolean",
            ),
            (
                "Extract data character by character using blind XPath injection",
                "xpath_blind_boolean",
            ),
        ],
        "file_inclusion": [
            ("Probe for path traversal and local file inclusion", "lfi_probe"),
            (
                "Try PHP wrappers (php://filter, php://input, data://) for source disclosure",
                "lfi_payload_generator",
            ),
            ("Read the flag file or application source code", "lfi_probe"),
            ("Chain with log poisoning if direct read fails", "lfi_payload_generator"),
        ],
        "command_injection": [
            ("Probe for command injection using common delimiters", "cmdi_probe"),
            ("Confirm injection with time-based payloads (e.g. sleep)", "cmdi_probe"),
            ("Extract command output or read the flag file", "cmdi_probe"),
        ],
        "ssrf": [
            ("Probe for SSRF using common internal URLs", "ssrf_probe"),
            ("Try cloud metadata endpoints (169.254.169.254, etc.)", "ssrf_probe"),
            ("Attempt internal service discovery on common ports", "ssrf_probe"),
            ("Use protocol handlers (file://, gopher://, dict://)", "ssrf_probe"),
        ],
        "nosql_injection": [
            ("Probe for NoSQL injection using operator payloads", "nosql_probe"),
            ("Try authentication bypass with $ne/$gt operators", "nosql_probe"),
            ("Extract data using regex-based blind NoSQL injection", "nosql_probe"),
        ],
        "crypto": [
            ("Identify the cryptographic scheme and parameters", "crypto_analyzer"),
            ("Detect weaknesses in the implementation", "crypto_probe"),
            (
                "Generate attack payloads targeting identified weaknesses",
                "crypto_payload_generator",
            ),
        ],
        "deserialization": [
            (
                "Detect the serialization format (PHP, Java, Python pickle, etc.)",
                "deserialization_probe",
            ),
            (
                "Craft malicious deserialization payload",
                "deserialization_payload_generator",
            ),
            (
                "Trigger execution by submitting the crafted payload",
                "deserialization_payload_generator",
            ),
        ],
        "file_upload": [
            (
                "Analyze upload restrictions (allowed types, size limits, validation)",
                "file_upload",
            ),
            (
                "Bypass extension filtering using double extensions, null bytes, etc.",
                "file_upload",
            ),
            ("Upload a web shell or malicious file", "file_upload"),
            (
                "Find the upload location to access the uploaded file",
                "upload_location_finder",
            ),
        ],
        "filter_bypass": [
            (
                "Enumerate blocked keywords and characters systematically",
                "filter_enumerator",
            ),
            (
                "Generate bypass variants using encoding, case mixing, concatenation",
                "payload_mutator",
            ),
            ("Retry the original attack with clean bypass payloads", "payload_mutator"),
        ],
        "ssti": [
            (
                "Probe for Server-Side Template Injection using math expressions",
                "ssti_probe",
            ),
            (
                "Identify the template engine (Jinja2, Twig, Freemarker, etc.)",
                "ssti_probe",
            ),
            (
                "Get exploit suggestions for the identified engine",
                "ssti_exploit_suggester",
            ),
        ],
        "xxe": [
            ("Probe for XML External Entity injection", "xxe_probe"),
            (
                "Generate XXE payloads for file read, SSRF, or data exfiltration",
                "xxe_payload_generator",
            ),
            (
                "Try reading sensitive files (/etc/passwd, flag, source code)",
                "xxe_payload_generator",
            ),
        ],
        "jwt": [
            ("Decode and analyze the JWT token structure", "jwt_tool"),
            ("Test for algorithm confusion (alg:none, RS256->HS256)", "jwt_tool"),
            ("Forge a new token with modified claims", "jwt_tool"),
        ],
        "unknown": [
            (
                "Perform initial reconnaissance by fetching the target page",
                "http_fetch",
            ),
            (
                "Inspect HTML source for hidden fields, comments, and clues",
                "html_analyzer",
            ),
            ("Check robots.txt, .git/, and other common paths", "http_fetch"),
            (
                "Try common injection types (SQLi, XSS, LFI, command injection)",
                "sqli_probe",
            ),
            (
                "Consult CTF knowledge base for hints based on challenge description",
                "ctf_knowledge_query",
            ),
        ],
    }

    def __init__(self) -> None:
        pass

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[AttackPlannerTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        operation = data.get("operation")
        if not operation:
            return "[AttackPlannerTool] Error: 'operation' is required."

        if operation not in ("suggest_plan", "suggest_next_step"):
            return (
                f"[AttackPlannerTool] Error: Unknown operation '{operation}'. "
                f"Valid operations: suggest_plan, suggest_next_step"
            )

        challenge_type = data.get("challenge_type")
        if not challenge_type:
            return "[AttackPlannerTool] Error: 'challenge_type' is required."

        if operation == "suggest_plan":
            return self._suggest_plan(
                challenge_type=challenge_type,
                current_findings=data.get("current_findings", ""),
                tools_tried=data.get("tools_tried", []),
            )
        else:
            return self._suggest_next_step(
                challenge_type=challenge_type,
                steps_completed=data.get("steps_completed", []),
                last_result=data.get("last_result", ""),
            )

    def _suggest_plan(
        self,
        challenge_type: str,
        current_findings: str,
        tools_tried: List[str],
    ) -> str:
        """Generate a full multi-step attack plan."""
        # Fall back to 'unknown' if the challenge type is not recognized
        if challenge_type not in self.ATTACK_PLANS:
            challenge_type = "unknown"

        plan_steps = self.ATTACK_PLANS[challenge_type]

        output_lines = [
            f"[AttackPlannerTool] Attack Plan for: {challenge_type}",
            "",
        ]

        # Include current findings context if provided
        if current_findings:
            output_lines.append(f"Current findings: {current_findings}")
            output_lines.append("")
            # Add contextual adjustments
            adjustments = self._adjust_for_findings(challenge_type, current_findings)
            if adjustments:
                output_lines.append("Adjustments based on findings:")
                for adj in adjustments:
                    output_lines.append(f"  - {adj}")
                output_lines.append("")

        output_lines.append("=== ATTACK PLAN ===")

        step_num = 1
        skipped_tools = []
        for description, tool_name in plan_steps:
            if tool_name in tools_tried:
                skipped_tools.append(
                    f"  [SKIP] Step: {description} (tool '{tool_name}' already tried)"
                )
            else:
                output_lines.append(f"  {step_num}. {description}")
                output_lines.append(f"     Tool: {tool_name}")
                step_num += 1

        if skipped_tools:
            output_lines.append("")
            output_lines.append("=== SKIPPED STEPS (tools already tried) ===")
            output_lines.extend(skipped_tools)

        if step_num == 1:
            output_lines.append("  All planned tools have already been tried.")
            output_lines.append(
                "  Consider trying a different challenge_type or reviewing findings."
            )

        output_lines.append("")
        output_lines.append(f"Total steps: {step_num - 1}")

        return "\n".join(output_lines)

    def _suggest_next_step(
        self,
        challenge_type: str,
        steps_completed: List[str],
        last_result: str,
    ) -> str:
        """Suggest the single best next action."""
        # Fall back to 'unknown' if the challenge type is not recognized
        if challenge_type not in self.ATTACK_PLANS:
            challenge_type = "unknown"

        plan_steps = self.ATTACK_PLANS[challenge_type]

        # Determine which phase we're in by matching completed steps to plan phases
        completed_phase = self._match_completed_phase(steps_completed, plan_steps)

        # Find the next uncompleted phase
        next_phase_idx = completed_phase + 1 if completed_phase >= 0 else 0
        if next_phase_idx >= len(plan_steps):
            next_phase_idx = len(plan_steps) - 1

        next_description, next_tool = plan_steps[next_phase_idx]

        output_lines = [
            f"[AttackPlannerTool] Next Step Suggestion for: {challenge_type}",
            "",
        ]

        if steps_completed:
            output_lines.append(f"Steps completed so far: {len(steps_completed)}")
            for sc in steps_completed:
                output_lines.append(f"  - {sc}")
            output_lines.append("")

        if last_result:
            output_lines.append(
                f"Last result summary: {last_result[:200]}{'...' if len(last_result) > 200 else ''}"
            )
            output_lines.append("")

        # Check if all steps are done
        if completed_phase >= len(plan_steps) - 1 and steps_completed:
            output_lines.append("All planned phases appear to be completed.")
            output_lines.append("Suggestions:")
            output_lines.append("  - Review all collected data for the flag")
            output_lines.append("  - Try a different attack vector if no flag found")
            output_lines.append("  - Re-examine earlier findings with new context")
            return "\n".join(output_lines)

        output_lines.append("=== RECOMMENDED NEXT STEP ===")
        output_lines.append(
            f"  Phase {next_phase_idx + 1}/{len(plan_steps)}: {next_description}"
        )
        output_lines.append(f"  Tool: {next_tool}")
        output_lines.append("")

        # Provide suggested input parameters based on the tool
        suggested_input = self._suggest_input(next_tool, challenge_type, last_result)
        if suggested_input:
            output_lines.append("Suggested tool input:")
            output_lines.append(f"  {suggested_input}")

        return "\n".join(output_lines)

    def _match_completed_phase(
        self, steps_completed: List[str], plan_steps: List[tuple]
    ) -> int:
        """
        Match completed steps to plan phases.
        Returns the index of the highest matched phase, or -1 if none matched.
        """
        if not steps_completed:
            return -1

        best_match = -1
        steps_lower = [s.lower() for s in steps_completed]

        for idx, (description, tool_name) in enumerate(plan_steps):
            desc_lower = description.lower()
            tool_lower = tool_name.lower()
            for completed in steps_lower:
                # Match if the completed step mentions the tool or key words from the description
                if tool_lower in completed or any(
                    word in completed
                    for word in desc_lower.split()
                    if len(word) > 4  # Only match on meaningful words
                ):
                    if idx > best_match:
                        best_match = idx

        return best_match

    def _adjust_for_findings(self, challenge_type: str, findings: str) -> List[str]:
        """Generate contextual adjustments based on current findings."""
        adjustments = []
        findings_lower = findings.lower()

        # Common finding patterns
        if "login" in findings_lower or "auth" in findings_lower:
            adjustments.append(
                "Login form detected - prioritize authentication bypass payloads"
            )

        if "error" in findings_lower or "sql" in findings_lower:
            adjustments.append(
                "SQL errors detected - try error-based extraction techniques"
            )

        if (
            "filter" in findings_lower
            or "blocked" in findings_lower
            or "waf" in findings_lower
        ):
            adjustments.append(
                "Input filtering detected - add filter bypass as an early step"
            )

        if "blind" in findings_lower or "no output" in findings_lower:
            adjustments.append(
                "No direct output - focus on blind/boolean-based techniques"
            )

        if (
            "cookie" in findings_lower
            or "session" in findings_lower
            or "token" in findings_lower
        ):
            adjustments.append(
                "Session/token found - check for JWT vulnerabilities or session manipulation"
            )

        if "upload" in findings_lower or "file" in findings_lower:
            adjustments.append(
                "File functionality detected - consider file upload or file inclusion attacks"
            )

        if "xml" in findings_lower:
            adjustments.append("XML processing detected - consider XXE injection")

        if "template" in findings_lower:
            adjustments.append("Template processing detected - consider SSTI attacks")

        return adjustments

    def _suggest_input(
        self, tool_name: str, challenge_type: str, last_result: str
    ) -> str:
        """Suggest input parameters for the next tool."""
        suggestions = {
            "sqli_probe": '{"url": "<target_url>", "param": "<vulnerable_param>", "method": "POST"}',
            "filter_enumerator": '{"url": "<target_url>", "param": "<vulnerable_param>", "method": "POST"}',
            "sqli_column_counter": '{"url": "<target_url>", "param": "<vulnerable_param>", "max_columns": 10}',
            "blind_sqli_boolean": '{"url": "<target_url>", "param": "<vulnerable_param>", "true_indicator": "<string_in_true_response>"}',
            "sqli_data_dumper": '{"url": "<target_url>", "param": "<vulnerable_param>", "num_columns": 3}',
            "xpath_probe": '{"url": "<target_url>", "param": "<vulnerable_param>"}',
            "xpath_blind_boolean": '{"url": "<target_url>", "param": "<vulnerable_param>", "true_indicator": "<string_in_true_response>"}',
            "lfi_probe": '{"url": "<target_url>", "param": "<file_param>"}',
            "lfi_payload_generator": '{"wrapper": "php_filter", "target_file": "/etc/passwd"}',
            "cmdi_probe": '{"url": "<target_url>", "param": "<vulnerable_param>"}',
            "ssrf_probe": '{"url": "<target_url>", "param": "<url_param>"}',
            "nosql_probe": '{"url": "<target_url>", "param": "<vulnerable_param>"}',
            "crypto_analyzer": '{"ciphertext": "<encrypted_data>"}',
            "crypto_probe": '{"ciphertext": "<encrypted_data>", "scheme": "<identified_scheme>"}',
            "crypto_payload_generator": '{"scheme": "<identified_scheme>", "weakness": "<identified_weakness>"}',
            "deserialization_probe": '{"data": "<serialized_data>"}',
            "deserialization_payload_generator": '{"format": "<serialization_format>", "command": "id"}',
            "file_upload": '{"url": "<upload_url>", "operation": "analyze"}',
            "upload_location_finder": '{"url": "<base_url>", "filename": "<uploaded_filename>"}',
            "payload_mutator": '{"payload": "<original_payload>", "blocked": ["<blocked_keyword>"]}',
            "ssti_probe": '{"url": "<target_url>", "param": "<vulnerable_param>"}',
            "ssti_exploit_suggester": '{"engine": "<template_engine>"}',
            "xxe_probe": '{"url": "<target_url>", "param": "<xml_param>"}',
            "xxe_payload_generator": '{"attack_type": "file_read", "target_file": "/etc/passwd"}',
            "jwt_tool": '{"token": "<jwt_token>", "operation": "decode"}',
            "http_fetch": '{"url": "<target_url>"}',
            "html_analyzer": '{"html": "<page_source>"}',
            "ctf_knowledge_query": '{"query": "<challenge_description>"}',
        }

        return suggestions.get(tool_name, "")
