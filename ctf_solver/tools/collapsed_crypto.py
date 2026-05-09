"""
Collapsed crypto family tool (v3.8 P0 main).

Dispatches to the three underlying crypto tools (``CryptoProbeTool``,
``CryptoAnalyzerTool``, ``CryptoPayloadGenerator``) via a single
``operation`` enum.
"""

from __future__ import annotations

import json
from typing import Optional

import requests

from ctf_solver.tools.core import parse_json_input
from ctf_solver.tools.crypto_tools import (
    CryptoAnalyzerTool,
    CryptoPayloadGenerator,
    CryptoProbeTool,
)

_ALLOWED_OPERATIONS = ("probe", "analyze", "generate_payload")


class CollapsedCryptoTool:
    """Single crypto entry point with an ``operation`` enum.

    Operations:
      - ``probe``: forwards to ``CryptoProbeTool`` — detect crypto
        weaknesses on a target URL (padding oracle, ECB, etc).
      - ``analyze``: forwards to ``CryptoAnalyzerTool`` — analyze a
        ciphertext / token for known weaknesses (no network).
      - ``generate_payload``: forwards to ``CryptoPayloadGenerator`` —
        emit attack payloads (padding oracle bytes, hash extension, etc).
    """

    name: str = "crypto_attack"
    description: str = (
        "Unified crypto entry point. Pick 'operation' to dispatch: "
        "'probe' (test target for crypto weakness — needs 'url'), "
        "'analyze' (offline analysis of a ciphertext/token — needs "
        "'data' or 'token'), or 'generate_payload' (emit attack "
        "payloads — needs 'attack_type')."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": list(_ALLOWED_OPERATIONS),
            },
            "url": {"type": "string"},
            "param": {"type": "string"},
            "method": {"type": "string"},
            "data": {"type": "object"},
            "token": {"type": "string"},
            "ciphertext": {"type": "string"},
            "attack_type": {"type": "string"},
            "key": {"type": "string"},
            "block_size": {"type": "integer"},
            "crypto_type": {"type": "string"},
        },
        "required": ["operation"],
        "additionalProperties": True,
    }
    samples = [
        {"operation": "probe", "url": "http://example.com/decrypt", "param": "token"},
        {"operation": "analyze", "token": "abc123"},
        {"operation": "generate_payload", "attack_type": "padding_oracle"},
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self._probe = CryptoProbeTool(session=session) if session else CryptoProbeTool()
        self._analyzer = CryptoAnalyzerTool()
        self._gen = CryptoPayloadGenerator()

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "CollapsedCryptoTool")
        if err:
            return err
        op = data.get("operation")
        if op not in _ALLOWED_OPERATIONS:
            return (
                f"[CollapsedCryptoTool] Error: 'operation' must be one of "
                f"{list(_ALLOWED_OPERATIONS)}, got {op!r}."
            )
        payload = {k: v for k, v in data.items() if k != "operation"}
        sub_input = json.dumps(payload)
        if op == "probe":
            return self._probe.use(sub_input)
        if op == "analyze":
            return self._analyzer.use(sub_input)
        return self._gen.use(sub_input)
