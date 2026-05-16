"""Live agent-trace renderer.

Receives trace events from ``AgentRunner.event`` and appends formatted
HTML blocks to a ``QTextBrowser``. Events are batched on a 60 Hz
``QTimer`` to cap repaints regardless of incoming event rate — important
for local models that can emit 50+ ``llm_thinking`` events per second.

Each event becomes one HTML block — no full-document re-renders, unlike
Streamlit's polling renderer which redraws the whole trace per step.
"""

from __future__ import annotations

import html
from collections import deque
from typing import Any, Optional

from PySide6.QtCore import QTimer, Slot
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import QTextBrowser, QWidget

# How long we wait between flushes (ms). 16ms ≈ 60 Hz repaints.
_FLUSH_INTERVAL_MS = 16
# Hard cap on retained blocks so a long run doesn't bloat memory.
_MAX_BLOCK_COUNT = 5000

_TYPE_ICONS = {
    "thought_action": "🧠",
    "observation": "👁",
    "final_answer": "🏁",
    "stall_nudge": "⚠",
    "llm_thinking": "💭",
}


def _esc(text: Any) -> str:
    return html.escape(str(text))


def _render_event_html(evt: dict) -> str:
    etype = evt.get("type", "?")
    icon = _TYPE_ICONS.get(etype, "·")
    step = evt.get("step", 0)
    header = f"<b>{icon} Step {step} — {_esc(etype)}</b>"

    if etype == "thought_action":
        thought = _esc(evt.get("thought", ""))
        tool = _esc(evt.get("tool", ""))
        tool_input = _esc(evt.get("tool_input", ""))
        body = (
            f"<div style='margin-left:1em;'>"
            f"<div><i>Thought:</i> {thought}</div>"
            f"<div><i>Action:</i> <code>{tool}</code> "
            f"<code style='color:#888;'>{tool_input}</code></div>"
            f"</div>"
        )
    elif etype == "observation":
        tool = _esc(evt.get("tool", ""))
        obs = _esc(evt.get("observation", ""))
        body = (
            f"<div style='margin-left:1em;'>"
            f"<div><i>Tool:</i> <code>{tool}</code></div>"
            f"<pre style='margin:.25em 0; white-space:pre-wrap;'>{obs}</pre>"
            f"</div>"
        )
    elif etype == "final_answer":
        text = _esc(evt.get("text", ""))
        body = (
            f"<div style='margin-left:1em; color:#27ae60;'>"
            f"<pre style='white-space:pre-wrap;'>{text}</pre></div>"
        )
    elif etype == "stall_nudge":
        tier = _esc(evt.get("tier", ""))
        content = _esc(evt.get("content", ""))
        body = (
            f"<div style='margin-left:1em; color:#e67e22;'>"
            f"<i>Tier {tier}:</i> {content}</div>"
        )
    elif etype == "llm_thinking":
        content = _esc(evt.get("content", ""))
        body = (
            f"<div style='margin-left:1em; opacity:.7; font-style:italic; "
            f"border-left:3px solid #888; padding-left:.5em;'>{content}</div>"
        )
    else:
        body = f"<div style='margin-left:1em;'>{_esc(evt)}</div>"

    return f"<div style='margin:.5em 0;'>{header}{body}</div>"


class TraceView(QTextBrowser):
    """High-throughput trace renderer.

    Public API: ``append_event(evt: dict)`` (slot) and ``clear()``.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setOpenExternalLinks(True)
        self.setReadOnly(True)
        self.document().setMaximumBlockCount(_MAX_BLOCK_COUNT)
        self._pending: deque[dict] = deque()
        self._flush_scheduled = False

    @Slot(dict)
    def append_event(self, evt: dict) -> None:
        self._pending.append(evt)
        if not self._flush_scheduled:
            self._flush_scheduled = True
            QTimer.singleShot(_FLUSH_INTERVAL_MS, self._flush)

    def _flush(self) -> None:
        self._flush_scheduled = False
        if not self._pending:
            return
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        # Drain entire deque in one append so the paint cost is amortised.
        chunks: list[str] = []
        while self._pending:
            chunks.append(_render_event_html(self._pending.popleft()))
        cursor.insertHtml("".join(chunks))
        # Auto-scroll to the bottom.
        bar = self.verticalScrollBar()
        bar.setValue(bar.maximum())
