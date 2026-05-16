"""Configuration sidebar widget.

Equivalent surface to ``streamlit_app.render_sidebar`` but with native Qt
widgets, conditional visibility wired via signals, and ``QSettings``
persistence for every field. All input options come from
``ctf_solver.ui.core`` so Streamlit and Qt share the same source of truth.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QSettings, Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSpinBox,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ctf_solver.config import (
    COMMON_FLAG_PATTERNS,
    DEFAULT_FLAG_REGEX,
    validate_flag_regex,
)
from ctf_solver.prompts import DEFAULT_SYSTEM_PROMPT
from ctf_solver.ui.core import (
    GRAMMAR_OPTIONS,
    MODEL_OPTIONS,
    PLATFORM_OPTIONS,
    RAG_MODE_LABELS,
    RAG_MODE_LEGACY_MAP,
    is_local_model,
)

_SETTINGS_PREFIX = "sidebar/"
_DEFAULT_DOCS_DIRS = "docs/"
_DEFAULT_KB_FILES = "Book-3-Web-Exploitation.pdf"
_WRITE_RAG_MODES = {"lessons_write", "lessons_buildonly"}
_LESSONS_READ_MODES = {"lessons_readonly", "lessons_buildonly", "lessons_write"}


def _section_label(text: str) -> QLabel:
    label = QLabel(text)
    f = label.font()
    f.setBold(True)
    label.setFont(f)
    return label


def _separator() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFrameShadow(QFrame.Shadow.Sunken)
    return line


class SidebarWidget(QWidget):
    """Configuration panel for the CTF Solver Qt UI."""

    # Emitted whenever a config field changes — main window listens to keep
    # downstream widgets (single-run, batch) in sync.
    config_changed = Signal()
    # Emitted when the validity of inputs changes (URL or regex). Day 3+
    # uses this to enable/disable the Run button.
    validation_changed = Signal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._settings = QSettings()
        self._project_root = Path.cwd()
        self._building = True  # suppress save-on-change while loading defaults

        self._build_ui()
        self._wire_signals()
        self._load_from_settings()
        self._refresh_conditional_visibility()
        self._refresh_kb_stats()
        self._refresh_api_key_status()
        self._refresh_mlx_check()

        self._building = False

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(scroll)

        inner = QWidget()
        scroll.setWidget(inner)
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        title = QLabel("🚩 CTF Solver")
        title_font = title.font()
        title_font.setPointSize(title_font.pointSize() + 4)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        layout.addWidget(_separator())

        # --- Platform Settings ---
        layout.addWidget(_section_label("Platform Settings"))

        self.platform_combo = QComboBox()
        self.platform_combo.addItems(PLATFORM_OPTIONS)
        layout.addWidget(QLabel("Platform"))
        layout.addWidget(self.platform_combo)

        self.platform_custom = QLineEdit()
        self.platform_custom.setPlaceholderText("Custom platform name")
        self.platform_custom.setVisible(False)
        layout.addWidget(self.platform_custom)

        layout.addWidget(QLabel("Challenge Name (for lessons tracking)"))
        self.challenge_name = QLineEdit()
        self.challenge_name.setPlaceholderText("e.g. 'Web Decode'")
        layout.addWidget(self.challenge_name)

        layout.addWidget(QLabel("Flag Pattern Preset"))
        self.flag_preset = QComboBox()
        self.flag_preset.addItems(["Custom"] + list(COMMON_FLAG_PATTERNS.keys()))
        layout.addWidget(self.flag_preset)

        self.flag_regex = QLineEdit()
        self.flag_regex.setPlaceholderText("Custom flag regex")
        layout.addWidget(self.flag_regex)

        self.flag_regex_error = QLabel("")
        self.flag_regex_error.setStyleSheet("color: #c0392b;")
        self.flag_regex_error.setWordWrap(True)
        self.flag_regex_error.setVisible(False)
        layout.addWidget(self.flag_regex_error)

        layout.addWidget(_separator())

        # --- Agent Settings ---
        layout.addWidget(_section_label("Agent Settings"))

        layout.addWidget(QLabel("LLM Model"))
        self.model_combo = QComboBox()
        self.model_combo.addItems(MODEL_OPTIONS)
        layout.addWidget(self.model_combo)

        self.mlx_status = QLabel("")
        self.mlx_status.setWordWrap(True)
        self.mlx_status.setVisible(False)
        layout.addWidget(self.mlx_status)

        self.grammar_label = QLabel("Grammar Constraint")
        self.grammar_combo = QComboBox()
        self.grammar_combo.addItems(GRAMMAR_OPTIONS.keys())
        layout.addWidget(self.grammar_label)
        layout.addWidget(self.grammar_combo)

        layout.addWidget(QLabel("Max Steps"))
        self.max_steps = QSpinBox()
        self.max_steps.setRange(5, 50)
        self.max_steps.setValue(30)
        layout.addWidget(self.max_steps)

        self.save_logs = QCheckBox("Save run logs to challenge_logs/")
        self.save_logs.setChecked(True)
        layout.addWidget(self.save_logs)

        layout.addWidget(_separator())

        # --- Knowledge Base ---
        layout.addWidget(_section_label("Knowledge Base"))

        layout.addWidget(QLabel("Document Directories (one per line)"))
        self.docs_dirs = QPlainTextEdit()
        self.docs_dirs.setFixedHeight(60)
        layout.addWidget(self.docs_dirs)

        layout.addWidget(QLabel("Specific Files (one per line)"))
        self.kb_files = QPlainTextEdit()
        self.kb_files.setFixedHeight(60)
        layout.addWidget(self.kb_files)

        self.project_root_caption = QLabel("")
        self.project_root_caption.setStyleSheet("color: #888; font-size: 11px;")
        self.project_root_caption.setWordWrap(True)
        layout.addWidget(self.project_root_caption)

        self.reset_kb_btn = QPushButton("🔄 Reset KB to Defaults")
        layout.addWidget(self.reset_kb_btn)

        self.kb_stats = QLabel("")
        self.kb_stats.setStyleSheet("color: #888; font-size: 11px;")
        self.kb_stats.setWordWrap(True)
        layout.addWidget(self.kb_stats)

        layout.addWidget(_separator())

        # --- Knowledge Base Mode (RAG) ---
        layout.addWidget(_section_label("Knowledge Base Mode"))

        self.rag_buttons: dict[str, QRadioButton] = {}
        for label, mode in RAG_MODE_LABELS.items():
            rb = QRadioButton(label)
            self.rag_buttons[mode] = rb
            layout.addWidget(rb)
        # Default to "Curated Docs Only".
        self.rag_buttons["original"].setChecked(True)

        self.lessons_enrich = QCheckBox("Enrich lessons with gpt-4o-mini")
        self.lessons_enrich.setToolTip(
            "After each run, call gpt-4o-mini to write richer causal "
            "explanations and reflexion summaries (~$0.0003/run)."
        )
        layout.addWidget(self.lessons_enrich)

        layout.addWidget(_separator())

        # --- API key status ---
        self.api_status = QLabel("")
        self.api_status.setWordWrap(True)
        layout.addWidget(self.api_status)

        layout.addWidget(_separator())

        # --- Advanced: agent prompt editor ---
        # Checkable so users can collapse the section visually; default
        # checked=True keeps the inner widgets enabled (children of an
        # unchecked checkable group box are disabled in Qt).
        self.prompt_group = QGroupBox("Agent System Prompt (Advanced)")
        self.prompt_group.setCheckable(True)
        self.prompt_group.setChecked(True)
        prompt_layout = QVBoxLayout(self.prompt_group)

        self.agent_prompt = QPlainTextEdit()
        self.agent_prompt.setPlainText(DEFAULT_SYSTEM_PROMPT)
        self.agent_prompt.setFixedHeight(140)
        prompt_layout.addWidget(self.agent_prompt)

        reset_row = QHBoxLayout()
        reset_row.addStretch()
        self.reset_prompt_btn = QToolButton()
        self.reset_prompt_btn.setText("Reset to Default")
        reset_row.addWidget(self.reset_prompt_btn)
        prompt_layout.addLayout(reset_row)

        layout.addWidget(self.prompt_group)

        layout.addStretch()

        # Project-root caption only after construction so cwd is known.
        self.project_root_caption.setText(f"📁 Project root: {self._project_root}")

    # ------------------------------------------------------------- signals

    def _wire_signals(self) -> None:
        # Save-on-change for every field.
        self.platform_combo.currentTextChanged.connect(self._on_platform_changed)
        self.platform_custom.textChanged.connect(self._save_and_emit)
        self.challenge_name.textChanged.connect(self._save_and_emit)
        self.flag_preset.currentTextChanged.connect(self._on_flag_preset_changed)
        self.flag_regex.textChanged.connect(self._on_flag_regex_changed)
        self.model_combo.currentTextChanged.connect(self._on_model_changed)
        self.grammar_combo.currentTextChanged.connect(self._save_and_emit)
        self.max_steps.valueChanged.connect(self._save_and_emit)
        self.save_logs.toggled.connect(self._save_and_emit)
        self.docs_dirs.textChanged.connect(self._save_and_emit)
        self.kb_files.textChanged.connect(self._save_and_emit)
        for mode, rb in self.rag_buttons.items():
            rb.toggled.connect(self._on_rag_mode_changed)
        self.lessons_enrich.toggled.connect(self._save_and_emit)
        self.agent_prompt.textChanged.connect(self._save_and_emit)

        # Action buttons.
        self.reset_kb_btn.clicked.connect(self._reset_kb)
        self.reset_prompt_btn.clicked.connect(self._reset_prompt)

    # ---------------------------------------------------------- persistence

    def _key(self, name: str) -> str:
        return _SETTINGS_PREFIX + name

    def _load_from_settings(self) -> None:
        s = self._settings

        platform = s.value(self._key("platform_name"), "Generic CTF", type=str)
        if platform in PLATFORM_OPTIONS:
            self.platform_combo.setCurrentText(platform)
        else:
            self.platform_combo.setCurrentText("Other")
            self.platform_custom.setText(platform)

        self.challenge_name.setText(s.value(self._key("challenge_name"), "", type=str))

        preset = s.value(self._key("flag_preset"), "Custom", type=str)
        if preset in ["Custom", *COMMON_FLAG_PATTERNS.keys()]:
            self.flag_preset.setCurrentText(preset)
        self.flag_regex.setText(
            s.value(self._key("flag_regex"), DEFAULT_FLAG_REGEX, type=str)
        )

        model = s.value(self._key("model_name"), "gpt-5.2", type=str)
        if model in MODEL_OPTIONS:
            self.model_combo.setCurrentText(model)

        grammar = s.value(self._key("grammar_mode"), "auto", type=str)
        # Find the display label for the stored internal value.
        for label, value in GRAMMAR_OPTIONS.items():
            if value == grammar:
                self.grammar_combo.setCurrentText(label)
                break

        self.max_steps.setValue(s.value(self._key("max_steps"), 30, type=int))
        self.save_logs.setChecked(s.value(self._key("save_logs"), True, type=bool))

        self.docs_dirs.setPlainText(
            s.value(self._key("docs_dirs"), _DEFAULT_DOCS_DIRS, type=str)
        )
        self.kb_files.setPlainText(
            s.value(self._key("kb_files"), _DEFAULT_KB_FILES, type=str)
        )

        rag_mode = s.value(self._key("rag_mode"), "original", type=str)
        rag_mode = RAG_MODE_LEGACY_MAP.get(rag_mode, rag_mode)
        if rag_mode in self.rag_buttons:
            self.rag_buttons[rag_mode].setChecked(True)

        self.lessons_enrich.setChecked(
            s.value(self._key("use_llm_for_lessons"), False, type=bool)
        )

        prompt = s.value(self._key("agent_prompt"), DEFAULT_SYSTEM_PROMPT, type=str)
        self.agent_prompt.setPlainText(prompt)

    def _save_all(self) -> None:
        if self._building:
            return
        s = self._settings
        s.setValue(self._key("platform_name"), self.current_platform_name())
        s.setValue(self._key("challenge_name"), self.challenge_name.text())
        s.setValue(self._key("flag_preset"), self.flag_preset.currentText())
        s.setValue(self._key("flag_regex"), self.flag_regex.text())
        s.setValue(self._key("model_name"), self.model_combo.currentText())
        s.setValue(self._key("grammar_mode"), self.current_grammar_mode())
        s.setValue(self._key("max_steps"), self.max_steps.value())
        s.setValue(self._key("save_logs"), self.save_logs.isChecked())
        s.setValue(self._key("docs_dirs"), self.docs_dirs.toPlainText())
        s.setValue(self._key("kb_files"), self.kb_files.toPlainText())
        s.setValue(self._key("rag_mode"), self.current_rag_mode())
        s.setValue(self._key("use_llm_for_lessons"), self.lessons_enrich.isChecked())
        s.setValue(self._key("agent_prompt"), self.agent_prompt.toPlainText())

    # --------------------------------------------------------- value getters

    def current_platform_name(self) -> str:
        selection = self.platform_combo.currentText()
        if selection == "Other":
            return self.platform_custom.text()
        return selection

    def current_grammar_mode(self) -> str:
        return GRAMMAR_OPTIONS.get(self.grammar_combo.currentText(), "auto")

    def current_rag_mode(self) -> str:
        for mode, rb in self.rag_buttons.items():
            if rb.isChecked():
                return mode
        return "original"

    def current_flag_regex(self) -> str:
        preset = self.flag_preset.currentText()
        if preset == "Custom":
            return self.flag_regex.text()
        return COMMON_FLAG_PATTERNS.get(preset, self.flag_regex.text())

    def is_valid(self) -> bool:
        """Used by Day 3+ to gate the Run button."""
        ok_regex, _ = validate_flag_regex(self.current_flag_regex())
        return ok_regex and bool(
            os.getenv("OPENAI_API_KEY") or os.getenv("GENAI_API_KEY")
        )

    # ------------------------------------------------------ event handlers

    def _save_and_emit(self) -> None:
        self._save_all()
        self.config_changed.emit()

    def _on_platform_changed(self, text: str) -> None:
        self.platform_custom.setVisible(text == "Other")
        self._save_and_emit()

    def _on_flag_preset_changed(self, preset: str) -> None:
        if preset != "Custom":
            # Push the preset's regex into the custom field so it's editable
            # and so to_config_dict has the right value either way.
            self.flag_regex.setText(COMMON_FLAG_PATTERNS[preset])
        self._refresh_regex_field_visibility()
        self._save_and_emit()

    def _on_flag_regex_changed(self, _text: str) -> None:
        self._validate_flag_regex()
        self._save_and_emit()

    def _on_model_changed(self, model: str) -> None:
        self._refresh_conditional_visibility()
        self._refresh_mlx_check()
        self._save_and_emit()

    def _on_rag_mode_changed(self) -> None:
        # Each RadioButton emits toggled twice (off + on); only react on the
        # active one to avoid duplicate work.
        sender = self.sender()
        if isinstance(sender, QRadioButton) and not sender.isChecked():
            return
        self._refresh_conditional_visibility()
        self._refresh_kb_stats()
        self._save_and_emit()

    def _reset_kb(self) -> None:
        self.docs_dirs.setPlainText(_DEFAULT_DOCS_DIRS)
        self.kb_files.setPlainText(_DEFAULT_KB_FILES)

    def _reset_prompt(self) -> None:
        self.agent_prompt.setPlainText(DEFAULT_SYSTEM_PROMPT)

    # ------------------------------------------------ conditional UI updates

    def _refresh_conditional_visibility(self) -> None:
        # Grammar dropdown visible only for local models.
        local = is_local_model(self.model_combo.currentText())
        self.grammar_label.setVisible(local)
        self.grammar_combo.setVisible(local)

        # Lessons-enrich checkbox visible only in write modes.
        rag_mode = self.current_rag_mode()
        self.lessons_enrich.setVisible(rag_mode in _WRITE_RAG_MODES)

        self._refresh_regex_field_visibility()

    def _refresh_regex_field_visibility(self) -> None:
        # Show the custom regex line only for the "Custom" preset.
        custom = self.flag_preset.currentText() == "Custom"
        self.flag_regex.setVisible(custom)
        # Always re-validate so the error label hides if we just hid the field.
        if custom:
            self._validate_flag_regex()
        else:
            self.flag_regex_error.setVisible(False)

    def _validate_flag_regex(self) -> None:
        ok, err = validate_flag_regex(self.flag_regex.text())
        if ok:
            self.flag_regex_error.setVisible(False)
        else:
            self.flag_regex_error.setText(f"Invalid regex: {err}")
            self.flag_regex_error.setVisible(True)
        self.validation_changed.emit()

    def _refresh_kb_stats(self) -> None:
        rag_mode = self.current_rag_mode()
        if rag_mode not in _LESSONS_READ_MODES and rag_mode != "lessons_buildonly":
            self.kb_stats.setVisible(False)
            return
        lessons_dir = self._project_root / "out" / "lessons_knowledge"
        failure_dir = self._project_root / "out" / "failure_knowledge"
        lessons_count = (
            len(list(lessons_dir.glob("lessons_*.md"))) if lessons_dir.exists() else 0
        )
        failure_count = (
            len(list(failure_dir.glob("failure_*.md"))) if failure_dir.exists() else 0
        )
        success_count = (
            len(list(failure_dir.glob("success_*.md"))) if failure_dir.exists() else 0
        )
        self.kb_stats.setText(
            f"Lessons DB: {lessons_count} doc(s) · "
            f"Legacy: {failure_count + success_count}"
        )
        self.kb_stats.setVisible(True)

    def _refresh_api_key_status(self) -> None:
        has_openai = bool(os.getenv("OPENAI_API_KEY"))
        has_genai = bool(os.getenv("GENAI_API_KEY"))
        parts: list[str] = []
        if has_openai:
            parts.append("<span style='color:#27ae60;'>✓ OPENAI_API_KEY</span>")
        else:
            parts.append("<span style='color:#c0392b;'>✗ OPENAI_API_KEY</span>")
        if has_genai:
            parts.append("<span style='color:#27ae60;'>✓ GENAI_API_KEY</span>")
        else:
            parts.append("<span style='color:#888;'>– GENAI_API_KEY</span>")
        self.api_status.setText(" · ".join(parts))
        self.api_status.setTextFormat(Qt.TextFormat.RichText)

    def _refresh_mlx_check(self) -> None:
        if not self.model_combo.currentText().startswith("mlx-community/"):
            self.mlx_status.setVisible(False)
            return
        try:
            import mlx_lm  # noqa: F401
            import outlines  # noqa: F401

            self.mlx_status.setText(
                "<span style='color:#27ae60;'>✓ MLX stack available</span>"
            )
        except ImportError:
            self.mlx_status.setText(
                "<span style='color:#c0392b;'>⚠ MLX selected but mlx_lm / "
                "outlines not importable. Run: "
                '<code>pip install "outlines[mlxlm]"</code></span>'
            )
        self.mlx_status.setTextFormat(Qt.TextFormat.RichText)
        self.mlx_status.setVisible(True)
