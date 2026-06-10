"""Cybench adapter (output-replay strategy).

Cybench has no protocol — it instantiates an agent class directly and grades
twice (strict ``Answer:`` equality, and a *looser* substring scan of every
iteration's stdout in ``grade_benchmark.py``). Rather than make our
FAIR/JSON agent mimic Cybench's free-text ``Command:``/``Answer:`` ABI, we:

1. parse ``metadata/metadata.json`` (filter to web),
2. stand the challenge service up ourselves via ``docker compose`` — skipping
   ``setup_environment``'s host-destructive ``rm -rf`` / ``docker system
   prune`` (those only belong inside Cybench's own container),
3. run our agent against ``http://<target_host>`` through the shared core,
4. emit a Cybench-shaped ``TaskRunCompletion`` JSON whose iterations carry
   our tool outputs as ``execution_output.stdout`` — so the substring grader
   credits the solve — and set ``subtask score = 1`` when our agent saw the
   flag.

See memory/cybench_protocol.md for the full protocol and the rationale for
output-replay over the SimpleAgent-subclass strategy.

Docker is required only at run time and only when ``start_container=True``;
the metadata parsing and JSON emission are pure and import nothing heavy.
"""

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ctf_solver.eval._core import RunResult, run_against_target_sync

# Flag-shaped token, used to pick the flag out of the subtask answers.
_FLAG_SHAPE = re.compile(r"[A-Za-z0-9_]+\{[^\n\r{}]{1,200}\}")


@dataclass
class CybenchTask:
    """Parsed view of one Cybench ``metadata/metadata.json``."""

    name: str
    task_dir: Path
    categories: List[str]
    target_host: str
    prompt: str
    flag: Optional[str]
    num_subtasks: int = 1
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_web(self) -> bool:
        return "web" in [c.lower() for c in self.categories]

    @property
    def target_url(self) -> str:
        host = self.target_host or "localhost"
        # target_host already looks like "web_flag:1337"; don't double-scheme.
        if host.startswith(("http://", "https://")):
            return host
        return f"http://{host}"


def _extract_flag(metadata: Dict[str, Any]) -> Optional[str]:
    """Pick the flag out of the subtask answers.

    The flag is the answer to the final 'What is the flag?' subtask. We scan
    subtask answers for a flag-shaped token and take the last match; if none
    is flag-shaped, fall back to the last subtask's raw answer.
    """
    subtasks = metadata.get("subtasks") or []
    flagged: Optional[str] = None
    last_answer: Optional[str] = None
    for st in subtasks:
        answer = (st or {}).get("answer")
        if not answer:
            continue
        last_answer = answer
        if _FLAG_SHAPE.search(answer):
            flagged = answer
    return flagged or last_answer


def parse_cybench_metadata(task_dir: Any, *, prompt_style: str = "hard") -> CybenchTask:
    """Read ``<task_dir>/metadata/metadata.json`` into a :class:`CybenchTask`.

    ``prompt_style`` selects ``hard_prompt`` (minimal, the default — closest
    to unguided) or ``easy_prompt`` (with hints). Falls back to whichever is
    present.
    """
    task_dir = Path(task_dir)
    meta_path = task_dir / "metadata" / "metadata.json"
    metadata = json.loads(meta_path.read_text(encoding="utf-8"))

    prompt = (
        metadata.get(f"{prompt_style}_prompt")
        or metadata.get("hard_prompt")
        or metadata.get("easy_prompt")
        or ""
    )
    return CybenchTask(
        name=task_dir.name,
        task_dir=task_dir,
        categories=list(metadata.get("categories") or []),
        target_host=metadata.get("target_host", ""),
        prompt=prompt,
        flag=_extract_flag(metadata),
        num_subtasks=len(metadata.get("subtasks") or []) or 1,
        raw=metadata,
    )


def build_task_run_completion(result: RunResult, task: CybenchTask) -> Dict[str, Any]:
    """Synthesize a Cybench-shaped ``TaskRunCompletion`` from our run.

    Each of our tool calls becomes one ``iteration`` whose
    ``execution_output.stdout`` carries the raw tool output; the final agent
    response is appended as a trailing iteration. Cybench's
    ``grade_benchmark.py`` substring-scans these stdouts, so the flag is
    credited as long as it appeared in any tool output — which our
    ``LoggingToolWrapper`` already captures. ``subtask_1.score`` is 1 iff our
    grading saw the expected flag.
    """
    tool_log: List[Dict[str, Any]] = result.stats.get("tool_call_log", []) or []
    iterations: List[Dict[str, Any]] = []
    for entry in tool_log:
        iterations.append(
            {
                "model_input": {"value": str(entry.get("input", "")), "num_tokens": 0},
                "model_response": {"value": "", "num_tokens": 0},
                "execution_output": {
                    "stdout": str(entry.get("output", "")),
                    "stderr": "",
                    "command": {
                        "command_type": 0,
                        "command_str": str(entry.get("tool", "")),
                    },
                },
            }
        )
    # Trailing iteration carrying the final response (belt-and-suspenders so a
    # flag that only appears in the answer is still substring-graded).
    iterations.append(
        {
            "model_input": {"value": "", "num_tokens": 0},
            "model_response": {"value": result.response, "num_tokens": 0},
            "execution_output": {
                "stdout": result.response,
                "stderr": "",
                "command": {"command_type": 1, "command_str": "Answer"},
            },
        }
    )

    score = 1 if result.solved else 0
    stats = result.stats
    return {
        "task": {
            "path": str(task.task_dir),
            "name": task.name,
            "categories": task.categories,
            # Single synthetic unguided subtask, matching Cybench's
            # unguided_mode(): the answer is the FINAL flag, never an
            # intermediate subtask answer. grade_benchmark.py reads
            # ``challenge_task['subtasks'][i]['answer']`` directly (i starts at
            # 0), so this key MUST exist and carry the real flag — otherwise the
            # grader raises KeyError, or substring-scans the wrong string and
            # credits nothing. ``or ""`` guards grade_benchmark's
            # ``re.search(pattern, flag)`` when flag extraction failed.
            "subtasks": [
                {
                    "question": "What is the flag?",
                    "answer": task.flag or "",
                    "answer_format": "",
                    "hints": [],
                    "commands": [],
                    "annotator_note": "",
                    "cyber_metadata": None,
                }
            ],
        },
        "task_run_input": {
            "task_run_config": {
                "run_with_subtasks": False,
                "use_easy_prompt": False,
            }
        },
        "subtask_completions": {
            "subtask_1": {
                "iterations": iterations,
                "score": score,
                "completion_status": "answered" if result.solved else "not_answered",
                "solved_with_hint": False,
                "time_taken_in_ms": round(result.duration_seconds * 1000.0, 1),
            }
        },
        "num_correct_subtasks": score,
        "num_subtasks": 1,
        "usage": {
            "input_tokens_used": int(stats.get("actual_prompt_tokens", 0) or 0),
            "output_tokens_used": int(stats.get("actual_completion_tokens", 0) or 0),
            "total_tokens": int(stats.get("total_tokens_est", 0) or 0),
            "iterations_used": len(iterations),
        },
        "time_taken_in_ms": round(result.duration_seconds * 1000.0, 1),
        # Provenance marker — this is a replayed run, not a native SimpleAgent.
        "ctf_solver_replay": True,
    }


def _require_docker() -> None:
    if shutil.which("docker") is None:
        raise RuntimeError(
            "Cybench adapter needs Docker to stand the challenge service up. "
            "Install Docker or pass start_container=False if the service is "
            "already running. See memory/cybench_protocol.md."
        )


def _compose_up(task_dir: Path, log_fn: Any) -> None:
    """``docker compose up -d`` — skips Cybench's destructive setup_environment.

    Cybench's ``setup_environment`` runs ``rm -rf /app/benchmark`` and
    ``docker system prune -a -f``; we deliberately do NOT, standing only this
    task's compose file up.
    """
    _require_docker()
    compose = task_dir / "docker-compose.yml"
    if not compose.is_file():
        raise FileNotFoundError(f"no docker-compose.yml under {task_dir}")
    log_fn(f"[cybench] docker compose up: {compose}")
    proc = subprocess.run(
        ["docker", "compose", "-f", str(compose), "up", "-d", "--force-recreate"],
        check=False,
        capture_output=True,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or b"").decode("utf-8", "replace").strip()
        raise RuntimeError(
            f"docker compose up failed (exit {proc.returncode}) for {compose}: "
            f"{stderr or '<no stderr captured>'}"
        )


def _compose_down(task_dir: Path, log_fn: Any) -> None:
    compose = task_dir / "docker-compose.yml"
    if not compose.is_file():
        return
    log_fn(f"[cybench] docker compose down: {compose}")
    subprocess.run(
        ["docker", "compose", "-f", str(compose), "down", "--volumes"],
        check=False,
        capture_output=True,
    )


def run_cybench_task(
    task_dir: Any,
    *,
    model: Optional[str] = None,
    provider: Optional[Any] = None,
    max_steps: Optional[int] = None,
    prompt_style: str = "hard",
    inject_rag: bool = False,
    start_container: bool = True,
    config: Optional[Any] = None,
    logs_dir: Optional[Any] = None,
    log_callback: Optional[Any] = None,
) -> RunResult:
    """Run our agent against one Cybench web task and emit a grading JSON.

    Parses the metadata, (optionally) brings the service up via
    ``docker compose`` — never running Cybench's destructive
    ``setup_environment`` — runs our agent, writes a ``TaskRunCompletion``
    JSON under ``logs_dir`` (default ``<task_dir>/logs``) for
    ``grade_benchmark.py``, and returns the :class:`RunResult`. Raises
    ``ValueError`` for non-web tasks. The container is always torn down.
    """
    log_fn = log_callback or (lambda *_a, **_k: None)
    task = parse_cybench_metadata(task_dir, prompt_style=prompt_style)
    if not task.is_web:
        raise ValueError(f"Pilot is web-only; {task.name} categories={task.categories}")

    if start_container:
        _compose_up(task.task_dir, log_fn)
    try:
        result = run_against_target_sync(
            url=task.target_url,
            description=task.prompt,
            expected_flag=task.flag,
            model=model,
            provider=provider,
            max_steps=max_steps,
            challenge_name=task.name,
            inject_rag=inject_rag,
            config=config,
            log_callback=log_fn,
        )
    finally:
        if start_container:
            try:
                _compose_down(task.task_dir, log_fn)
            except Exception as exc:  # noqa: BLE001 — teardown must not mask result
                log_fn(f"[cybench] teardown error (ignored): {exc}")

    out_dir = Path(logs_dir) if logs_dir else (task.task_dir / "logs")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{task.name}_ctf_solver_replay.json"
    completion = build_task_run_completion(result, task)
    out_path.write_text(json.dumps(completion, indent=2), encoding="utf-8")
    log_fn(
        f"[cybench] wrote TaskRunCompletion: {out_path} (score={completion['num_correct_subtasks']})"
    )
    return result
