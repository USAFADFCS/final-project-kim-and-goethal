"""NYU CTF Bench adapter.

Loads a challenge via the ``nyuctf`` Python package, stands its service
container up (clean ``docker compose up -d`` / ``down --volumes`` — no
destructive host prune, unlike Cybench), runs our agent against it, and
returns a plain :class:`~ctf_solver.eval._core.RunResult`.

Web-only for the pilot: ``server_type == "web"`` (category ∈ {web, misc} and
not ``proto == "nc"``). See memory/comparative_eval_harnesses.md for the
schema and the original ≈40-LOC sketch this fills in.

``nyuctf`` and Docker are imported/required lazily — importing this module
costs nothing and never fails on a machine without them.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from ctf_solver.eval._core import RunResult, run_against_target_sync

_NYUCTF_HINT = (
    "The NYU adapter needs the 'nyuctf' package and Docker. Install with "
    "`pip install nyuctf` and ensure `docker compose` works. See "
    "memory/comparative_eval_harnesses.md."
)


def _import_nyuctf() -> Any:
    """Return ``(CTFDataset, CTFChallenge)`` or raise a clear ImportError."""
    try:
        from nyuctf.challenge import CTFChallenge  # type: ignore
        from nyuctf.dataset import CTFDataset  # type: ignore
    except ImportError as exc:  # pragma: no cover — env-dependent
        raise ImportError(_NYUCTF_HINT) from exc
    return CTFDataset, CTFChallenge


def _read_challenge_files(chal: Any) -> Dict[str, str]:
    """Read agent-visible challenge files into a ``{name: content}`` dict.

    ``chal.files`` is a list of names relative to the challenge dir. Binary
    or unreadable files are skipped rather than aborting the run.
    """
    files: Dict[str, str] = {}
    names: List[str] = list(getattr(chal, "files", []) or [])
    base = getattr(chal, "challenge_dir", None) or getattr(chal, "basedir", None)
    if base is None:
        return files
    base = Path(base)
    for name in names:
        path = base / name
        try:
            files[str(name)] = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue
    return files


def _target_url(chal: Any) -> str:
    """Build the challenge target URL from the nyuctf challenge object.

    NOTE: ``box``/``server_name`` is the alias on nyuctf's ``ctfnet`` Docker
    network (e.g. ``web.chal.csaw.io``), and many challenges publish NO host
    port. That URL is reachable from a container joined to ``ctfnet`` — which
    is how nyuctf's own harness runs the agent — but NOT from a host-side,
    in-process agent. See the host-reachability TODO in ``run_nyu_challenge``.
    """
    host = (
        getattr(chal, "server_name", None) or getattr(chal, "box", None) or "localhost"
    )
    port = getattr(chal, "port", None) or getattr(chal, "internal_port", None) or 80
    return f"http://{host}:{port}"


def run_nyu_challenge(
    canonical_name: str,
    *,
    split: str = "test",
    model: Optional[str] = None,
    provider: Optional[Any] = None,
    max_steps: Optional[int] = None,
    inject_rag: bool = False,
    start_container: bool = True,
    config: Optional[Any] = None,
    log_callback: Optional[Any] = None,
) -> RunResult:
    """Run our agent against one NYU CTF Bench web challenge.

    ``canonical_name`` is the ``{year}{q|f}-{cat3}-{name}`` key (e.g.
    ``2021q-web-no_pass_needed``). Raises ``ValueError`` for non-web
    challenges (the pilot is web-only) and ``ImportError`` when ``nyuctf``
    is unavailable. The challenge container is always torn down, even on
    error. ``start_container=False`` skips the Docker lifecycle (the target
    is assumed already up) — useful for re-runs and for tests.

    WARNING: ``start_container=True`` brings the service up on nyuctf's
    ``ctfnet`` Docker network but does NOT guarantee it is reachable from this
    host-side agent — see the TODO below.
    """
    log_fn = log_callback or (lambda *_a, **_k: None)
    # TODO: host-reachability for NYU web targets — _target_url returns the
    # ctfnet alias:internal_port (e.g. http://web.chal.csaw.io:3000), which a
    # host-side in-process agent cannot reach (the service often publishes no
    # host port). Either (a) run the agent inside a container joined to ctfnet
    # (nyuctf's intended path; see nyuctf/python/tests/test_challenges.py), or
    # (b) start the challenge with a compose override publishing internal_port
    # to 127.0.0.1:<freeport> and target that. Needs Docker to validate, so it
    # is deferred. Until then a host-side run against an unpublished target
    # connection-fails and is recorded as solved=False (a misleading benchmark
    # number) — only run NYU with this adapter once reachability is wired.
    CTFDataset, CTFChallenge = _import_nyuctf()

    ds = CTFDataset(split=split)
    chal = CTFChallenge(ds.get(canonical_name), ds.basedir)

    server_type = getattr(chal, "server_type", "web")
    if server_type != "web":
        raise ValueError(
            f"Pilot is web-only; {canonical_name} has server_type={server_type!r}"
        )

    if start_container:
        log_fn(f"[nyu] starting container for {canonical_name}")
        chal.start_challenge_container()
    try:
        result = run_against_target_sync(
            url=_target_url(chal),
            description=getattr(chal, "description", None),
            expected_flag=getattr(chal, "flag", None),
            files=_read_challenge_files(chal),
            model=model,
            provider=provider,
            max_steps=max_steps,
            challenge_name=canonical_name,
            inject_rag=inject_rag,
            config=config,
            log_callback=log_fn,
        )
    finally:
        if start_container:
            log_fn(f"[nyu] stopping container for {canonical_name}")
            try:
                chal.stop_challenge_container()
            except Exception as exc:  # noqa: BLE001 — teardown must not mask result
                log_fn(f"[nyu] container teardown error (ignored): {exc}")
    return result


def list_web_challenges(split: str = "test") -> List[str]:
    """Return canonical names of the web challenges in ``split``.

    Thin wrapper over ``CTFDataset.filter(category="web")``. That generator
    yields bare metadata dicts (``{year, event, category, challenge, path}``)
    with no canonical key/attr, so the canonical name must be DERIVED via
    nyuctf's own ``get_canonical_name`` (the same function the dataset index
    uses). Raises ``ImportError`` when ``nyuctf`` is missing.
    """
    CTFDataset, _ = _import_nyuctf()
    ds = CTFDataset(split=split)
    names: List[str] = []
    for entry in ds.filter(category="web"):
        if isinstance(entry, str):
            names.append(entry)
            continue
        # Prefer an explicit canonical field/attr if a future nyuctf provides
        # one; otherwise derive it from the metadata dict via nyuctf's own
        # get_canonical_name (imported lazily, only when actually needed).
        explicit = None
        if isinstance(entry, dict):
            explicit = entry.get("canonical") or entry.get("canonical_name")
        else:
            explicit = getattr(entry, "canonical_name", None) or getattr(
                entry, "name", None
            )
        if explicit:
            names.append(str(explicit))
        else:
            from nyuctf.utils import get_canonical_name  # type: ignore

            names.append(str(get_canonical_name(entry)))
    return names
