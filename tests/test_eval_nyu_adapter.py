"""NYU adapter: web-only filter, container lifecycle, file reading, guards.

``nyuctf`` is not installed in this environment, so the real ``_import_nyuctf``
genuinely raises — we assert that — and otherwise patch it with fakes.
"""

import pytest

from ctf_solver.eval import nyu_adapter
from ctf_solver.eval._core import RunResult


def _make_fakes(state, *, server_type="web", files=None, raise_on_start=False):
    class FakeChallenge:
        def __init__(self, meta, basedir):
            self.meta = meta
            self.basedir = basedir
            self.server_type = server_type
            self.server_name = "host"
            self.port = 8000
            self.flag = "MetaCTF{nyu}"
            self.flag_format = "MetaCTF{...}"
            self.description = "a web challenge"
            self.files = files or []
            self.challenge_dir = basedir

        def start_challenge_container(self):
            state["started"] = True
            if raise_on_start:
                raise RuntimeError("compose up failed")

        def stop_challenge_container(self):
            state["stopped"] = True

    class FakeDataset:
        def __init__(self, split="test"):
            self.split = split
            self.basedir = state.get("basedir", "/tmp/nyu")

        def get(self, name):
            return {"canonical": name}

        def filter(self, **kw):
            return ["2021q-web-a", "2021q-web-b"]

    return FakeDataset, FakeChallenge


def _patch_run(monkeypatch, capture):
    def fake_run(**kwargs):
        capture.update(kwargs)
        return RunResult(challenge=kwargs.get("challenge_name", "?"), solved=True)

    monkeypatch.setattr(nyu_adapter, "run_against_target_sync", fake_run)


# ---------------------------------------------------------------------------
# Dependency guard (real — nyuctf is not installed here)
# ---------------------------------------------------------------------------


def test_import_guard_raises_clear_error():
    with pytest.raises(ImportError, match="nyuctf"):
        nyu_adapter._import_nyuctf()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_web_challenge_runs_with_container_lifecycle(monkeypatch):
    state = {}
    monkeypatch.setattr(nyu_adapter, "_import_nyuctf", lambda: _make_fakes(state))
    capture = {}
    _patch_run(monkeypatch, capture)

    result = nyu_adapter.run_nyu_challenge("2021q-web-no_pass_needed")

    assert state.get("started") is True
    assert state.get("stopped") is True
    assert capture["url"] == "http://host:8000"
    assert capture["expected_flag"] == "MetaCTF{nyu}"
    assert capture["challenge_name"] == "2021q-web-no_pass_needed"
    assert result.solved is True


def test_non_web_challenge_rejected_before_start(monkeypatch):
    state = {}
    monkeypatch.setattr(
        nyu_adapter, "_import_nyuctf", lambda: _make_fakes(state, server_type="nc")
    )
    _patch_run(monkeypatch, {})
    with pytest.raises(ValueError, match="web-only"):
        nyu_adapter.run_nyu_challenge("2021q-pwn-x")
    assert "started" not in state  # never spun up a non-web container


def test_start_container_false_skips_lifecycle(monkeypatch):
    state = {}
    monkeypatch.setattr(nyu_adapter, "_import_nyuctf", lambda: _make_fakes(state))
    capture = {}
    _patch_run(monkeypatch, capture)

    nyu_adapter.run_nyu_challenge("2021q-web-x", start_container=False)
    assert "started" not in state
    assert "stopped" not in state
    assert capture["url"] == "http://host:8000"


def test_container_torn_down_even_on_run_error(monkeypatch):
    state = {}
    monkeypatch.setattr(nyu_adapter, "_import_nyuctf", lambda: _make_fakes(state))

    def boom(**_kw):
        raise RuntimeError("agent died")

    monkeypatch.setattr(nyu_adapter, "run_against_target_sync", boom)
    with pytest.raises(RuntimeError, match="agent died"):
        nyu_adapter.run_nyu_challenge("2021q-web-x")
    assert state.get("stopped") is True  # finally-block teardown ran


def test_config_passed_through(monkeypatch):
    state = {}
    monkeypatch.setattr(nyu_adapter, "_import_nyuctf", lambda: _make_fakes(state))
    capture = {}
    _patch_run(monkeypatch, capture)
    sentinel = object()
    nyu_adapter.run_nyu_challenge("2021q-web-x", config=sentinel, model="gpt-5.2")
    assert capture["config"] is sentinel
    assert capture["model"] == "gpt-5.2"


# ---------------------------------------------------------------------------
# File reading + URL building
# ---------------------------------------------------------------------------


def test_read_challenge_files(tmp_path):
    (tmp_path / "a.py").write_text("print('hi')", encoding="utf-8")
    (tmp_path / "b.txt").write_text("data", encoding="utf-8")

    class Chal:
        files = ["a.py", "b.txt", "missing.bin"]
        challenge_dir = tmp_path

    files = nyu_adapter._read_challenge_files(Chal())
    assert files["a.py"] == "print('hi')"
    assert files["b.txt"] == "data"
    assert "missing.bin" not in files  # unreadable skipped, not fatal


def test_target_url_prefers_server_name_port():
    class Chal:
        server_name = "web.chal"
        port = 1337

    assert nyu_adapter._target_url(Chal()) == "http://web.chal:1337"


def test_target_url_fallbacks_to_box_internal_port():
    class Chal:
        box = "boxhost"
        internal_port = 9000

    assert nyu_adapter._target_url(Chal()) == "http://boxhost:9000"


def test_list_web_challenges_string_entries(monkeypatch):
    state = {}
    monkeypatch.setattr(nyu_adapter, "_import_nyuctf", lambda: _make_fakes(state))
    names = nyu_adapter.list_web_challenges()
    assert names == ["2021q-web-a", "2021q-web-b"]


def test_list_web_challenges_derives_canonical_from_dicts(monkeypatch):
    # Real CTSDataset.filter yields bare metadata DICTS with no canonical key;
    # the canonical name must be derived via nyuctf.utils.get_canonical_name.
    # Regression for review finding #8 (previously returned []).
    import sys
    import types

    entries = [
        {"year": "2021", "event": "CSAW-Quals", "category": "web", "challenge": "np"},
        {"year": "2013", "event": "CSAW-Finals", "category": "web", "challenge": "hp"},
    ]

    class FakeDataset:
        def __init__(self, split="test"):
            self.basedir = "/tmp/nyu"

        def filter(self, **kw):
            return iter(entries)

    class FakeChallenge:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(
        nyu_adapter, "_import_nyuctf", lambda: (FakeDataset, FakeChallenge)
    )
    # Inject a fake nyuctf.utils.get_canonical_name (nyuctf isn't installed).
    fake_nyuctf = types.ModuleType("nyuctf")
    fake_utils = types.ModuleType("nyuctf.utils")
    fake_utils.get_canonical_name = lambda d: f"{d['year']}-{d['challenge']}"
    fake_nyuctf.utils = fake_utils
    monkeypatch.setitem(sys.modules, "nyuctf", fake_nyuctf)
    monkeypatch.setitem(sys.modules, "nyuctf.utils", fake_utils)

    names = nyu_adapter.list_web_challenges()
    assert names == ["2021-np", "2013-hp"]
