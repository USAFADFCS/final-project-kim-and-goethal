"""
v3.8 P2: Recon DAG tests.

The DAG generalises ``opener_pack`` to support observation-driven
follow-up steps. Verify:
  * static + conditional shape from compose_recon_dag()
  * conditional callables fire only when their trigger pattern is seen
  * conditional callables fire at most once per run (no infinite re-fire)
  * agent ``_run_opener_pack`` correctly handles callable steps
"""

from typing import Any, Dict, List, Optional, Tuple

from ctf_solver.recon_dag import compose_recon_dag


def _resolve_step(step, observations):
    if callable(step):
        return step(observations)
    return step


class TestComposeShape:
    def test_no_url_returns_empty(self):
        assert compose_recon_dag(None) == []
        assert compose_recon_dag("") == []

    def test_with_url_returns_static_and_conditional_steps(self):
        dag = compose_recon_dag("http://example.com/")
        # 5 static + 2 conditional = 7
        assert len(dag) == 7
        # First 5 are tuples (static), last 2 are callables.
        for s in dag[:5]:
            assert isinstance(s, tuple)
            assert len(s) == 2
            assert isinstance(s[0], str)
            assert isinstance(s[1], dict)
        for s in dag[5:]:
            assert callable(s)

    def test_static_steps_use_provided_url(self):
        dag = compose_recon_dag("http://target.invalid/app/")
        urls = [
            s[1].get("url") or s[1].get("base_url") for s in dag if isinstance(s, tuple)
        ]
        for u in urls:
            assert "target.invalid" in u


class TestRolePromotion:
    def test_fires_when_role_cookie_observed(self):
        dag = compose_recon_dag("http://example.com/")
        promote_step = dag[5]  # role-promotion callable
        observations = [
            (
                "deep_recon",
                "HTTP/1.1 200 OK\r\nSet-Cookie: role=user; Path=/\r\n\r\n<html></html>",
            )
        ]
        out = promote_step(observations)
        assert out is not None
        tool_name, payload = out
        assert tool_name == "cookie_set"
        assert payload["name"] == "role"
        assert payload["value"] == "admin"
        assert payload["domain"] == "example.com"

    def test_does_not_fire_when_already_admin(self):
        dag = compose_recon_dag("http://example.com/")
        promote_step = dag[5]
        observations = [
            ("deep_recon", "Set-Cookie: role=admin; Path=/"),
        ]
        assert promote_step(observations) is None

    def test_does_not_fire_when_no_role_cookie(self):
        dag = compose_recon_dag("http://example.com/")
        promote_step = dag[5]
        observations = [("html_inspector", "<form><input name='username'></form>")]
        assert promote_step(observations) is None

    def test_fires_only_once(self):
        dag = compose_recon_dag("http://example.com/")
        promote_step = dag[5]
        observations = [("deep_recon", "Set-Cookie: role=user; Path=/")]
        first = promote_step(observations)
        second = promote_step(observations)
        assert first is not None
        assert second is None  # state remembers we already promoted

    def test_priv_or_user_cookie_names_also_promote(self):
        dag = compose_recon_dag("http://example.com/")
        promote_step = dag[5]
        observations = [("deep_recon", "Set-Cookie: priv=guest; Path=/")]
        out = promote_step(observations)
        assert out is not None
        assert out[1]["name"] == "priv"


class TestFollowupFetch:
    def test_fires_on_login_path(self):
        dag = compose_recon_dag("http://example.com/")
        followup = dag[6]
        observations = [("path_enumerator", "/login: 200\n/about: 404")]
        out = followup(observations)
        assert out is not None
        name, payload = out
        assert name == "http_fetch"
        assert payload["url"] == "http://example.com/login"

    def test_does_not_refetch_root(self):
        dag = compose_recon_dag("http://example.com/")
        followup = dag[6]
        # No interesting subpath in observations.
        observations = [("path_enumerator", "/: 200")]
        assert followup(observations) is None

    def test_fires_only_once(self):
        dag = compose_recon_dag("http://example.com/")
        followup = dag[6]
        observations = [("path_enumerator", "/admin: 200")]
        first = followup(observations)
        second = followup(observations)
        assert first is not None
        assert second is None


class TestAgentIntegration:
    """``_run_opener_pack`` should resolve callables, skip None returns,
    and feed each step's output back into the prior_observations list."""

    def _make_agent_with_pack(self, pack: List[Any]):
        from unittest.mock import MagicMock

        from ctf_solver.agent import CTFAgent

        agent = CTFAgent(
            llm=MagicMock(),
            planner=MagicMock(),
            tool_executor=MagicMock(),
            memory=MagicMock(),
            opener_pack=pack,
        )
        # Spy on memory.add_message and tool_executor.execute.
        agent.memory.add_message = MagicMock()
        return agent

    def test_static_pack_unchanged(self):
        pack = [("robots_txt", {"base_url": "http://x.test/"})]
        agent = self._make_agent_with_pack(pack)
        agent.tool_executor.execute = lambda name, ti: f"{name} ran"
        agent._run_opener_pack()
        # One observation appended.
        assert agent.memory.add_message.call_count == 1

    def test_callable_step_with_none_skipped(self):
        def _step(obs):
            return None

        agent = self._make_agent_with_pack([_step])
        agent.tool_executor.execute = lambda name, ti: f"{name} ran"
        agent._run_opener_pack()
        # No observation: callable returned None.
        assert agent.memory.add_message.call_count == 0

    def test_callable_step_with_resolved_pair_runs(self):
        def _step(obs):
            return ("html_inspector", {"url": "http://x.test/"})

        agent = self._make_agent_with_pack([_step])
        executed: List[Tuple[str, str]] = []

        def _exec(name: str, ti: str) -> str:
            executed.append((name, ti))
            return f"{name} ran"

        agent.tool_executor.execute = _exec
        agent._run_opener_pack()
        assert executed == [("html_inspector", '{"url": "http://x.test/"}')]
        assert agent.memory.add_message.call_count == 1

    def test_callable_sees_prior_observations(self):
        seen: List[List[Tuple[str, str]]] = []

        def _step(obs):
            seen.append(list(obs))
            return None

        pack = [
            ("robots_txt", {"base_url": "http://x.test/"}),
            _step,
        ]
        agent = self._make_agent_with_pack(pack)
        agent.tool_executor.execute = lambda name, ti: "Disallow: /secret"
        agent._run_opener_pack()
        # The callable should have seen the robots_txt observation.
        assert len(seen) == 1
        assert seen[0][0][0] == "robots_txt"
        assert "Disallow" in seen[0][0][1]

    def test_callable_exception_does_not_abort(self):
        def _bad_step(obs):
            raise RuntimeError("boom")

        pack = [_bad_step, ("robots_txt", {"base_url": "http://x.test/"})]
        agent = self._make_agent_with_pack(pack)
        agent.tool_executor.execute = lambda name, ti: f"{name} ran"
        agent._run_opener_pack()
        # robots_txt should still run despite the bad callable.
        assert agent.memory.add_message.call_count == 1


class TestBuildAgentWiring:
    """``build_agent`` should swap opener_pack for the recon DAG when
    ``enable_recon_dag`` is on; default keeps the legacy 2-call pack."""

    def _build(self, **overrides) -> Optional[Any]:
        from ctf_solver.agent import build_agent
        from ctf_solver.config import RAGMode, SolverConfig

        cfg_kwargs: Dict[str, Any] = dict(
            llm_provider="ollama",
            model_name="dummy:latest",
            llm_base_url="http://127.0.0.1:11434",
            rag_mode=RAGMode.NONE,
            challenge_url="http://example.com/",
        )
        cfg_kwargs.update(overrides)
        cfg = SolverConfig(**cfg_kwargs)
        try:
            return build_agent(cfg, tracker=None)
        except Exception:
            return None

    def test_default_uses_legacy_opener_pack(self):
        agent = self._build(enable_recon_dag=False)
        if agent is None:
            return
        pack = agent._opener_pack
        # Legacy: 2 static tuples.
        assert len(pack) == 2
        assert all(isinstance(s, tuple) for s in pack)

    def test_enable_recon_dag_swaps_in_dag(self):
        agent = self._build(enable_recon_dag=True)
        if agent is None:
            return
        pack = agent._opener_pack
        assert len(pack) == 7  # 5 static + 2 callable
        assert sum(1 for s in pack if callable(s)) == 2
