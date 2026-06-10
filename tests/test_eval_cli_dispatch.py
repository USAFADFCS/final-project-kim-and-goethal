"""Regression: the eval CLI path must not crash on nested asyncio.run.

The adapters call ``run_against_target_sync`` → ``asyncio.run(...)`` internally.
``main()`` runs inside ``cli_main``'s event loop, so the dispatch must hop off
the loop (``asyncio.to_thread``) or the inner ``asyncio.run`` raises
"cannot be called from a running event loop". Review finding #10.
"""

import asyncio

import ctf_solver.runner as runner


def test_eval_dispatch_survives_inner_asyncio_run(monkeypatch):
    called = {}

    async def _inner():
        return "ok"

    def fake_adapter(args):
        # Simulate the adapter chain calling asyncio.run() (as
        # run_against_target_sync does). Pre-fix this raised RuntimeError
        # because main() already holds a running loop.
        called["result"] = asyncio.run(_inner())

    monkeypatch.setattr(runner, "_run_eval_adapter", fake_adapter)
    # main() calls parse_args() with no args → reads sys.argv.
    monkeypatch.setattr("sys.argv", ["runner", "--nyu-challenge", "2021q-web-x"])

    # Drive the real async main(); must not raise the running-loop error.
    asyncio.run(runner.main())
    assert called.get("result") == "ok"
