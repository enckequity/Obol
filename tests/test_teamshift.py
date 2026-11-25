"""TeamShift carry fixes: white-label text, per-workspace restricted key, stripped runtime, per-call approvals.

Hermes-dependent checks skip when Hermes is not importable.
"""

from __future__ import annotations

import ast
import contextlib
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PY = [ROOT / "__init__.py", ROOT / "schemas.py", *sorted((ROOT / "src" / "obol_lib").glob("*.py"))]
WRITES = {
    "obol_create_invoice": {"customer_email": "ap@globex.test", "customer_name": "Globex", "send": True,
                            "line_items": [{"description": "Retainer", "amount": 900}]},
    "obol_send_invoice": {"invoice_id": "in_1Abcdef"},
    "obol_send_reminder": {"invoice_id": "in_1Abcdef"},
    "obol_void_invoice": {"invoice_id": "in_1Abcdef"},
    "obol_mark_paid": {"invoice_id": "in_1Abcdef"},
}


# -- 1. white-label -------------------------------------------------------------------------------
def _user_strings(path: Path) -> list[str]:
    """String literals in a module, minus docstrings (developer text a person never sees)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings]


@pytest.mark.parametrize("path", RUNTIME_PY, ids=lambda p: p.name)
def test_no_engine_name_in_runtime_text(path):
    bad = [s for s in _user_strings(path) if re.search(r"\bHermes\b|hermes obol|hermes config|hermes-plugin", s)]
    assert not bad, bad


def test_no_engine_name_in_manifest_or_skill_text():
    from yaml import safe_load
    manifest = safe_load((ROOT / "plugin.yaml").read_text())
    visible = [manifest["description"]] + [e["description"] for e in manifest["optional_env"]]
    for spec in manifest["config_schema"].values():
        visible += [str(spec.get("label", "")), str(spec.get("description", ""))]
    visible.append((ROOT / "skills" / "invoicing" / "SKILL.md").read_text())
    assert not [v for v in visible if re.search(r"\bHermes\b", v)]


def test_injection_warning_and_empty_ledger_are_neutral():
    sys.path.insert(0, str(ROOT / "src"))
    from obol_lib import security, service
    from obol_lib.store import Store
    assert "Hermes" not in security._LABELS["override"]
    assert "Hermes" not in service.ledger_text(Store.memory())


# -- 2. per-workspace restricted key --------------------------------------------------------------
def test_live_secret_key_is_refused_even_with_allow_live():
    from obol_lib.stripe_client import KEY_ENV, StripeClient, StripeError
    with pytest.raises(StripeError) as exc:
        StripeClient("sk_live_full_account_key", allow_live=True)
    assert exc.value.kind == "live_secret_refused" and "rk_live_" in str(exc.value) and KEY_ENV in str(exc.value)
    assert "full_account_key" not in str(exc.value)


def test_live_needs_both_the_setting_and_a_restricted_key():
    from obol_lib import gate
    from obol_lib.stripe_client import StripeClient, StripeError
    with pytest.raises(StripeError) as exc:
        StripeClient("rk_live_x")
    assert exc.value.kind == "live_blocked"
    StripeClient("rk_live_x", allow_live=True).close()
    kw = dict(unattended=False, summary=lambda: "x", assess=lambda: [])
    for allow in (False, True):
        d = gate.decide("obol_send_invoice", {"invoice_id": "in_1"}, mode="live_secret", allow_live=allow, **kw)
        assert d["action"] == "block" and "sk_live_" in d["message"]
    assert gate.decide("obol_send_invoice", {"invoice_id": "in_1"}, mode="live", allow_live=False, **kw)["action"] == "block"
    assert gate.decide("obol_send_invoice", {"invoice_id": "in_1"}, mode="live", allow_live=True, **kw)["action"] == "approve"


def test_allow_live_defaults_false_and_only_a_real_true_turns_it_on():
    from obol_lib import runtime
    assert runtime.settings_from(lambda k, d: d).allow_live is False
    for value in ("true", "yes", 1, "1"):
        assert runtime.settings_from(lambda k, d, v=value: v if k == "allow_live" else d).allow_live is False
    assert runtime.settings_from(lambda k, d: True if k == "allow_live" else d).allow_live is True


def test_key_comes_only_from_the_secret_route_under_its_own_name(monkeypatch):
    pytest.importorskip("agent.secret_scope")
    import agent.secret_scope as scope
    from obol_lib import runtime
    asked = []
    monkeypatch.setattr(scope, "get_secret", lambda name, default=None: asked.append(name) or "rk_test_ws")
    monkeypatch.setenv("STRIPE_API_KEY", "sk_live_shared_fleet_key")
    assert runtime.api_key() == "rk_test_ws" and asked == ["OBOL_STRIPE_RESTRICTED_KEY"]
    src = (ROOT / "src" / "obol_lib" / "runtime.py").read_text()
    assert "os.environ" not in src and "getenv" not in src


def test_bank_transfer_never_reads_a_key(monkeypatch, tmp_path):
    from obol_lib import runtime
    from obol_lib.bank_client import BankClient
    from obol_lib.store import Store

    def boom():
        raise AssertionError("bank-transfer mode read the Stripe key")
    monkeypatch.setattr(runtime, "api_key", boom)
    st = Store.memory()
    monkeypatch.setattr(runtime, "store", lambda: st)
    monkeypatch.setattr(runtime, "pdf_dir", lambda: tmp_path)
    settings = runtime.settings_from(lambda k, d: {"provider": "bank_transfer", "bank_account_name": "Dana Okafor",
                                                   "bank_account_number": "0123456789"}.get(k, d))
    assert runtime.mode(settings) == "bank"
    client = runtime.make_client(settings)
    assert isinstance(client, BankClient)
    from obol_lib import service
    out = service.create_invoice(client, st, settings, dict(WRITES["obol_create_invoice"]))
    assert out.get("issued") is True and Path(out["invoice_pdf"]).read_bytes()[:5] == b"%PDF-"


# -- 3. runtime without tests/, catalog/, scripts/, dashboard/ or the demo ------------------------
def test_runtime_does_not_import_stripped_paths():
    for path in RUNTIME_PY:
        text = path.read_text(encoding="utf-8")
        for name in ("demo_seed", "record_stripe_fixtures", "recording", "fake_stripe", "plugin_api", "dashboard"):
            assert not re.search(rf"^\s*(from|import)\s+[.\w]*{name}", text, re.M), (path.name, name)
    assert not (ROOT / "src" / "obol_lib" / "demo_seed.py").exists()


def test_stripped_copy_loads_in_hermes(tmp_path):
    pytest.importorskip("hermes_cli.plugins")
    plugin = tmp_path / "home" / "plugins" / "obol"
    shutil.copytree(ROOT, plugin, ignore=shutil.ignore_patterns(
        ".git", "tests", "catalog", "scripts", "dashboard", "docs", ".github", "__pycache__", "README.md"))
    (tmp_path / "home" / "config.yaml").write_text(
        "plugins:\n  enabled: [obol]\n  isolation: in_process\n  entries:\n    obol:\n      settings: {}\n")
    script = textwrap.dedent("""
        import argparse, sys
        from hermes_cli.plugins import discover_plugins, get_plugin_manager
        discover_plugins(force=True)
        from tools.registry import registry
        names = [n for n in registry.get_all_tool_names() if n.startswith("obol_")]
        mod = sys.modules["hermes_plugins.obol"]
        p = argparse.ArgumentParser(); mod._cli_setup(p)
        subs = sorted(next(a for a in p._actions if isinstance(a, argparse._SubParsersAction)).choices)
        leaked = [m for m in sys.modules if m.split(".")[-1] in ("demo_seed", "recording", "fake_stripe", "plugin_api")]
        print(len(names), ",".join(subs), leaked)
    """)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("HERMES_", "OBOL_", "STRIPE_"))}
    env.update(HERMES_HOME=str(tmp_path / "home"), HOME=str(tmp_path))
    out = subprocess.run([sys.executable, "-c", script], env=env, cwd=tmp_path, capture_output=True, text=True,
                         timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.strip().splitlines()[-1] == "8 doctor,ledger,sync []"


# -- 4. every write asks, per call; cron cannot write ---------------------------------------------
@contextlib.contextmanager
def _env(**values):
    saved = {k: os.environ.get(k) for k in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _hook(tool_name, args):
    from hermes_cli.plugins import invoke_hook
    return next((r for r in invoke_hook("pre_tool_call", tool_name=tool_name, args=args, task_id="t")
                 if isinstance(r, dict)), None)


try:
    from test_hermes_integration import fake, hermes  # noqa: F401
except pytest.skip.Exception:  # Hermes not importable
    hermes = fake = None


@pytest.mark.skipif(hermes is None, reason="needs Hermes")
def test_each_write_asks_with_its_own_rule_key(hermes, fake):
    keys = set()
    for tool, args in WRITES.items():
        first, second = _hook(tool, dict(args)), _hook(tool, dict(args))
        for d in (first, second):
            assert d["action"] == "approve", tool
            assert d["rule_key"].startswith(f"obol:{tool}:") and d["rule_key"] != tool
        keys |= {first["rule_key"], second["rule_key"]}
    assert len(keys) == 2 * len(WRITES)   # an "always" answer can never cover another invoice


@pytest.mark.skipif(hermes is None, reason="needs Hermes")
def test_cron_session_cannot_write_even_from_a_delegated_child(hermes, fake):
    plugin = sys.modules["hermes_plugins.obol"]

    class NoCronIdentity:            # what a subagent delegated from a cron run sees
        def current_cron_execution(self):
            return None
    with _env(HERMES_CRON_SESSION="1"):
        assert plugin._unattended(NoCronIdentity()) is True
        for tool, args in WRITES.items():
            d = _hook(tool, dict(args))
            assert d["action"] == "block" and "unattended" in d["message"], tool
    assert not [c for c in fake.calls if c[0] == "POST"]
    assert plugin._unattended(NoCronIdentity()) is False


@pytest.mark.skipif(hermes is None, reason="needs Hermes")
def test_engine_resolves_the_approve_directive_with_obols_rule_key(hermes, fake, monkeypatch):
    import tools.approval as approval
    seen = []

    def fake_gate(tool_name, reason, *, rule_key="", approval_callback=None):
        seen.append(rule_key)
        return {"approved": False, "message": "BLOCKED: denied"}
    monkeypatch.setattr(approval, "request_tool_approval", fake_gate)
    from hermes_cli.plugins import resolve_pre_tool_block
    for _ in range(2):
        assert resolve_pre_tool_block("obol_send_invoice", {"invoice_id": "in_1Abcdef"}, task_id="t")
    assert len(seen) == 2 and seen[0] != seen[1] and all(k.startswith("obol:obol_send_invoice:") for k in seen)
    assert not [c for c in fake.calls if c[0] == "POST"]
