"""Hermes-facing plumbing: settings, credentials and the per-profile store.

Hermes modules are imported lazily inside functions so the rest of obol_lib stays importable
(and testable) without Hermes.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Mapping, Optional

from .service import Settings
from .store import Store
from .stripe_client import KEY_ENV, StripeClient

PLUGIN_NAME = "obol"

_stores: dict[str, Store] = {}
_stores_lock = threading.Lock()

# Tests replace this to route every client through a fake transport.
client_factory: Callable[..., StripeClient] = StripeClient


def _number(getter: Callable[[str, Any], Any], key: str, default: Any, lo: float, hi: float, cast: type) -> Any:
    try:
        value = cast(getter(key, default))
    except (TypeError, ValueError):
        return default
    return value if lo <= value <= hi else default


def settings_from(getter: Callable[[str, Any], Any]) -> Settings:
    """Build Settings from a ``(key, default) -> value`` getter, coercing bad values to defaults."""
    d = Settings()
    currency = getter("default_currency", d.default_currency)
    return Settings(
        default_currency=currency.lower() if isinstance(currency, str) and len(currency) == 3 else d.default_currency,
        default_days_until_due=_number(getter, "default_days_until_due", d.default_days_until_due, 0, 365, int),
        allow_live=getter("allow_live", d.allow_live) is True,
        risk_duplicate_window_days=_number(getter, "risk_duplicate_window_days", d.risk_duplicate_window_days, 0, 365, int),
        risk_amount_multiplier=_number(getter, "risk_amount_multiplier", d.risk_amount_multiplier, 0, 1000, float),
        risk_amount_min_history=_number(getter, "risk_amount_min_history", d.risk_amount_min_history, 1, 100, int),
        risk_contact_change_days=_number(getter, "risk_contact_change_days", d.risk_contact_change_days, 0, 30, int),
        risk_lookalike_domains=getter("risk_lookalike_domains", d.risk_lookalike_domains) is not False,
        risk_impersonation=getter("risk_impersonation", d.risk_impersonation) is not False,
        provider="bank_transfer" if getter("provider", d.provider) == "bank_transfer" else "stripe",
        business_name=_text(getter, "business_name"),
        bank_account_name=_text(getter, "bank_account_name"),
        bank_name=_text(getter, "bank_name"),
        bank_account_number=_text(getter, "bank_account_number"),
        bank_routing=_text(getter, "bank_routing"),
    )


def _text(getter: Callable[[str, Any], Any], key: str) -> str:
    value = getter(key, "")
    return value.strip()[:200] if isinstance(value, str) else ""


def settings_from_config(config: Mapping[str, Any]) -> Settings:
    """Settings from a full Hermes config dict (``plugins.entries.obol.settings``)."""
    node: Any = config
    for part in ("plugins", "entries", PLUGIN_NAME, "settings"):
        node = node.get(part) if isinstance(node, Mapping) else None
    node = node if isinstance(node, Mapping) else {}
    return settings_from(lambda k, default: node.get(k, default))


def api_key() -> Optional[str]:
    """This workspace's own restricted Stripe key, read only through the engine's profile-scoped
    secret route (never the process environment directly, never a shared/generic ``STRIPE_API_KEY``)."""
    from agent.secret_scope import get_secret
    return get_secret(KEY_ENV)


LOCAL_PLATFORMS = frozenset({"cli", "tui", "desktop", "local"})
COMMAND_REFUSED = "Only an approved sender can use this command."


def _norm(value: Any) -> str:
    return str(getattr(value, "value", value) or "").strip().lower()


def command_senders(getter: Callable[[str, Any], Any]) -> set[str]:
    """The ``command_senders`` setting as a set of ``platform:user_id`` (a list or comma-separated text)."""
    value = getter("command_senders", [])
    if isinstance(value, str):
        value = value.split(",")
    out = set()
    for item in value if isinstance(value, (list, tuple, set)) else ():
        platform, sep, user = str(item).strip().partition(":")
        if sep and platform.strip() and user.strip():
            out.add(f"{platform.strip().lower()}:{user.strip()}")
    return out


def command_allowed(getter: Callable[[str, Any], Any], context: Mapping[str, Any]) -> bool:
    """May the caller of ``/invoices`` run it? Open unless ``restrict_commands`` is true. Then a local session may
    (no source, or a local source, on a local platform), a messaging sender only when listed in ``command_senders``,
    and a call without calling context never may. An unreadable setting counts as restricted (fails closed)."""
    try:
        restricted = getter("restrict_commands", False)
    except Exception:  # noqa: BLE001
        return False
    if restricted is not True and str(restricted).strip().lower() not in ("true", "yes", "on", "1"):
        return True
    platform = _norm(context.get("platform"))
    source = context.get("source")
    if source is None or _norm(getattr(source, "platform", "")) == "local":
        return platform in LOCAL_PLATFORMS
    user = str(getattr(source, "user_id", "") or "").strip()
    source_platform = _norm(getattr(source, "platform", ""))
    try:
        senders = command_senders(getter)
    except Exception:  # noqa: BLE001
        return False
    return bool(user and source_platform) and f"{source_platform}:{user}" in senders


def make_client(settings: Settings, key: Optional[str] = None, **kwargs: Any) -> Any:
    if settings.provider == "bank_transfer":
        from .bank_client import BankClient
        return BankClient(store(), settings, pdf_dir())
    return client_factory(key if key is not None else api_key(), allow_live=settings.allow_live, **kwargs)


def mode(settings: Settings) -> str:
    """'bank' in bank-transfer mode, else the Stripe key's mode: test / live / missing / invalid."""
    if settings.provider == "bank_transfer":
        return "bank"
    from .stripe_client import key_mode
    return key_mode(api_key())


def pdf_dir() -> Any:
    from pathlib import Path
    from plugins.plugin_storage import plugin_data_dir
    return Path(plugin_data_dir(PLUGIN_NAME)) / "invoices"


def store() -> Store:
    from plugins.plugin_storage import plugin_data_dir, plugin_db
    data_dir = str(plugin_data_dir(PLUGIN_NAME))  # follows the active profile
    with _stores_lock:
        st = _stores.get(data_dir)
        if st is None:
            st = _stores[data_dir] = Store(plugin_db(PLUGIN_NAME))
        return st
