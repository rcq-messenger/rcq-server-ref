"""Runtime, operator-settable server settings — overrides layered over the
`.env` baseline (app/core/config.py).

The admin console writes overrides here so an operator can flip a feature or a
limit WITHOUT editing `.env` and restarting (which would kill the worker serving
the console). `/server/info` and the feature routers consult `effective()` /
`get()`; an absent override falls back to the env/code default in the registry
below.

Cross-worker propagation: each worker caches the override rows for `_TTL`
seconds, so a toggle written on one worker is visible everywhere within that
window (the writing worker is updated immediately). Feature flags tolerate a
few seconds of lag, so this avoids a DB read on every request without needing a
pub/sub invalidation.
"""
import time as _time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from sqlalchemy import select

from app.core.config import settings as _env
from app.core.db import SessionLocal
from app.models.server_setting import ServerSetting


@dataclass(frozen=True)
class SettingSpec:
    key: str
    type: str                       # "bool" | "int" | "str"
    default: Callable[[], Any]      # baseline when no override row exists
    group: str                      # "features" | "limits" | "branding"
    label: str
    help: str = ""
    min: Optional[int] = None
    max: Optional[int] = None
    choices: Optional[tuple] = None


REGISTRY: dict[str, SettingSpec] = {}


def _reg(spec: SettingSpec) -> SettingSpec:
    REGISTRY[spec.key] = spec
    return spec


# ── Consumer features (off => router gated + hidden in the client via /server/info)
_reg(SettingSpec("random_enabled", "bool", lambda: True, "features", "Random Chat",
                 "Anonymous roulette-style 1:1 chat."))
# `hood_enabled` and `stories_enabled` were removed from the registry on
# 2026-08-22 along with both routers and all four tables. Deleting the KEYS,
# rather than flipping their defaults to False, is deliberate: an island that
# had already written an override row saying `true` would otherwise keep
# advertising a feature whose endpoints are gone, and every client that honours
# the flag would show a tab that 404s. With no key in the registry the stale
# override is ignored and `/server/info` reports both as off, permanently.
# Leftover rows in `server_settings` are harmless: `describe()` iterates the
# registry, and `validate()` refuses an unknown key.
_reg(SettingSpec("reports_enabled", "bool", lambda: True, "features", "Reports",
                 "Let members report abuse and file bug reports to you, and read "
                 "your answers back. Turning this off closes intake; reports "
                 "already filed stay readable to both sides."))

# ── Limits & policy
_reg(SettingSpec("registration_policy", "str", lambda: _env.REGISTRATION_POLICY, "limits",
                 "Registration", "Who may create an account on this island.",
                 choices=("open", "invite")))
_reg(SettingSpec("max_accounts_per_device", "int", lambda: 5, "limits",
                 "Max accounts / device",
                 "How many accounts one device may hold (advertised to clients, client-enforced).",
                 min=1, max=50))

# ── Branding
#
# ⚠ HISTORY, because the help text below is a promise and it has been broken
# before. Both of these were served on /server/info from the day islands
# existed and read by NOTHING: on 2026-08-08 iOS decoded `name` and threw it
# away, Android had the field and never read it, and web-chat referenced
# neither. An operator could type both and see nothing change anywhere. Android
# picked them up in 0.100 and the rest followed with the logo. If a client ever
# stops rendering one of these, this help text is a lie and has to say so.
#
# These carried a warning that nothing rendered them, which was true for as
# long as it took somebody to ask why typing here changed nothing. All four
# clients read the name now, and it travels with the logo: wherever an island
# is drawn it is drawn as picture + name (the account switcher, the join
# confirm, the island card in Settings).
#
# ⚠ The LOGO is not in this registry and cannot be. Values here are strings in
# a VARCHAR(2048) that `validate()` truncates to fit, and a truncated data URI
# is an image that will not open; `describe()` also hands every value back to
# the admin console on every poll. It lives in its own single-row table with
# its own endpoints (models/island_logo.py has the full reasoning), and reaches
# clients as a 12-character `logo_version` on /server/info plus the public
# GET /server/logo.
_reg(SettingSpec("island_name", "str", lambda: _env.APP_NAME, "branding",
                 "Island name",
                 "What your island calls itself. Shown next to your logo "
                 "wherever a client names this island: the account switcher, "
                 "the confirm before somebody joins, and the island card in "
                 "Settings. Leave empty to use the server's own default name."))
_reg(SettingSpec("welcome_text", "str", lambda: "", "branding",
                 "Welcome / rules",
                 "Shown on the confirm before somebody joins this island, "
                 "which is the one moment house rules get read, and under the "
                 "island card in Settings. Leave empty for none."))


def _parse(spec: SettingSpec, raw: str) -> Any:
    if spec.type == "bool":
        return raw == "true"
    if spec.type == "int":
        try:
            return int(raw)
        except (TypeError, ValueError):
            return spec.default()
    return raw


class _Cache:
    rows: dict[str, str] = {}
    at: float = -1e9


_cache = _Cache()
_TTL = 5.0  # seconds


async def _overrides() -> dict[str, str]:
    now = _time.monotonic()
    if now - _cache.at < _TTL:
        return _cache.rows
    try:
        async with SessionLocal() as db:
            rows = (await db.execute(select(ServerSetting.key, ServerSetting.value))).all()
    except Exception:  # noqa: BLE001
        # A DB blip must NOT take down /server/info (unauth, boot-polled) or a
        # feature route — fall back to the last-known overrides (or defaults if
        # we never loaded) and retry on the next call without poisoning `at`.
        return _cache.rows
    _cache.rows = {k: v for k, v in rows}
    _cache.at = now
    return _cache.rows


async def effective() -> dict[str, Any]:
    """The full effective settings map (override ?? default) for every key."""
    ov = await _overrides()
    return {
        key: (_parse(spec, ov[key]) if key in ov else spec.default())
        for key, spec in REGISTRY.items()
    }


async def get(key: str) -> Any:
    spec = REGISTRY[key]
    ov = await _overrides()
    return _parse(spec, ov[key]) if key in ov else spec.default()


async def get_bool(key: str) -> bool:
    return bool(await get(key))


async def island_name() -> str:
    """The name this island answers to: the operator's override, else the
    server's own name. The ONE chain for it: /server/info answers with this,
    and so does everything that signs as the island (a news post). A reader
    must see the same name in both places, and two callers each doing
    `override or default` did not (a whitespace-only override passed the
    first and not the second). Rows written before validate() stripped are
    why the strip is here as well."""
    return str(await get("island_name") or "").strip() or _env.APP_NAME


def validate(updates: dict[str, Any]) -> dict[str, str]:
    """Coerce a {key: value} patch to {key: serialized}. Raises ValueError on a
    bad key / type / range / choice so the endpoint can 400 cleanly."""
    out: dict[str, str] = {}
    for key, value in updates.items():
        spec = REGISTRY.get(key)
        if spec is None:
            raise ValueError(f"unknown setting '{key}'")
        if spec.type == "bool":
            if not isinstance(value, bool):
                raise ValueError(f"'{key}' must be a boolean")
            out[key] = "true" if value else "false"
        elif spec.type == "int":
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"'{key}' must be an integer")
            if spec.min is not None and value < spec.min:
                raise ValueError(f"'{key}' must be >= {spec.min}")
            if spec.max is not None and value > spec.max:
                raise ValueError(f"'{key}' must be <= {spec.max}")
            out[key] = str(value)
        else:
            if not isinstance(value, str):
                raise ValueError(f"'{key}' must be a string")
            # Whitespace is not a value. The help text promises that an empty
            # island name means the server's own, and an operator who saved
            # three spaces meant empty; stripped once here so no reader has to
            # know (/server/info once showed the spaces while the news
            # signature fell back to the default).
            value = value.strip()
            if spec.choices is not None and value not in spec.choices:
                raise ValueError(f"'{key}' must be one of {list(spec.choices)}")
            out[key] = value[:2048]
    return out


async def apply(db, serialized: dict[str, str]) -> None:
    """Upsert validated overrides on the caller's session + bust the local
    cache. The caller commits."""
    for key, raw in serialized.items():
        row = await db.get(ServerSetting, key)
        if row is None:
            db.add(ServerSetting(key=key, value=raw))
        else:
            row.value = raw
    await db.flush()
    _cache.at = -1e9  # force a refresh on the next read (this worker; others ≤ _TTL)


async def describe() -> list[dict[str, Any]]:
    """For the admin UI: every setting with its effective value + metadata."""
    ov = await _overrides()
    out: list[dict[str, Any]] = []
    for key, spec in REGISTRY.items():
        out.append({
            "key": key,
            "type": spec.type,
            "group": spec.group,
            "label": spec.label,
            "help": spec.help,
            "value": (_parse(spec, ov[key]) if key in ov else spec.default()),
            "default": spec.default(),
            "overridden": key in ov,
            "min": spec.min,
            "max": spec.max,
            "choices": list(spec.choices) if spec.choices else None,
        })
    return out
