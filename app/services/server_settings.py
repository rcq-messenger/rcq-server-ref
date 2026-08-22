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
_reg(SettingSpec("nearby_enabled", "bool", lambda: True, "features", "Nearby",
                 "Geo 'people near you' discovery."))
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
# ⚠ Both of these are served on /server/info and BOTH ARE CURRENTLY IGNORED BY
# EVERY CLIENT. Checked 2026-08-08 across all three:
#   iOS      — ServerInfoResponse decodes `name` and ServerInfoService.fetch()
#              returns only ServerCapabilities, so the name is dropped on the
#              floor; `welcome` is not in the struct at all.
#   Android  — Session.kt reads `api.serverInfo().capabilities`; the data class
#              has `name` and never reads it, and no `welcome` field.
#   web-chat — neither field is referenced.
#
# These carried a warning that nothing rendered them, which was true for as
# long as it took somebody to ask why typing here changed nothing. Android
# reads both as of 0.100; iOS and the web client do not yet, so the help says
# where it shows and where it does not rather than going quiet about it.
_reg(SettingSpec("island_name", "str", lambda: _env.APP_NAME, "branding",
                 "Island name",
                 "Shown on Android: on the confirm before somebody joins this "
                 "island, and beside the address in Settings → Network. iOS and "
                 "the web client do not render it yet."))
_reg(SettingSpec("welcome_text", "str", lambda: "", "branding",
                 "Welcome / rules",
                 "Shown on Android on the confirm before somebody joins this "
                 "island, which is the one moment house rules get read. Leave "
                 "empty for none. iOS and the web client do not render it yet."))


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
