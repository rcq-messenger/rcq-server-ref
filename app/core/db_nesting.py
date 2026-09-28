"""A tripwire for the one database mistake that took the island down.

⚠⚠ THE MISTAKE: a request handler holds its session's connection (it ran a
query, so it has an open transaction and, behind PgBouncer in TRANSACTION
mode, a pinned backend) and then something it calls opens ANOTHER session and
waits for a second connection. Each such request needs two connections to
finish and gives back none until it does, so a burst of them fills the pool
with holders waiting on each other. That was the 11.09-28.09 stalls, see
core/single_flight.py. It is invisible in every test that does not run a
burst against a small pool, which is why it survived for weeks.

What this does: when a session begins a transaction on a connection while the
SAME task's request session (the one `get_db` handed out) is holding one, it
logs a warning naming the call site. It never changes what the code does.

⚠ Exactly that condition and nothing looser, because a detector that cries
wolf gets switched off:

  * "holding" is tracked by the `after_begin` / `after_transaction_end`
    session events, i.e. when the request session really has a connection.
    `get_db` enters `async with SessionLocal()` long before the first query,
    and a handler that asks a cache for something BEFORE its first query
    holds nothing and is fine (`/users/search` reads the guest set first);
  * "the same task": a task a handler spawns copies the handler's context,
    so a push fan-out started with `create_task` sees the request session
    too. It does not make the request wait, so it is not the mistake. The
    refresh tasks in single_flight.py are also started in a clean context;
  * a request that awaits somebody else's pool work (a cold, invalidated or
    over-age cache waiting for the shared refresh) is the same mistake by
    other means, bounded but still a wait, and the caches report it
    themselves through `note_wait`.

It fires AFTER the second connection was obtained (that is when a transaction
begins), so it does not fire in the middle of a real stall. It is not a stall
alarm; it is a guard that names the call site the first time a code path
nests, in the tests and on a quiet island, long before a burst finds it.

Switched by RCQ_DB_NESTING_CHECK: "1" on, "0" off. When unset it is on for
ENV=dev (the local tests, a laptop) and off elsewhere. Each call site is
logged once per worker per `_REPEAT_SECONDS`, so a hot path that regresses
costs a line every ten minutes, not one per request.
"""
from __future__ import annotations

import asyncio
import contextvars
import logging
import os
import sys
import time
import traceback
from typing import Optional

from sqlalchemy import event
from sqlalchemy.orm import Session

log = logging.getLogger("rcq.db_nesting")

_REPEAT_SECONDS = 600.0
_INFO_REQUEST = "rcq_request_session"
_INFO_HOLDING = "rcq_holding_connection"

#: (the request's sync Session, the task that owns the request). Set by
#: `get_db`; each request runs in its own task with its own copy of the
#: context, so this never leaks from one request into another.
_REQUEST: contextvars.ContextVar[Optional[tuple[Session, asyncio.Task]]] = contextvars.ContextVar(
    "rcq_request_session", default=None
)

_enabled = False
_installed = False
_last_logged: dict[str, float] = {}

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#: The project root: `app/` plus the tools and the local tests beside it.
_ROOT = os.path.dirname(_APP_DIR)
_SELF = os.path.abspath(__file__)


def _default_enabled() -> bool:
    raw = os.environ.get("RCQ_DB_NESTING_CHECK", "").strip()
    if raw in ("0", "1"):
        return raw == "1"
    try:
        from app.core.config import settings

        return settings.ENV == "dev"
    except Exception:  # noqa: BLE001
        return False


def enabled() -> bool:
    return _enabled


def set_enabled(value: bool) -> None:
    """For tests and tools."""
    global _enabled
    _enabled = bool(value)


def mark_request_session(session) -> None:
    """Called by `get_db` for the session it hands to a request."""
    if not _enabled:
        return
    try:
        task = asyncio.current_task()
    except RuntimeError:
        return
    if task is None:
        return
    sync = session.sync_session
    sync.info[_INFO_REQUEST] = True
    _REQUEST.set((sync, task))


def _request_holding() -> Optional[Session]:
    """The current task's request session when it holds a connection now."""
    held = _REQUEST.get()
    if held is None:
        return None
    sync, task = held
    try:
        if asyncio.current_task() is not task:
            return None
    except RuntimeError:
        return None
    return sync if sync.info.get(_INFO_HOLDING) else None


def _call_site() -> str:
    """The project frames that led here, outermost first (the innermost six).

    Inside a session event we are running in the greenlet SQLAlchemy spawned
    for the sync half of the call, so the interesting frames (the handler and
    the helper that opened the session) are on the PARENT greenlet, which is
    suspended in `greenlet_spawn` with the whole coroutine chain linked above
    it through f_back.
    """
    frame = None
    try:
        import greenlet

        parent = greenlet.getcurrent().parent
        if parent is not None:
            frame = parent.gr_frame
    except Exception:  # noqa: BLE001
        frame = None
    if frame is None:
        frame = sys._getframe(2)
    picked = []
    for fs in traceback.extract_stack(frame):
        path = os.path.abspath(fs.filename)
        if (
            path.startswith(_ROOT + os.sep)
            and path != _SELF
            and "site-packages" not in path
            and f"{os.sep}.venv{os.sep}" not in path
        ):
            rel = os.path.relpath(path, _ROOT)
            picked.append(f"{rel}:{fs.lineno} {fs.name}")
    return " > ".join(picked[-6:]) or "(no project frame)"


def _warn(kind: str, site: str) -> None:
    now = time.monotonic()
    key = f"{kind}|{site}"
    if now - _last_logged.get(key, -1e9) < _REPEAT_SECONDS:
        return
    _last_logged[key] = now
    log.warning(
        "[db-nesting] %s while this request's session holds a connection: %s",
        kind, site,
    )


def note_wait(what: str) -> None:
    """A cache is about to make the current task wait for pool work done
    elsewhere (a cold cache waiting for the shared refresh). Same mistake as a
    nested session when the request is holding a connection, so the same
    warning."""
    if not _enabled:
        return
    if _request_holding() is not None:
        _warn(f"waiting on {what}", _call_site())


def _after_begin(session, transaction, connection) -> None:
    if not _enabled:
        return
    if session.info.get(_INFO_REQUEST):
        session.info[_INFO_HOLDING] = True
        return
    holder = _request_holding()
    if holder is not None and holder is not session:
        _warn("a second session took a connection", _call_site())


def _after_transaction_end(session, transaction) -> None:
    if transaction.parent is None and session.info.get(_INFO_REQUEST):
        # The root transaction is over: commit, rollback or close gave the
        # connection back to the pool.
        session.info[_INFO_HOLDING] = False


def install() -> None:
    """Idempotent. Listens on the Session CLASS, so every session any module
    opens is seen, including the ones opened by `SessionLocal()` in helpers."""
    global _installed, _enabled
    if _installed:
        return
    _installed = True
    _enabled = _default_enabled()
    event.listen(Session, "after_begin", _after_begin)
    event.listen(Session, "after_transaction_end", _after_transaction_end)
