"""One refresh at a time, and never on a connection somebody else is holding.

⚠⚠ WHY THIS EXISTS: the stalls of 11.09-28.09. The island went dark for 2-11
minutes at a time, 24 times in 30 days and 4-8 times a day at the end, while
the droplet sat 90% idle. The mechanism was hold-and-wait on the database
pool, and it lived in the small per-worker caches:

  * a request handler (GET /users/{uin}/info above all) runs its first query,
    which opens a transaction and holds one pooled connection and, behind
    PgBouncer in TRANSACTION mode, one of the island's 15 backends;
  * it then asks a cached helper for a setting, a host name or the guest set,
    finds the cache stale, and the helper opens a SECOND session to reload it,
    while the first one is still held;
  * nothing stopped every concurrent request from doing the same, so a burst
    of ~25-30 of them (a client opening a room with 2271 members and asking
    for a card per member) filled the pool with holders each waiting for a
    second connection only another holder could give back. Only the pool's
    20 s timeout and PgBouncer's ~120 s queue timeout broke it, and a failed
    reload left the cache stale, so the next request nested again.

The rule this module gives the caches: a request that finds a cache stale is
answered from what the cache already holds and a refresh is started BEHIND it,
one per worker, on a connection the request does not hold. Only a cache that
has never been read has nothing to answer with, and those are warmed in the
lifespan before the worker takes traffic.

⚠⚠ And a clock, not traffic, keeps them fresh. Serving stale on its own
means a worker that nobody asked for an hour answers its next request with
hour-old settings (a paid island still "open", the old payout wallet) and
only then refreshes. So the lifespan also runs a ticker (main.py
`_cache_ticker`) that refreshes each cache as soon as it is due, whether or
not anybody is asking, and the settings cache refuses to serve rows past a
hard age without first giving one refresh a moment (server_settings.py).

Two tools:

  * `SingleFlight`: at most one refresh task in flight per worker, bound to
    the running event loop and started in a CLEAN context;
  * `RedisMirror`: the same for the three Redis mirrors of a table (guest
    set, uin epochs, suspended set), which also need one rebuild per ISLAND
    rather than per worker, and have to tell "the marker lapsed" from "this
    Redis has never held the mirror".
"""
from __future__ import annotations

import asyncio
import contextvars
import logging
import time
from typing import Any, Awaitable, Callable, Optional

log = logging.getLogger(__name__)

#: A refresh that failed is logged, but not once per retry: during a real
#: outage every cache on every worker retries every couple of seconds, and on
#: 28.09 journald threw away ~171k lines in three minutes because each failure
#: wrote a traceback. One line per cache per worker per this many seconds, with
#: a count of what was held back.
_LOG_EVERY_SECONDS = 60.0


def _short(exc: BaseException) -> str:
    text = str(exc).replace("\n", " ")
    return f"{type(exc).__name__}: {text[:200]}"


class SingleFlight:
    """At most one refresh task in flight per worker.

    ⚠ BOUND TO THE LOOP IT WAS STARTED ON. Tools (`asyncio.run`) and the local
    tests run several event loops in one process, one after another, and a
    task left over from a closed loop never becomes done() in the next one: a
    module-level "is one running?" check that ignored the loop would wait on
    it for ever and never refresh again. A task from another loop counts as
    no task at all.

    ⚠ STARTED IN A CLEAN `contextvars.Context`. `create_task` copies the
    caller's context by default, and the caller is a request: its context
    carries the request's database session for the nesting detector
    (core/db_nesting.py). A refresh is not part of that request and must not
    be judged as if it were.

    The task body never raises to its waiters. It returns True when it did
    its job and False when it failed (logged here, rate-limited), so nobody
    has to retrieve an exception from a task they did not start, and a task
    that finishes with no waiter at all does not print "exception was never
    retrieved" at shutdown.
    """

    def __init__(self, label: str) -> None:
        self.label = label
        self._task: Optional[asyncio.Task] = None
        #: `time.monotonic()` when the refresh in flight (or the last one) was
        #: started. A cache that lets readers wait budgets that wait per
        #: ATTEMPT from here, not per reader: see `wait_for_attempt`.
        self.started_at = 0.0
        self._last_log = 0.0
        self._held_back = 0

    def current(self) -> Optional[asyncio.Task]:
        """The refresh in flight on THIS loop, or None."""
        task = self._task
        if task is None or task.done():
            return None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return None
        if task.get_loop() is not loop:
            self._task = None
            return None
        return task

    def start(self, factory: Callable[[], Awaitable[Any]]) -> asyncio.Task:
        """The refresh in flight, starting one from `factory` if there is none.
        Never waits: the caller decides whether to."""
        task = self.current()
        if task is not None:
            return task
        loop = asyncio.get_running_loop()
        task = loop.create_task(self._guard(factory), context=contextvars.Context())
        self._task = task
        self.started_at = time.monotonic()
        return task

    async def _guard(self, factory: Callable[[], Awaitable[Any]]) -> bool:
        try:
            result = await factory()
            return result is not False
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a refresh never fails its waiters
            self._log_failure(exc)
            return False

    def _log_failure(self, exc: BaseException) -> None:
        now = time.monotonic()
        if now - self._last_log < _LOG_EVERY_SECONDS:
            self._held_back += 1
            return
        held, self._held_back, self._last_log = self._held_back, 0, now
        more = f" (+{held} more since the last line)" if held else ""
        log.warning("[%s] refresh failed, serving what is cached: %s%s", self.label, _short(exc), more)

    async def wait(self, task: asyncio.Task, timeout: Optional[float] = None) -> bool:
        """Wait for `task` without being able to cancel it: the refresh belongs
        to everybody waiting on it, and one impatient client must not take it
        away from the others. False on failure or on timeout."""
        try:
            if timeout is None:
                return bool(await asyncio.shield(task))
            return bool(await asyncio.wait_for(asyncio.shield(task), timeout))
        except asyncio.TimeoutError:
            return False

    async def wait_for_attempt(self, task: asyncio.Task, budget: float) -> bool:
        """Wait for `task`, but only until `budget` seconds after the attempt
        STARTED, whoever started it. False at once when that is already past.

        ⚠ Why per attempt and not per reader. One request can read the same
        cache several times in a row (/server/info reads the settings five
        times). With a per-reader timeout, a refresh that hangs on a pool in
        trouble costs that request the timeout once per read, which is the
        chain of swallowed waits that made /server/info take 90-162 s on 28.09.
        Per attempt, everybody together spends at most `budget` on one hung
        refresh, and the reads after that answer at once."""
        left = self.started_at + budget - time.monotonic()
        if left <= 0:
            # `_guard` never raises to a waiter; only a cancelled task has no
            # result.
            return task.done() and not task.cancelled() and bool(task.result())
        return await self.wait(task, left)


async def read_on(db, fn: Callable[[Any], Awaitable[Any]]) -> Any:
    """Run the read `fn(session)` on the CALLER'S session when it has one, else
    on a short session of its own.

    ⚠⚠ The caller's session is the whole point. A handler that already ran a
    query holds a pooled connection with an open transaction; opening a second
    session here would ask the pool for another connection while holding that
    one, which is the hold-and-wait the module docstring is about. On the
    caller's session the read is one more statement on the connection it
    already has.

    Autoflush is off for the read: pending objects of the handler are flushed
    when the HANDLER decides, not as a side effect of a cache miss (a flush
    here could raise the handler's own IntegrityError from inside a guest
    check).

    `SessionLocal` is looked up at call time, so a test that swaps
    `app.core.db.SessionLocal` for one that fails reaches this path too.
    """
    if db is not None:
        with db.no_autoflush:
            return await fn(db)
    from app.core.db import SessionLocal

    async with SessionLocal() as own:
        return await fn(own)


class RedisMirror:
    """A Redis copy of a small table, trusted while a marker with a TTL lives.

    Three keys besides the mirror itself:

      * `marker` (TTL): while it exists, the mirror is trusted as is;
      * `built` (no TTL): the mirror has been built at least once since this
        Redis last lost its data. It dies with a flush or a restart without
        persistence, exactly when the mirror itself does;
      * `lock` (SET NX EX): one rebuild per ISLAND at a time, not one per
        worker.

    ⚠⚠ WHAT CHANGED, and why it is safe. The marker used to be the only key:
    when it lapsed, EVERY authorized request on EVERY worker that noticed
    rebuilt the mirror inline, from inside the request, and a rebuild is a
    second database session. That was one of the nested sessions behind the
    28.09 stalls: the guest marker expired in the middle of a stall and every
    request after that nested twice (`[guest] cache unavailable ... QueuePool
    limit` 114 times in 95 s).

    The mirrors are authoritative on WRITE: every path that changes a row
    changes the mirror in the same breath (mark before commit, write-through
    after), so a lapsed marker does not make the mirror wrong, it only makes
    it due for a resync. So now:

      * marker alive: answer from the mirror;
      * marker gone, mirror built: answer from the mirror NOW and rebuild it
        in the background, one worker at a time (the lock), one task per
        worker (SingleFlight);
      * never built (a flushed or brand-new Redis): the mirror is not an
        answer at all, so it is rebuilt inline as before, on the caller's
        session when there is one (`read_on`).
    """

    def __init__(
        self,
        label: str,
        *,
        marker: str,
        built: str,
        lock: str,
        rebuild: Callable[[Any, Any], Awaitable[None]],
        lock_ttl: int = 30,
        retry_after: float = 2.0,
    ) -> None:
        self.label = label
        self.marker = marker
        self.built = built
        self.lock = lock
        self._rebuild = rebuild
        self.lock_ttl = lock_ttl
        self.retry_after = retry_after
        self._flight = SingleFlight(label)
        self._next_kick = 0.0

    async def ensure(self, redis, db=None) -> None:
        """Make the mirror answerable. Raises only when it had to rebuild
        inline and could not, which the callers treat as a cache failure."""
        marker, built = await redis.mget([self.marker, self.built])
        if marker is not None:
            return
        if built is not None:
            self.kick(redis)
            return
        await self._rebuild(redis, db)

    async def prime(self, redis) -> None:
        """Build the mirror now if this Redis has never held it. For the
        lifespan, where nothing is held: the first deploy of the `built` key
        finds live markers and no `built`, and without this the first lapse
        of each marker would still rebuild inline, one last time, on every
        request that noticed it."""
        if await redis.exists(self.built):
            return
        await self._rebuild(redis, None)

    def kick(self, redis) -> None:
        """Start a background rebuild, unless one is running on this worker or
        this worker's last one ended less than `retry_after` ago. The request
        that noticed never waits for it."""
        if time.monotonic() < self._next_kick or self._flight.current() is not None:
            return
        self._flight.start(lambda: self._background(redis))

    async def _background(self, redis) -> bool:
        try:
            # One worker per island. A worker that does not get the lock has
            # nothing to do: somebody else is rebuilding, and until they
            # finish every reader keeps answering from the mirror as it is.
            if not await redis.set(self.lock, "1", nx=True, ex=self.lock_ttl):
                return True
            try:
                await self._rebuild(redis, None)
            finally:
                try:
                    await redis.delete(self.lock)
                except Exception:  # noqa: BLE001 - it expires on its own
                    pass
            return True
        finally:
            # ⚠ Counted from when the attempt ENDED, not from when it was
            # kicked. A rebuild that fails does so on the pool's 20 s timeout,
            # and a pause measured from the kick would be long over by then:
            # the next reader would start the next 20 s attempt at once.
            self._next_kick = time.monotonic() + self.retry_after
