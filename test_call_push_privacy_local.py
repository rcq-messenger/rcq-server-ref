"""Local-only verification that a CALL wake names nobody.

The thing being pinned. `routers/ws.py` wakes an offline callee with a flat
payload, and that payload used to carry the caller's `nickname`. The wake goes
to Apple (PushKit) on iOS and to whatever UnifiedPush distributor the callee
installed on Android, which for our own `push.rcq.app` is a Cloudflare edge
that terminates TLS. So a call to a phone that happened to be asleep told a
third party WHO CALLED WHOM AND WHEN, by name: a named edge of the social
graph, strictly more than the group name that left the message push on
2026-08-22.

What the tests below check, in the order they matter:

  1. the offer wake carries the four routing fields and nothing else, and no
     field of it contains the caller's nickname anywhere at any depth;
  2. `from_uin` IS still there, because that is the minimum a client needs to
     resolve the name from its own roster, and a wake without it cannot be
     answered at all (an over-eager future scrub would fail here);
  3. the two follow-up wakes on the same road, the `call_end` fallback and the
     answered-elsewhere un-ring, are clean too. They never carried a name, and
     the point of pinning them is that they are the obvious place to put one
     back;
  4. neither sender ADDS identity of its own on the way out: the UnifiedPush
     body is the payload plus exactly `v`, `type`, `to_uin`.

The nickname used here is a string that cannot occur by accident, so a match
anywhere in the serialized wake is proof and not a coincidence.

Throwaway SQLite, no Redis, no network: everything the call path reaches
outside the DB is stubbed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_call_push_privacy_local.py
"""
import asyncio
import json
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_call_push.db"
os.environ["ENV"] = "dev"
os.environ.setdefault("JWT_SECRET", "t" * 64)

for _f in ("test_call_push.db",):
    try:
        os.remove(_f)
    except FileNotFoundError:
        pass

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.models.device_token import DeviceToken  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers import ws as ws_mod  # noqa: E402
from app.services import unifiedpush  # noqa: E402

CALLER = 7001
CALLEE = 7002
# Unmistakable on purpose: if this shows up anywhere in a wake, it got there
# from the User row and not by chance.
CALLER_NICK = "Zzq-Caller-Nickname-Marker-42"

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name if ok else f"{name} {detail}".strip())
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{'' if ok else '  ' + detail}")


def contains_marker(obj: object) -> bool:
    """Is the marker anywhere in this structure, at any depth?"""
    return CALLER_NICK.lower() in json.dumps(obj, default=str).lower()


class FakeManager:
    """Everything `_handle_client_message` asks of the connection manager.

    `send` returns False for the callee, which is the whole precondition of
    this test: an offline callee is the only one that gets a wake.
    """

    def __init__(self) -> None:
        self.sent: list[tuple[int, dict]] = []

    async def touch_device(self, uin: int, device_id: str) -> None:
        return None

    async def send(self, uin: int, payload: dict, **kw: object) -> bool:
        self.sent.append((uin, payload))
        return False


class Captured:
    """Stands in for both push senders and records what it was handed."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def make(self):
        async def fn(uin: int, *, payload: dict, **kw: object) -> int:
            self.calls.append({"uin": uin, "payload": payload, "kw": kw})
            return 1

        return fn


async def offer(voip: Captured, up: Captured) -> None:
    await ws_mod._handle_client_message(
        CALLER,
        {
            "type": "call_offer",
            "to_uin": CALLEE,
            "call_id": "call-abc",
            "media": "video",
            "sdp": "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\n",
        },
        device_id="dev-caller",
    )


async def main() -> int:
    await init_db()
    async with SessionLocal() as db:
        db.add(User(uin=CALLER, nickname=CALLER_NICK, identity_key="ik-a", signing_key="sk-a"))
        # `call_policy` defaults to "contacts", and this test is not about the
        # policy gate: an offer that never gets past it never reaches a wake.
        db.add(User(
            uin=CALLEE, nickname="Callee", identity_key="ik-b", signing_key="sk-b",
            call_policy="everyone",
        ))
        # A wakeable device, so the offer path takes the push branch rather
        # than the "nothing can ring" short-circuit.
        db.add(DeviceToken(uin=CALLEE, platform="ios-voip", token="tok-voip", device_id="dev-callee"))
        await db.commit()

    fake_manager = FakeManager()
    voip, up = Captured(), Captured()

    ws_mod.manager = fake_manager
    ws_mod.send_voip_to_user = voip.make()
    ws_mod.up_call = up.make()

    async def always_register(call_id: str, a: int, b: int) -> bool:
        return True

    ws_mod._register_call = always_register

    print("\n1. the offer wake")
    await offer(voip, up)

    check("iOS VoIP wake was sent", len(voip.calls) == 1)
    check("Android UnifiedPush wake was sent", len(up.calls) == 1)
    if not voip.calls or not up.calls:
        return 1

    payload = voip.calls[0]["payload"]
    check(
        "iOS and Android are handed the SAME payload",
        up.calls[0]["payload"] == payload,
        f"ios={payload} android={up.calls[0]['payload']}",
    )
    check(
        "no `nickname` field",
        "nickname" not in payload,
        f"payload={payload}",
    )
    check(
        "the caller's name is nowhere in the wake, at any depth",
        not contains_marker(payload),
        f"payload={payload}",
    )
    check(
        "exactly the four routing fields",
        set(payload) == {"call_id", "from_uin", "media", "sdp"},
        f"keys={sorted(payload)}",
    )
    # The other direction. Scrubbing `from_uin` too would leave a wake nobody
    # can answer, and it buys nothing: the callee's own number is in the same
    # payload already.
    check(
        "`from_uin` survives, so the client can resolve the name itself",
        payload.get("from_uin") == CALLER,
        f"from_uin={payload.get('from_uin')}",
    )

    print("\n2. the follow-up wakes on the same road")
    voip.calls.clear()
    up.calls.clear()
    await ws_mod._handle_client_message(
        CALLER,
        {"type": "call_end", "to_uin": CALLEE, "call_id": "call-abc", "reason": "remote_ended"},
        device_id="dev-caller",
    )
    check("call_end fallback wake was sent", len(voip.calls) == 1)
    if voip.calls:
        check(
            "call_end wake names nobody",
            not contains_marker(voip.calls[0]["payload"]),
            f"payload={voip.calls[0]['payload']}",
        )

    voip.calls.clear()
    up.calls.clear()
    # The answered-elsewhere un-ring: sent BY the callee, TO the callee's own
    # other devices. Its payload names the caller by uin and must not do more.
    await ws_mod._handle_client_message(
        CALLEE,
        {"type": "call_answer", "to_uin": CALLER, "call_id": "call-abc", "sdp": "v=0\r\n"},
        device_id="dev-callee",
    )
    check("answered-elsewhere un-ring was sent", len(voip.calls) == 1)
    if voip.calls:
        p = voip.calls[0]["payload"]
        check(
            "un-ring names nobody",
            not contains_marker(p) and "nickname" not in p,
            f"payload={p}",
        )

    print("\n3. neither sender adds identity of its own")
    # `send_call_to_user` is the one that wraps: it is the only place between
    # `ws.py` and the distributor where a field could be added back.
    scheduled: list[dict] = []

    def fake_schedule(uin: int, body: dict, ttl: int, kindtag: str, *a: object, **kw: object) -> None:
        scheduled.append(body)

    real_schedule = unifiedpush._schedule
    unifiedpush._schedule = fake_schedule
    try:
        await unifiedpush.send_call_to_user(
            CALLEE, payload={"call_id": "c", "from_uin": CALLER, "media": "audio", "sdp": "x"}
        )
    finally:
        unifiedpush._schedule = real_schedule

    check("the UnifiedPush body was built", len(scheduled) == 1)
    if scheduled:
        body = scheduled[0]
        check(
            "wrapper adds only v/type/to_uin",
            set(body) - {"call_id", "from_uin", "media", "sdp"} == {"v", "type", "to_uin"},
            f"keys={sorted(body)}",
        )
        check("wrapper adds no name", not contains_marker(body), f"body={body}")

    # `_set_answered_mark` on the call_answer path opens the shared redis
    # client. Closing it here keeps the run from ending in a page of
    # "Event loop is closed" from the connection's finalizer.
    try:
        from app.core.redis import close_redis

        await close_redis()
    except Exception:  # noqa: BLE001 - a stubborn client must not fail the run
        pass

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for f in FAIL:
        print(f"  FAILED: {f}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
