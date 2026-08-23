"""Local-only verification that a group fan-out reads push endpoints ONCE.

The pool is small (PgBouncer, transaction mode) and a post to the ~1.9k-member
beta group used to ask it for a connection per recipient per transport. This
pins the batched shape: `group_push_targets` returns the endpoints along with
the targets, and neither sender opens a session when it is handed them.

Runs against a throwaway SQLite DB; the network side of both senders is stubbed.
NOT part of the prod suite; NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_push_fanout_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_push_fanout.db"
os.environ["ENV"] = "dev"

for f in ("test_push_fanout.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

from app.core.db import init_db, SessionLocal  # noqa: E402
from app.models.user import User  # noqa: E402
from app.models.device_token import DeviceToken  # noqa: E402
from app.services import apns, unifiedpush  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=33):
    return base64.b64encode(os.urandom(n)).decode()


GID = 42
IOS_AND_ANDROID = 3001   # both transports registered
ANDROID_ONLY = 3002
MUTED = 3003             # has a token, muted this group
NO_ENDPOINT = 3004
VOIP_ONLY = 3005         # only an ios-voip token: not a target for alerts


class ExplodingSession:
    """Any attempt to open a DB session is the bug this test is about."""

    def __init__(self):
        self.opened = 0

    def __call__(self, *a, **kw):
        self.opened += 1
        raise AssertionError("opened a DB session during a batched fan-out")


async def main():
    await init_db()
    async with SessionLocal() as db:
        for uin, muted in (
            (IOS_AND_ANDROID, []), (ANDROID_ONLY, []), (MUTED, [GID]),
            (NO_ENDPOINT, []), (VOIP_ONLY, []),
        ):
            db.add(User(
                uin=uin, nickname=f"u{uin}", identity_key=b64(32), signing_key=b64(32),
                push_preferences={"muted_group_ids": muted} if muted else None,
            ))
        db.add(DeviceToken(uin=IOS_AND_ANDROID, token="ios-tok", platform="ios", device_id="phone"))
        db.add(DeviceToken(uin=IOS_AND_ANDROID, token="https://up.example/aaa", platform="android-up", device_id="phone"))
        db.add(DeviceToken(uin=ANDROID_ONLY, token="https://up.example/bbb", platform="android-up", device_id="tab"))
        db.add(DeviceToken(uin=MUTED, token="ios-muted", platform="ios", device_id="m"))
        db.add(DeviceToken(uin=VOIP_ONLY, token="voip-tok", platform="ios-voip", device_id="v"))
        await db.commit()

    recipients = [IOS_AND_ANDROID, ANDROID_ONLY, MUTED, NO_ENDPOINT, VOIP_ONLY]
    async with SessionLocal() as db:
        wake = await apns.group_push_targets(db, recipients, GID)

    check("targets are keyed by uin", isinstance(wake, dict))
    check("only the two wakeable members are targets", list(wake) == [IOS_AND_ANDROID, ANDROID_ONLY])
    check("muted member excluded", MUTED not in wake)
    check("member with no endpoint excluded", NO_ENDPOINT not in wake)
    check("voip-only member is not an alert target", VOIP_ONLY not in wake)
    check("ios endpoint carried through", [t for _, t, _ in wake[IOS_AND_ANDROID].ios] == ["ios-tok"])
    check(
        "android endpoint carried through",
        [t for _, t, _, _, _ in wake[IOS_AND_ANDROID].android] == ["https://up.example/aaa"],
    )
    check("android-only member has no ios rows", wake[ANDROID_ONLY].ios == [])

    # --- Neither sender may touch the DB when handed the rows --------------
    delivered: list[str] = []

    async def fake_send_one(token, payload, **kw):
        delivered.append(token)
        return True, False

    async def fake_deliver(endpoint, body, ttl):
        delivered.append(endpoint)
        return "ok", "200"

    async def exploding_lookup(uin):
        raise AssertionError("re-read endpoints that were handed in")

    apns._send_one = fake_send_one
    apns._is_configured = lambda: True
    apns.SessionLocal = ExplodingSession()
    unifiedpush._deliver = fake_deliver
    unifiedpush._endpoints_for = exploding_lookup
    unifiedpush.SessionLocal = ExplodingSession()

    ends = wake[IOS_AND_ANDROID]
    sent = await apns.send_to_user(IOS_AND_ANDROID, envelope_b64="x", tokens=ends.ios)
    check("apns sent to the handed-in token without a session", sent == 1 and "ios-tok" in delivered)

    # Health bookkeeping is deferred and batched: the delivery task itself must
    # not write, or a 1.9k fan-out is 1.9k sessions the moment the hourly stamp
    # comes due.
    written: list[tuple[list, list, list]] = []

    async def fake_record(ok, failed, dead):
        written.append((list(ok), list(failed), list(dead)))

    unifiedpush._record_health = fake_record
    unifiedpush._HEALTH_FLUSH_DELAY = 0.05

    await unifiedpush._fan_out(
        IOS_AND_ANDROID, {"v": 1}, 60, "msg", frozenset(), frozenset(), ends.android
    )
    check(
        "unifiedpush delivered to the handed-in endpoint without a session",
        "https://up.example/aaa" in delivered,
    )
    check("the delivery task itself writes nothing", written == [])

    # A second recipient finishing in the same beat must join the same write.
    await unifiedpush._fan_out(
        ANDROID_ONLY, {"v": 1}, 60, "msg", frozenset(), frozenset(), wake[ANDROID_ONLY].android
    )
    await asyncio.sleep(0.3)
    check("both recipients' bookkeeping landed in ONE write", len(written) == 1)
    check(
        "and it carries both endpoints",
        written and sorted(written[0][0]) == sorted(
            [ends.android[0][0], wake[ANDROID_ONLY].android[0][0]]
        ),
    )

    print("\nALL PUSH FAN-OUT CHECKS PASSED ✅" if fails == 0 else f"\n{fails} CHECK(S) FAILED ❌")
    raise SystemExit(0 if fails == 0 else 1)


asyncio.run(main())
