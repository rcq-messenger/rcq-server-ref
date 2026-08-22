"""Local-only verification of stage 1c: stop telling third parties who is
talking to whom.

Three unrelated-looking changes with one shape. Each removes an identifier from
somewhere a party OUTSIDE the island can read it, and each has a way of looking
fine while being broken:

  push payload   Removing the room name is one line. Removing it in a way that
                 still WAKES the right devices, still groups five messages into
                 one banner, and still lets the receiver's mute gate fire
                 before it decrypts anything, is the part worth testing. A
                 payload missing `group_id` mutes nothing and a payload missing
                 `thread-id` is five banners.
  log lines      A suppressed field is easy to get wrong in the direction that
                 does not show up in a smoke test: it looks suppressed on the
                 dev box (flag off) and prints on the island that turned the
                 flag on for something else. Both directions are checked.
  redis keys     The dangerous half is not the hashing, it is the MIGRATION.
                 Orphaning `dev_revoked:<uin>` un-revokes a revoked browser,
                 and orphaning `devices:<uin>` serves the v=2 bundle to a
                 multi-device identity. So the fold is tested with the racing
                 write it was built for: a session created on the new key
                 BEFORE the legacy key is folded must survive the fold.

Needs a local Redis (`redis-server`, default localhost:6379). Uses db 15 so a
dev box's real keyspace is never touched.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_stage1c_local.py
"""
import asyncio
import json
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_stage1c.db"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ["ENV"] = "dev"
os.environ["JWT_SECRET"] = "stage1c-secret-for-bucket-derivation"

for f in ("test_stage1c.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import inspect  # noqa: E402

from app.core import config  # noqa: E402
from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.rate_limit import bucket_name  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.redis_keys import (  # noqa: E402
    DEV_REVOKED_PREFIX,
    DEVICES_PREFIX,
    ONLINE_DEVS_PREFIX,
    account_key,
    migrate_legacy_account_keys,
)
from app.core.security import device_is_revoked  # noqa: E402
from app.models.device_token import DeviceToken  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers import devices as devices_router  # noqa: E402
from app.services import apns, unifiedpush  # noqa: E402

PASS, FAIL = [], []

UIN_A = 100200300
UIN_B = 688303020
GROUP_ID = 41
GROUP_NAME = "Ночной созвон"


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{'' if ok else '  ← ' + detail}")


# ── 1. the push payload ──────────────────────────────────────────────────
#
# Both senders are captured at the last point before the bytes leave: for APNs
# that is `_send_one`, for UnifiedPush the scheduled fan-out. Nothing is
# mocked deeper than the socket, so what these assert is literally what a
# third party would receive.


async def capture_apns(**kwargs) -> dict:
    """Run apns.send_to_user against one fake iOS token, return the payload."""
    seen: dict = {}

    async def fake_send_one(token, payload, *, push_type, topic):
        seen["payload"] = payload
        seen["push_type"] = push_type
        return True, False

    # `_is_configured` is False on a box with no .p8, and send_to_user
    # short-circuits before it builds anything. Stubbed so the payload under
    # test is the one production would build.
    real, real_cfg = apns._send_one, apns._is_configured
    apns._send_one = fake_send_one
    apns._is_configured = lambda: True
    try:
        await apns.send_to_user(UIN_A, tokens=[(1, "aa" * 32, "dev-1")], **kwargs)
    finally:
        apns._send_one, apns._is_configured = real, real_cfg
    return seen.get("payload", {})


async def capture_up(**kwargs) -> dict:
    """Run unifiedpush.send_to_user, return the JSON body it would POST."""
    seen: dict = {}

    async def fake_deliver(endpoint, body, ttl):
        seen["body"] = json.loads(body.decode())
        return "ok", "200"

    real = unifiedpush._deliver
    unifiedpush._deliver = fake_deliver
    try:
        await unifiedpush.send_to_user(
            UIN_A, endpoints=[(1, "https://push.rcq.app/topic", None, "dev-1", None)], **kwargs
        )
        # `_schedule` fires a background task the sender never awaits.
        for _ in range(50):
            await asyncio.sleep(0.01)
            if "body" in seen:
                break
    finally:
        unifiedpush._deliver = real
    return seen.get("body", {})


def flat_strings(obj) -> list[str]:
    """Every string anywhere in a nested payload, for the leak assertions."""
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            out.extend(flat_strings(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(flat_strings(v))
    else:
        out.append(str(obj))
    return out


async def test_push_payload() -> None:
    print("\npush payload")

    # The signature is the guard rail. A caller cannot leak a name it has no
    # parameter to pass, and this is what stops the fix rotting back.
    for name, fn in (("apns", apns.send_to_user), ("unifiedpush", unifiedpush.send_to_user)):
        params = set(inspect.signature(fn).parameters)
        check(
            f"{name}.send_to_user has no alert_title/group_name parameter",
            not ({"alert_title", "group_name"} & params),
            f"still accepts {sorted({'alert_title', 'group_name'} & params)}",
        )

    group_kwargs = dict(
        alert_body="New group message",
        envelope_b64="Y2lwaGVydGV4dA==",
        envelope_type="gmsg",
        thread_id=f"group-{GROUP_ID}",
        group_id=GROUP_ID,
    )
    ios = await capture_apns(**group_kwargs)
    android = await capture_up(**group_kwargs)

    check("apns group push produced a payload", bool(ios))
    check("unifiedpush group push produced a payload", bool(android))

    for name, payload in (("apns", ios), ("unifiedpush", android)):
        strings = flat_strings(payload)
        check(f"{name}: the room name appears nowhere", GROUP_NAME not in strings)
        check(f"{name}: no group_name field", "group_name" not in payload)

    check("apns: banner title is the constant", ios.get("aps", {}).get("alert", {}).get("title") == "RCQ")
    check("unifiedpush: banner title is the constant", android.get("title") == "RCQ")

    # The three things the client half needs, which a careless strip removes.
    check("apns: thread-id survives, so five messages stay one banner",
          ios.get("aps", {}).get("thread-id") == f"group-{GROUP_ID}")
    check("unifiedpush: thread_id survives", android.get("thread_id") == f"group-{GROUP_ID}")
    check("apns: group_id survives, so the pre-decrypt mute gate still fires",
          ios.get("group_id") == GROUP_ID)
    check("unifiedpush: group_id survives", android.get("group_id") == GROUP_ID)
    check("apns: to_uin survives, so a multi-account device picks the right store",
          ios.get("to_uin") == UIN_A)
    check("apns: the ciphertext is carried verbatim", ios.get("env") == "Y2lwaGVydGV4dA==")

    # Non-sealed kinds are the other half of the leak: the title used to be the
    # SENDER'S nickname, which is a real person's name against a device token.
    nick_kwargs = dict(
        alert_body="wants to add you as a contact",
        thread_id="pending",
        notif_kind="contact_request",
    )
    ios_req = await capture_apns(**nick_kwargs)
    android_req = await capture_up(**nick_kwargs)
    check("apns: contact-request banner is not titled with a nickname",
          ios_req.get("aps", {}).get("alert", {}).get("title") == "RCQ")
    check("unifiedpush: contact-request banner is not titled with a nickname",
          android_req.get("title") == "RCQ")
    check("apns: notif_kind survives, so the client can still localize the line",
          ios_req.get("notif_kind") == "contact_request")


# ── 2. the log lines ─────────────────────────────────────────────────────


async def test_log_suppression(caplines) -> None:
    print("\nlog lines")
    import logging

    async def emit(flag: bool) -> list[str]:
        caplines.clear()
        config.settings.RCQ_LOG_IDENTITIES = flag
        # APNs device token: hashed unconditionally, NOT behind the flag:
        # a token is a credential-shaped device pseudonym, not a debug field.
        logging.getLogger("t").warning("token=%s", apns._token_label("bb" * 32))
        # The four flag-gated ones, in the shape their call sites use.
        logging.getLogger("t").warning("keys uin=%s", config.log_identity(UIN_A))
        logging.getLogger("t").warning("devices uin=%s", config.log_identity(UIN_A))
        logging.getLogger("t").warning("grant %s -> %s",
                                       config.log_identity(UIN_A), config.log_identity(UIN_B))
        return list(caplines)

    off = await emit(False)
    check("flag OFF: no account number in any line",
          not any(str(UIN_A) in ln or str(UIN_B) in ln for ln in off),
          "; ".join(off))
    check("flag OFF: the field is a placeholder, not a dropped field",
          all("=-" in ln or "- -> -" in ln for ln in off[1:]), "; ".join(off[1:]))

    on = await emit(True)
    check("flag ON: the account is back, so the switch is a real switch",
          any(str(UIN_A) in ln for ln in on) and any(str(UIN_B) in ln for ln in on))

    config.settings.RCQ_LOG_IDENTITIES = False
    token = "cc" * 32
    label = apns._token_label(token)
    check("apns token label never contains the token", token[:12] not in label and token not in label)
    check("apns token label is stable, so two lines about one device still join up",
          label == apns._token_label(token))
    check("apns token label separates two devices", label != apns._token_label("dd" * 32))


# ── 3. redis key names ───────────────────────────────────────────────────


async def test_redis_keys() -> None:
    print("\nredis key names")
    redis = await get_redis()
    async for k in redis.scan_iter(match="*"):
        await redis.delete(k)

    for prefix in (DEVICES_PREFIX, DEV_REVOKED_PREFIX, ONLINE_DEVS_PREFIX):
        key = account_key(prefix, UIN_A)
        check(f"{prefix}: key name carries no account number", str(UIN_A) not in key, key)
        check(f"{prefix}: key is bound to the account it is for",
              key.endswith(bucket_name(f"uin:{UIN_A}")) and key != account_key(prefix, UIN_B))

    # The new prefixes must not match the legacy SCAN patterns, or the second
    # boot hashes its own output and every linked session is lost.
    check("new prefixes cannot be re-migrated",
          not account_key(DEVICES_PREFIX, UIN_A).startswith("devices:")
          and not account_key(DEV_REVOKED_PREFIX, UIN_A).startswith("dev_revoked:"))

    # ── the fold, with the boot-window race it exists for ──
    await redis.hset("devices:%d" % UIN_A, "old-browser", json.dumps({"label": "Web"}))
    await redis.expire("devices:%d" % UIN_A, 3600)
    await redis.sadd("dev_revoked:%d" % UIN_A, "burned-browser")
    await redis.expire("dev_revoked:%d" % UIN_A, 3600)
    # A worker that finished booting first has already served a link request
    # and written the NEW key. A RENAME here would drop this on the floor.
    await redis.hset(account_key(DEVICES_PREFIX, UIN_A), "new-browser", json.dumps({"label": "Web"}))

    moved = await migrate_legacy_account_keys()
    check("fold reported both legacy keys", moved == 2, str(moved))
    check("legacy device key is gone", not await redis.exists("devices:%d" % UIN_A))
    check("legacy revoked key is gone", not await redis.exists("dev_revoked:%d" % UIN_A))

    folded = await redis.hgetall(account_key(DEVICES_PREFIX, UIN_A))
    folded = {(k.decode() if isinstance(k, bytes) else k) for k in folded}
    check("the pre-existing linked session survived the fold", "old-browser" in folded, str(folded))
    check("the session written during the boot window survived too",
          "new-browser" in folded, str(folded))
    ttl = int(await redis.ttl(account_key(DEVICES_PREFIX, UIN_A)))
    check("the 90-day TTL rode along, so sessions do not become immortal", ttl > 0, str(ttl))

    check("a revoked browser is STILL revoked after the fold",
          await device_is_revoked(UIN_A, "burned-browser"))
    check("an unrelated device is still not revoked",
          not await device_is_revoked(UIN_A, "some-other-browser"))

    # Idempotence: every boot from now on runs this.
    again = await migrate_legacy_account_keys()
    check("second pass is a no-op", again == 0, str(again))
    folded2 = await redis.hgetall(account_key(DEVICES_PREFIX, UIN_A))
    check("second pass changed nothing", len(folded2) == 2, str(folded2))

    # Nothing anywhere in the keyspace names the account any more, which is the
    # property the whole item is about.
    leaking = [
        (k.decode() if isinstance(k, bytes) else k)
        async for k in redis.scan_iter(match="*")
        if str(UIN_A) in (k.decode() if isinstance(k, bytes) else k)
    ]
    check("no key in the keyspace names the account", not leaking, str(leaking))

    # The router's own helpers must agree with the module, or a revoke written
    # by one and read by the other silently misses.
    check("devices router builds the same key",
          devices_router._devices_key(UIN_A) == account_key(DEVICES_PREFIX, UIN_A))
    check("devices router builds the same revoked key",
          devices_router._revoked_key(UIN_A) == account_key(DEV_REVOKED_PREFIX, UIN_A))

    async for k in redis.scan_iter(match="*"):
        await redis.delete(k)


# ── the delivery path still delivers ─────────────────────────────────────


async def test_push_still_targets() -> None:
    """The payload lost two fields; it must not have lost the fan-out. Reads
    real rows through `group_push_targets`, the query the group send uses."""
    print("\ndelivery is unchanged")
    async with SessionLocal() as db:
        db.add_all([
            User(uin=UIN_A, nickname="a", identity_key="k", signing_key="s"),
            User(uin=UIN_B, nickname="b", identity_key="k", signing_key="s"),
        ])
        await db.commit()
        db.add_all([
            DeviceToken(uin=UIN_A, token="tok-ios", platform="ios", device_id="d1"),
            DeviceToken(uin=UIN_B, token="https://push.rcq.app/t", platform="android-up",
                        device_id="d2"),
        ])
        await db.commit()
        targets = await apns.group_push_targets(db, [UIN_A, UIN_B], GROUP_ID)
    check("both members are still woken", set(targets) == {UIN_A, UIN_B}, str(set(targets)))
    check("the iOS endpoint is routed to APNs", bool(targets[UIN_A].ios))
    check("the Android endpoint is routed to UnifiedPush", bool(targets[UIN_B].android))

    async with SessionLocal() as db:
        user = await db.get(User, UIN_A)
        user.push_preferences = {"muted_group_ids": [GROUP_ID]}
        await db.commit()
        targets = await apns.group_push_targets(db, [UIN_A, UIN_B], GROUP_ID)
    check("a muted member is still dropped server-side", set(targets) == {UIN_B}, str(set(targets)))


async def main() -> None:
    import logging

    caplines: list[str] = []

    class Cap(logging.Handler):
        def emit(self, record):
            caplines.append(record.getMessage())

    logging.getLogger("t").addHandler(Cap())
    logging.getLogger("t").setLevel(logging.WARNING)

    await init_db()
    await test_push_payload()
    await test_log_suppression(caplines)
    await test_redis_keys()
    await test_push_still_targets()
    await close_redis()

    print(f"\n{len(PASS)}/{len(PASS) + len(FAIL)} passed")
    if FAIL:
        print("FAILED: " + ", ".join(FAIL))
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
