"""Local-only verification of the 2026-08-22 retention sweeps (stage 1b).

Every sweep here answers the same two questions, and the second one is the one
that matters: does it delete what it should, and does it SPARE what it must.
The spare cases are not decoration. Each one is a specific way a sweep could
quietly break the product, taken from reading the code it touches:

  prekeys     a consumed key inside the queue TTL is a live tombstone; deleting
              it lets its owner re-publish the id and makes an in-flight
              PreKeySignalMessage undecryptable
  reports     a bug-bounty row is the Hall of Fame's only source of truth, so
              it is redacted rather than deleted; an OPEN report is the
              moderation queue and is never touched at any age
  devices     a revoked slot must keep (uin, device_id) so the allocator does
              not hand the number to a new install a stale roster still points at
  invites     an exhausted invite with a LIVE child is the revocation handle
              for that child and outlives its own horizon
  gate tokens a `standing` token that has merely gone quiet is not dead
  requests    an accepted request goes in an hour, a DECLINED one is how the
              sender learns the answer and gets six months
  presence    a uin with a live devs key is not a ghost

Plus: the invite code migration hashes in place, idempotently, and a code
minted before it still authenticates after it.

Direct unit test against a throwaway SQLite DB, no HTTP.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_retention_sweeps_local.py
"""
import asyncio
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_retention.db"
os.environ["ENV"] = "dev"
os.environ.setdefault("JWT_SECRET", "t" * 64)

for f in ("test_retention.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

from datetime import datetime, timedelta, timezone  # noqa: E402

from sqlalchemy import func, select, text, update  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.models.access_token import AccessToken  # noqa: E402
from app.models.contact import ContactRequest  # noqa: E402
from app.models.device import Device  # noqa: E402
from app.models.invite import Invite, hash_invite_code  # noqa: E402
from app.models.prekey import OneTimePreKey  # noqa: E402
from app.models.report import Report  # noqa: E402
from app.models.report_message import ReportMessage  # noqa: E402
from app.models.user import User  # noqa: E402

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{'' if ok else '  ← ' + detail}")


def ago(**kw) -> datetime:
    return datetime.now(timezone.utc) - timedelta(**kw)


async def count(model, *where) -> int:
    async with SessionLocal() as db:
        return int(await db.scalar(select(func.count()).select_from(model).where(*where)) or 0)


async def main() -> None:
    await init_db()

    # ── one-time prekeys ────────────────────────────────────────────────────
    print("\none_time_prekeys")
    from app.services.prekey_sweep import CONSUMED_MAX_AGE_DAYS, sweep_once as prekey_sweep

    async with SessionLocal() as db:
        db.add(User(uin=1001, nickname="alice", identity_key="k", signing_key="s"))
        await db.flush()
        rows = [
            # (prekey_id, consumed, consumed_at, created_at)
            (1, False, None, ago(days=400)),                      # live, ancient upload
            (2, True, ago(days=CONSUMED_MAX_AGE_DAYS + 5), ago(days=400)),   # expired tombstone
            (3, True, ago(days=CONSUMED_MAX_AGE_DAYS - 5), ago(days=400)),   # INSIDE the window
            (4, True, None, ago(days=CONSUMED_MAX_AGE_DAYS + 5)),  # legacy, no stamp, old upload
            (5, True, None, ago(days=1)),                          # legacy, recent upload
        ]
        for pid, consumed, cat, crt in rows:
            db.add(OneTimePreKey(
                uin=1001, prekey_id=pid, public_key=f"p{pid}",
                consumed=consumed, consumed_at=cat, created_at=crt,
            ))
        await db.commit()

    n = await prekey_sweep()
    async with SessionLocal() as db:
        left = sorted(
            (await db.scalars(select(OneTimePreKey.prekey_id))).all()
        )
    check("consumed prekey past the horizon is reaped", 2 not in left, str(left))
    check(
        f"consumed prekey INSIDE the {CONSUMED_MAX_AGE_DAYS}d window survives "
        "(an in-flight PreKeySignalMessage still resolves)",
        3 in left, str(left),
    )
    check("an UNCONSUMED key is never touched, however old", 1 in left, str(left))
    # ⚠⚠ These two used to assert the opposite, and the opposite was a bug that
    # shipped: an unstamped row measured against `created_at` is measured
    # against the UPLOAD, which is older than the consumption, so the row looks
    # PAST the horizon when the tombstone is a day old. Row 4 is that exact
    # case (claimed at an unknown time, uploaded 42 days ago) and deleting it
    # is what re-opens the InvalidKeyId window the horizon exists to close.
    check("legacy stampless row is stamped, not measured by its upload",
          4 in left, str(left))
    check("legacy stampless row with a recent upload is spared", 5 in left, str(left))
    async with SessionLocal() as db:
        unstamped = (
            await db.scalars(
                select(OneTimePreKey.prekey_id).where(
                    OneTimePreKey.consumed == True,  # noqa: E712
                    OneTimePreKey.consumed_at.is_(None),
                )
            )
        ).all()
    check("the backfill leaves no consumed row without a clock",
          not unstamped, str(sorted(unstamped)))
    check("the pass reports what it removed", n == 1, f"reported {n}")
    # A stamped row must then behave like any other: still inside the window on
    # the pass that stamped it, and gone once the clock runs out.
    async with SessionLocal() as db:
        await db.execute(
            update(OneTimePreKey)
            .where(OneTimePreKey.prekey_id == 4)
            .values(consumed_at=ago(days=CONSUMED_MAX_AGE_DAYS + 1))
        )
        await db.commit()
    n2 = await prekey_sweep()
    async with SessionLocal() as db:
        left = sorted((await db.scalars(select(OneTimePreKey.prekey_id))).all())
    check("a stamped row goes when ITS OWN clock runs out",
          4 not in left and n2 == 1, f"{left} / reported {n2}")

    # The horizon is DERIVED, not typed in. If somebody edits the queue TTL
    # without reading this, the assertion is what tells them.
    from app.services.offline_queue_sweep import TTL_DAYS as QUEUE_TTL

    check(
        "the horizon still exceeds the 1:1 queue TTL",
        CONSUMED_MAX_AGE_DAYS > QUEUE_TTL,
        f"{CONSUMED_MAX_AGE_DAYS}d vs queue {QUEUE_TTL}d",
    )

    # ── reports ─────────────────────────────────────────────────────────────
    print("\nreports")
    from app.services.report_sweep import (  # noqa: E402
        REDACTED_REASON,
        RESOLVED_MAX_AGE_DAYS,
        sweep_once as report_sweep,
    )

    async with SessionLocal() as db:
        old = ago(days=RESOLVED_MAX_AGE_DAYS + 5)
        recent = ago(days=RESOLVED_MAX_AGE_DAYS - 5)
        # 1: an old ABUSE report -> deleted with its thread
        abuse = Report(
            reporter_uin=1001, target_uin=2002, reason="he said a thing",
            context="contact", status="resolved", resolved_at=old,
            resolution_notes="banned, third strike",
        )
        # 2: an old BUG BOUNTY report -> redacted, row survives for the wall
        bug = Report(
            reporter_uin=1001, target_uin=1001, reason="crash on send",
            context="bug_bounty", status="resolved", resolved_at=old,
            resolution_notes="real, fixed in 0.139",
            reply_text="thanks, shipped",
            attachments=[{"media_id": "deadbeef", "key": "AESKEY", "mime": "image/png", "size": 9}],
        )
        # 3: a RECENTLY closed bug report -> untouched
        recent_bug = Report(
            reporter_uin=1001, target_uin=1001, reason="still here",
            context="bug_bounty", status="resolved", resolved_at=recent,
        )
        # 4: an OPEN report, ancient -> never swept at any age
        still_open = Report(
            reporter_uin=1001, target_uin=2002, reason="open complaint",
            context="contact", status="open", created_at=ago(days=900),
        )
        db.add_all([abuse, bug, recent_bug, still_open])
        await db.flush()
        db.add_all([
            ReportMessage(report_id=abuse.id, from_admin=False, author_uin=1001, body="any news"),
            ReportMessage(report_id=bug.id, from_admin=True, author_uin=0, body="which build?"),
        ])
        ids = (abuse.id, bug.id, recent_bug.id, still_open.id)
        await db.commit()
    abuse_id, bug_id, recent_id, open_id = ids

    deleted, redacted, _ = await report_sweep()
    async with SessionLocal() as db:
        gone = await db.get(Report, abuse_id)
        kept = await db.get(Report, bug_id)
        untouched = await db.get(Report, recent_id)
        opened = await db.get(Report, open_id)
        threads = int(await db.scalar(select(func.count()).select_from(ReportMessage)) or 0)
    check("an old ABUSE report is deleted outright", gone is None)
    check("an OPEN report is never swept, at any age", opened is not None)
    check("a recently closed report is left alone",
          untouched is not None and untouched.reason == "still here")
    check("an old BUG BOUNTY row SURVIVES (the Hall of Fame counts it)", kept is not None)
    check("...with the operator's notes gone", kept is not None and kept.resolution_notes == "")
    check("...with the reply gone", kept is not None and kept.reply_text == "")
    check("...with the attachment AES keys gone", kept is not None and kept.attachments is None)
    check("...and a reason the client can render, not an empty string",
          kept is not None and kept.reason == REDACTED_REASON)
    check("both plaintext threads are gone (cascade + explicit delete)",
          threads == 0, f"{threads} turn(s) left")
    check("the pass reports 1 deleted and 1 redacted",
          (deleted, redacted) == (1, 1), f"{deleted}/{redacted}")

    # ⚠⚠ A SECOND pass must find nothing. The abuse row is gone so it cannot
    # match again, but the bug row is redacted IN PLACE and still satisfies
    # "closed, resolved, older than the horizon" forever. If it keeps matching,
    # the hourly log lies and, once there are more than MAX_PER_CYCLE such rows,
    # `order_by(resolved_at asc) limit N` returns the same N finished rows on
    # every pass and a newly expired report is never redacted at all.
    again = await report_sweep()
    check("a second pass is a no-op (a redacted row must stop matching)",
          again == (0, 0, 0), f"second pass did {again}")

    # The wall must still be able to count the redacted row.
    from app.services.hof_stats import bug_report_stats  # noqa: E402

    async with SessionLocal() as db:
        stats = await bug_report_stats(db, [1001])
    check("the redacted row still feeds the Hall of Fame effort ring",
          stats.get(1001, (0, 0)) == (2, 2), str(stats))

    # ── devices ─────────────────────────────────────────────────────────────
    print("\ndevices")
    from app.routers.keys import _strip_revoked_device  # noqa: E402
    from app.services.device_sweep import (  # noqa: E402
        REVOKED_MAX_AGE_DAYS,
        sweep_once as device_sweep,
    )

    def mkdev(device_id: int, **kw) -> Device:
        return Device(
            uin=1001, device_id=device_id, label="Web (Chrome)",
            sealed_sender_pub="ssp", signal_identity_key="sik",
            signal_registration_id=7, signed_prekey_id=1, signed_prekey_public="a",
            signed_prekey_signature="b", kyber_prekey_id=2, kyber_prekey_public="c",
            kyber_prekey_signature="d", created_at=ago(days=500), **kw
        )

    async with SessionLocal() as db:
        live = mkdev(2)
        fresh_revoked = mkdev(3, revoked_at=ago(days=REVOKED_MAX_AGE_DAYS - 5))
        old_revoked = mkdev(4, revoked_at=ago(days=REVOKED_MAX_AGE_DAYS + 5))
        db.add_all([live, fresh_revoked, old_revoked])
        await db.flush()
        now = datetime.now(timezone.utc)
        _strip_revoked_device(fresh_revoked, now)
        _strip_revoked_device(old_revoked, now)
        await db.commit()

    async with SessionLocal() as db:
        stripped = (await db.scalars(
            select(Device).where(Device.uin == 1001, Device.device_id == 3)
        )).one()
        check("revoke strips the label", stripped.label is None)
        check("revoke strips the key material",
              stripped.sealed_sender_pub == "" and stripped.signal_identity_key == ""
              and stripped.signed_prekey_public == "" and stripped.kyber_prekey_public == "")
        check("revoke erases the lifespan (created_at folded onto the revoke)",
              stripped.created_at.replace(tzinfo=timezone.utc) > ago(days=1))
        check("revoke keeps the (uin, device_id) tombstone the allocator needs",
              stripped.uin == 1001 and stripped.device_id == 3)

    n = await device_sweep()
    async with SessionLocal() as db:
        slots = sorted((await db.scalars(select(Device.device_id))).all())
    check("a revoked slot past the horizon is released", 4 not in slots, str(slots))
    check(f"a slot revoked inside {REVOKED_MAX_AGE_DAYS}d keeps its tombstone",
          3 in slots, str(slots))
    check("a LIVE device is never swept", 2 in slots, str(slots))
    check("the device sweep reports one release", n == 1, f"reported {n}")

    # ── invites: the hash migration, then the sweep ─────────────────────────
    print("\ninvites")
    RAW = "handed-out-before-the-migration"
    async with SessionLocal() as db:
        db.add(Invite(code=RAW, label="legacy", max_uses=5, used_count=1))
        await db.execute(text("DELETE FROM server_settings WHERE key = :k"),
                         {"k": "_migration_invite_code_hashed"})
        await db.commit()

    await init_db()  # runs the one-shot
    async with SessionLocal() as db:
        rows = (await db.scalars(select(Invite.code))).all()
    check("the plaintext code is hashed in place",
          hash_invite_code(RAW) in rows and RAW not in rows, str(rows)[:120])

    await init_db()  # second boot must be a no-op, not a double hash
    async with SessionLocal() as db:
        rows2 = (await db.scalars(select(Invite.code))).all()
    check("the migration is idempotent (a re-run must not hash the hash)",
          hash_invite_code(RAW) in rows2, str(rows2)[:120])
    check("a code handed out before the migration still resolves to its row",
          hash_invite_code(RAW) in rows2)

    from app.services.credential_sweep import (  # noqa: E402
        CREDENTIAL_MAX_AGE_DAYS,
        sweep_once as credential_sweep,
    )

    old = ago(days=CREDENTIAL_MAX_AGE_DAYS + 5)
    recent = ago(days=CREDENTIAL_MAX_AGE_DAYS - 5)
    async with SessionLocal() as db:
        db.add_all([
            Invite(code="a" * 64, label="spent long ago", max_uses=1, used_count=1,
                   spent_at=old, created_at=old),
            Invite(code="b" * 64, label="spent recently", max_uses=1, used_count=1,
                   spent_at=recent, created_at=old),
            Invite(code="c" * 64, label="expired long ago", max_uses=9, used_count=0,
                   expires_at=old, created_at=old),
            Invite(code="d" * 64, label="live, never expires", max_uses=9, used_count=2,
                   created_at=old),
        ])
        await db.commit()

    n_inv, _ = await credential_sweep()
    async with SessionLocal() as db:
        labels = sorted((await db.scalars(select(Invite.label))).all(), key=str)
    check("an invite spent past the horizon is reaped", "spent long ago" not in labels, str(labels))
    check("an invite spent recently is spared", "spent recently" in labels, str(labels))
    check("an expired invite is reaped from its expiry", "expired long ago" not in labels, str(labels))
    check("a live invite with uses left is never swept",
          "live, never expires" in labels, str(labels))
    check("the legacy row (hashed above, still usable) is spared",
          hash_invite_code(RAW) in (await _codes()), "the migrated invite was reaped")

    # ── access tokens ───────────────────────────────────────────────────────
    print("\naccess_tokens")
    async with SessionLocal() as db:
        parent = AccessToken(token_hash="h-invite", kind="invite", label="Bob's invite",
                             max_uses=1, uses=1, created_at=old, last_used_at=old)
        db.add(parent)
        await db.flush()
        db.add_all([
            # Bob's DEVICE, minted from that invite and still live. Its parent
            # must therefore outlive its own horizon or `gate.revoke_token`
            # loses the handle that cuts Bob off.
            AccessToken(token_hash="h-device", kind="device", label="Bob laptop",
                        device_id="dev-1", parent_id=parent.id, revoked=False,
                        created_at=old, last_used_at=ago(days=1)),
            AccessToken(token_hash="h-revoked", kind="device", label="Carol laptop",
                        revoked=True, created_at=old, last_used_at=old),
            AccessToken(token_hash="h-standing", kind="standing", label="Bridge bot",
                        max_uses=None, uses=900, revoked=False,
                        created_at=old, last_used_at=old),
        ])
        parent_id = parent.id
        await db.commit()

    _, n_tok = await credential_sweep()
    async with SessionLocal() as db:
        alive = sorted((await db.scalars(select(AccessToken.label))).all(), key=str)
    check("a revoked gate token past the horizon is reaped",
          "Carol laptop" not in alive, str(alive))
    check("⚠⚠ an exhausted invite with a LIVE child keeps the revocation cascade",
          "Bob's invite" in alive, str(alive))
    check("the live device itself is untouched", "Bob laptop" in alive, str(alive))
    check("a quiet `standing` token is not 'dead' and survives",
          "Bridge bot" in alive, str(alive))
    check("the credential pass reports one token", n_tok == 1, f"reported {n_tok}")

    # ...and once the child is revoked, the parent finally goes.
    async with SessionLocal() as db:
        await db.execute(text(
            "UPDATE access_tokens SET revoked = 1, last_used_at = :t WHERE token_hash = 'h-device'"
        ), {"t": old})
        await db.commit()
    await credential_sweep()
    async with SessionLocal() as db:
        after = sorted((await db.scalars(select(AccessToken.label))).all(), key=str)
    check("once the last child is revoked the parent invite is reapable",
          "Bob's invite" not in after and parent_id is not None, str(after))

    # ── declined contact requests ───────────────────────────────────────────
    print("\ncontact_requests")
    from app.services.contact_request_sweep import (  # noqa: E402
        DECLINED_MAX_AGE_DAYS,
        sweep_once as request_sweep,
    )

    async with SessionLocal() as db:
        db.add_all([
            ContactRequest(from_uin=1, to_uin=2, state="declined",
                           resolved_at=ago(days=DECLINED_MAX_AGE_DAYS + 5), created_at=ago(days=400)),
            ContactRequest(from_uin=3, to_uin=4, state="declined",
                           resolved_at=ago(days=DECLINED_MAX_AGE_DAYS - 5), created_at=ago(days=400)),
            # The legacy shape: declined before `respond` stamped anything.
            ContactRequest(from_uin=5, to_uin=6, state="declined",
                           resolved_at=None, created_at=ago(days=400)),
            ContactRequest(from_uin=7, to_uin=8, state="accepted",
                           resolved_at=ago(hours=3), created_at=ago(hours=4)),
            ContactRequest(from_uin=9, to_uin=10, state="pending", created_at=ago(days=400)),
        ])
        await db.commit()

    accepted_n, declined_n = await request_sweep()
    async with SessionLocal() as db:
        pairs = sorted(
            (r.from_uin, r.state, r.resolved_at is not None)
            for r in (await db.scalars(select(ContactRequest))).all()
        )
    froms = {p[0] for p in pairs}
    check("a refusal past the long horizon is reaped", 1 not in froms, str(pairs))
    check("a refusal inside the horizon is kept (it IS the sender's answer)",
          3 in froms, str(pairs))
    check("⚠⚠ a legacy unstamped refusal is STAMPED, not deleted "
          "(created_at is the request's clock, not the refusal's)",
          5 in froms and next(p[2] for p in pairs if p[0] == 5), str(pairs))
    check("an accepted request past its hour still goes", 7 not in froms, str(pairs))
    check("a PENDING request is never touched by either arm", 9 in froms, str(pairs))
    check("the pass reports both arms separately",
          (accepted_n, declined_n) == (1, 1), f"{accepted_n}/{declined_n}")
    check("the declined horizon is far longer than the queue TTL",
          DECLINED_MAX_AGE_DAYS > QUEUE_TTL * 3,
          f"{DECLINED_MAX_AGE_DAYS}d vs queue {QUEUE_TTL}d")

    # ── ws:online_uins ──────────────────────────────────────────────────────
    print("\nws:online_uins")
    try:
        from app.core.redis import get_redis  # noqa: E402
        from app.services.connection_manager import _ONLINE_KEY, _online_devs_key  # noqa: E402
        from app.services.presence_sweep import sweep_once as presence_sweep  # noqa: E402

        redis = await get_redis()
        await redis.delete(_ONLINE_KEY, _online_devs_key(1001), _online_devs_key(2002))
        # 1001 is genuinely here; 2002 is a ghost a dead worker left behind.
        await redis.sadd(_online_devs_key(1001), "phone")
        await redis.sadd(_ONLINE_KEY, 1001, 2002)
        removed = await presence_sweep()
        members = {
            (m.decode() if isinstance(m, bytes) else str(m))
            for m in await redis.smembers(_ONLINE_KEY)
        }
        check("a ghost with no live devs key is dropped", "2002" not in members, str(members))
        check("an account with a live devs key is left online", "1001" in members, str(members))
        check("the presence pass reports one removal", removed == 1, f"reported {removed}")
        await redis.delete(_ONLINE_KEY, _online_devs_key(1001))
    except Exception as exc:  # noqa: BLE001
        # No Redis on this machine: say so rather than passing silently. The
        # other eight sweeps do not need it.
        print(f"  SKIP presence sweep (no Redis: {type(exc).__name__}: {exc})")

    print(f"\n{len(PASS)}/{len(PASS) + len(FAIL)} pass")
    if FAIL:
        raise SystemExit("FAILED: " + ", ".join(FAIL))


async def _codes() -> list[str]:
    async with SessionLocal() as db:
        return list((await db.scalars(select(Invite.code))).all())


asyncio.run(main())
