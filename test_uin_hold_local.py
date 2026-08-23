"""Local-only verification that a HELD number is nobody else's to take, and
that a migration keeps the number it moved off.

Two bugs, one table. `owned_uins` is the collection: a row there means somebody
holds that number without answering as it, so the number has no `users` row at
all (models/owned_uin.py). Every client says in as many words that a number in
your collection is yours and nobody else can have it.

  * The four paths that HAND OUT numbers read `users` only, so an ordinary
    registration, a `desired_uin`, a reserved invite or the random allocator
    could walk off with a number that was already in somebody's collection.
    The spec says otherwise (§2.1: the allocator rejects a collision "with an
    existing account or with a UIN reserved by the UIN shop").
  * `/account/migrate` re-keyed the collection onto the new number but let the
    number the caller was SITTING ON fall back into the allocator pool, which
    is the opposite of §10.1.1 / §10.1.3 item 3. The shop's own two routes
    (/uin/purchase with switch, /uin/activate) already kept it, so "new number"
    in settings was the one route that still lost one.

A third table joined the question on 2026-08-23: `invites`. A live, unspent
invite RESERVES its number for whoever holds the code, and that number has no
row in either of the other two until the code is redeemed, so the random
allocator, `desired_uin` and the shop all saw free space where an operator had
made a promise. The two operator paths already asked each other; nobody else
did. The failure it produced is the silent one this whole file is about:
`auth.register` spends the invite use BEFORE it tests availability, so the
person holding the code gets an unrelated random number and no error is raised
anywhere.

Pins:
  * a held number is refused to `POST /admin/invites`, is not granted to a
    proven `desired_uin`, is not handed over by an invite that reserved it,
    and is never returned by the allocator (which exhausts rather than hand
    one out);
  * a number a LIVE invite reserves is taken the same way: not to a
    `desired_uin`, not to `/uin/purchase`, not to the random allocator, and
    still granted to the code that reserved it, including a multi-use code
    whose own use is already spent by the time availability is tested;
  * a DEAD invite reserves nothing, both ways of dying: spent, and expired
    unredeemed. Otherwise the fix above would leave a number locked up until
    the ninety-day credential sweep;
  * the holder can still activate their OWN held number, which is the one flow
    that must keep working;
  * a migration puts the old number in the caller's collection, under the new
    number, and the rest of the collection comes with it;
  * that number is then unavailable to a stranger's registration, and the
    caller can migrate back onto it;
  * the collection cap does not block a migration (it is allowed one over, see
    routers/migrate.py) and `/uin/purchase` is what refuses to grow it further;
  * buying with `switch: true` still records the previous number exactly once,
    now that the bookkeeping moved into the migration itself.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT part of the prod suite, NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_uin_hold_local.py
"""
import asyncio
import base64
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_uin_hold.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ["UIN_SHOP_ENABLED"] = "true"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "test-pass"

for f in ("test_uin_hold.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.models.invite import Invite, hash_invite_code  # noqa: E402
from app.models.owned_uin import OwnedUin  # noqa: E402
from app.routers.uin_shop import MAX_OWNED_UINS  # noqa: E402
from app.services.uin import allocate_uin, uin_is_taken  # noqa: E402

fails = 0

ADMIN = {"Authorization": "Basic " + base64.b64encode(b"admin:test-pass").decode()}


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


def keypair():
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return sk, base64.b64encode(pub).decode()


def sign(sk, msg: str) -> str:
    return base64.b64encode(sk.sign(msg.encode())).decode()


def H(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def register(c, **extra):
    """A plain account. Returns (uin, token)."""
    _, pub = keypair()
    r = await c.post(
        "/auth/register",
        json={"nickname": "someone", "identity_key": b64(), "signing_key": pub, **extra},
    )
    assert r.status_code == 201, r.text
    return r.json()["uin"], r.json()["token"]


async def register_proven(c, **extra):
    """A registration that PROVES its signing key, which is what unlocks
    `desired_uin`. Returns the response so the caller can read the status."""
    sk, pub = keypair()
    ch = (await c.post("/auth/register/challenge", json={"signing_key": pub})).json()["challenge"]
    return await c.post(
        "/auth/register",
        json={
            "nickname": "someone",
            "identity_key": b64(),
            "signing_key": pub,
            "challenge": ch,
            "signature": sign(sk, ch),
            **extra,
        },
    )


async def owned(c, token) -> list[int]:
    r = await c.get("/uin/mine", headers=H(token))
    assert r.status_code == 200, r.text
    return sorted(int(row["uin"]) for row in r.json()["owned"])


async def grant(c, uin: int, to_uin: int):
    return await c.post("/admin/uin/grant", headers=ADMIN, json={"uin": uin, "to_uin": to_uin})


async def clear_limiter():
    """The limiters live in the shared dev Redis, not in the throwaway DB, so a
    second run of this file would trip `auth_register` (20/hour per IP) and fail
    on a check that has nothing to do with what is being tested."""
    try:
        from app.core.redis import get_redis
        redis = await get_redis()
        for pattern in ("rl:auth_register*", "rl:uin_*"):
            keys = [k async for k in redis.scan_iter(match=pattern)]
            if keys:
                await redis.delete(*keys)
    except Exception as exc:  # noqa: BLE001 - no Redis is fine, the limiter opens up
        print(f"  (limiter not cleared: {exc})")


HELD = 555_000_111


async def main():
    await init_db()
    await clear_limiter()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        print("\nA number in somebody's collection is taken:")
        holder, holder_tok = await register(c)
        r = await grant(c, HELD, holder)
        check("the operator can put a number in a member's collection", r.status_code == 200)
        check("  ... and it shows up there", await owned(c, holder_tok) == [HELD])
        async with SessionLocal() as db:
            check("★ the shared check calls it taken", await uin_is_taken(db, HELD) is True)

        r = await c.post("/admin/invites", headers=ADMIN, json={"uin": HELD, "max_uses": 1})
        check(f"★ an invite cannot reserve a held number ({r.status_code})", r.status_code == 409)
        check("  ... and says why", r.json().get("detail", {}).get("code") == "uin_held")

        r = await register_proven(c, desired_uin=HELD)
        check("a registration asking for a held number still registers", r.status_code == 201)
        check("★ but does NOT get it", r.json().get("uin") != HELD)
        check("  ... and the holder still holds it", await owned(c, holder_tok) == [HELD])

        # The reserved-invite path, in the direction `POST /admin/uin/grant`
        # used to miss: the invite is minted while the number is still free, and
        # the operator then hands the same number to a member. `POST
        # /admin/invites` has always refused the mirror image of this
        # (`uin_held`); the grant side has to refuse too, because the conflict
        # is resolved on the REDEEMER and resolved silently: `auth.register`
        # spends the invite use in the atomic UPDATE before it tests
        # availability, so the newcomer walks away with an unrelated random
        # number, the single-use code is burnt, and neither side is told.
        reserved = 555_000_222
        r = await c.post("/admin/invites", headers=ADMIN, json={"uin": reserved, "max_uses": 1})
        check("an invite may reserve a free number", r.status_code == 201)
        code = r.json()["raw_code"]
        r = await grant(c, reserved, holder)
        check(f"★ granting a number a live invite reserves is refused ({r.status_code})",
              r.status_code == 409)
        check("  ... and says why", r.json().get("detail", {}).get("code") == "uin_reserved")
        check("  ... so the operator's collection is unchanged", await owned(c, holder_tok) == [HELD])
        r = await register_proven(c, invite=code)
        check("★ and the promise that WAS made is kept",
              r.status_code == 201 and r.json()["uin"] == reserved)

        # ── The §2.1 gap: a number a LIVE invite reserves ───────────────────
        # `uin_is_taken` read `users` and `owned_uins` only, so the two
        # operator paths asked each other about live invites and nobody else
        # did. A promised number therefore looked like free space to the
        # random allocator, to `desired_uin` and to the shop.
        print("\nA number a live invite reserves is taken too:")
        await clear_limiter()
        promised = 555_000_444
        r = await c.post("/admin/invites", headers=ADMIN, json={"uin": promised, "max_uses": 1})
        check("an invite reserves a free number", r.status_code == 201)
        promised_code = r.json()["raw_code"]
        async with SessionLocal() as db:
            check("★ the shared check calls a reserved number taken",
                  await uin_is_taken(db, promised) is True)
        # A second reserved number for the shop probe, so neither check can
        # pass because the other one already took the number away.
        promised_shop = 555_000_888
        r = await c.post("/admin/invites", headers=ADMIN, json={"uin": promised_shop, "max_uses": 1})
        check("  ... and a second one beside it", r.status_code == 201)
        r = await c.post("/uin/purchase", headers=H(holder_tok), json={"uin": promised_shop, "switch": False})
        check(f"★ it cannot be bought out from under the code holder ({r.status_code})",
              r.status_code == 409)
        check("  ... and says why", r.json().get("detail", {}).get("code") == "taken")
        r = await register_proven(c, desired_uin=promised)
        check("a proven registration asking for it still registers", r.status_code == 201)
        check("★ but does NOT get it", r.json().get("uin") != promised)
        r = await register_proven(c, invite=promised_code)
        check("★ and the person actually holding the code does",
              r.status_code == 201 and r.json()["uin"] == promised)

        # A MULTI-USE reserved invite is the regression this fix could have
        # caused: `auth.register` spends one use BEFORE it asks whether the
        # number is free, so with max_uses > 1 the row is still live at that
        # moment and would report its own redeemer's number as taken. The
        # redeemer would then be handed a random number and the vanity code
        # would have done nothing at all: the exact failure being fixed,
        # reintroduced from the other side.
        multi = 555_000_555
        r = await c.post("/admin/invites", headers=ADMIN, json={"uin": multi, "max_uses": 3})
        check("an invite may reserve a number for several uses", r.status_code == 201)
        multi_code = r.json()["raw_code"]
        r = await register_proven(c, invite=multi_code)
        check("★ a multi-use reserved invite still grants ITS OWN number",
              r.status_code == 201 and r.json()["uin"] == multi)
        r = await register_proven(c, invite=multi_code)
        check("  ... and the second redeemer falls back, because it is a `users` row now",
              r.status_code == 201 and r.json()["uin"] != multi)

        # ⚠ The other half: a DEAD invite must not lock a number up. Both ways
        # of dying are pinned, because they have different clocks (spent is
        # stamped, expired is not) and the sweep that deletes the rows runs
        # hourly with a ninety-day horizon, far too late to be the answer.
        print("\nA dead invite reserves nothing:")
        async with SessionLocal() as db:
            check("★ the number of a SPENT invite is free again",
                  await uin_is_taken(db, 555_000_222) is True)  # taken by its redeemer
            spent_row = await db.get(Invite, hash_invite_code(promised_code))
            check("  ... (the row is still there, spent)",
                  spent_row is not None and spent_row.used_count >= spent_row.max_uses)
            expired_num = 555_000_666
            db.add(Invite(
                code=hash_invite_code("expired-code-for-the-test"),
                label="expired", max_uses=1, used_count=0, uin=expired_num,
                expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
            ))
            await db.commit()
            check("★ the number of an EXPIRED, never-redeemed invite is free",
                  await uin_is_taken(db, expired_num) is False)
            unspent_num = 555_000_777
            db.add(Invite(
                code=hash_invite_code("live-code-for-the-test"),
                label="live", max_uses=1, used_count=0, uin=unspent_num,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ))
            await db.commit()
            check("  ... while an unexpired one beside it still reserves",
                  await uin_is_taken(db, unspent_num) is True)
            # And the exclusion the redeeming registration passes.
            check("★ except to the code being redeemed right now",
                  await uin_is_taken(
                      db, unspent_num,
                      except_invite=hash_invite_code("live-code-for-the-test"),
                  ) is False)
            check("  ... which excludes exactly one row, not the question",
                  await uin_is_taken(
                      db, unspent_num, except_invite=hash_invite_code("some-other-code"),
                  ) is True)

        print("\nThe allocator:")
        # A two-number window, so "never returns a held number" is a fact
        # rather than a probability. allocate_uin draws from [MIN, MAX).
        lo, hi = settings.UIN_MIN, settings.UIN_MAX
        settings.UIN_MIN, settings.UIN_MAX = 910_000_000, 910_000_002
        try:
            async with SessionLocal() as db:
                db.add(OwnedUin(uin=910_000_000, owner_uin=holder, source="purchase"))
                await db.commit()
                picks = {await allocate_uin(db) for _ in range(20)}
                check("★ the allocator skips the held number", picks == {910_000_001})
                # The other number goes to a live INVITE rather than a second
                # collection row, so the window pins the §2.1 gap: the random
                # allocator used to walk straight onto a promised number,
                # which is the one failure nobody is told about (the invite
                # use is spent before availability is tested).
                window_code = hash_invite_code("window-code-for-the-test")
                db.add(Invite(
                    code=window_code, label="window", max_uses=1, used_count=0,
                    uin=910_000_001, expires_at=None,
                ))
                await db.commit()
                exhausted = False
                try:
                    await allocate_uin(db)
                except RuntimeError:
                    exhausted = True
                check("★ with one held and one PROMISED it exhausts rather than hand one out",
                      exhausted)
                # Kill the invite the way an unredeemed one dies, and the
                # number has to come straight back: a dead invite that locked
                # a number until the ninety-day sweep would be its own bug.
                (await db.get(Invite, window_code)).expires_at = (
                    datetime.now(timezone.utc) - timedelta(minutes=1)
                )
                await db.commit()
                picks = {await allocate_uin(db) for _ in range(20)}
                check("★ and an EXPIRED invite hands the number back at once",
                      picks == {910_000_001})
                await db.execute(Invite.__table__.delete().where(Invite.code == window_code))
                await db.execute(OwnedUin.__table__.delete().where(OwnedUin.uin >= 910_000_000))
                await db.commit()
        finally:
            settings.UIN_MIN, settings.UIN_MAX = lo, hi

        print("\nThe holder is not a stranger:")
        r = await c.post("/uin/activate", headers=H(holder_tok), json={"uin": HELD})
        check(f"★ activating your OWN held number still works ({r.status_code})", r.status_code == 200)
        holder_tok = r.json()["token"]
        check("  ... the number is now the account", r.json()["new_uin"] == HELD)
        check("  ... and the one it left is in the collection", holder in await owned(c, holder_tok))

        print("\nA migration keeps the number it left (§10.1.3):")
        mover, mover_tok = await register(c)
        spare = 555_000_333
        check("the mover holds a spare", (await grant(c, spare, mover)).status_code == 200)
        r = await c.post("/account/migrate", headers=H(mover_tok))
        check(f"migrate -> 200 ({r.status_code})", r.status_code == 200)
        moved = r.json()["new_uin"]
        mover_tok = r.json()["token"]
        after = await owned(c, mover_tok)
        check("★ the number migrated FROM is in the collection", mover in after)
        check("  ... and the rest of the collection came along", spare in after)
        check("  ... and nothing else appeared", after == sorted([mover, spare]))
        async with SessionLocal() as db:
            row = await db.get(OwnedUin, mover)
            check("  ... exactly one row, owned by the new number", row is not None and int(row.owner_uin) == moved)
            check("  ... stamped as the spec names it", row is not None and row.source == "migrated")

        r = await register_proven(c, desired_uin=mover)
        check("★ a stranger cannot register the number just migrated off", r.status_code == 201 and r.json()["uin"] != mover)

        r = await c.post("/uin/activate", headers=H(mover_tok), json={"uin": mover})
        check(f"★ the mover can move back onto it ({r.status_code})", r.status_code == 200)
        mover_tok = r.json()["token"]
        check("  ... and the number they left is now the held one", await owned(c, mover_tok) == sorted([moved, spare]))

        print("\nThe collection cap does not block a migration:")
        capped, capped_tok = await register(c)
        for i in range(MAX_OWNED_UINS):
            assert (await grant(c, 556_000_000 + i, capped)).status_code == 200
        check(f"the account is at the cap ({MAX_OWNED_UINS})", len(await owned(c, capped_tok)) == MAX_OWNED_UINS)
        r = await c.post("/account/migrate", headers=H(capped_tok))
        check(f"★ migrating at the cap is not refused ({r.status_code})", r.status_code == 200)
        capped_tok = r.json()["token"]
        check("★ and the number is kept rather than dropped (one over the cap)",
              capped in await owned(c, capped_tok) and len(await owned(c, capped_tok)) == MAX_OWNED_UINS + 1)
        r = await c.post("/uin/purchase", headers=H(capped_tok), json={"uin": 557_000_001, "switch": False})
        check(f"  ... and acquiring another IS refused, which is the containment ({r.status_code})", r.status_code == 409)
        check("  ... and says why", r.json().get("detail", {}).get("code") == "too_many_uins")
        # ★ "One over" has to actually BE one over. There is no cooldown by
        # default and no rate limit on /account/migrate, so an exemption with no
        # ceiling is an unbounded collection for anyone willing to loop, and
        # every row in it is a number the allocator can never hand out again.
        one_over = await owned(c, capped_tok)
        r = await c.post("/account/migrate", headers=H(capped_tok))
        check(f"★ migrating AGAIN past the cap is still not refused ({r.status_code})",
              r.status_code == 200)
        capped_tok = r.json()["token"]
        check("★ but this time the number goes back to the pool, not the collection",
              await owned(c, capped_tok) == one_over)

        print("\nA migration never takes a number somebody else holds:")
        occupant, occupant_tok = await register(c)
        victim, victim_tok = await register(c)
        # The corrupt state the pre-2026-08-23 registration path could produce:
        # a number with BOTH a `users` row and an `owned_uins` row naming
        # somebody else. Written directly, because no endpoint can create it any
        # more (services/uin.uin_is_taken now reads both tables).
        async with SessionLocal() as db:
            db.add(OwnedUin(uin=occupant, owner_uin=victim, source="purchase"))
            await db.commit()
        check("the victim holds the number the occupant is answering as",
              occupant in await owned(c, victim_tok))
        r = await c.post("/account/migrate", headers=H(occupant_tok))
        check(f"★ the occupant may still migrate ({r.status_code})", r.status_code == 200)
        check("★ and does NOT walk off with the victim's number",
              await owned(c, victim_tok) == [occupant])
        check("  ... it is not in the occupant's collection either",
              occupant not in await owned(c, r.json()["token"]))
        r = await c.post("/uin/activate", headers=H(victim_tok), json={"uin": occupant})
        check(f"★ so the holder can still take the number back ({r.status_code})",
              r.status_code == 200)

        print("\nBuying with a switch still keeps the previous number, exactly once:")
        buyer, buyer_tok = await register(c)
        r = await c.post("/uin/purchase", headers=H(buyer_tok), json={"uin": 558_000_777, "switch": True})
        check(f"purchase with switch -> 200 ({r.status_code})", r.status_code == 200)
        buyer_tok = r.json()["token"]
        check("★ the previous number is held, once", r.json()["owned"] == [buyer] and await owned(c, buyer_tok) == [buyer])
        check("  ... and the account answers as the new one", r.json()["new_uin"] == 558_000_777)
        async with SessionLocal() as db:
            rows = (await db.execute(select(OwnedUin.uin).where(OwnedUin.uin == buyer))).scalars().all()
            check("  ... with no duplicate row (the bookkeeping moved, it was not copied)", len(rows) == 1)

    await close_redis()
    print("\nALL UIN-HOLD CHECKS PASSED" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
