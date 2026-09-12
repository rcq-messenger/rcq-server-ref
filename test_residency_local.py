"""Residency bought on an existing account, and the free drip for the people
who were here first.

Two features, one counter, and the failure that matters for each is the quiet
one. For the purchase it is a paid code burnt by a double tap, or a second
account made resident by a code that was already spent. For the drip it is an
entry credential handed to a row that a script minted, or to somebody who
walked in on a friend's invite last week. So the tests are mostly refusals,
each one a clause, and the counter is checked before and after everything.

Runs on SQLite with a throwaway Ed25519 till and patched settings: no server,
no Redis, no network.
Run: cd backend && .venv/bin/python test_residency_local.py
"""
import asyncio
import base64
import json
import os
import pathlib
import re
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, '/Users/tager/Documents/RCQ/backend')
DB = pathlib.Path('/Users/tager/Documents/RCQ/backend/test_residency.db')
if DB.exists():
    DB.unlink()
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{DB}")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from sqlalchemy import func, select

from app.core.db import SessionLocal, init_db
from app.models.contact import Contact
from app.models.invite import Invite
from app.models.uin_sale import SpentVoucher
from app.models.user import User, earned_badges
from app.routers import invites as I
from app.routers import residency as R
from app.services import account_signal
from app.services import dead_account_sweep as sweep
from app.services import server_settings as S
from app.services import uin_voucher as V

checks = []


def check(name, cond):
    checks.append((name, cond))
    print(("ok   " if cond else "FAIL ") + name)


# ── The till, the island, and the settings ───────────────────────────────
HOST = "island.test"
key = Ed25519PrivateKey.generate()
pub = base64.b64encode(key.public_key().public_bytes_raw()).decode()
V.public_key_b64 = lambda: pub

OVERRIDES: dict = {"island_host": HOST}


async def fake_get(k):
    return OVERRIDES[k] if k in OVERRIDES else S.REGISTRY[k].default()


S.get = fake_get  # both routers read settings through the module attribute

announced: list = []


async def fake_announce(db, uin, nickname, badge=...):
    announced.append((uin, badge))


R._announce_rename = fake_announce


def mint(host=HOST, nonce=None, ttl=3600):
    nonce = nonce or ("n" + str(time.time_ns()))[:32].ljust(32, "x")
    exp = int(time.time()) + ttl
    body = V.entry_signed_bytes(host=host, nonce=nonce, exp=exp)
    doc = {"v": V.VERSION, "kind": "entry", "host": host, "nonce": nonce, "exp": exp,
           "sig": base64.b64encode(key.sign(body)).decode()}
    return base64.b64encode(json.dumps(doc).encode()).decode(), nonce


CUTOFF = datetime(2026, 9, 7, tzinfo=timezone.utc)
NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)


def account(uin, *, nickname, created, seen_after=timedelta(days=2), entered_via=None,
            resident_since=None, badge=None):
    return User(
        uin=uin, nickname=nickname, identity_key="k" * 44, signing_key="s" * 44,
        created_at=created, identity_created_at=created, last_seen=created + seen_after,
        entered_via=entered_via, resident_since=resident_since, badge=badge,
        badges_earned=badge, invites_minted=0,
    )


async def redeem(uin, voucher):
    """(status, code) on refusal, or the RedeemOut on success."""
    async with SessionLocal() as db:
        try:
            return await R.redeem(R.RedeemIn(voucher=voucher), uin=uin, db=db)
        except HTTPException as e:
            code = e.detail.get("code") if isinstance(e.detail, dict) else e.detail
            return (e.status_code, code)


async def spent_count(db):
    return int(await db.scalar(select(func.count()).select_from(SpentVoucher)) or 0)


async def is_spent(db, nonce):
    return await db.get(SpentVoucher, nonce) is not None


class _Req:
    """Only what `mint` reads off a request."""
    headers: dict = {}

    class url:
        hostname = HOST


async def mint_invite(uin):
    async with SessionLocal() as db:
        try:
            return await I.mint(_Req(), uin=uin, db=db)
        except HTTPException as e:
            code = e.detail.get("code") if isinstance(e.detail, dict) else e.detail
            return (e.status_code, code)


async def main():
    await init_db()
    long_ago = CUTOFF - timedelta(days=400)
    async with SessionLocal() as db:
        db.add_all([
            # Part 2: buying residency.
            account(1001, nickname="Anna", created=long_ago),
            account(1002, nickname="Banned", created=long_ago),
            account(1003, nickname="Boris", created=long_ago, badge="tester"),
            # Part 1: the free drip. All created before the cutoff unless said.
            account(2001, nickname="Legacy", created=long_ago),                      # a person: yes
            account(2002, nickname="Invited", created=long_ago, entered_via="invite"),  # let in: no
            account(2003, nickname="Newcomer", created=CUTOFF + timedelta(days=1)),  # after: no
            account(2004, nickname="user-2004", created=long_ago),                   # no signals: no
            account(2005, nickname="Blink", created=long_ago, seen_after=timedelta(minutes=50)),  # left within the hour: no
            account(2006, nickname="Walkin", created=long_ago, entered_via="open"),  # stamped open: no
            # Part 3: the sweep. Both look like the flood; one paid.
            account(3001, nickname="user-3001", created=long_ago, seen_after=timedelta(seconds=60)),
            account(3002, nickname="user-3002", created=long_ago, seen_after=timedelta(seconds=60),
                    resident_since=long_ago + timedelta(days=1)),
        ])
        await db.commit()
        # 2001 and 2005 added somebody, which is the deliberate act 2004 lacks.
        db.add_all([Contact(owner_uin=2001, contact_uin=1001), Contact(owner_uin=2005, contact_uin=1001)])
        u = await db.get(User, 1002)
        u.is_suspended = True
        u = await db.get(User, 1003)
        u.invites_minted = 1
        await db.commit()

    # ── Part 2: buying residency on an existing account ──────────────────
    print("\n-- residency: the purchase")
    good, good_nonce = mint()
    out = await redeem(1001, good)
    ok = not isinstance(out, tuple)
    check("a good voucher makes an existing account a resident", ok)
    async with SessionLocal() as db:
        u = await db.get(User, 1001)
        check("resident_since is stamped on the row", u.resident_since is not None)
        check("the resident mark is held and, with nothing else worn, worn",
              "resident" in earned_badges(u) and u.badge == "resident")
        check("entered_via is left as it was (history is not rewritten)", u.entered_via is None)
        check("the nonce is recorded as spent", await is_spent(db, good_nonce))
        check("exactly one spent row so far", await spent_count(db) == 1)
    check("the answer carries the invites view, from the paid source, one granted",
          ok and out.invites.kind == "resident" and out.invites.granted == 1 and out.invites.eligible)
    check("the answer names the mark and the set", ok and out.badge == "resident" and out.badges_earned == ["resident"])
    check("contacts are told about the mark", (1001, "resident") in announced)

    print("\n-- residency: the refusals")
    check("the same voucher on a second account is a conflict, voucher_spent",
          await redeem(1003, good) == (409, "voucher_spent"))
    async with SessionLocal() as db:
        check("...and does not add a second spent row", await spent_count(db) == 1)
        u = await db.get(User, 1003)
        check("...and the second account is not made resident", u.resident_since is None)

    fresh, fresh_nonce = mint()
    check("an account that is already a resident is refused, already_resident",
          await redeem(1001, fresh) == (409, "already_resident"))
    async with SessionLocal() as db:
        check("★ ...BEFORE the voucher is spent: the nonce stays unspent (a double tap must not burn a paid code)",
              not await is_spent(db, fresh_nonce) and await spent_count(db) == 1)

    other, other_nonce = mint(host="cheap.example")
    check("a voucher for another island is refused", await redeem(1003, other) == (403, "voucher_other_island"))
    banned, banned_nonce = mint()
    check("a suspended account is refused, suspended", await redeem(1002, banned) == (403, "suspended"))
    async with SessionLocal() as db:
        check("...and its voucher is still good for somebody who is not", not await is_spent(db, banned_nonce))
    check("garbage is refused as bad_voucher", await redeem(1003, "x" * 40) == (403, "bad_voucher"))

    saved, V.public_key_b64 = V.public_key_b64, lambda: None
    check("an island with no till is a 404 sales_disabled", await redeem(1003, fresh) == (404, "sales_disabled"))
    V.public_key_b64 = saved
    OVERRIDES["island_host"] = ""
    check("an island that does not know its own name is a 404 sales_disabled too",
          await redeem(1003, fresh) == (404, "sales_disabled"))
    OVERRIDES["island_host"] = HOST

    print("\n-- residency: the counter")
    out = await redeem(1003, fresh)
    ok = not isinstance(out, tuple)
    check("the tester who pays becomes a resident", ok)
    async with SessionLocal() as db:
        u = await db.get(User, 1003)
        check("★ invites_minted is untouched by a purchase (it was 1, it is 1)", u.invites_minted == 1)
        check("the worn mark stays tester; resident joins the set",
              u.badge == "tester" and earned_badges(u) == ["tester", "resident"])
    check("the invites view shows one granted, one used, none left: the spent one carried over",
          ok and out.invites.granted == 1 and out.invites.used == 1 and out.invites.remaining == 0)

    # ── Part 1: the free drip, pure arithmetic ───────────────────────────
    print("\n-- free drip: the arithmetic")

    def free(joined, now, total=3, min_age=30, period=30, cutoff=CUTOFF):
        u = User()
        u.uin = 1
        u.created_at = joined
        u.identity_created_at = None
        u.resident_since = None
        u.entered_via = None
        return I._accrued_free(u, total=total, cutoff=cutoff, min_age_days=min_age,
                               period_days=period, now=now)

    old = CUTOFF - timedelta(days=200)
    check("a legacy row has one on the day entry went on sale", free(old, CUTOFF)[0] == 1)
    check("still one the day before the month is up", free(old, CUTOFF + timedelta(days=29))[0] == 1)
    check("two when the month has passed", free(old, CUTOFF + timedelta(days=30))[0] == 2)
    check("three after two months", free(old, CUTOFF + timedelta(days=60))[0] == 3)
    check("still three after a year: the cap is a cap", free(old, CUTOFF + timedelta(days=365))[0] == 3)
    check("the next one is dated from the cutoff, not from now",
          free(old, CUTOFF + timedelta(days=5))[1] == CUTOFF + timedelta(days=30))
    check("no next date once they hold the lot", free(old, CUTOFF + timedelta(days=90))[1] is None)
    week_before = CUTOFF - timedelta(days=7)
    check("a row a week old on the cutoff day waits out the month: nothing yet, and the date says when",
          free(week_before, CUTOFF) == (0, week_before + timedelta(days=30)))
    check("...and has one once the month is up", free(week_before, week_before + timedelta(days=30))[0] == 1)
    check("a total of zero means nobody has any", free(old, CUTOFF + timedelta(days=90), total=0) == (0, None))
    check("no cutoff means the feature is off", free(old, CUTOFF + timedelta(days=90), cutoff=None) == (0, None))
    naive = User()
    naive.uin = 2
    naive.created_at = old.replace(tzinfo=None)
    naive.identity_created_at = None
    check("a timezone-naive created_at (SQLite) still counts",
          I._accrued_free(naive, total=3, cutoff=CUTOFF, min_age_days=30, period_days=30,
                          now=CUTOFF + timedelta(days=30))[0] == 2)

    # ── Part 1: the free drip, end to end against the rows ───────────────
    print("\n-- free drip: who qualifies")
    OVERRIDES.update({"free_invites_total": 3, "free_invites_before": "2026-09-07T00:00:00Z",
                      "free_invites_min_age_days": 30})

    async def view(uin, now=NOW):
        async with SessionLocal() as db:
            return await I.invites_out(db, await db.get(User, uin), now=now)

    v = await view(2001)
    check("a legacy row that looks like a person draws the free source, one granted",
          v.kind == "free" and v.eligible and v.total == 3 and v.granted == 1 and v.remaining == 1)
    check("two after a month, three after two, capped",
          (await view(2001, CUTOFF + timedelta(days=31))).granted == 2
          and (await view(2001, CUTOFF + timedelta(days=61))).granted == 3
          and (await view(2001, CUTOFF + timedelta(days=500))).granted == 3)
    v = await view(2002)
    check("a row let in on an invite gets nothing", v.kind == "" and not v.eligible and v.granted == 0)
    v = await view(2006)
    check("a row stamped as an open walk-in gets nothing either: only NULL is legacy",
          v.kind == "" and v.granted == 0)
    v = await view(2003)
    check("a row created after the cutoff gets nothing", v.kind == "" and v.granted == 0)
    v = await view(2004)
    check("a user-% nickname with no signals gets nothing", v.kind == "" and v.granted == 0)
    v = await view(2005)
    check("a row that left within its first day gets nothing, whatever else it did",
          v.kind == "" and v.granted == 0)
    v = await view(1001)
    check("a resident draws the paid source, not the free one", v.kind == "resident" and v.total == 5)
    async with SessionLocal() as db:
        check("the signal says no for a number that does not exist",
              not await account_signal.looks_like_a_person(db, 999_999_999))
    OVERRIDES["free_invites_total"] = 0
    check("free total 0 switches the drip off", (await view(2001)).kind == "")
    OVERRIDES["free_invites_total"] = 3
    OVERRIDES["free_invites_before"] = ""
    check("an empty cutoff switches the drip off", (await view(2001)).kind == "")
    OVERRIDES["free_invites_before"] = "2026-09-07T00:00:00Z"

    print("\n-- free drip: minting")
    got = await mint_invite(2001)
    check("a legacy account can mint its free one", not isinstance(got, tuple) and got.code)
    async with SessionLocal() as db:
        u = await db.get(User, 2001)
        rows = (await db.execute(select(Invite).where(Invite.created_by == 2001))).scalars().all()
        check("the counter went up by one", u.invites_minted == 1)
        check("the invite is single-use and carries no reserved number",
              len(rows) == 1 and rows[0].max_uses == 1 and rows[0].uin is None and rows[0].expires_at is not None)
    check("a second mint the same day is refused, no_invites_left",
          await mint_invite(2001) == (409, "no_invites_left"))
    check("an account with no source is refused with the old code, not_a_resident",
          await mint_invite(2002) == (403, "not_a_resident"))
    check("a suspended account is refused before any source is looked up",
          await mint_invite(1002) == (403, "account_suspended"))

    # Carry-over: 2001 spent 1 of 3 free, now buys. The counter is 1, the
    # paid total is 5, so 4 are left to mint over the paid drip.
    later, _ = mint()
    out = await redeem(2001, later)
    ok = not isinstance(out, tuple)
    check("★ spent 1 of 3 free, then buys: 5 in total, 1 used, nothing reset",
          ok and out.invites.kind == "resident" and out.invites.total == 5 and out.invites.used == 1
          and out.invites.granted == 1 and out.invites.remaining == 0)

    # ── Part 3: the sweep spares a resident ──────────────────────────────
    print("\n-- the sweep")
    reaped = await sweep._sweep_once()
    async with SessionLocal() as db:
        check(f"the unpaid flood row is reaped (got {reaped})", reaped == 1 and await db.get(User, 3001) is None)
        check("★ the identical row that PAID is spared", await db.get(User, 3002) is not None)

    # ── Wiring, by grep: the things that would ship silently ─────────────
    print("\n-- wiring")
    auth = pathlib.Path('app/routers/auth.py').read_text()
    check("registration stamps a voucher entry", 'entered_via = "voucher"' in auth)
    check("registration stamps an invited entry, on both branches that consume a row",
          auth.count('entered_via = "invite"') == 2)
    check("registration stamps a walk-in as open, never NULL", 'entered_via = "open"' in auth
          and "entered_via=entered_via" in auth)
    mig = pathlib.Path('app/routers/migrate.py').read_text()
    check("the stamp survives a change of number", "entered_via=user.entered_via" in mig)
    dbsrc = pathlib.Path('app/core/db.py').read_text()
    check("the column is in the additive list", '("entered_via", "VARCHAR(16)")' in dbsrc)
    main = pathlib.Path('app/main.py').read_text()
    check("the residency router is mounted", "app.include_router(residency.router)" in main)
    users = pathlib.Path('app/routers/users.py').read_text()
    check("/users/me tells the owner, and only the owner, when they paid and how they got in",
          "resident_since=(u.resident_since if owner_self else None)" in users
          and "entered_via=(u.entered_via if owner_self else None)" in users)
    sw = pathlib.Path('app/services/dead_account_sweep.py').read_text()
    check("the sweep's query exempts residents in one clause", "AND u.resident_since IS NULL" in sw)
    res = pathlib.Path('app/routers/residency.py').read_text()
    check("already_resident is decided before the voucher is verified",
          res.index("already_resident") < res.index("verify_entry("))
    check("the redeem route is rate limited fail-closed",
          re.search(r'rate_limit\("residency_redeem", 10, 3600, fail_closed=True\)', res) is not None)
    check("the settings exist with the agreed defaults",
          S.REGISTRY["free_invites_total"].default() == 3
          and S.REGISTRY["free_invites_before"].default() == ""
          and S.REGISTRY["free_invites_min_age_days"].default() == 30)
    check("the cutoff's help text says it is the cutoff and names the sale day",
          "cutoff" in S.REGISTRY["free_invites_before"].help.lower()
          and "2026-09-07T00:00:00Z" in S.REGISTRY["free_invites_before"].help)
    check("the console accepts the Z form of the cutoff",
          S.validate({"free_invites_before": "2026-09-07T00:00:00Z"}) == {"free_invites_before": "2026-09-07T00:00:00Z"})
    try:
        S.validate({"free_invites_before": "next tuesday"})
        refused = False
    except ValueError:
        refused = True
    check("...and refuses one it cannot read, rather than saving an off switch", refused)
    check("InvitesOut.kind is additive: absent means the old shape",
          I.InvitesOut(enabled=True, eligible=False, total=5, granted=0, used=0, remaining=0).kind == "")

    bad = [n for n, c in checks if not c]
    print(f"\n{len(checks) - len(bad)}/{len(checks)} прошло")
    sys.exit(1 if bad else 0)


asyncio.run(main())
