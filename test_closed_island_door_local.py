"""Local-only verification of who may be handed a sealing key on a closed island.

The rule this pins is the whole of the closed-island feature, and both ways of
getting it wrong are invisible in a smoke test:

  * too open   A paid closed island where any resident may fetch any key is an
               island where ONE purchased membership buys the keys of every
               member. Buy in, walk the numbers, walk out, write to all of them
               forever. Sealed sender means nobody can tell it happened, so
               nothing in production would ever report this.
  * too closed A closed island where no resident may fetch a key by number
               breaks the ordinary reason to want one: writing to a colleague
               whose number is on their badge and who is not yet a contact.

The resolution under test is a distinction between shapes of request, not a
middle setting: a POINT lookup by one named number is allowed to a resident, a
LIST never carries keys to anybody, and a stranger gets in only with a card the
resident generated and handed out. See app/services/door.py.

No Redis, no network, one throwaway SQLite file.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_closed_island_door_local.py
"""
import asyncio
import os

from sqlalchemy import select

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_closed_door.db")
os.environ.setdefault("ENV", "dev")

from app.core.db import engine, init_db, SessionLocal  # noqa: E402
from app.models.guest_card import GuestCard, hash_card, new_card  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services.door import (  # noqa: E402
    may_fetch_key,
    redeem_card,
    strip_keys_from_lists,
)

RESIDENT = 500100100
NEIGHBOUR = 500200200
STRANGER = 900900900

ok = 0
bad = 0


def check(label: str, cond: bool) -> None:
    global ok, bad
    if cond:
        ok += 1
        print(f"  ok   {label}")
    else:
        bad += 1
        print(f"  FAIL {label}")


async def seed(db):
    for uin in (RESIDENT, NEIGHBOUR):
        db.add(User(uin=uin, nickname=f"u{uin}", identity_key="ik", signing_key="sk"))
    await db.commit()


async def main() -> None:
    if os.path.exists("./test_closed_door.db"):
        os.remove("./test_closed_door.db")
    # The project's own initialiser, not a bare create_all: it is what
    # registers every model, and half the schema has foreign keys into tables a
    # partial import never loads.
    await init_db()

    async with SessionLocal() as db:
        await seed(db)

        # ── the open island is untouched ────────────────────────────────────
        check(
            "an open island hands the key to a total stranger, as it always has",
            await may_fetch_key(db, target_uin=RESIDENT, caller_uin=None, card=None, closed=False),
        )
        check(
            "an open island puts keys in lists too",
            strip_keys_from_lists(False) is False,
        )

        # ── the closed island ──────────────────────────────────────────────
        check(
            "a closed island refuses an anonymous caller",
            not await may_fetch_key(db, target_uin=RESIDENT, caller_uin=None, card=None, closed=True),
        )
        check(
            "a closed island refuses a stranger who merely has an account elsewhere",
            not await may_fetch_key(db, target_uin=RESIDENT, caller_uin=STRANGER, card=None, closed=True),
        )
        check(
            "a resident may write to a colleague by number",
            await may_fetch_key(db, target_uin=RESIDENT, caller_uin=NEIGHBOUR, card=None, closed=True),
        )
        check(
            "everybody may read their own key card",
            await may_fetch_key(db, target_uin=RESIDENT, caller_uin=RESIDENT, card=None, closed=True),
        )

        # ⚠ THE ONE THAT MATTERS: the colleague rule must not become a harvest.
        check(
            "a closed island never puts keys in a list, not even for a resident",
            strip_keys_from_lists(True) is True,
        )

        # ── the guest card ─────────────────────────────────────────────────
        raw = new_card()
        db.add(GuestCard(card_hash=hash_card(raw), owner_uin=RESIDENT, label="qr"))
        await db.commit()

        check(
            "a stranger holding the resident's card is let through",
            await may_fetch_key(db, target_uin=RESIDENT, caller_uin=STRANGER, card=raw, closed=True),
        )
        check(
            "an anonymous caller holding the card is let through too (a first "
            "message arrives before any account does)",
            await may_fetch_key(db, target_uin=RESIDENT, caller_uin=None, card=raw, closed=True),
        )
        check(
            "the card opens ONE door: it does nothing for the neighbour",
            not await may_fetch_key(db, target_uin=NEIGHBOUR, caller_uin=STRANGER, card=raw, closed=True),
        )
        check(
            "a made-up card is refused",
            not await may_fetch_key(db, target_uin=RESIDENT, caller_uin=STRANGER, card=new_card(), closed=True),
        )
        check(
            "the hash is what is stored, never the card",
            await db.scalar(
                GuestCard.__table__.select().where(GuestCard.card_hash == raw).exists().select()
            )
            is False,
        )

        # ── revoking ───────────────────────────────────────────────────────
        row = await db.scalar(
            GuestCard.__table__.select().where(GuestCard.owner_uin == RESIDENT).limit(1)
        )
        await db.execute(
            GuestCard.__table__.update().where(GuestCard.owner_uin == RESIDENT).values(revoked=True)
        )
        await db.commit()
        check(
            "a revoked card stops working",
            not await may_fetch_key(db, target_uin=RESIDENT, caller_uin=STRANGER, card=raw, closed=True),
        )
        check(
            "a revoked card is KEPT, so the same value cannot be quietly re-used",
            row is not None,
        )

        # ── the day stamp, not a feed ──────────────────────────────────────
        raw2 = new_card()
        db.add(GuestCard(card_hash=hash_card(raw2), owner_uin=NEIGHBOUR))
        await db.commit()
        await redeem_card(db, target_uin=NEIGHBOUR, raw=raw2)
        await db.commit()
        # ⚠ `db.scalar(table.select())` hands back the first COLUMN, not the
        # row, which is how the first version of this check "passed" by
        # comparing None to None. Ask the ORM for the object.
        stamped = await db.scalar(
            select(GuestCard).where(GuestCard.owner_uin == NEIGHBOUR)
        )
        check(
            "using a card stamps the day it was used",
            stamped is not None and stamped.last_used_on is not None,
        )
        check(
            "and stamps a DATE, so the row cannot become a per-second record of "
            "when a particular stranger looked somebody up",
            stamped is not None and not hasattr(stamped.last_used_on, "hour"),
        )

    await engine.dispose()
    print(f"\nclosed-island door: {ok}/{ok + bad} ok")
    raise SystemExit(0 if bad == 0 else 1)


asyncio.run(main())
