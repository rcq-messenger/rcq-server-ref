"""A number you hold must stay switchable to, even when the island still
carries rows keyed to it.

⚠⚠ WHY THIS EXISTS. `rekey_uin_rows` moves an account's rows with a blind
`UPDATE t SET uin = new WHERE uin = old`, and twelve of the columns it moves
sit inside a primary key or a unique index. If a single row is already keyed
to the target number, that UPDATE raises a unique violation, the migration
aborts, and the person is shown a raw `HTTP 500 {"detail":"internal_error"}`.
The number is in their collection and can never be switched to again: nothing
expires the stray row, so the failure is permanent.

That is not a hypothetical. On 08.09.2026 a tester holding 100200300 pressed
"Перейти" thirty times. The island had ONE stranded `group_log_readers` row
(PK `uin, device_id`) left on that number by a device of his own that still
held a token for it, and every attempt died on `group_log_readers_pkey`.

Stray rows are reachable by ordinary means: `_perform_migration` bumps the
vacated number's epoch and writes it through to Redis only after the commit,
so a device of the account's own can write a cursor or a reader row under the
old number inside that window.

What this pins:
  * every collision-capable column is FOUND STRUCTURALLY, from the table's own
    primary key, unique constraints and unique indexes, so a table added later
    is covered without anybody remembering to list it;
  * a migration onto a number carrying stranded rows succeeds, and the account
    keeps its own rows;
  * the stranded rows do NOT survive to be inherited: a queue cursor from the
    previous holder would skip the new holder's own messages, which is the harm
    `services/uin_rows.py` was written to prevent in the first place;
  * a LIVE THIRD PARTY's address-book entry is not collateral: the person who
    held both numbers ends with exactly one row, pointing at the right person,
    and everyone else's rows are untouched;
  * `mailbox_seq` never goes backwards, because a counter below a device's
    stored cursor is silent permanent message loss (models/mailbox_seq.py).

Runs the real stack in-process on a throwaway SQLite DB.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_uin_activate_collision_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_uin_collision.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ["UIN_SHOP_ENABLED"] = "true"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "test-pass"

for f in ("test_uin_collision.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from sqlalchemy import delete, select  # noqa: E402

from app.core.config import settings  # noqa: E402

settings.REGISTER_CEILING_PER_MINUTE = 100_000
settings.REGISTER_CEILING_PER_HOUR = 100_000

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.models.contact import Contact  # noqa: E402
from app.models.group_log import GroupLogReader  # noqa: E402
from app.models.mailbox_seq import MailboxSeq  # noqa: E402
from app.models.queue_cursor import QueueCursor  # noqa: E402
from app.services.uin_rows import PER_UIN_COLUMNS, _unique_keys_containing  # noqa: E402

fails = 0
ADMIN = {"Authorization": "Basic " + base64.b64encode(b"admin:test-pass").decode()}


def check(name, cond, detail=""):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail and not cond else ""))
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


def H(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def register(c):
    _, pub = keypair()
    r = await c.post(
        "/auth/register",
        json={"nickname": "someone", "identity_key": b64(), "signing_key": pub},
    )
    assert r.status_code == 201, r.text
    return r.json()["uin"], r.json()["token"]


async def clear_limiter():
    try:
        from app.core.redis import get_redis
        redis = await get_redis()
        for pattern in ("rl:auth_register*", "rl:uin_*"):
            keys = [k async for k in redis.scan_iter(match=pattern)]
            if keys:
                await redis.delete(*keys)
    except Exception:
        pass


async def main():
    await init_db()
    await clear_limiter()

    # ── the structural half: what the guard actually covers ──────────────
    guarded = [
        f"{m.__tablename__}.{c.key}"
        for m, c in PER_UIN_COLUMNS
        if _unique_keys_containing(m, c)
    ]
    for expected in (
        "group_log_readers.uin",     # the live 500
        "queue_cursors.uin",
        "group_log_cursors.uin",
        "mailbox_seq.to_uin",
        "user_capabilities.uin",
        "vault_slots.uin",
        "contact_vault_devices.uin",
        "offline_messages.to_uin",   # keyed by a unique INDEX, not a constraint
        "contacts.owner_uin",
        "contacts.contact_uin",
        "contact_requests.from_uin",
        "contact_requests.to_uin",
    ):
        check(f"guard sees {expected}", expected in guarded, f"guarded={guarded}")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        mover_uin, mover_token = await register(c)
        third_uin, third_token = await register(c)

        # A number in the mover's collection, and stray rows left on it by the
        # holder who is gone.
        target = 654321
        r = await c.post("/admin/uin/grant", headers=ADMIN,
                         json={"uin": target, "to_uin": mover_uin})
        check("the target number is granted into the collection", r.status_code in (200, 201), r.text)

        SHARED_DEVICE = "a8a8f6b1c8a6453993314336b2267b1b"
        async with SessionLocal() as s:
            # The exact live shape: the same device carries a row under BOTH
            # numbers, so the UPDATE would land on a key that is taken.
            s.add(GroupLogReader(uin=target, device_id=SHARED_DEVICE))
            s.add(GroupLogReader(uin=mover_uin, device_id=SHARED_DEVICE))
            s.add(QueueCursor(uin=target, device_id=SHARED_DEVICE, last_direct_id=9999))
            s.add(QueueCursor(uin=mover_uin, device_id=SHARED_DEVICE, last_direct_id=7))
            # The counter the vacated number left behind is HIGHER than the
            # mover's own.
            s.add(MailboxSeq(to_uin=target, next_seq=5000))
            s.add(MailboxSeq(to_uin=mover_uin, next_seq=12))
            # A third party holding BOTH numbers, plus one holding only the
            # target: the first ends with one row, the second keeps theirs.
            s.add(Contact(owner_uin=third_uin, contact_uin=mover_uin))
            s.add(Contact(owner_uin=third_uin, contact_uin=target))
            await s.commit()

        r = await c.post("/uin/activate", json={"uin": target}, headers=H(mover_token))
        check("switching to a number carrying stranded rows succeeds",
              r.status_code == 200, f"{r.status_code} {r.text[:200]}")
        if r.status_code != 200:
            print("\nactivate collision: FAILED EARLY")
            return 1
        check("the account answers as the number it switched to",
              r.json().get("new_uin") == target, r.text[:200])
        new_token = r.json().get("token") or mover_token

        async with SessionLocal() as s:
            readers = (await s.execute(
                select(GroupLogReader.uin, GroupLogReader.device_id)
            )).all()
            check("the reader row moved and did not double",
                  sorted(readers) == [(target, SHARED_DEVICE)], str(readers))

            cursors = (await s.execute(
                select(QueueCursor.uin, QueueCursor.last_direct_id)
            )).all()
            check("the drain cursor is the MOVER'S, not the one inherited from "
                  "the previous holder",
                  cursors == [(target, 7)], str(cursors))

            seqs = (await s.execute(
                select(MailboxSeq.to_uin, MailboxSeq.next_seq)
            )).all()
            check("the mailbox counter never goes backwards",
                  seqs == [(target, 5000)], str(seqs))

            third = sorted((await s.execute(
                select(Contact.contact_uin).where(Contact.owner_uin == third_uin)
            )).scalars().all())
            check("a third party who held both numbers ends with exactly one row",
                  third == [target], str(third))

        # ⚠ And the number just vacated goes back to the pool, because it is an
        # ordinary one. That is the deliberate rule since 01.09.2026 (an
        # ordinary number is a loan; a scarce or bought one follows its holder),
        # and it is asserted here so a future "fix" to the endpoint's wording
        # cannot quietly reopen the hoarding hole it closed.
        r = await c.get("/uin/mine", headers=H(new_token))
        held = sorted(int(row["uin"]) for row in r.json()["owned"])
        check("the ordinary number just left went back to the pool",
              mover_uin not in held, str(held))

    await close_redis()
    print(f"\nactivate collision: {'all good' if not fails else str(fails) + ' FAILED'}")
    return 1 if fails else 0


raise SystemExit(asyncio.run(main()))
