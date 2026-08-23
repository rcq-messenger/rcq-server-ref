"""Local-only verification of stage 4a of the metadata plan: the vault.

An account gets a small set of opaque, client-sealed slots on its island:
PUT/GET/DELETE /vault/{slot}. The island stores ciphertext and a version and
holds neither a key nor a schema for the contents. The one rule that matters
is the #605 rule (17.08): a write names the version it was based on, and a
stale write is refused with 409 so that two devices can never silently
un-publish each other's half. Pins:
  * a slot that was never written reads 404; the first write must name
    version 0 and lands as version 1;
  * a write based on the current version advances it by one; a write based
    on an older version (the second device that read v1 while the first
    wrote v2) is refused with 409 and the reply carries the current version,
    so the client can re-read, merge and retry; a "fresh" write (version 0)
    onto an existing slot is refused the same way;
  * slots are per account: the same slot name on another account is a
    different slot, and a stranger reads 404;
  * the slot name is 32 hex characters, the blob is base64 under a size cap,
    and there is a cap on slots per account;
  * DELETE names the version it is based on (required), with a stale version
    is 409, and a second delete is a no-op;
  * a delete leaves a tombstone: the slot reads 404 WITH its version, a
    "fresh" write (version 0) is refused, and the next write must name the
    tombstone's version, so a version number is never reused within a slot
    (the ABA case: a device that remembered "version 3" from before the
    delete must never read a re-created version 3 as "nothing changed");
  * every write and delete nudges the account's other sessions over the
    socket with the slot and the new version (no blob), which is how the
    account's devices learn to re-read without a second sync protocol;
  * GET /vault lists the live slots and versions, tombstones excluded;
  * a burned account takes its slots with it, a migrated account keeps them
    under the new number (the uin_rows lists), a key reissue empties them;
  * the access-log redactor masks the slot name;
  * the capability and the caps are advertised.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_stage4_vault_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_stage4.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
for f in ("test_stage4.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.user import User  # noqa: E402
from app.models.vault import VaultSlot  # noqa: E402
from app.routers import vault as vault_router  # noqa: E402
from app.services import connection_manager  # noqa: E402
from app.services.uin_rows import purge_uin_rows, rekey_uin_rows  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=40):
    return base64.b64encode(os.urandom(n)).decode()


A, B = 5201, 5202
SLOT = os.urandom(16).hex()
SLOT2 = os.urandom(16).hex()


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


async def count(model, *where):
    async with SessionLocal() as db:
        return (await db.execute(select(func.count()).select_from(model).where(*where))).scalar_one()


async def main():
    global fails
    await init_db()
    # The rate-limit buckets live in Redis and outlive the throwaway DB; a
    # few runs in a row would otherwise hit the hourly write cap.
    from app.core.redis import get_redis  # noqa: E402
    await (await get_redis()).flushdb()
    async with SessionLocal() as db:
        for u in (A, B):
            db.add(User(uin=u, nickname=f"u{u}", identity_key=b64(32), signing_key=b64(32)))
        await db.commit()

    tokA1 = issue_token(A, 0, "phone")
    tokA2 = issue_token(A, 0, "desktop")
    tokB = issue_token(B, 0, "phone")

    # Capture the socket nudges instead of opening sockets.
    nudges: list[tuple[list[int], dict]] = []

    async def fake_broadcast(uins, payload):
        nudges.append((list(uins), payload))

    connection_manager.manager.broadcast = fake_broadcast  # type: ignore[method-assign]

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        print("First write:")
        r = await c.get(f"/vault/{SLOT}", headers=H(tokA1))
        check("an unwritten slot reads 404", r.status_code == 404)
        blob1 = b64(64)
        r = await c.put(f"/vault/{SLOT}", headers=H(tokA1), json={"blob": blob1, "version": 3})
        check("a first write must be based on version 0 (409 otherwise)", r.status_code == 409 and r.json()["detail"]["version"] == 0)
        r = await c.put(f"/vault/{SLOT}", headers=H(tokA1), json={"blob": blob1, "version": 0})
        check(f"the first write lands as version 1 ({r.status_code})", r.status_code == 200 and r.json()["version"] == 1)
        r = await c.get(f"/vault/{SLOT}", headers=H(tokA1))
        check("  ... and reads back with the blob and version 1", r.status_code == 200 and r.json() == {"blob": blob1, "version": 1})
        check("  ... the write nudged the account (slot + version, no blob)",
              nudges[-1][0] == [A] and nudges[-1][1] == {"type": "vault_changed", "slot": SLOT, "version": 1})

        print("\nThe #605 rule:")
        r = await c.get(f"/vault/{SLOT}", headers=H(tokA2))
        check("the desktop reads version 1", r.json()["version"] == 1)
        blob2 = b64(64)
        r = await c.put(f"/vault/{SLOT}", headers=H(tokA1), json={"blob": blob2, "version": 1})
        check("the phone writes on top of version 1 -> version 2", r.status_code == 200 and r.json()["version"] == 2)
        blob_desktop = b64(64)
        r = await c.put(f"/vault/{SLOT}", headers=H(tokA2), json={"blob": blob_desktop, "version": 1})
        check("the desktop's write on top of version 1 is refused (409)", r.status_code == 409)
        check("  ... and the refusal names the current version (2)", r.json()["detail"] == {"code": "stale", "version": 2})
        r = await c.get(f"/vault/{SLOT}", headers=H(tokA2))
        check("  ... the phone's blob is still what is stored", r.json() == {"blob": blob2, "version": 2})
        r = await c.put(f"/vault/{SLOT}", headers=H(tokA2), json={"blob": blob_desktop, "version": 0})
        check("a 'fresh' write (version 0) onto an existing slot is refused too", r.status_code == 409 and r.json()["detail"]["version"] == 2)
        r = await c.put(f"/vault/{SLOT}", headers=H(tokA2), json={"blob": blob_desktop, "version": 2})
        check("re-read, merge, retry on version 2 -> version 3", r.status_code == 200 and r.json()["version"] == 3)
        r = await c.put(f"/vault/{SLOT}", headers=H(tokA2), json={"blob": blob_desktop, "version": 3})
        check("an unchanged blob still advances the version (the island does not compare contents)", r.status_code == 200 and r.json()["version"] == 4)

        print("\nPer account:")
        r = await c.get(f"/vault/{SLOT}", headers=H(tokB))
        check("a stranger reads 404 on the same slot name", r.status_code == 404)
        r = await c.put(f"/vault/{SLOT}", headers=H(tokB), json={"blob": b64(), "version": 0})
        check("  ... and writes its own slot of that name from version 1", r.status_code == 200 and r.json()["version"] == 1)
        r = await c.get(f"/vault/{SLOT}", headers=H(tokA1))
        check("  ... without touching A's", r.json()["version"] == 4)
        check("two rows in the table, one per account", await count(VaultSlot, VaultSlot.slot == SLOT) == 2)

        print("\nShapes and caps:")
        r = await c.put("/vault/contacts", headers=H(tokA1), json={"blob": b64(), "version": 0})
        check(f"a slot name that is not 32 hex characters is refused ({r.status_code})", r.status_code in (400, 422))
        r = await c.put(f"/vault/{SLOT.upper()}", headers=H(tokA1), json={"blob": b64(), "version": 0})
        check(f"  ... upper-case hex too ({r.status_code})", r.status_code in (400, 422))
        r = await c.put(f"/vault/{SLOT2}", headers=H(tokA1), json={"blob": "not base64!!", "version": 0})
        check(f"a blob that is not base64 is refused ({r.status_code})", r.status_code == 400)
        r = await c.put(f"/vault/{SLOT2}", headers=H(tokA1), json={"blob": "", "version": 0})
        check(f"an empty blob is refused ({r.status_code})", r.status_code == 400)
        too_big = base64.b64encode(os.urandom(vault_router.MAX_BLOB_BYTES + 1)).decode()
        r = await c.put(f"/vault/{SLOT2}", headers=H(tokA1), json={"blob": too_big, "version": 0})
        check(f"a blob over the cap is refused ({r.status_code})", r.status_code == 413)
        at_cap = base64.b64encode(os.urandom(vault_router.MAX_BLOB_BYTES)).decode()
        r = await c.put(f"/vault/{SLOT2}", headers=H(tokA1), json={"blob": at_cap, "version": 0})
        check("a blob exactly at the cap is accepted", r.status_code == 200)
        check("  ... no slot was created by the refused writes", await count(VaultSlot, VaultSlot.uin == A) == 2)
        made = 0
        last = None
        for _ in range(vault_router.MAX_SLOTS):
            last = await c.put(f"/vault/{os.urandom(16).hex()}", headers=H(tokA1), json={"blob": b64(), "version": 0})
            if last.status_code != 200:
                break
            made += 1
        check(f"the slot cap holds at {vault_router.MAX_SLOTS} per account ({made + 2} made, then {last.status_code})",
              made + 2 == vault_router.MAX_SLOTS and last.status_code == 400 and last.json()["detail"]["code"] == "slot_limit")
        r = await c.put(f"/vault/{SLOT}", headers=H(tokA1), json={"blob": b64(), "version": 4})
        check("  ... an existing slot can still be rewritten at the cap", r.status_code == 200 and r.json()["version"] == 5)

        print("\nDelete:")
        r = await c.delete(f"/vault/{SLOT}", headers=H(tokA2))
        check(f"delete without a version is refused ({r.status_code})", r.status_code == 422)
        r = await c.delete(f"/vault/{SLOT}?version=4", headers=H(tokA2))
        check("delete with a stale version is 409", r.status_code == 409 and r.json()["detail"]["version"] == 5)
        r = await c.get(f"/vault/{SLOT}", headers=H(tokA2))
        check("  ... and the slot is still there", r.status_code == 200)
        nudges.clear()
        r = await c.delete(f"/vault/{SLOT}?version=5", headers=H(tokA2))
        check("delete with the current version is 204", r.status_code == 204)
        check("  ... and nudged the account with the tombstone's version (6)", nudges[-1][1] == {"type": "vault_changed", "slot": SLOT, "version": 6})
        r = await c.get(f"/vault/{SLOT}", headers=H(tokA1))
        check("  ... the slot reads 404 now, carrying version 6", r.status_code == 404 and r.json()["detail"] == {"code": "no_slot", "version": 6})
        r = await c.get(f"/vault/{os.urandom(16).hex()}", headers=H(tokA1))
        check("  ... a never-written slot reads 404 carrying version 0", r.status_code == 404 and r.json()["detail"] == {"code": "no_slot", "version": 0})
        nudges.clear()
        r = await c.delete(f"/vault/{SLOT}?version=5", headers=H(tokA1))
        check("a second delete is a no-op 204 whatever version it names", r.status_code == 204)
        r = await c.delete(f"/vault/{SLOT}?version=6", headers=H(tokA1))
        check("  ... so is a delete naming the tombstone's version", r.status_code == 204)
        check("  ... and neither nudges", not nudges)
        r = await c.delete(f"/vault/{SLOT2}?version=1", headers=H(tokA1))
        check("the at-cap slot is deleted (204)", r.status_code == 204)
        r = await c.get(f"/vault/{SLOT2}", headers=H(tokA1))
        check("  ... and reads 404 with version 2", r.status_code == 404 and r.json()["detail"]["version"] == 2)

        print("\nNo version is ever reused (ABA):")
        r = await c.put(f"/vault/{SLOT}", headers=H(tokA1), json={"blob": b64(), "version": 0})
        check("a 'fresh' write onto a tombstone is refused with its version (6)", r.status_code == 409 and r.json()["detail"]["version"] == 6)
        r = await c.put(f"/vault/{SLOT}", headers=H(tokA1), json={"blob": b64(), "version": 3})
        check("  ... and so is a write naming a pre-delete version", r.status_code == 409 and r.json()["detail"]["version"] == 6)
        r = await c.put(f"/vault/{SLOT}", headers=H(tokA1), json={"blob": b64(), "version": 6})
        check("a write naming the tombstone's version re-creates the slot as 7", r.status_code == 200 and r.json()["version"] == 7)
        r = await c.get(f"/vault/{SLOT}", headers=H(tokA2))
        check("  ... and it reads back as version 7", r.status_code == 200 and r.json()["version"] == 7)
        r = await c.get(f"/vault/{SLOT}", headers=H(tokB))
        check("B's slot of the same name was never touched (version 1, own blob)", r.status_code == 200 and r.json()["version"] == 1)
        check("tombstones do not count against the cap: A can still create a slot", (await c.put(f"/vault/{os.urandom(16).hex()}", headers=H(tokA1), json={"blob": b64(), "version": 0})).status_code == 200)

        print("\nListing:")
        r = await c.get("/vault", headers=H(tokA1))
        listed = {x["slot"]: x["version"] for x in r.json()["slots"]}
        check(f"GET /vault lists the live slots with versions ({len(listed)})", r.status_code == 200 and listed.get(SLOT) == 7 and SLOT2 not in listed)
        check("  ... exactly the live ones", len(listed) == await count(VaultSlot, VaultSlot.uin == A, VaultSlot.blob.is_not(None)))
        check("  ... and no blobs", all(set(x.keys()) == {"slot", "version"} for x in r.json()["slots"]))

        print("\nReissue empties the vault:")
        r = await c.post("/auth/reissue", headers=H(tokA1), json={"identity_key": b64(32), "signing_key": b64(32)})
        check(f"reissue accepted ({r.status_code})", r.status_code == 200)
        check("  ... every slot of A is gone, tombstones included", await count(VaultSlot, VaultSlot.uin == A) == 0)
        check("  ... B's is not", await count(VaultSlot, VaultSlot.uin == B) == 1)
        for _ in range(3):
            await c.put(f"/vault/{os.urandom(16).hex()}", headers=H(tokA1), json={"blob": b64(), "version": 0})

        print("\nBurn and migrate:")
        n_a = await count(VaultSlot, VaultSlot.uin == A)
        async with SessionLocal() as db:
            await rekey_uin_rows(db, A, 5203)
            await db.commit()
        check("a migration moves every slot to the new number", await count(VaultSlot, VaultSlot.uin == 5203) == n_a and await count(VaultSlot, VaultSlot.uin == A) == 0)
        async with SessionLocal() as db:
            await purge_uin_rows(db, 5203)
            await db.commit()
        check("a burn removes every slot of the account", await count(VaultSlot, VaultSlot.uin == 5203) == 0)
        check("  ... and leaves the other account's alone", await count(VaultSlot, VaultSlot.uin == B) == 1)

        print("\nCapabilities:")
        info = (await c.get("/server/info")).json()["capabilities"]
        check("vault advertised", info.get("vault") is True)
        check("  ... with its caps", info.get("vault_max_blob_bytes") == vault_router.MAX_BLOB_BYTES and info.get("vault_max_slots") == vault_router.MAX_SLOTS)

        print("\nShapes the driver must never see:")
        r = await c.put(f"/vault/{SLOT}", headers=H(tokB), json={"blob": b64(), "version": 99999999999999999999})
        check(f"an absurd version is 422, not a 500 at the bind ({r.status_code})", r.status_code == 422)
        r = await c.delete(f"/vault/{SLOT}?version=99999999999999999999", headers=H(tokB))
        check(f"  ... on delete too ({r.status_code})", r.status_code == 422)

    print("\nAccess log:")
    from app.main import _RedactSecretsInLogs  # noqa: E402
    f = _RedactSecretsInLogs()
    line = f._scrub(f'INFO: 185.102.11.202:0 - "PUT /vault/{SLOT} HTTP/1.1" 200', paths=True)
    check("the slot name is masked in an access line", "/vault/<slot>" in line and SLOT not in line)
    line = f._scrub('"GET /vault HTTP/1.1" 200', paths=True)
    check("  ... the listing path is left alone", line == '"GET /vault HTTP/1.1" 200')

    await close_redis()
    print(f"\n{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
    return fails


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
