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
    account's devices learn to re-read without a second sync protocol; the
    WRITING install is skipped by name, so it is not told to re-read what it
    has just written (an unnamed "primary" install is not skipped, because
    two of those cannot be told apart and skipping would silence the real
    other device);
  * a slot beside the contact list (the chat-list sections of stage 4b) needs
    no server change: the island takes 32 hex characters and attaches no
    meaning to any of them, and the version rule is per (account, slot), so a
    new slot inherits the whole #605 discipline as it is created;
  * GET /vault lists the live slots and versions, tombstones excluded;
  * a burned account takes its slots with it, a migrated account keeps them
    under the new number (the uin_rows lists), a key reissue empties them;
  * and that emptying is ANNOUNCED, which it was not until 2026-08-23: one
    account-level `{"type": "vault_reset", "reason": "identity_reissued"}` to
    the account's other sessions, never a `vault_changed` per slot, because a
    reissue rotates the identity the slot NAMES derive from, so the slots are
    not at a new version, they are at new names. The rotating install is
    skipped by name like any writer; an unnamed "primary" rotator is not, so
    the frame means "re-derive and republish" and never "wipe what you have";
  * the access-log redactor masks the slot name;
  * the capability and the caps are advertised.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_stage4_vault_local.py
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import time

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
# C is only ever used by the two-device section at the end, so the caps, the
# tombstones and the burn the other two go through cannot reach it.
C = 5204
SLOT = os.urandom(16).hex()
SLOT2 = os.urandom(16).hex()
# What a first-party client would use for account C: the identity private key
# never leaves the client, the island only ever sees the derived hex.
C_IDENTITY_PRIV = os.urandom(32)


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


def slot_id(identity_priv: bytes, name: str) -> str:
    """The client's slot derivation, copied from web-chat/src/lib/vault.ts:
    hex(HKDF-SHA256(identity_priv, 32 zero bytes of salt,
    "rcq.vault.slot.v1|" + name, 16)). Here to prove that what a client
    derives for a NEW label is an ordinary slot name to the island: no schema,
    no list of known names, no server change."""
    prk = hmac.new(bytes(32), identity_priv, hashlib.sha256).digest()
    info = f"rcq.vault.slot.v1|{name}".encode()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:16].hex()


class FakeSocket:
    """Enough of a WebSocket for the connection manager: it accepts, it takes
    text, it closes. Frames the island fans out to it land in `.frames`."""

    def __init__(self) -> None:
        self.frames: list[dict] = []

    async def accept(self) -> None:
        pass

    async def send_text(self, text: str) -> None:
        self.frames.append(json.loads(text))

    async def close(self, code: int = 1000, reason: str = "") -> None:
        pass


async def wait_for_frame(sock: FakeSocket, timeout: float = 3.0):
    """The nudge is published to Redis and comes back into this process
    through the manager's own subscriber, so it lands a moment AFTER the HTTP
    reply, not with it."""
    deadline = time.monotonic() + timeout
    while not sock.frames and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
    # Sockets of one account are delivered to in a single gather, so once one
    # of them has the frame the others either have it too or never will.
    await asyncio.sleep(0.1)
    return sock.frames[-1] if sock.frames else None


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
        for u in (A, B, C):
            db.add(User(uin=u, nickname=f"u{u}", identity_key=b64(32), signing_key=b64(32)))
        await db.commit()

    tokA1 = issue_token(A, 0, "phone")
    tokA2 = issue_token(A, 0, "desktop")
    tokB = issue_token(B, 0, "phone")
    tokC1 = issue_token(C, 0, "phone")
    tokC2 = issue_token(C, 0, "desktop")
    # A token with no `dev` claim: an install that never named itself, which
    # the server reads as "primary", i.e. as no name at all.
    tokC_unnamed = issue_token(C, 0, None)

    # Capture the socket nudges instead of opening sockets. The two-device
    # section at the end puts the real fanout back and uses real sockets.
    real_send = connection_manager.manager.send
    nudges: list[tuple[int, dict, str | None]] = []

    async def fake_send(uin, payload, except_device=None):
        nudges.append((uin, payload, except_device))
        return True

    connection_manager.manager.send = fake_send  # type: ignore[method-assign]

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
              nudges[-1][0] == A and nudges[-1][1] == {"type": "vault_changed", "slot": SLOT, "version": 1})
        check("  ... skipping the install that wrote it", nudges[-1][2] == "phone")

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
        check("  ... and nudged the account with the tombstone's version (6), skipping the deleting install",
              nudges[-1][1] == {"type": "vault_changed", "slot": SLOT, "version": 6} and nudges[-1][2] == "desktop")
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

        print("\nReissue empties the vault, and says so:")
        nudges.clear()
        r = await c.post("/auth/reissue", headers=H(tokA1), json={"identity_key": b64(32), "signing_key": b64(32)})
        check(f"reissue accepted ({r.status_code})", r.status_code == 200)
        check("  ... every slot of A is gone, tombstones included", await count(VaultSlot, VaultSlot.uin == A) == 0)
        check("  ... B's is not", await count(VaultSlot, VaultSlot.uin == B) == 1)
        # ★ Until 2026-08-23 that emptying was silent. A second device then
        # read a slot name that no longer existed and got 404 with version 0,
        # which is byte for byte what a slot NOBODY HAS EVER WRITTEN reads, so
        # it concluded "fresh account, publish what I have" and wrote its
        # cached copy as version 1 under the RETIRED derivation; the rotating
        # device wrote version 2 over it from its own. Two devices silently
        # un-publishing each other, which is the #605 shape walking in through
        # the one door the version rule cannot watch.
        check("★ the emptying announces itself, exactly once", len(nudges) == 1)
        # Read defensively so a build that announces nothing fails every check
        # in this block rather than raising IndexError on the second one.
        first = nudges[0] if nudges else (None, {}, "not-a-device")
        check("★ as ONE account-level frame, not a vault_changed per slot",
              first[1] == {"type": "vault_reset", "reason": "identity_reissued"})
        check("  ... addressed to the account it emptied", first[0] == A)
        # Skipped by name, exactly as a writer is skipped: the rotating device
        # is the one that will write the state back, and it must not be told to
        # drop the copy it is holding.
        check("  ... skipping the install that rotated", first[2] == "phone")
        check("  ... and no per-slot nudge rides along: the NAMES changed too, so a "
              "vault_changed would send a device to re-read a name that will never exist",
              not any(n[1].get("type") == "vault_changed" for n in nudges))
        check("  ... and nobody else's account hears it", all(n[0] == A for n in nudges))

        for _ in range(3):
            await c.put(f"/vault/{os.urandom(16).hex()}", headers=H(tokA1), json={"blob": b64(), "version": 0})
        check("A writes three fresh slots under the new identity",
              await count(VaultSlot, VaultSlot.uin == A) == 3)
        # ⚠ "primary" is the ABSENCE of an install name, not a device (§2.11),
        # so an unnamed rotator cannot be skipped and hears its own reset. That
        # is why the frame means "the island's copy is gone, re-derive and
        # republish" and never "wipe what you have": a client reading it as a
        # wipe loses the only remaining copy the moment it rotates from an
        # unnamed install.
        nudges.clear()
        tokA_unnamed = issue_token(A, 0, None)
        r = await c.post("/auth/reissue", headers=H(tokA_unnamed), json={"identity_key": b64(32), "signing_key": b64(32)})
        check(f"a rotation from an UNNAMED install is accepted ({r.status_code})", r.status_code == 200)
        check("  ... and empties the vault the same way", await count(VaultSlot, VaultSlot.uin == A) == 0)
        resets = [n for n in nudges if n[1].get("type") == "vault_reset"]
        check("★ it announces the reset too", len(resets) == 1)
        check("★ and skips NOBODY, because 'primary' is no name to skip by",
              bool(resets) and resets[0][2] is None)

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

        print("\nA second slot ('sections'), two devices, real sockets:")
        # From here on the real fanout is back: the frames go out over Redis
        # pub/sub and come back into this process through the manager's own
        # subscriber, which is the path a device actually receives them on.
        connection_manager.manager.send = real_send  # type: ignore[method-assign]
        phone, desktop = FakeSocket(), FakeSocket()
        await connection_manager.manager.connect(C, phone, "phone")
        await connection_manager.manager.connect(C, desktop, "desktop")
        contacts_slot = slot_id(C_IDENTITY_PRIV, "contacts")
        sections = slot_id(C_IDENTITY_PRIV, "sections")
        r = await c.put("/vault/sections", headers=H(tokC2), json={"blob": b64(), "version": 0})
        check(f"the label itself is not a slot name: 'sections' is refused ({r.status_code})", r.status_code in (400, 422))
        check("the derived name is 32 hex characters like any other", len(sections) == 32 and sections != contacts_slot)
        r = await c.put(f"/vault/{contacts_slot}", headers=H(tokC1), json={"blob": b64(), "version": 0})
        check("the contacts slot lands as version 1", r.status_code == 200 and r.json()["version"] == 1)
        phone.frames.clear()
        desktop.frames.clear()
        sec1 = b64(200)
        r = await c.put(f"/vault/{sections}", headers=H(tokC2), json={"blob": sec1, "version": 0})
        check("the desktop creates the sections slot with no server change (version 1)", r.status_code == 200 and r.json()["version"] == 1)
        frame = await wait_for_frame(phone)
        check("  ... the phone is nudged over its socket with the slot and the new version",
              frame == {"type": "vault_changed", "slot": sections, "version": 1})
        check("  ... no blob rides the nudge", frame is not None and set(frame) == {"type", "slot", "version"})
        check("  ... and the desktop, which wrote it, is not nudged", desktop.frames == [])
        r = await c.get(f"/vault/{sections}", headers=H(tokC1))
        check("  ... the phone reads the new version and the blob it names", r.status_code == 200 and r.json() == {"blob": sec1, "version": 1})

        # The version rule is per (account, slot), so the second slot is under
        # the #605 discipline from its first byte and the first slot is not
        # dragged along by it.
        phone.frames.clear()
        desktop.frames.clear()
        sec2 = b64(200)
        r = await c.put(f"/vault/{sections}", headers=H(tokC1), json={"blob": sec2, "version": 1})
        check("the phone writes on top of version 1 -> version 2", r.status_code == 200 and r.json()["version"] == 2)
        r = await c.put(f"/vault/{sections}", headers=H(tokC2), json={"blob": b64(200), "version": 1})
        check("  ... the desktop's write from version 1 is refused with the current version", r.status_code == 409 and r.json()["detail"] == {"code": "stale", "version": 2})
        frame = await wait_for_frame(desktop)
        check("  ... and the desktop heard the phone's write, not its own refusal",
              frame == {"type": "vault_changed", "slot": sections, "version": 2} and len(desktop.frames) == 1)
        r = await c.get(f"/vault/{contacts_slot}", headers=H(tokC2))
        check("the contacts slot is still at its own version 1: the counters do not share", r.json()["version"] == 1)
        r = await c.get("/vault", headers=H(tokC1))
        listed = {x["slot"]: x["version"] for x in r.json()["slots"]}
        check("GET /vault lists both slots of the account", listed == {contacts_slot: 1, sections: 2})

        phone.frames.clear()
        desktop.frames.clear()
        r = await c.put(f"/vault/{sections}", headers=H(tokC_unnamed), json={"blob": b64(200), "version": 2})
        check("a write from an install with no name is accepted (version 3)", r.status_code == 200 and r.json()["version"] == 3)
        frame = await wait_for_frame(phone)
        check("  ... and nudges EVERY device, because 'primary' is no name and cannot be skipped safely",
              frame == {"type": "vault_changed", "slot": sections, "version": 3} and desktop.frames == [frame])

        # And the reset over a real socket, which is the path a device actually
        # receives it on: through Redis pub/sub and back into this process via
        # the manager's own subscriber.
        phone.frames.clear()
        desktop.frames.clear()
        r = await c.post("/auth/reissue", headers=H(tokC2), json={"identity_key": b64(32), "signing_key": b64(32)})
        check(f"the desktop rotates C's identity ({r.status_code})", r.status_code == 200)
        frame = await wait_for_frame(phone)
        check("★ the phone hears the reset on its socket, one account-level frame",
              frame == {"type": "vault_reset", "reason": "identity_reissued"})
        check("  ... and the install that rotated does not", desktop.frames == [])
        check("  ... the slots really are gone", await count(VaultSlot, VaultSlot.uin == C) == 0)

        # ★★★ The retry. The documented flow is read the slots, reissue, write
        # them back under the new derivation, so a second copy of the SAME call
        # (a gateway timeout on the reply, a double tap) lands after the
        # republish. It used to delete the slots the client had just rewritten
        # and announce a reset for a derivation that had not moved.
        keys = {"identity_key": b64(32), "signing_key": b64(32)}
        r = await c.post("/auth/reissue", headers=H(tokC2), json=keys)
        check(f"a real rotation still goes through ({r.status_code})", r.status_code == 200)
        republished = b64(200)
        r = await c.put(f"/vault/{sections}", headers=H(tokC2), json={"blob": republished, "version": 0})
        check("  ... and the client republishes under the new derivation", r.status_code == 200)
        phone.frames.clear()
        r = await c.post("/auth/reissue", headers=H(tokC2), json=keys)
        check(f"★ the same call again is a no-op, not a second wipe ({r.status_code})", r.status_code == 200)
        r = await c.get(f"/vault/{sections}", headers=H(tokC1))
        check("  ★ the republished slot is still there", r.status_code == 200 and r.json()["blob"] == republished)
        await asyncio.sleep(0.15)
        check("  ★ and no reset is announced for a derivation that did not move",
              [f for f in phone.frames if f.get("type") == "vault_reset"] == [])

        await connection_manager.manager.disconnect(C, phone)
        await connection_manager.manager.disconnect(C, desktop)
        await connection_manager.manager.shutdown()

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
