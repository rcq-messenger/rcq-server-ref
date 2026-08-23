"""Local-only verification of stage 4b: the vault mark and the batch read.

Stage 4a gave every account a vault and all four clients started mirroring
their contact list into it, with the island's `contacts` table still
authoritative. Stage 4b is the measurement and the plumbing for the step
after it: every install advertises whether it keeps its list in the vault,
the island records that per DEVICE, and a client holding numbers from its own
slot can render a list without the `/contacts` JOIN.

⚠⚠ THE ISLAND STILL WRITES EVERY EDGE. The first cut of this stage froze the
pair once both accounts had moved, and the review killed it: a frozen pair is
not "a pair whose list lives elsewhere", it is a pair that is a STRANGER to
all five server-side rules on the day of the freeze, with no client-side
replacement shipped -- no calls (`call_policy` is "contacts" by default), no
room invites (so is `group_invite_policy`), no presence, no `last_seen`, no
picture, and random chat pairing two people who know each other. Worse, the
4a mirror every client ships is server-wins, so one sibling install still on
that phase folds the empty answer over the pair and tombstones it out of the
shared vault slot. The freeze is the DROP and it moves with the five rules
and the client halves, which is what `FREEZE_NEW_EDGES` names. Pins:

  * every accepted pair gets both rows, moved or not, on `/contacts/respond`
    and on the mutual-request auto-accept;
  * a pair that moved and became contacts AFTER the flip still gets all five
    answers: callable, invitable, presence-watched, `last_seen` and picture
    through `/users/lookup`, and known to random chat;
  * the drop switch is off, and `edges_frozen` is what it will gate;
  * the mark is per INSTALL and an account with a second install still
    draining the legacy queue does NOT count as moved -- the stage 5 lesson,
    where an account's phone updating first must not silence its old desktop;
  * a device can unmark itself, and a mark that stops being re-advertised
    (a downgrade to a build that never heard of the field) ages out;
  * `GET /contacts` is untouched: it serves every row that exists;
  * removals still land: a relationship that ended has to stop granting
    calls and invites;
  * `POST /users/lookup` answers per uin exactly what `GET /users/{uin}/info`
    answers the same caller: same card gate, same picture rule, same
    last_seen and gender gates, and it never reports `blocked`;
  * it omits what it cannot serve (unknown, suspended, self) identically, so
    a padded batch is indistinguishable from a batch full of misses;
  * it answers in ascending uin order whatever order it was asked in;
  * it takes the batch in ascending order only, so a client cannot leak its
    own display order in the request body;
  * `callable` is answered for a contact and never for a stranger, because
    `GET /users/{uin}/info` gives no such field for a third party;
  * its rate-limit bucket names the ACCOUNT and never the looked-up numbers,
    and the daily budget counter is charged in whole quanta so it is not a
    live measure of how many people the caller renders;
  * the mark rides `uin_rows` (migration and burn), and the capability is
    advertised.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_stage4b_contacts_readonly_local.py
"""
import asyncio
import base64
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_stage4b.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("JWT_SECRET", "t" * 64)
for f in ("test_stage4b.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.contact import Contact, ContactRequest, ContactVaultDevice  # noqa: E402
from app.models.group import Group, GroupMember  # noqa: E402
from app.models.queue_cursor import QueueCursor  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services import connection_manager  # noqa: E402
from app.services import contact_source  # noqa: E402
from app.services.contact_source import vault_backed  # noqa: E402
from app.services.uin_rows import PER_UIN_COLUMNS, purge_uin_rows, rekey_uin_rows  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


# Two ordinary accounts, two that will move, and one that moves on one
# install while a second install of it still drains the legacy queue.
A, B = 7101, 7102          # never move
V1, V2 = 7103, 7104        # both move
HALF = 7105                # moved on one install only
STRANGER = 7106            # for the lookup gates
SUSPENDED = 7107


async def edges(a, b):
    """How many of the two directed rows of this pair exist."""
    async with SessionLocal() as db:
        return (await db.execute(
            select(func.count()).select_from(Contact).where(
                ((Contact.owner_uin == a) & (Contact.contact_uin == b))
                | ((Contact.owner_uin == b) & (Contact.contact_uin == a))
            )
        )).scalar_one()


async def wipe_pair(a, b):
    async with SessionLocal() as db:
        rows = (await db.execute(select(Contact).where(
            ((Contact.owner_uin == a) & (Contact.contact_uin == b))
            | ((Contact.owner_uin == b) & (Contact.contact_uin == a))
        ))).scalars().all()
        for r in rows:
            await db.delete(r)
        reqs = (await db.execute(select(ContactRequest).where(
            ((ContactRequest.from_uin == a) & (ContactRequest.to_uin == b))
            | ((ContactRequest.from_uin == b) & (ContactRequest.to_uin == a))
        ))).scalars().all()
        for r in reqs:
            await db.delete(r)
        await db.commit()


async def become_contacts(c, tok_from, frm, to, tok_to):
    """The real flow: request, then accept."""
    r = await c.post("/contacts/request", headers=H(tok_from), json={"to_uin": to})
    assert r.status_code in (200, 202), r.text
    rid = r.json()["id"]
    r = await c.post("/contacts/respond", headers=H(tok_to), json={"request_id": rid, "accept": True})
    assert r.status_code == 200, r.text
    return r.json()


async def main():
    global fails
    await init_db()
    # The limiter buckets live in Redis and outlive the throwaway DB; a few
    # runs in a row would otherwise hit the hourly caps.
    await (await get_redis()).flushdb()

    async with SessionLocal() as db:
        for u in (A, B, V1, V2, HALF, STRANGER, SUSPENDED):
            db.add(User(uin=u, nickname=f"u{u}", identity_key=b64(), signing_key=b64()))
        await db.commit()
        # STRANGER carries every gate we want to read back through lookup.
        s = await db.get(User, STRANGER)
        s.avatar_media_id, s.avatar_media_key = "m-stranger", b64(16)
        s.gender, s.gender_visibility = "f", "contacts"
        s.last_seen_visibility = "contacts"
        s.profile_card_policy = "contacts"
        s.call_policy = "contacts"
        s.status_message = "hello"
        b = await db.get(User, B)
        b.avatar_media_id, b.avatar_media_key = "m-b", b64(16)
        # V2 moves to the vault and then becomes a contact of V1. Everything
        # a contact of theirs should still see is set here.
        v2 = await db.get(User, V2)
        v2.avatar_media_id, v2.avatar_media_key = "m-v2", b64(16)
        v2.last_seen = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
        v2.last_seen_visibility = "contacts"
        v2.call_policy = "contacts"
        v2.group_invite_policy = "contacts"
        sus = await db.get(User, SUSPENDED)
        sus.is_suspended = True
        await db.commit()

    tokA = issue_token(A, 0, "phone")
    tokB = issue_token(B, 0, "phone")
    tokV1 = issue_token(V1, 0, "phone")
    tokV2 = issue_token(V2, 0, "phone")
    tokHalf1 = issue_token(HALF, 0, "phone")
    tokHalf2 = issue_token(HALF, 0, "desktop")

    # Swallow the socket fan-out; nothing here is about delivery.
    real_send = connection_manager.manager.send
    real_broadcast = connection_manager.manager.broadcast
    sent: list[tuple] = []

    async def fake_send(uin, payload, except_device=None):
        sent.append((uin, payload))
        return False

    async def fake_broadcast(uins, payload):
        return None

    connection_manager.manager.send = fake_send  # type: ignore[method-assign]
    connection_manager.manager.broadcast = fake_broadcast  # type: ignore[method-assign]

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:

        print("\nThe island still writes for an ordinary pair:")
        await become_contacts(c, tokA, A, B, tokB)
        check("accept writes both directed rows", await edges(A, B) == 2)
        r = await c.get("/contacts", headers=H(tokA))
        check("GET /contacts serves the row", r.status_code == 200 and [x["uin"] for x in r.json()] == [B])
        r = await c.post("/contacts/request", headers=H(tokA), json={"to_uin": B})
        check("a second request is 409 'already in your contact list'", r.status_code == 409)

        print("\nAdvertising the capability:")
        r = await c.post("/users/me/capabilities", headers=H(tokV1), json={"vault_contacts": True})
        check("POST /users/me/capabilities takes vault_contacts", r.status_code == 204)
        async with SessionLocal() as db:
            row = await db.get(ContactVaultDevice, (V1, "phone"))
            check("the mark is per (account, install)", row is not None)
            check("V1 counts as moved", await vault_backed(db, [V1]) == {V1})
            check("V2 does not yet", await vault_backed(db, [V2]) == set())
        r = await c.post("/users/me/capabilities", headers=H(tokV1), json={"vault_contacts": True})
        check("re-advertising is idempotent", r.status_code == 204)
        async with SessionLocal() as db:
            check("still one row", (await db.execute(
                select(func.count()).select_from(ContactVaultDevice).where(ContactVaultDevice.uin == V1)
            )).scalar_one() == 1)
        # The old flag still works and did not become mutually exclusive.
        r = await c.post("/users/me/capabilities", headers=H(tokV1), json={"sender_keys": True})
        check("sender_keys still rides the same endpoint", r.status_code == 204)

        print("\nOne side moved is not enough:")
        await become_contacts(c, tokV1, V1, A, tokA)
        check("both rows still written when only one side has moved", await edges(V1, A) == 2)
        r = await c.get("/contacts", headers=H(tokA))
        check("the un-moved side sees the new contact", B in [x["uin"] for x in r.json()] and V1 in [x["uin"] for x in r.json()])

        print("\nBoth sides moved, and the island still records the edge:")
        r = await c.post("/users/me/capabilities", headers=H(tokV2), json={"vault_contacts": True})
        check("V2 advertises too", r.status_code == 204)
        async with SessionLocal() as db:
            check("the pair counts as moved", await vault_backed(db, [V1, V2]) == {V1, V2})
        resp = await become_contacts(c, tokV1, V1, V2, tokV2)
        check("the accept still answers accepted", resp.get("state") == "accepted")
        check("both rows are written for a moved pair too", await edges(V1, V2) == 2)
        check("the requester is still told over the socket", any(
            u == V1 and p.get("type") == "contact_response" and p.get("accepted") for u, p in sent
        ))
        async with SessionLocal() as db:
            state = (await db.execute(select(ContactRequest.state).where(
                ContactRequest.from_uin == V1, ContactRequest.to_uin == V2
            ))).scalar_one()
            check("the consent record is still marked accepted", state == "accepted")
        r = await c.get("/contacts", headers=H(tokV1))
        check("a moved account's list gains the new person", V2 in [x["uin"] for x in r.json()])
        check("and still holds what it had before", A in [x["uin"] for x in r.json()])

        print("\nThe five rules answer for a pair that became contacts AFTER the flip:")
        from app.routers.ws import _caller_allowed as caller_allowed  # noqa: E402
        from app.routers.groups import _can_invite_to_group as can_invite  # noqa: E402
        from app.routers.presence import presence_watchers  # noqa: E402
        from app.routers.random import _are_already_connected  # noqa: E402
        check("call_policy=contacts lets the new contact ring",
              await caller_allowed(V1, V2) is True)
        async with SessionLocal() as db:
            invitee = await db.get(User, V2)
            check("group_invite_policy=contacts lets them add the new contact to a room",
                  await can_invite(db, inviter_uin=V1, invitee=invitee) is True)
            check("presence still reaches the new contact",
                  V1 in await presence_watchers(db, V2))
            check("random chat still knows the two are connected",
                  await _are_already_connected(db, V1, V2) is True)
        r = await c.post("/users/lookup", headers=H(tokV1), json={"uins": [V2]})
        row = r.json()["users"][0]
        check("the new contact's picture is served", row["avatar_media_id"] == "m-v2")
        check("and their last_seen", row["last_seen"] is not None)
        check("and they are callable", row["callable"] is True)

        print("\nThe drop switch is off:")
        check("FREEZE_NEW_EDGES is False", contact_source.FREEZE_NEW_EDGES is False)
        async with SessionLocal() as db:
            check("so no pair is frozen", await contact_source.edges_frozen(db, V1, V2) is False)
            contact_source.FREEZE_NEW_EDGES = True
            try:
                check("and it is the moved pair the drop will freeze",
                      await contact_source.edges_frozen(db, V1, V2) is True)
                check("an un-moved pair is untouched by it either way",
                      await contact_source.edges_frozen(db, A, B) is False)
            finally:
                contact_source.FREEZE_NEW_EDGES = False

        print("\nThe mutual-request auto-accept takes the same path:")
        await wipe_pair(V1, V2)
        r = await c.post("/contacts/request", headers=H(tokV1), json={"to_uin": V2})
        check("request goes out", r.status_code in (200, 202))
        r = await c.post("/contacts/request", headers=H(tokV2), json={"to_uin": V1})
        check("the reverse request auto-accepts", r.status_code in (200, 202) and r.json().get("auto") is True)
        check("and writes both rows", await edges(V1, V2) == 2)

        print("\nAn account with an install still on the legacy queue is NOT moved:")
        async with SessionLocal() as db:
            db.add(QueueCursor(uin=HALF, device_id="desktop", last_direct_id=0, last_group_id=0))
            await db.commit()
        r = await c.post("/users/me/capabilities", headers=H(tokHalf1), json={"vault_contacts": True})
        check("the phone advertises", r.status_code == 204)
        async with SessionLocal() as db:
            check("the account does not count as moved", await vault_backed(db, [HALF]) == set())
        await become_contacts(c, tokHalf1, HALF, V1, tokV1)
        check("so its rows are still written", await edges(HALF, V1) == 2)
        r = await c.post("/users/me/capabilities", headers=H(tokHalf2), json={"vault_contacts": True})
        check("the desktop advertises too", r.status_code == 204)
        async with SessionLocal() as db:
            check("now the account is moved", await vault_backed(db, [HALF]) == {HALF})

        print("\nA device can go back:")
        r = await c.post("/users/me/capabilities", headers=H(tokHalf2), json={"vault_contacts": False})
        check("unmark is accepted", r.status_code == 204)
        async with SessionLocal() as db:
            check("and the account is on the server list again", await vault_backed(db, [HALF]) == set())
        await wipe_pair(HALF, V2)
        await become_contacts(c, tokHalf1, HALF, V2, tokV2)
        check("rows are written again", await edges(HALF, V2) == 2)

        print("\nA mark that stops being re-advertised ages out:")
        # The rollback the unmark above cannot cover: a build that predates
        # the field can never post `false`, so the mark has to expire on its
        # own or the account counts as moved forever.
        async with SessionLocal() as db:
            row = await db.get(ContactVaultDevice, (V1, "phone"))
            row.last_seen = datetime.now(timezone.utc) - timedelta(
                days=contact_source.VAULT_MARK_TTL_DAYS + 1
            )
            await db.commit()
            check("a stale mark does not count as moved", await vault_backed(db, [V1]) == set())
            row = await db.get(ContactVaultDevice, (V1, "phone"))
            row.last_seen = datetime.now(timezone.utc)
            await db.commit()
            check("re-advertising brings it back", await vault_backed(db, [V1]) == {V1})

        print("\nRemovals land as they always did:")
        r = await c.delete(f"/contacts/{V2}", headers=H(tokHalf1))
        check("DELETE /contacts/{uin} is 204", r.status_code == 204)
        check("and both directed rows are gone", await edges(HALF, V2) == 0)

        print("\nThe five rules are untouched for an ordinary pair:")
        # 1. callability, and 5. the 409 above.
        from app.routers.ws import _caller_allowed  # noqa: E402
        async with SessionLocal() as db:
            u = await db.get(User, A)
            u.call_policy = "contacts"
            await db.commit()
        check("call_policy=contacts lets a contact through", await _caller_allowed(B, A) is True)
        check("and refuses a stranger", await _caller_allowed(STRANGER, A) is False)
        # 2. the group invite policy.
        from app.routers.groups import _can_invite_to_group, _filter_blocked  # noqa: E402
        async with SessionLocal() as db:
            u = await db.get(User, A)
            u.group_invite_policy = "contacts"
            await db.commit()
            invitee = await db.get(User, A)
            check("a contact may add them to a room",
                  await _can_invite_to_group(db, inviter_uin=B, invitee=invitee) is True)
            check("a stranger may not",
                  await _can_invite_to_group(db, inviter_uin=STRANGER, invitee=invitee) is False)
        # 3/4. the card gate and the picture, through the endpoint.
        r = await c.get(f"/users/{B}/info", headers=H(tokA))
        check("a contact still gets the picture", r.status_code == 200 and r.json()["avatar_media_id"] == "m-b")
        r = await c.get(f"/users/{B}/info", headers=H(tokV2))
        check("a stranger still does not", r.status_code == 200 and r.json()["avatar_media_id"] is None)

        print("\nPOST /users/lookup answers as GET /users/{uin}/info does:")
        # A is a contact of B and of V1; STRANGER is nobody's contact.
        r = await c.post("/users/lookup", headers=H(tokA), json={"uins": [B, STRANGER]})
        check("200", r.status_code == 200)
        got = {row["uin"]: row for row in r.json()["users"]}
        check("the answer is in ascending uin order",
              [row["uin"] for row in r.json()["users"]] == sorted(got))
        r2 = await c.post("/users/lookup", headers=H(tokA), json={"uins": [STRANGER, B]})
        check("a batch in display order is refused, not silently sorted",
              r2.status_code == 422)
        r2 = await c.post("/users/lookup", headers=H(tokA), json={"uins": [B, B]})
        check("and so is a repeat", r2.status_code == 422)
        check("a contact's picture comes back", got[B]["avatar_media_id"] == "m-b")
        check("a stranger's does not", got[STRANGER]["avatar_media_id"] is None)
        check("gender_visibility=contacts hides from a stranger", got[STRANGER]["gender"] is None)
        check("last_seen_visibility=contacts hides from a stranger", got[STRANGER]["last_seen"] is None)
        check("profile_card_policy=contacts closes the card", got[STRANGER]["profile_openable"] is False)
        # ⚠ NOT the real verdict. `GET /users/{uin}/info` returns `call_policy`
        # as null to every non-self viewer, so answering it here for an
        # arbitrary number would classify 256 strangers' call settings per
        # request off an endpoint that promises to answer exactly what the
        # per-uin route answers.
        check("a stranger's call policy is not reported", got[STRANGER]["callable"] is True)
        r_info = await c.get(f"/users/{STRANGER}/info", headers=H(tokA))
        check("and the per-uin route still gives no call_policy for a third party",
              r_info.json()["call_policy"] is None)
        check("no `blocked` field anywhere in the answer",
              all("blocked" not in row for row in r.json()["users"]))
        # Now the same numbers to somebody who IS the stranger's contact.
        await become_contacts(c, tokB, B, STRANGER, issue_token(STRANGER, 0, "phone"))
        r = await c.post("/users/lookup", headers=H(tokB), json={"uins": [STRANGER]})
        row = r.json()["users"][0]
        check("a contact sees the gated gender", row["gender"] == "f")
        check("a contact may open the card", row["profile_openable"] is True)
        check("a contact may call", row["callable"] is True)
        check("and gets the picture", row["avatar_media_id"] == "m-stranger")
        # Group co-membership hands over the picture without a contact edge,
        # the same rule /users/{uin}/info applies.
        async with SessionLocal() as db:
            g = Group(name="room", owner_uin=STRANGER)
            db.add(g)
            await db.flush()
            db.add_all([GroupMember(group_id=g.id, uin=STRANGER, role="owner"),
                        GroupMember(group_id=g.id, uin=V2, role="member")])
            await db.commit()
        r = await c.post("/users/lookup", headers=H(tokV2), json={"uins": [STRANGER]})
        check("a room co-member gets the picture", r.json()["users"][0]["avatar_media_id"] == "m-stranger")
        check("but still cannot open the card", r.json()["users"][0]["profile_openable"] is False)
        async with SessionLocal() as db:
            u = await db.get(User, STRANGER)
            u.call_policy = "nobody"
            await db.commit()
        r = await c.post("/users/lookup", headers=H(tokB), json={"uins": [STRANGER]})
        check("a contact still learns they may not call", r.json()["users"][0]["callable"] is False)
        r = await c.post("/users/lookup", headers=H(tokV2), json={"uins": [STRANGER]})
        check("a non-contact learns nothing either way", r.json()["users"][0]["callable"] is True)

        print("\nWhat lookup will not tell you:")
        r = await c.post("/users/lookup", headers=H(tokA), json={"uins": sorted([999999, SUSPENDED, A, B])})
        got = [row["uin"] for row in r.json()["users"]]
        check("an unknown number is omitted", 999999 not in got)
        check("a suspended account is omitted", SUSPENDED not in got)
        check("self is omitted", A not in got)
        check("a miss and chaff are the same answer", got == [B])
        r = await c.post("/users/lookup", headers=H(tokA), json={"uins": []})
        check("an empty batch is a 422, not a whole-directory read", r.status_code == 422)
        r = await c.post("/users/lookup", headers=H(tokA), json={"uins": list(range(1, 400))})
        check("an oversized batch is refused", r.status_code == 422)
        r = await c.post("/users/lookup", json={"uins": [B]})
        check("and it takes a session", r.status_code in (401, 403))

        print("\nIt writes nothing:")
        async with SessionLocal() as db:
            before = (await db.execute(select(func.count()).select_from(Contact))).scalar_one()
        for _ in range(3):
            await c.post("/users/lookup", headers=H(tokA), json={"uins": [B, STRANGER]})
        async with SessionLocal() as db:
            after = (await db.execute(select(func.count()).select_from(Contact))).scalar_one()
        check("no contact row appears from a lookup", before == after)
        redis = await get_redis()
        keys = [k if isinstance(k, str) else k.decode() for k in await redis.keys("rl*")]
        check("no limiter key names a looked-up number",
              not any(str(STRANGER) in k or str(B) in k for k in keys))
        # ⚠ What the caller's OWN keys hold is the other half of it: charging
        # the exact de-duplicated batch size would put |render set| into
        # Redis on every list refresh, live, for 24 hours.
        budget = [k for k in keys if k.startswith("rlc:users_lookup_uins:")]
        check("the daily budget counter exists", len(budget) >= 1)
        from app.routers import users as users_router  # noqa: E402
        charged = int(await redis.get(budget[0]))
        check("and is charged in whole quanta, not in exact uins",
              charged > 0 and charged % users_router.LOOKUP_COST_QUANTUM == 0)

        print("\nThe wire says so:")
        r = await c.get("/server/info")
        caps = r.json()["capabilities"]
        check("capabilities.users_lookup is advertised", caps.get("users_lookup") is True)
        check("contacts_readonly answers FALSE rather than disappearing",
              caps.get("contacts_readonly") is False)
        check("and the vault is still advertised beside it", caps.get("vault") is True)

    print("\nMigration and burn carry the mark:")
    check("ContactVaultDevice is in the uin_rows inventory",
          any(m is ContactVaultDevice for m, _ in PER_UIN_COLUMNS))
    async with SessionLocal() as db:
        db.add(User(uin=7201, nickname="new", identity_key=b64(), signing_key=b64()))
        await db.commit()
        await rekey_uin_rows(db, V1, 7201)
        await db.commit()
        moved = (await db.execute(
            select(func.count()).select_from(ContactVaultDevice).where(ContactVaultDevice.uin == 7201)
        )).scalar_one()
        check("a migration takes the mark to the new number", moved == 1)
        left = (await db.execute(
            select(func.count()).select_from(ContactVaultDevice).where(ContactVaultDevice.uin == V1)
        )).scalar_one()
        check("and leaves none on the old one", left == 0)
        await purge_uin_rows(db, 7201)
        await db.commit()
        gone = (await db.execute(
            select(func.count()).select_from(ContactVaultDevice).where(ContactVaultDevice.uin == 7201)
        )).scalar_one()
        check("a burn takes it", gone == 0)

    connection_manager.manager.send = real_send  # type: ignore[method-assign]
    connection_manager.manager.broadcast = real_broadcast  # type: ignore[method-assign]
    await close_redis()
    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILURES'}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
