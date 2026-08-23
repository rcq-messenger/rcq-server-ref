"""Local-only verification of `profile_card_policy` (founder item 22):
who may OPEN my profile card.

Until 2026-08-23 all three clients shipped the setting and the island had no
column for it: `ProfileUpdate` did not declare the key, Pydantic's
`extra="ignore"` dropped it, and the PUT answered 200. The iOS copy had to say
out loud that the switch did nothing.

The point of the test is that the gate holds on EVERY route that serves those
fields, not just on the one the setting is named after. A setting enforced on
`/users/{uin}/info` alone is not enforced at all: `/users/search`, the group
roster, the audio-room roster, the contact list and the UNAUTHENTICATED
`/federation/keys/{uin}` all hand out pieces of the same card.

Pins:
  * the field round-trips through `PUT /users/me`, is validated, and is echoed
    ONLY to its owner (a peer never learns the raw policy, only the verdict);
  * `GET /users/{uin}/info` withholds every card field from a viewer who may
    not open the card, including `last_seen` whose own tri-state says
    "everyone", and publishes `profile_openable`;
  * the IDENTITY FLOOR survives the gate — nickname and both keys are still
    served, because the founder's own copy promises a shut-out person "will
    still be able to write to you", and a 403 would take that away;
  * the AVATAR survives the gate, because it is handed out on the membership
    relationship and the group roster keeps handing it out; the two disagreeing
    about one person is a bug this codebase already fixed once;
  * a group roster stays fully usable (uin, nickname, avatar, both keys) and
    changes exactly one thing: `profile_openable`;
  * a roster built for a BROADCAST carries no verdict at all (null), because
    one payload sent to every member has no single viewer to answer for;
  * `/users/search`, `GET /contacts`, `GET /groups`, `GET /groups/{id}`, the
    `room_roster` WS packet and `/federation/keys/{uin}` all agree with
    `/users/{uin}/info` about the same person;
  * the search text clause cannot be used as an oracle either: a shut-out
    profile stops answering questions about its own first/last name.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_profile_card_policy_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_profile_card.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
for f in ("test_profile_card.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.audio_room import AudioRoom, AudioRoomMembership  # noqa: E402
from app.models.contact import Contact  # noqa: E402
from app.models.group import Group, GroupMember  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers.groups import _members_with_users  # noqa: E402
from app.services.connection_manager import manager  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


# SUBJECT owns the setting. FRIEND is a mutual contact. STRANGER shares a group
# and an audio room with SUBJECT and nothing else, which is exactly the person
# the founder's complaint is about: being in a room is enough to read a card.
SUBJECT, FRIEND, STRANGER = 8301, 8302, 8303

# Every card field the response model can carry, so a new one cannot be added
# without this test noticing it is ungated.
CARD_FIELDS = (
    "first_name", "last_name", "age", "gender", "city", "country",
    "about", "homepage", "status_message", "last_seen",
)


def card_is_empty(body: dict) -> bool:
    return (
        all(body.get(k) is None for k in CARD_FIELDS)
        and not body.get("interests")
    )


def card_is_full(body: dict) -> bool:
    return (
        body.get("first_name") == "Vera"
        and body.get("city") == "Kazan"
        and body.get("about") == "reads at night"
        and body.get("interests") == ["books"]
        and body.get("status_message") == "afk"
    )


def identity_floor_intact(body: dict) -> bool:
    """What a shut-out viewer must still get, or they cannot write to SUBJECT."""
    return (
        body.get("uin") == SUBJECT
        and body.get("nickname") == "vera"
        and bool(body.get("identity_key"))
        and bool(body.get("signing_key"))
        and body.get("status") is not None
    )


async def set_policy(c: httpx.AsyncClient, token: str, value: str) -> httpx.Response:
    return await c.put(
        "/users/me",
        headers={"Authorization": f"Bearer {token}"},
        json={"profile_card_policy": value},
    )


async def main():
    global fails
    await init_db()
    # users_info is 180/min and users_search 60/min per identity, and the
    # buckets live in Redis. Throwaway db, so wipe it or a second run inside
    # the minute measures the rate limiter instead of the gate.
    await (await get_redis()).flushdb()

    async with SessionLocal() as db:
        db.add(User(
            uin=SUBJECT, nickname="vera", identity_key=b64(), signing_key=b64(),
            first_name="Vera", last_name="P", age=31, gender="female",
            city="Kazan", country="RU", about="reads at night",
            interests="books", homepage="https://example.invalid",
            status_message="afk",
            # Deliberately the most permissive neighbours, so anything the card
            # gate hides is hidden BY the card gate and not by something else.
            profile_visibility="everyone",
            gender_visibility="everyone",
            last_seen_visibility="everyone",
            avatar_media_id="blob-vera", avatar_media_key="key-vera",
        ))
        db.add(User(uin=FRIEND, nickname="friend", identity_key=b64(), signing_key=b64()))
        db.add(User(uin=STRANGER, nickname="stranger", identity_key=b64(), signing_key=b64()))
        # Mutual contact edges. `/users/{uin}/info` reads the viewer's own edge,
        # `GET /contacts` reads the owner's, so both directions are needed to
        # exercise both routes.
        db.add(Contact(owner_uin=FRIEND, contact_uin=SUBJECT))
        db.add(Contact(owner_uin=SUBJECT, contact_uin=FRIEND))
        g = Group(name="room 101", owner_uin=STRANGER, avatar_seed=1, share_token="tok")
        db.add(g)
        await db.flush()
        gid = g.id
        for u in (SUBJECT, FRIEND, STRANGER):
            db.add(GroupMember(group_id=gid, uin=u, role="owner" if u == STRANGER else "member"))
        room = AudioRoom(name="voice", owner_uin=STRANGER, join_key="jk")
        db.add(room)
        await db.flush()
        rid = room.id
        for u in (SUBJECT, STRANGER):
            db.add(AudioRoomMembership(room_id=rid, uin=u))
        await db.commit()

    t_subject = issue_token(SUBJECT, 0, "phone")
    t_friend = issue_token(FRIEND, 0, "phone")
    t_stranger = issue_token(STRANGER, 0, "phone")
    H_S = {"Authorization": f"Bearer {t_subject}"}
    H_F = {"Authorization": f"Bearer {t_friend}"}
    H_X = {"Authorization": f"Bearer {t_stranger}"}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:

        print("\nThe field exists and is validated:")
        r = await set_policy(c, t_subject, "contacts")
        check("PUT /users/me accepts profile_card_policy", r.status_code == 200)
        check("  ... and echoes it back to its owner", r.json().get("profile_card_policy") == "contacts")
        async with SessionLocal() as db:
            stored = (await db.get(User, SUBJECT)).profile_card_policy
        check("  ... and it reached the column (not dropped by extra=ignore)", stored == "contacts")
        r = await set_policy(c, t_subject, "friends-of-friends")
        check("a value outside the tri-state is 400, not a silent 200", r.status_code == 400)
        r = await c.put("/users/me", headers=H_S, json={"nickname": "vera"})
        check("an unrelated PUT does not clear it", r.status_code == 200)
        async with SessionLocal() as db:
            check("  ... column still 'contacts'", (await db.get(User, SUBJECT)).profile_card_policy == "contacts")

        print("\n'contacts' — /users/{uin}/info:")
        r = await c.get(f"/users/{SUBJECT}/info", headers=H_X)
        b = r.json()
        check("stranger: profile_openable false", b.get("profile_openable") is False)
        check("  ... every card field withheld", card_is_empty(b))
        check("  ... including last_seen, whose own setting says 'everyone'", b.get("last_seen") is None)
        check("  ... identity floor intact, so they can still write", identity_floor_intact(b))
        check("  ... avatar still served (group co-member, roster agrees)", b.get("avatar_media_id") == "blob-vera")
        check("  ... the raw policy is NOT echoed to a peer", b.get("profile_card_policy") is None)
        r = await c.get(f"/users/{SUBJECT}/info", headers=H_F)
        b = r.json()
        check("contact: profile_openable true", b.get("profile_openable") is True)
        check("  ... and the card is served", card_is_full(b))
        r = await c.get(f"/users/{SUBJECT}/info", headers=H_S)
        b = r.json()
        check("self: always openable", b.get("profile_openable") is True)
        check("  ... own card is served", card_is_full(b))
        check("  ... own policy echoed", b.get("profile_card_policy") == "contacts")

        print("\n'nobody' — /users/{uin}/info:")
        await set_policy(c, t_subject, "nobody")
        r = await c.get(f"/users/{SUBJECT}/info", headers=H_F)
        b = r.json()
        check("even a mutual contact: profile_openable false", b.get("profile_openable") is False)
        check("  ... card empty", card_is_empty(b))
        check("  ... identity floor intact", identity_floor_intact(b))
        check("  ... avatar still served (mutual contact)", b.get("avatar_media_id") == "blob-vera")
        r = await c.get(f"/users/{SUBJECT}/info", headers=H_S)
        check("self still opens their own card", r.json().get("profile_openable") is True and card_is_full(r.json()))

        print("\n'everyone' — /users/{uin}/info:")
        await set_policy(c, t_subject, "everyone")
        r = await c.get(f"/users/{SUBJECT}/info", headers=H_X)
        b = r.json()
        check("stranger: profile_openable true", b.get("profile_openable") is True)
        check("  ... and the card is served", card_is_full(b))

        print("\nBypass 1 — /users/search:")
        r = await c.get("/users/search", params={"q": "vera"}, headers=H_X)
        row = next((x for x in r.json() if x["uin"] == SUBJECT), None)
        check("open card: search row openable, fields present", row is not None and row["profile_openable"] is True and row["first_name"] == "Vera")
        await set_policy(c, t_subject, "contacts")
        r = await c.get("/users/search", params={"q": "vera"}, headers=H_X)
        row = next((x for x in r.json() if x["uin"] == SUBJECT), None)
        check("shut out: the row still surfaces (nickname is identity)", row is not None)
        check("  ... but carries profile_openable false", row["profile_openable"] is False)
        check("  ... and no card fields", card_is_empty(row))
        r = await c.get("/users/search", params={"q": "vera"}, headers=H_F)
        row = next((x for x in r.json() if x["uin"] == SUBJECT), None)
        check("a contact searching gets openable true + the fields", row["profile_openable"] is True and row["first_name"] == "Vera")
        await set_policy(c, t_subject, "nobody")
        r = await c.get("/users/search", params={"q": "Vera P"}, headers=H_X)
        check(
            "search is not an oracle: a shut-out real name matches nothing",
            not any(x["uin"] == SUBJECT for x in r.json()),
        )

        print("\nBypass 2 — GET /contacts:")
        r = await c.get("/contacts", headers=H_F)
        row = next((x for x in r.json() if x["uin"] == SUBJECT), None)
        check("'nobody': the contact row is not a link", row is not None and row["profile_openable"] is False)
        check("  ... but the row is untouched otherwise (it is a list you built)", row["nickname"] == "vera" and row["avatar_media_id"] == "blob-vera")
        await set_policy(c, t_subject, "contacts")
        r = await c.get("/contacts", headers=H_F)
        row = next((x for x in r.json() if x["uin"] == SUBJECT), None)
        check("'contacts': a mutual contact may open it", row["profile_openable"] is True)

        print("\nBypass 3 — the group roster:")
        await set_policy(c, t_subject, "nobody")
        r = await c.get(f"/groups/{gid}", headers=H_X)
        row = next((m for m in r.json()["members"] if m["uin"] == SUBJECT), None)
        check("'nobody': roster row is not a link", row is not None and row["profile_openable"] is False)
        check("  ... nickname still there (a roster of numbers is not a member list)", row["nickname"] == "vera")
        check("  ... avatar still there (membership is the relationship)", row["avatar_media_id"] == "blob-vera")
        check("  ... both keys still there (group ciphertext is sealed per member)", bool(row["identity_key"]) and bool(row["signing_key"]))
        check("  ... and the group is still whole", len(r.json()["members"]) == 3)
        await set_policy(c, t_subject, "contacts")
        r = await c.get(f"/groups/{gid}", headers=H_X)
        row = next((m for m in r.json()["members"] if m["uin"] == SUBJECT), None)
        check("'contacts': a co-member who is NOT a contact is still shut out", row["profile_openable"] is False)
        r = await c.get(f"/groups/{gid}", headers=H_F)
        row = next((m for m in r.json()["members"] if m["uin"] == SUBJECT), None)
        check("  ... a co-member who IS a contact may open it", row["profile_openable"] is True)
        r = await c.get("/groups", headers=H_X)
        row = next((m for m in r.json()[0]["members"] if m["uin"] == SUBJECT), None)
        check("the group LIST agrees with the single-group read", row["profile_openable"] is False)
        r = await c.get(f"/groups/{gid}", headers=H_S)
        row = next((m for m in r.json()["members"] if m["uin"] == SUBJECT), None)
        check("subject sees themselves as openable", row["profile_openable"] is True)

        print("\nA broadcast roster answers for nobody:")
        async with SessionLocal() as db:
            anon = await _members_with_users(db, gid)
            mine = await _members_with_users(db, gid, viewer_uin=STRANGER)
        check("no viewer → profile_openable null on every row", all(m.profile_openable is None for m in anon))
        check("  ... and the rows are otherwise complete", all(m.nickname and m.identity_key for m in anon))
        check("a viewer → a real verdict", next(m for m in mine if m.uin == SUBJECT).profile_openable is False)

        print("\nBypass 4 — the audio-room roster (WS):")
        packets: list[tuple[int, dict]] = []
        real_send = manager.send

        async def capture(target_uin, payload):
            packets.append((target_uin, payload))

        manager.send = capture
        try:
            from app.routers.ws import _handle_client_message
            await _handle_client_message(STRANGER, {"type": "room_enter", "room_id": rid})
            await _handle_client_message(SUBJECT, {"type": "room_enter", "room_id": rid})
            # The roster the SUBJECT's entry sent to the stranger is the one
            # addressed to a single viewer; grab the stranger's own roster.
            rosters = [p for t, p in packets if p.get("type") == "room_roster" and t == STRANGER]
            check("stranger got a room roster", bool(rosters))
            # Re-enter so the stranger's roster contains the subject.
            packets.clear()
            await _handle_client_message(STRANGER, {"type": "room_enter", "room_id": rid})
            roster = next(p for t, p in packets if t == STRANGER and p.get("type") == "room_roster")
            row = next((m for m in roster["members"] if m["uin"] == SUBJECT), None)
            check("'contacts': the room row is not a link for a non-contact", row is not None and row["profile_openable"] is False)
            check("  ... nickname and avatar untouched", row["nickname"] == "vera" and row["avatar_media_id"] == "blob-vera")
            await set_policy(c, t_subject, "everyone")
            packets.clear()
            await _handle_client_message(STRANGER, {"type": "room_enter", "room_id": rid})
            roster = next(p for t, p in packets if t == STRANGER and p.get("type") == "room_roster")
            row = next(m for m in roster["members"] if m["uin"] == SUBJECT)
            check("'everyone': the room row is a link again", row["profile_openable"] is True)
        finally:
            manager.send = real_send

        print("\nBypass 5 — /federation/keys/{uin} (unauthenticated):")
        r = await c.get(f"/federation/keys/{SUBJECT}")
        b = r.json()
        check("'everyone': the open key card carries the optional bits", b["status_message"] == "afk" and b["gender"] == "female")
        check("  ... and says openable", b["profile_openable"] is True)
        await set_policy(c, t_subject, "contacts")
        r = await c.get(f"/federation/keys/{SUBJECT}")
        b = r.json()
        check("'contacts': an anonymous caller has no edge, so the bits are gone", b["status_message"] is None and b["gender"] is None)
        check("  ... says not openable", b["profile_openable"] is False)
        check("  ... but the keys and the nickname still ship (this is a KEY card)", bool(b["identity_key"]) and b["nickname"] == "vera")
        await set_policy(c, t_subject, "nobody")
        r = await c.get(f"/federation/keys/{SUBJECT}")
        b = r.json()
        check("'nobody': same, closed", b["status_message"] is None and b["profile_openable"] is False)

        print("\nThe default is 'everyone' (a fresh account is not silently shut):")
        r = await c.get(f"/users/{STRANGER}/info", headers=H_S)
        check("an account that never touched the setting is openable", r.json().get("profile_openable") is True)
        r = await c.put("/users/me", headers=H_X, json={"nickname": "stranger"})
        check("  ... and its own echo reads 'everyone'", r.json().get("profile_card_policy") == "everyone")

    await close_redis()
    print(f"\n{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
    return fails


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
