"""Room signalling on the wire: the field names, and the roster payload.

Why this exists: the web client shipped 14.08 addressed its peer as `to` and
read the sender as `from`, while the island reads `to_uin` and answers with
`from_uin`. Every offer, answer and ICE candidate was dropped by the relay
without a word, so a web participant entered the room, saw the roster, and
could neither hear nor be heard. Nothing failed loudly, which is exactly why
it needs a test on the wire rather than a reading of the client.

Run against a local island:
    DATABASE_URL="sqlite+aiosqlite:///./test_rooms.db" \
        .venv/bin/uvicorn app.main:app --port 8099
    .venv/bin/python test_room_signalling_local.py
"""

import asyncio
import base64
import json
import os
import secrets
import sys

import httpx
import websockets

BASE = os.environ.get("ISLAND", "http://127.0.0.1:8099")
WS_BASE = BASE.replace("http://", "ws://").replace("https://", "wss://")

ok = 0
bad = 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global ok, bad
    if cond:
        ok += 1
        print(f"  ok   {label}")
    else:
        bad += 1
        print(f"  FAIL {label} {detail}")


async def register(client: httpx.AsyncClient, nick: str) -> dict:
    body = {
        "nickname": nick,
        "identity_key": base64.b64encode(secrets.token_bytes(32)).decode(),
        "signing_key": base64.b64encode(secrets.token_bytes(32)).decode(),
        "device_id": secrets.token_hex(16),
    }
    r = await client.post(f"{BASE}/auth/register", json=body)
    r.raise_for_status()
    return r.json()


async def recv_until(ws, kind: str, timeout: float = 3.0) -> dict | None:
    """Next frame of this type, ignoring the presence chatter in between."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=deadline - loop.time())
        except asyncio.TimeoutError:
            return None
        msg = json.loads(raw)
        if msg.get("type") == kind:
            return msg
    return None


async def main() -> int:
    async with httpx.AsyncClient(timeout=10) as client:
        alice = await register(client, "alice-rooms")
        boris = await register(client, "boris-rooms")

        a_hdr = {"Authorization": f"Bearer {alice['token']}"}
        b_hdr = {"Authorization": f"Bearer {boris['token']}"}

        r = await client.post(f"{BASE}/audio_rooms", json={"name": "wire"}, headers=a_hdr)
        r.raise_for_status()
        room = r.json()
        room_id = room["id"]

        r = await client.post(
            f"{BASE}/audio_rooms/join", json={"join_key": room["join_key"]}, headers=b_hdr
        )
        check("boris joins by key", r.status_code == 200, str(r.status_code))

        # Avatars are what item 5 needs on the roster; set one for boris so the
        # roster has something to carry.
        r = await client.put(
            f"{BASE}/users/me",
            json={"avatar_media_id": "a" * 32, "avatar_media_key": "k" * 44},
            headers=b_hdr,
        )
        check("avatar set on profile", r.status_code in (200, 204), str(r.status_code))

        a_ws = await websockets.connect(f"{WS_BASE}/ws/{alice['uin']}?token={alice['token']}")
        b_ws = await websockets.connect(f"{WS_BASE}/ws/{boris['uin']}?token={boris['token']}")

        await a_ws.send(json.dumps({"type": "room_enter", "room_id": room_id}))
        roster_a = await recv_until(a_ws, "room_roster")
        check("alice gets a roster", roster_a is not None)

        await b_ws.send(json.dumps({"type": "room_enter", "room_id": room_id}))
        roster_b = await recv_until(b_ws, "room_roster")
        check("boris gets a roster", roster_b is not None)

        entered = await recv_until(a_ws, "room_member_entered")
        check("alice is told boris walked in", entered is not None)

        # --- item 5: the roster carries pictures ---------------------------
        boris_row = None
        for m in (roster_b or {}).get("members", []):
            if m.get("uin") == boris["uin"]:
                boris_row = m
        check("roster row has avatar_media_id", bool(boris_row and boris_row.get("avatar_media_id")))
        check("roster row has avatar_media_key", bool(boris_row and boris_row.get("avatar_media_key")))
        member = (entered or {}).get("member", {})
        check(
            "room_member_entered carries the avatar too",
            bool(member.get("avatar_media_id")) and bool(member.get("avatar_media_key")),
            json.dumps(member),
        )

        # --- the wire: to_uin / from_uin ------------------------------------
        await a_ws.send(json.dumps({
            "type": "room_offer",
            "room_id": room_id,
            "to_uin": boris["uin"],
            "sdp": "v=0-fake-offer",
        }))
        offer = await recv_until(b_ws, "room_offer")
        check("offer addressed with to_uin arrives", offer is not None)
        check(
            "and it names the sender as from_uin",
            bool(offer) and offer.get("from_uin") == alice["uin"],
            json.dumps(offer or {}),
        )
        check("sdp survives the relay", bool(offer) and offer.get("sdp") == "v=0-fake-offer")

        # The old spelling, the one that shipped: it must NOT arrive. This is
        # the regression itself, kept as a test so it cannot come back quietly.
        await a_ws.send(json.dumps({
            "type": "room_offer",
            "room_id": room_id,
            "to": boris["uin"],
            "sdp": "v=0-wrong-key",
        }))
        stray = await recv_until(b_ws, "room_offer", timeout=1.5)
        check("offer addressed with the old `to` is dropped", stray is None, json.dumps(stray or {}))

        # --- speaking -------------------------------------------------------
        await b_ws.send(json.dumps({"type": "room_speaking", "room_id": room_id, "speaking": True}))
        spk = await recv_until(a_ws, "room_speaking")
        check("room_speaking reaches the other side", spk is not None)
        check(
            "speaking frame identifies the talker by uin",
            bool(spk) and spk.get("uin") == boris["uin"] and spk.get("speaking") is True,
            json.dumps(spk or {}),
        )

        # --- deletion is `audio_room_deleted` -------------------------------
        r = await client.delete(f"{BASE}/audio_rooms/{room_id}", headers=a_hdr)
        check("owner deletes the room", r.status_code in (200, 204), str(r.status_code))
        gone = await recv_until(b_ws, "audio_room_deleted")
        check("the island announces audio_room_deleted", gone is not None)

        await a_ws.close()
        await b_ws.close()

    print(f"\n{ok} ok, {bad} failed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
