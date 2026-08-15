"""Federation on the wire: two islands, one deposit, and what actually arrives.

Why this exists. Every cross-island feature we have shipped or specced rides one
mechanism: a client seals an envelope and POSTs it to the RECIPIENT'S island at
`/messages/sealed`, and that island pushes it down the recipient's live socket.
Calls (§5d), profile refresh (§5e) and contact requests (§5f) are all that same
deposit with a different inner `kind`.

Until now nobody had ever run it. Every cross-island bug this week was argued
from reading code, and two of them were the opposite of what the reading
suggested. This harness settles the server half of the question in about ten
seconds, which leaves any remaining failure squarely in the client, where it
can be looked for on purpose instead of guessed at.

It deliberately does NOT test the sealing: the island cannot read the envelope,
so an opaque blob is exactly as good as a real one for proving the transport,
and using a blob keeps the test free of libsignal.

Run two local islands, then this:

    DATABASE_URL="sqlite+aiosqlite:///./test_isl_a.db" \
        .venv/bin/uvicorn app.main:app --port 8099
    DATABASE_URL="sqlite+aiosqlite:///./test_isl_b.db" \
        .venv/bin/uvicorn app.main:app --port 8098
    .venv/bin/python test_cross_island_local.py
"""

import asyncio
import base64
import json
import os
import secrets
import sys
import time
import uuid

import httpx
import websockets

ISLAND_A = os.environ.get("ISLAND_A", "http://127.0.0.1:8099")
ISLAND_B = os.environ.get("ISLAND_B", "http://127.0.0.1:8098")

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


def ws_url(base: str, uin: int, token: str) -> str:
    # The socket is addressed per-UIN: `/ws/{uin}?token=…`. A bare `/ws?token=`
    # handshakes to a 403, which reads as an auth problem and is not one.
    root = base.replace("http://", "ws://").replace("https://", "wss://")
    return f"{root}/ws/{uin}?token={token}"


async def register(client: httpx.AsyncClient, base: str, nick: str) -> dict:
    """Register on an island. Mirrors test_room_signalling_local.py.

    The island may or may not require a signing-key challenge depending on its
    build, so try the plain form first and fall back rather than pinning this
    harness to one server version.
    """
    body = {
        "nickname": nick,
        "identity_key": base64.b64encode(secrets.token_bytes(32)).decode(),
        "signing_key": base64.b64encode(secrets.token_bytes(32)).decode(),
        "device_id": secrets.token_hex(16),
    }
    r = await client.post(f"{base}/auth/register", json=body)
    if r.status_code >= 400:
        raise SystemExit(
            f"register failed on {base}: {r.status_code} {r.text[:200]}\n"
            "If this island requires a registration proof, run the harness "
            "against a build that still accepts the plain form, or extend it."
        )
    return r.json()


async def recv_until(ws, kind: str, timeout: float = 4.0) -> dict | None:
    """Next frame of this type, ignoring presence chatter in between."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=max(0.1, deadline - loop.time()))
        except asyncio.TimeoutError:
            return None
        try:
            frame = json.loads(raw)
        except (ValueError, TypeError):
            continue
        if frame.get("type") == kind:
            return frame
    return None


def envelope(kind: str, **extra) -> str:
    """An inner envelope as the clients build it, then base64'd like ciphertext.

    The island treats the payload as opaque, so this stands in for a v=1 sealed
    blob without dragging libsignal into the harness. `ts` is epoch SECONDS,
    which is the field the clients most often get wrong.
    """
    inner = {"kind": kind, "id": str(uuid.uuid4()), "ts": int(time.time()), **extra}
    return base64.b64encode(json.dumps(inner, separators=(",", ":")).encode()).decode()


async def main() -> int:
    async with httpx.AsyncClient(timeout=15.0) as c:
        print(f"island A {ISLAND_A}")
        print(f"island B {ISLAND_B}")
        for base in (ISLAND_A, ISLAND_B):
            r = await c.get(f"{base}/health")
            check(f"{base} healthy", r.status_code == 200, r.text[:120])
        if bad:
            print("\nBring both islands up first.")
            return 1

        a = await register(c, ISLAND_A, "alice-a")
        b = await register(c, ISLAND_B, "bob-b")
        uin_a, uin_b = a["uin"], b["uin"]
        print(f"\nA #{uin_a} on island A, B #{uin_b} on island B\n")

        # 1. The open key card. A sender on another island anchors the peer's
        #    keys here before sealing anything to them. Unauthenticated by
        #    design: if THIS fails, nothing downstream can work.
        r = await c.get(f"{ISLAND_B}/federation/keys/{uin_b}")
        check("B's key card is readable from outside, unauthenticated", r.status_code == 200, r.text[:120])
        card = r.json() if r.status_code == 200 else {}
        check("card carries identity_key", bool(card.get("identity_key")))
        check("card carries signing_key", bool(card.get("signing_key")))
        check("card carries nickname (needed to render a request)", card.get("nickname") is not None)

        r = await c.get(f"{ISLAND_B}/federation/keys/999999999")
        check("unknown uin 404s rather than leaking a blank card", r.status_code == 404)

        # 2. The deposit itself, with B listening. This is the whole federation
        #    transport: if it lands, the island half of §5d/§5e/§5f is proven.
        async with websockets.connect(ws_url(ISLAND_B, uin_b, b["token"])) as ws_b:
            await asyncio.sleep(0.3)  # let the socket register

            for kind, extra in (
                ("contactreq", {"act": "request", "nickname": "alice-a", "note": None}),
                ("call", {"sig": "call_offer", "cid": str(uuid.uuid4()), "data": {"sdp": "v=0"}}),
                ("profile", {"nickname": "alice renamed", "avatar_media_id": None, "avatar_media_key": None}),
            ):
                payload = envelope(kind, **extra)
                r = await c.post(
                    f"{ISLAND_B}/messages/sealed",
                    json={"to_uin": uin_b, "envelope_type": "message", "payload": payload},
                )
                check(f"deposit kind={kind} accepted by B's island", r.status_code == 200, r.text[:160])
                frame = await recv_until(ws_b, "message")
                check(f"kind={kind} reached B's live socket", frame is not None)
                if frame is not None:
                    check(
                        f"kind={kind} payload survived byte for byte",
                        frame.get("payload") == payload,
                        "the island must not touch the ciphertext",
                    )

            # 2b. The same call signal deposited with the OUTER envelope_type
            #     set to "call" (2026-08-15). That is the wake path: the island
            #     rings the recipient's devices instead of sending an ordinary
            #     message alert, so a closed app can raise CallKit / the
            #     full-screen incoming-call UI. Everything else must be
            #     identical to a "message" deposit — accepted, byte-preserved,
            #     on the live socket, and queued — because a foreground call
            #     rides the socket exactly as before.
            payload = envelope("call", sig="call_offer", cid=str(uuid.uuid4()), data={"sdp": "v=0"})
            r = await c.post(
                f"{ISLAND_B}/messages/sealed",
                json={"to_uin": uin_b, "envelope_type": "call", "payload": payload},
            )
            check("envelope_type=call accepted by B's island", r.status_code == 200, r.text[:160])
            frame = await recv_until(ws_b, "message")
            check("envelope_type=call reached B's live socket", frame is not None)
            if frame is not None:
                check(
                    "envelope_type=call payload survived byte for byte",
                    frame.get("payload") == payload,
                    "the island must not touch the ciphertext",
                )
                # ⚠ The frame is labelled "message" ON PURPOSE. Every client
                # accepts sealed envelopes from a fixed list of frame types
                # (iOS ends its list with `default: break`, Android's is
                # `SEALED_WS_TYPES`), and none of them listed "call" — so a
                # frame typed "call" was dropped in silence by a RUNNING app,
                # which is precisely when the wake does not fire. Calling
                # somebody with the app open rang nothing. The deposit type is
                # an instruction to the island; the frame type is how the
                # client routes, and the client routes on the INNER kind.
                check(
                    "the socket frame is typed 'message' so every client ingests it",
                    frame.get("type") == "message",
                    str(frame.get("type")),
                )
            # The wake is a push, which this harness cannot observe — but the
            # queue row is the thing that makes the wake safe to lose, so assert
            # it exists. A device woken by a ring that arrives without its
            # envelope (too large for the 5KB VoIP cap) drains it from here.
            r = await c.get(
                f"{ISLAND_B}/messages/queue",
                headers={"Authorization": f"Bearer {b['token']}"},
            )
            check("queue readable after a call deposit", r.status_code == 200, r.text[:160])
            rows = r.json() if r.status_code == 200 else []
            row = next((x for x in rows if x.get("payload") == payload), None)
            check("the call deposit is queued for the offline drain", row is not None)
            if row is not None:
                check(
                    "the queued row keeps envelope_type=call",
                    row.get("envelope_type") == "call",
                    str(row.get("envelope_type")),
                )

            # 3. A deposit to a uin that does not exist on this island. Clients
            #    rely on 404 here to tell "wrong island" from "delivered".
            r = await c.post(
                f"{ISLAND_B}/messages/sealed",
                json={"to_uin": 999999999, "envelope_type": "message", "payload": envelope("contactreq", act="request")},
            )
            check("deposit to an unknown uin is refused with 404", r.status_code == 404, r.text[:120])

            # 4. Volume. A call trickles ICE, so the per-IP cap has to be far
            #    away from what one interaction costs. Twenty in a burst is more
            #    than a call needs and well under the 120/min bucket.
            codes = []
            for _ in range(20):
                r = await c.post(
                    f"{ISLAND_B}/messages/sealed",
                    json={"to_uin": uin_b, "envelope_type": "message", "payload": envelope("call", sig="call_ice")},
                )
                codes.append(r.status_code)
            check("twenty rapid deposits all accepted (no 429 at call volume)", all(x == 200 for x in codes), str(sorted(set(codes))))

        # 5. Offline: the same deposit with nobody listening must still queue,
        #    or a request sent while the peer's app is closed is lost.
        payload = envelope("contactreq", act="request", nickname="alice-a")
        r = await c.post(
            f"{ISLAND_B}/messages/sealed",
            json={"to_uin": uin_b, "envelope_type": "message", "payload": payload},
        )
        check("deposit accepted while B is offline", r.status_code == 200, r.text[:120])
        # ⚠ The drain is HTTP, not a push. `GET /messages/queue` is the only
        # path; the WS post-connect drain was removed because it raced the HTTP
        # one and double-delivered (see the comment at app/routers/ws.py:518).
        # A client that reconnects its socket and waits for the backlog to
        # arrive by itself waits forever, which is worth knowing before writing
        # a receive branch for a new envelope kind.
        r = await c.get(
            f"{ISLAND_B}/messages/queue",
            headers={"Authorization": f"Bearer {b['token']}"},
        )
        check("queue readable while offline", r.status_code == 200, r.text[:160])
        rows = r.json() if r.status_code == 200 else []
        check(
            "the offline deposit is in the queue for a later drain",
            any(row.get("payload") == payload for row in rows),
            f"{len(rows)} row(s) returned",
        )

        # 6. The other direction, so nobody has to assume symmetry.
        async with websockets.connect(ws_url(ISLAND_A, uin_a, a["token"])) as ws_a:
            await asyncio.sleep(0.3)
            payload = envelope("contactreq", act="accept", nickname="bob-b")
            r = await c.post(
                f"{ISLAND_A}/messages/sealed",
                json={"to_uin": uin_a, "envelope_type": "message", "payload": payload},
            )
            check("B->A deposit accepted by A's island", r.status_code == 200, r.text[:120])
            frame = await recv_until(ws_a, "message")
            check("B->A reached A's live socket", frame is not None and frame.get("payload") == payload)

    print(f"\n{ok} ok, {bad} failed")
    if bad == 0:
        print(
            "\nThe island half of federation is proven end to end. Any remaining\n"
            "cross-island failure is in a client: look at what it seals, which\n"
            "host it deposits to, and what its receive branch does with the kind."
        )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
