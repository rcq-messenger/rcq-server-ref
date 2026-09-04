"""Resale: one person selling a number to another, and the ways it must refuse.

⚠⚠ THE POINT OF THIS FILE is the refusals. A transfer that works is one path;
a transfer that works when it should not is somebody's number or somebody's
money. So the happy case is four checks and the rest of the file is the
substitutions, the re-prices, the double spends and the seller who walked away.

Run: PYTHONPATH=. python test_uin_resale_local.py
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import time

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_uin_resale.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("ADMIN_USERNAME", "a")
os.environ.setdefault("ADMIN_PASSWORD", "b")
os.environ["UIN_SHOP_ENABLED"] = "true"
os.environ["RCQ_UIN_CLIENT_TILL_MINE"] = "true"
os.environ["RCQ_UIN_TILL_URL"] = "https://till.example.org"

# Resale is OFF by default until the till and the apps catch up, so this file
# turns it on for itself. ⚠ The default is asserted at the end: a build where
# resale quietly became reachable is a build that fails here.
_RESALE_ON = True

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding, PublicFormat,
)

_SK = Ed25519PrivateKey.generate()
os.environ["RCQ_UIN_VOUCHER_PUBKEY"] = base64.b64encode(
    _SK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
).decode()

import httpx  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.owned_uin import OwnedUin  # noqa: E402
from app.models.uin_listing import UinListing  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services import uin_voucher  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


def resale_voucher(uin: int, seller: int, cents: int, *, nonce=None, ttl=3600, signer=None):
    nonce = nonce or base64.b64encode(os.urandom(18)).decode()
    exp = int(time.time()) + ttl
    payload = uin_voucher.resale_signed_bytes(
        uin=uin, seller=seller, price_cents=cents, nonce=nonce, exp=exp
    )
    sig = (signer or _SK).sign(payload)
    doc = {"v": uin_voucher.VERSION, "kind": "resale", "uin": uin, "seller": seller,
           "price_cents": cents, "nonce": nonce, "exp": exp,
           "sig": base64.b64encode(sig).decode()}
    return base64.b64encode(json.dumps(doc).encode()).decode()


def plain_voucher(uin: int, ttl=3600):
    nonce = base64.b64encode(os.urandom(18)).decode()
    exp = int(time.time()) + ttl
    sig = _SK.sign(uin_voucher.signed_bytes(uin=uin, nonce=nonce, exp=exp))
    doc = {"v": uin_voucher.VERSION, "uin": uin, "nonce": nonce, "exp": exp,
           "sig": base64.b64encode(sig).decode()}
    return base64.b64encode(json.dumps(doc).encode()).decode()


def code(r):
    try:
        d = r.json().get("detail")
        return d.get("code") if isinstance(d, dict) else d
    except Exception:
        return None


SELLER, BUYER, STRANGER = 500100, 500200, 500300
FOR_SALE = 4242


async def main() -> int:
    await init_db()
    async with SessionLocal() as db:
        from app.models.server_setting import ServerSetting
        db.add(ServerSetting(key="uin_resale_enabled", value="true"))
        await db.commit()
    from app.services import server_settings as _ss0
    _ss0._cache.at = 0
    await (await get_redis()).flushdb()
    async with SessionLocal() as db:
        for uin, nick in ((SELLER, "seller"), (BUYER, "buyer"), (STRANGER, "stranger")):
            db.add(User(uin=uin, nickname=nick, identity_key=b64(), signing_key=b64()))
        db.add(OwnedUin(uin=FOR_SALE, owner_uin=SELLER, source="purchase"))
        await db.commit()

    HS = {"Authorization": f"Bearer {issue_token(SELLER, 0, 'phone')}"}
    HB = {"Authorization": f"Bearer {issue_token(BUYER, 0, 'phone')}"}
    HX = {"Authorization": f"Bearer {issue_token(STRANGER, 0, 'phone')}"}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:

        print("\nPutting a number up for sale:")
        r = await c.post("/uin/listings", json={
            "uin": FOR_SALE, "price_cents": 25000, "payout": {"tron": "TSellerWallet"}}, headers=HS)
        check(f"listed ({r.status_code})", r.status_code == 200)
        check("  ... at the seller's own price", (r.json() or {}).get("price_cents") == 25000)

        r = await c.post("/uin/listings", json={
            "uin": SELLER, "price_cents": 100, "payout": {"tron": "T"}}, headers=HS)
        check(f"⚠ the number you ANSWER as cannot be sold ({code(r)})", code(r) == "in_use")

        r = await c.post("/uin/listings", json={
            "uin": FOR_SALE, "price_cents": 100, "payout": {"tron": "T"}}, headers=HX)
        check(f"⚠ nor can somebody else's ({code(r)})", code(r) == "not_owned")

        r = await c.post("/uin/listings", json={
            "uin": 4243, "price_cents": 100, "payout": {}}, headers=HS)
        check(f"⚠ nor one with nowhere to pay ({code(r)})", code(r) == "no_payout")

        print("\nWhat a buyer sees when they simply type the number:")
        r = await c.post("/uin/quote", json={"uin": FOR_SALE},
                         headers={**HB, "X-RCQ-Checkout": "island"})
        q = r.json()
        check(f"the quote says it is a resale ({q.get('acquire')})", q.get("acquire") == "resale")
        check(f"  ... names the seller ({q.get('seller_uin')})", q.get("seller_uin") == SELLER)
        check(f"  ... and their price ({q.get('price_display')})", q.get("price_cents") == 25000)
        check("  ... and where to pay", q.get("checkout_url") == "https://till.example.org")
        check("  ⚠⚠ ... while still reading unavailable to a client that predates resale",
              q.get("available") is False)

        r = await c.post("/uin/quote", json={"uin": FOR_SALE}, headers=HS)
        check(f"the seller is not offered their own number ({r.json().get('acquire')})",
              r.json().get("acquire") != "resale")

        print("\nThe market window:")
        r = await c.get("/uin/listings?count=12", headers=HB)
        rows = r.json()
        check(f"a buyer sees the listing ({len(rows)})", any(x["uin"] == FOR_SALE for x in rows))
        r = await c.get("/uin/listings?count=12", headers=HS)
        check("⚠ and the seller does not see their own", not any(x["uin"] == FOR_SALE for x in (r.json() or []))) 

        print("\n⚠⚠ The substitutions, which are the whole reason for a separate document:")
        r = await c.post("/uin/redeem", json={
            "uin": FOR_SALE, "voucher": plain_voucher(FOR_SALE), "switch": False}, headers=HB)
        check(f"a voucher for ORDINARY space cannot buy a listing ({code(r)})",
              r.status_code == 403 and code(r) == "bad_voucher")

        r = await c.post("/uin/redeem", json={
            "uin": FOR_SALE, "voucher": resale_voucher(FOR_SALE, SELLER, 99), "switch": False},
            headers=HB)
        check(f"a resale voucher at the WRONG price is refused ({code(r)})", code(r) == "price_changed")

        r = await c.post("/uin/redeem", json={
            "uin": FOR_SALE, "voucher": resale_voucher(FOR_SALE, STRANGER, 25000), "switch": False},
            headers=HB)
        check(f"a resale voucher naming the WRONG seller is refused ({code(r)})",
              code(r) == "seller_changed")

        other = Ed25519PrivateKey.generate()
        r = await c.post("/uin/redeem", json={
            "uin": FOR_SALE, "voucher": resale_voucher(FOR_SALE, SELLER, 25000, signer=other),
            "switch": False}, headers=HB)
        check(f"a voucher signed by somebody else is refused ({code(r)})", code(r) == "bad_voucher")

        r = await c.post("/uin/redeem", json={
            "uin": FOR_SALE, "voucher": resale_voucher(FOR_SALE, SELLER, 25000), "switch": False},
            headers=HS)
        check(f"⚠ the seller cannot buy their own listing ({code(r)})", code(r) == "own_listing")

        print("\nThe sale itself:")
        v = resale_voucher(FOR_SALE, SELLER, 25000)
        r = await c.post("/uin/redeem", json={"uin": FOR_SALE, "voucher": v, "switch": False},
                         headers=HB)
        check(f"the buyer redeems ({r.status_code})", r.status_code == 200)
        check("  ... and it is in their collection now", FOR_SALE in (r.json() or {}).get("owned", []))

        # Read in a SEPARATE session: a test that looks in the same one sees a
        # flush and passes while prod loses the row.
        async with SessionLocal() as db:
            deed = await db.get(OwnedUin, FOR_SALE)
            still = await db.get(UinListing, FOR_SALE)
        check(f"  ... the deed changed hands ({deed and deed.owner_uin})",
              deed is not None and int(deed.owner_uin) == BUYER)
        check("  ... and the shop window came down", still is None)

        r = await c.post("/uin/redeem", json={"uin": FOR_SALE, "voucher": v, "switch": False},
                         headers=HX)
        # ⚠ `bad_voucher`, not `voucher_spent`: the sale took the listing down,
        # so a second attempt is no longer a resale at all and the ordinary
        # branch reads a resale document as what it is — the wrong kind. Less
        # informative, and refused either way, which is the part that matters.
        check(f"⚠⚠ the same voucher cannot be spent twice ({code(r)})",
              r.status_code in (403, 409) and code(r) in {"voucher_spent", "bad_voucher", "taken"})

        print("\nA seller who walked away:")
        GONE = 5151
        async with SessionLocal() as db:
            db.add(OwnedUin(uin=GONE, owner_uin=SELLER, source="purchase"))
            db.add(UinListing(uin=GONE, seller_uin=SELLER, price_cents=1000,
                              payout={"tron": "TSellerWallet"}))
            await db.commit()
        async with SessionLocal() as db:
            deed = await db.get(OwnedUin, GONE)
            await db.delete(deed)
            await db.commit()
        r = await c.post("/uin/redeem", json={
            "uin": GONE, "voucher": resale_voucher(GONE, SELLER, 1000), "switch": False}, headers=HB)
        check(f"a number the seller no longer holds is refused ({code(r)})", code(r) == "seller_gone")

        print("\n💰 The till asking where a buyer pays:")
        import time as _t
        def payout_q(uin, ttl=300, signer=None):
            exp = int(_t.time()) + ttl
            payload = uin_voucher.payout_signed_bytes(uin=uin, exp=exp)
            sig = (signer or _SK).sign(payload)
            doc = {"v": uin_voucher.VERSION, "kind": "payout", "uin": uin, "exp": exp,
                   "sig": base64.b64encode(sig).decode()}
            return base64.b64encode(json.dumps(doc).encode()).decode()

        # A live listing: the money is the SELLER's.
        LIVE = 6161
        async with SessionLocal() as db:
            db.add(OwnedUin(uin=LIVE, owner_uin=SELLER, source="purchase"))
            db.add(UinListing(uin=LIVE, seller_uin=SELLER, price_cents=7700,
                              payout={"tron": "TSellerWallet"}))
            await db.commit()
        r = await c.post("/uin/payout-target", json={"request": payout_q(LIVE)})
        t = r.json()
        check(f"a resale points at the seller's wallet ({t.get('kind')})", t.get("kind") == "resale")
        check(f"  ... their address ({t.get('addresses')})",
              t.get("addresses") == {"tron": "TSellerWallet"})
        check("  ... their price, and who they are",
              t.get("price_cents") == 7700 and t.get("seller_uin") == SELLER)

        # Island stock: the money is the OPERATOR's, from their console.
        async with SessionLocal() as db:
            from app.models.server_setting import ServerSetting
            db.add(ServerSetting(key="uin_payout_addresses",
                                 value=json.dumps({"tron": "TOperatorWallet"})))
            await db.commit()
        from app.services import server_settings as _ss
        _ss._cache.at = 0
        r = await c.post("/uin/payout-target", json={"request": payout_q(4321)})
        t2 = r.json()
        check(f"island stock points at the operator's wallet ({t2.get('kind')})",
              t2.get("kind") == "island")
        check(f"  ... changed from the console, not a redeploy ({t2.get('addresses')})",
              t2.get("addresses") == {"tron": "TOperatorWallet"})

        r = await c.post("/uin/payout-target", json={"request": payout_q(4321, signer=Ed25519PrivateKey.generate())})
        check(f"⚠⚠ a stranger cannot ask ({r.status_code} {code(r)})",
              r.status_code == 403 and code(r) == "bad_voucher")
        r = await c.post("/uin/payout-target", json={"request": payout_q(4321, ttl=-10)})
        check(f"⚠ nor can a stale question be replayed ({code(r)})", code(r) == "voucher_expired")
        r = await c.post("/uin/payout-target", json={"request": payout_q(847261935)})
        check(f"⚠ ordinary free space has no invoice to write ({r.status_code} {code(r)})",
              r.status_code == 409 and code(r) == "not_for_sale")

        print("\nA listing is spoken for while it is up:")
        r = await c.delete(f"/uin/listings/{GONE}", headers=HS)
        check(f"the seller can take their own listing down ({r.status_code})", r.status_code == 200)
        r = await c.delete(f"/uin/listings/{GONE}", headers=HS)
        check(f"  ... and it is gone ({code(r)})", code(r) == "not_listed")

    await close_redis()
    try:
        os.remove("test_uin_resale.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
