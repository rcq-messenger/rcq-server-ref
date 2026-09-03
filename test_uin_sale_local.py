"""Local-only verification of selling a number for money the island never sees.

The shape (founder, 2026-09-03): a free number is a LOAN and goes back to the
pool when you step off it; a bought number is PROPERTY and waits in your
collection until you sell or release it; up to ten of them plus the one you
answer as; paid once, no rent.

The island's whole share of a sale is a signature. A till outside it watches
the founder's own wallets and, when a transfer lands, signs a voucher naming
the number. The island checks the signature, checks the number is still free,
spends the nonce once, and writes one row. No amount, no chain, no address, no
invoice, no buyer.

Checks:
  * a voucher the till signed grants the number INTO THE COLLECTION without
    moving the account, which is the branch that was closed on 01-09;
  * ⚠ the same voucher twice is refused - the nonce is a primary key, not a
    SELECT-then-INSERT;
  * a voucher for another number, an expired one, and a forged one are refused;
  * ⚠⚠ moving onto a bought number and then off it KEEPS it: this is the rule
    the old code broke, where "new number" silently took back what somebody had
    paid for;
  * the free number an account was lent goes back to the pool when it moves off;
  * a hold keeps a number off the shelf while somebody pays, and an expired hold
    does not;
  * the collection is capped, and never lists the number you answer as.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_uin_sale_local.py
"""
import asyncio
import base64
import json
import os
import time
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_uin_sale.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "adminpw")
os.environ["UIN_SHOP_ENABLED"] = "true"
import tempfile  # noqa: E402
SITES_TMP = tempfile.mkdtemp(prefix="rcq-sites-sale-")
os.environ["RCQ_SITES_DIR"] = SITES_TMP

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    PublicFormat,
)

# The till's key pair. Only the public half ever reaches the island, exactly as
# in production, where the private half lives in the worker's secrets.
TILL = Ed25519PrivateKey.generate()
os.environ["RCQ_UIN_VOUCHER_PUBKEY"] = base64.b64encode(
    TILL.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
).decode()

for f in ("test_uin_sale.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import shutil  # noqa: E402

import httpx  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.owned_uin import OwnedUin  # noqa: E402
from app.models.uin_sale import UinHold  # noqa: E402
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


def voucher(uin: int, *, nonce: str | None = None, ttl: int = 3600, signer=None) -> str:
    """What the till hands the buyer once the money has landed."""
    nonce = nonce or base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip("=")
    exp = int(time.time()) + ttl
    body = uin_voucher.signed_bytes(uin=uin, nonce=nonce, exp=exp)
    sig = (signer or TILL).sign(body)
    doc = {
        "v": uin_voucher.VERSION, "uin": uin, "nonce": nonce, "exp": exp,
        "sig": base64.b64encode(sig).decode(),
    }
    return base64.b64encode(json.dumps(doc).encode()).decode()


ALICE = 700400001
ADMIN = ("admin", "adminpw")


def code(r):
    try:
        return (r.json().get("detail") or {}).get("code")
    except Exception:  # noqa: BLE001
        return None


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()
    async with SessionLocal() as db:
        db.add(User(uin=ALICE, nickname="alice", identity_key=b64(), signing_key=b64()))
        await db.commit()
    t_alice = issue_token(ALICE, 0, "phone")
    H = {"Authorization": f"Bearer {t_alice}"}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:

        print("\nBuying a short number, which is scarce stock nothing else can hand out:")
        r = await c.post("/uin/redeem", json={"uin": 4242, "voucher": voucher(4242)}, headers=H)
        check(f"redeemed into the collection ({r.status_code})", r.status_code == 200)
        body = r.json() if r.status_code == 200 else {}
        check("  the account did NOT move onto it", body.get("switched") is False)
        check("  and it is in the collection", body.get("owned") == [4242])

        print("\nThe same voucher again:")
        again = voucher(4242)
        r = await c.post("/uin/redeem", json={"uin": 4242, "voucher": again}, headers=H)
        check(f"a fresh voucher for a number now taken is refused ({r.status_code} {code(r)})",
              r.status_code == 409 and code(r) == "taken")
        v = voucher(777, nonce="replay-me-please-1234")
        r = await c.post("/uin/redeem", json={"uin": 777, "voucher": v}, headers=H)
        check(f"a second number redeems ({r.status_code})", r.status_code == 200)
        r = await c.post("/uin/redeem", json={"uin": 777, "voucher": v}, headers=H)
        check(f"⚠ replaying that exact voucher is refused ({r.status_code} {code(r)})",
              r.status_code == 409 and code(r) in ("voucher_spent", "taken"))

        print("\nVouchers that are not for this:")
        r = await c.post("/uin/redeem", json={"uin": 555, "voucher": voucher(556)}, headers=H)
        check(f"one signed for another number ({r.status_code} {code(r)})",
              r.status_code == 403 and code(r) == "voucher_other_uin")
        r = await c.post("/uin/redeem", json={"uin": 558, "voucher": voucher(558, ttl=-10)}, headers=H)
        check(f"an expired one ({r.status_code} {code(r)})",
              r.status_code == 403 and code(r) == "voucher_expired")
        forged = Ed25519PrivateKey.generate()
        r = await c.post("/uin/redeem", json={"uin": 559, "voucher": voucher(559, signer=forged)},
                         headers=H)
        check(f"one signed by somebody else ({r.status_code} {code(r)})",
              r.status_code == 403 and code(r) == "bad_voucher")

        print("\n⚠⚠ Moving onto a bought number and then off it:")
        r = await c.post("/uin/activate", json={"uin": 4242}, headers=H)
        check(f"activated ({r.status_code})", r.status_code == 200)
        moved = r.json() if r.status_code == 200 else {}
        check("  the account answers as 4242 now", moved.get("new_uin") == 4242)
        check("  and the collection no longer lists the number in use",
              4242 not in (moved.get("owned") or []))
        check(f"  ... but 777, also bought, is still there ({moved.get('owned')})",
              777 in (moved.get("owned") or []))
        async with SessionLocal() as db:
            deed = await db.get(OwnedUin, 4242)
            check("  the deed to 4242 SURVIVED being used", deed is not None)
            check("    ... and points at the account's new number",
                  deed is not None and int(deed.owner_uin) == 4242)
            lent = await db.get(User, ALICE)
            check("  the free number the network lent went back to the pool",
                  lent is None and await db.get(OwnedUin, ALICE) is None)

        # ⚠ The token from the RESPONSE, not a hand-rolled one: a migration bumps
        # the number's epoch and every token minted for the previous holder dies
        # with it, which is the point of the epoch.
        H2 = {"Authorization": f"Bearer {moved.get('token')}"}
        r = await c.post("/uin/activate", json={"uin": 777}, headers=H2)
        check(f"moving on to 777 ({r.status_code})", r.status_code == 200)
        back = r.json() if r.status_code == 200 else {}
        check("  ⚠⚠ 4242 came BACK into the collection, not into the pool",
              4242 in (back.get("owned") or []))

        print("\nA hold keeps a number off the shelf while somebody pays:")
        r = await c.post("/admin/uin/hold", json={"uin": 7654321, "hold_id": "inv-abc123"}, auth=ADMIN)
        check(f"held ({r.status_code})", r.status_code == 200)
        H3 = {"Authorization": f"Bearer {back.get('token')}"}
        q = await c.post("/uin/quote", json={"uin": 7654321}, headers=H3)
        check("  the shop no longer offers it",
              q.status_code == 200 and q.json().get("available") is False)
        r = await c.post("/admin/uin/hold", json={"uin": 7654321, "hold_id": "inv-other-9"}, auth=ADMIN)
        check(f"  a second hold on it is refused ({r.status_code} {code(r)})",
              r.status_code == 409 and code(r) == "taken")
        async with SessionLocal() as db:
            hold = await db.get(UinHold, 7654321)
            hold.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            await db.commit()
        q = await c.post("/uin/quote", json={"uin": 7654321}, headers=H3)
        check("  an EXPIRED hold holds nothing",
              q.status_code == 200 and q.json().get("available") is True)
        r = await c.delete("/admin/uin/hold/7654321", auth=ADMIN)
        check(f"releasing a hold is idempotent ({r.status_code})", r.status_code == 200)

        print("\n⚠⚠ A site belongs to the person, unless its name is the number:")
        # One site per account, so the two rules need two accounts.
        async def publish(headers, name, version=1):
            return await c.put(
                f"/sites/{name}",
                data={"manifest": json.dumps({"version": version}), "owner_key": f"k-{name}",
                      "title": f"{name} page", "listed": "true"},
                files=[("files", ("index.html", b"<h1>hi</h1>", "text/html"))],
                headers=headers,
            )

        H4 = {"Authorization": f"Bearer {back.get('token')}"}   # answering as 777
        r = await publish(H4, "weather")
        check(f"an ordinary page is published ({r.status_code})", r.status_code == 200)

        digits, digits_tok = 700400777, None
        async with SessionLocal() as db:
            db.add(User(uin=digits, nickname="dg", identity_key=b64(), signing_key=b64()))
            await db.commit()
        digits_tok = issue_token(digits, 0, "phone")
        HD = {"Authorization": f"Bearer {digits_tok}"}
        r = await publish(HD, str(digits))
        check(f"a page named after its owner's number is published ({r.status_code})",
              r.status_code == 200)

        r = await c.post("/uin/activate", json={"uin": 4242}, headers=H4)
        check(f"the ordinary owner moves to 4242 ({r.status_code})", r.status_code == 200)
        H5 = {"Authorization": f"Bearer {r.json().get('token')}"}
        r = await c.post("/uin/redeem", json={"uin": 8642, "voucher": voucher(8642), "switch": True},
                         headers=HD)
        check(f"the other owner moves off their digit number ({r.status_code})",
              r.status_code == 200)

        names = {row["name"] for row in (await c.get("/sites")).json()}
        check("  the ordinary page followed the person", "weather" in names)
        check("  ⚠ the page NAMED after the old number is gone", str(digits) not in names)
        r = await publish(H5, "weather", version=2)
        check(f"  ... and the owner still updates theirs from the new number ({r.status_code})",
              r.status_code == 200)

        print("\nThe collection is capped:")
        H3 = H5
        got = 0
        for n in range(500001, 500020):
            r = await c.post("/uin/redeem", json={"uin": n, "voucher": voucher(n)}, headers=H3)
            if r.status_code == 200:
                got += 1
                continue
            check(f"stopped at {got + 1} held ({r.status_code} {code(r)})",
                  r.status_code == 409 and code(r) == "collection_full")
            break
        check(f"  the cap is ten plus the one in use (held {got + 1})", got + 1 == 10)

    await close_redis()
    shutil.rmtree(SITES_TMP, ignore_errors=True)
    try:
        os.remove("test_uin_sale.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
