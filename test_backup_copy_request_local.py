"""Local-only verification of #1054: a contact request to a BACKUP copy.

Multihoming (federation §5a) puts a person's existing keys on a second island
as an ordinary account. Nothing reads contact requests there, so a request to
that number hung at "pending" forever. The island now tells the copy apart by
the owner's own signed home-island record and:

  * refuses `POST /contacts/request` to a copy with 403 `backup_copy`, naming
    the home (`home_host`, `home_uin`), and writes no request row;
  * leaves every account it cannot prove to be a copy alone: a native, a
    native with a backup elsewhere, a record under another key, a tampered
    signature, a record that does not name this island, a "primary" on this
    island under another number;
  * reads this island's names from the Host header and the CDN fronts, with
    the port and case normalised;
  * drops copies from name search, keeps an exact-number hit and marks it
    with `home`, and marks `/users/{uin}/info` and `/contacts/outgoing` too;
  * the one-off cleanup tool counts and deletes only pending rows to copies.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. .venv/bin/python test_backup_copy_request_local.py
"""
import asyncio
import base64
import json
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_backup_copy_request.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
# The shared island ceiling in db 15, raised for this file only (see the note
# in test_contact_pending_withdraw_local.py).
os.environ.setdefault("REGISTER_CEILING_PER_MINUTE", "5000")
os.environ.setdefault("REGISTER_CEILING_PER_HOUR", "5000")


def _caller_addr():
    """A caller address nobody else shares, fresh on every run, so the per-IP
    and per-/24 registration limits in Redis do not depend on other files."""
    who = os.getpid()
    return (f"10.{(who >> 8) & 0xFF}.{who & 0xFF}.{(who >> 16) % 254 + 1}", 44444)


for f in ("test_backup_copy_request.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.models.contact import ContactRequest  # noqa: E402

fails = 0
HOST = "t"  # the base_url below, i.e. the Host header every call carries


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


def detail_of(r):
    try:
        d = r.json().get("detail")
    except ValueError:
        return {}
    return d if isinstance(d, dict) else {}


class Key:
    def __init__(self):
        self.priv = Ed25519PrivateKey.generate()
        self.sk = b64(self.priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    def record(self, homes, ts=1_760_000_000):
        """A §2.3 record signed the way the clients sign it (and the way
        `routers/federation._record_signed_bytes` rebuilds it)."""
        ik = b64(os.urandom(32))
        part = {"v": 1, "ik": ik, "sk": self.sk,
                "homes": [{"host": h, "uin": u} for h, u in homes], "ts": ts}
        signed = json.dumps(part, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return {**part, "sig": b64(self.priv.sign(signed))}


async def register(c, nick, key: Key | None = None):
    key = key or Key()
    r = await c.post("/auth/register", json={
        "nickname": nick, "identity_key": b64(os.urandom(32)), "signing_key": key.sk,
    })
    assert r.status_code == 201, r.text
    body = r.json()
    return body["uin"], body["token"], key


async def publish(c, tok, doc):
    r = await c.put("/federation/island-record", headers=H(tok), json=doc)
    assert r.status_code == 200, r.text


async def rows_to(uin):
    async with SessionLocal() as db:
        return await db.scalar(select(func.count()).select_from(ContactRequest).where(ContactRequest.to_uin == uin))


async def pending_count():
    async with SessionLocal() as db:
        return await db.scalar(select(func.count()).select_from(ContactRequest).where(ContactRequest.state == "pending"))


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()
    transport = httpx.ASGITransport(app=app, client=_caller_addr())
    async with httpx.AsyncClient(transport=transport, base_url=f"http://{HOST}") as c:
        q_uin, q_tok, _ = await register(c, "asker")
        # vss's situation: a person who lives on api.rcq.app as 134, with a
        # backup here under a different number and the same nickname.
        copy_uin, copy_tok, copy_key = await register(c, "vsscopy")
        await publish(c, copy_tok, copy_key.record([("api.rcq.app", 134), (HOST, copy_uin)]))
        # vss's OWN account on this island: a person, primary here.
        nat_uin, nat_tok, nat_key = await register(c, "vssnative")
        await publish(c, nat_tok, nat_key.record([(HOST, nat_uin)]))

        print("\nThe copy refuses, and says where the person lives:")
        before = await rows_to(copy_uin)
        r = await c.post("/contacts/request", headers=H(q_tok), json={"to_uin": copy_uin})
        d = detail_of(r)
        check(f"★ request to a backup copy is 403 ({r.status_code})", r.status_code == 403)
        check("  ... code backup_copy", d.get("code") == "backup_copy")
        check("  ... home_host / home_uin are the record's primary",
              d.get("home_host") == "api.rcq.app" and d.get("home_uin") == 134)
        check("  ... a sentence an old client can print", "134@api.rcq.app" in (d.get("message") or ""))
        check("  ... the whole body fits Android's 200-character error text", len(r.text) <= 200)
        check("★ no request row was written", await rows_to(copy_uin) == before == 0)
        r = await c.post("/contacts/request", headers=H(q_tok), json={"to_uin": copy_uin})
        check("asking again is the same refusal, not a row", r.status_code == 403 and await rows_to(copy_uin) == 0)

        print("\nPeople are left alone:")
        r = await c.post("/contacts/request", headers=H(q_tok), json={"to_uin": nat_uin})
        check(f"a native account with a one-home record: 202 ({r.status_code})", r.status_code == 202)
        bare_uin, _, _ = await register(c, "norecord")
        r = await c.post("/contacts/request", headers=H(q_tok), json={"to_uin": bare_uin})
        check(f"an account with no record at all: 202 ({r.status_code})", r.status_code == 202)
        prim_uin, prim_tok, prim_key = await register(c, "primhere")
        await publish(c, prim_tok, prim_key.record([(HOST, prim_uin), ("api.rcq.app", 5)]))
        r = await c.post("/contacts/request", headers=H(q_tok), json={"to_uin": prim_uin})
        check(f"primary HERE with a backup elsewhere: 202 ({r.status_code})", r.status_code == 202)

        print("\nOnly a record the key signed, naming this mailbox, counts:")
        other = Key()
        w_uin, w_tok, _ = await register(c, "wrongkey")
        await publish(c, w_tok, other.record([("api.rcq.app", 7), (HOST, w_uin)]))
        r = await c.post("/contacts/request", headers=H(q_tok), json={"to_uin": w_uin})
        check(f"record under ANOTHER key (stale after a key change): 202 ({r.status_code})", r.status_code == 202)
        t_uin, t_tok, t_key = await register(c, "tampered")
        doc = t_key.record([("api.rcq.app", 8), (HOST, t_uin)])
        doc["homes"][0]["uin"] = 9  # changed after signing
        await publish(c, t_tok, doc)
        r = await c.post("/contacts/request", headers=H(q_tok), json={"to_uin": t_uin})
        check(f"a record whose signature does not verify: 202 ({r.status_code})", r.status_code == 202)
        n_uin, n_tok, n_key = await register(c, "othername")
        await publish(c, n_tok, n_key.record([("api.rcq.app", 10), ("is2.example.org", n_uin)]))
        r = await c.post("/contacts/request", headers=H(q_tok), json={"to_uin": n_uin})
        check(f"a record that names this island by no name we know: 202 ({r.status_code})", r.status_code == 202)
        s_uin, s_tok, s_key = await register(c, "twohere")
        await publish(c, s_tok, s_key.record([(HOST, 99999), (HOST, s_uin)]))
        r = await c.post("/contacts/request", headers=H(q_tok), json={"to_uin": s_uin})
        check(f"'primary' on THIS island under another number: 202 ({r.status_code})", r.status_code == 202)
        j_uin, j_tok, j_key = await register(c, "junkhost")
        await publish(c, j_tok, j_key.record([("https://evil.example/x", 11), (HOST, j_uin)]))
        r = await c.post("/contacts/request", headers=H(q_tok), json={"to_uin": j_uin})
        check(f"a home that is not a bare host is never repeated: 202 ({r.status_code})", r.status_code == 202)

        print("\nThis island's names:")
        f_uin, f_tok, f_key = await register(c, "viafront")
        await publish(c, f_tok, f_key.record([("api.rcq.app", 12), ("CDN.rcq.app:443", f_uin)]))
        r = await c.post("/contacts/request", headers=H(q_tok), json={"to_uin": f_uin})
        check(f"a record naming this island by its CDN front, any case, :443: 403 ({r.status_code})",
              r.status_code == 403 and detail_of(r).get("home_uin") == 12)
        r = await c.post("/contacts/request", headers={**H(q_tok), "Host": "T:443"}, json={"to_uin": copy_uin})
        check(f"Host header 'T:443' is this island too: 403 ({r.status_code})", r.status_code == 403)

        print("\nSearch, profile, outgoing:")
        r = await c.get("/users/search", headers=H(q_tok), params={"q": "vss"})
        uins = [u["uin"] for u in r.json()]
        check("★ name search finds the person and not the copy",
              nat_uin in uins and copy_uin not in uins)
        r = await c.get("/users/search", headers=H(q_tok), params={"q": f"#{copy_uin}"})
        rows = r.json()
        check("an exact #number still finds the copy ...", [u["uin"] for u in rows] == [copy_uin])
        check("  ... marked with its home",
              rows and rows[0].get("home") == {"host": "api.rcq.app", "uin": 134})
        r = await c.get("/users/search", headers=H(q_tok), params={"q": str(copy_uin)})
        hit = [u for u in r.json() if u["uin"] == copy_uin]
        check("a bare exact number too, marked", hit and hit[0].get("home", {}).get("uin") == 134)
        r = await c.get("/users/search", headers=H(q_tok), params={"q": "vssnative"})
        check("a person's row carries home = null", r.json() and r.json()[0].get("home") is None)
        r = await c.get(f"/users/{copy_uin}/info", headers=H(q_tok))
        check(f"/users/{{copy}}/info carries home ({r.status_code})",
              r.status_code == 200 and r.json().get("home") == {"host": "api.rcq.app", "uin": 134})
        r = await c.get(f"/users/{nat_uin}/info", headers=H(q_tok))
        check("/users/{native}/info has home = null", r.status_code == 200 and r.json().get("home") is None)
        r = await c.get(f"/users/{copy_uin}/info", headers=H(copy_tok))
        check("the copy's owner reading itself is not told it is a copy", r.json().get("home") is None)

        # A request written before the refusal existed (the two on is2).
        async with SessionLocal() as db:
            db.add(ContactRequest(from_uin=q_uin, to_uin=copy_uin, state="pending"))
            await db.commit()
        r = await c.get("/contacts/outgoing", headers=H(q_tok))
        out = {row["to_uin"]: row for row in r.json()}
        check("★ an old pending row to a copy is marked with its home in /outgoing",
              out.get(copy_uin, {}).get("home") == {"host": "api.rcq.app", "uin": 134})
        check("  ... and a row to a person is not", out.get(nat_uin, {}).get("home", "x") is None)

        print("\nThe one-off cleanup (app/tools/backup_copy_requests.py):")
        from app.tools.backup_copy_requests import run as cleanup
        pending_before = await pending_count()
        check("dry run counts exactly the one row to a copy", await cleanup([HOST], apply=False) == 1)
        check("  ... and deletes nothing", await pending_count() == pending_before)
        check("--apply deletes that one", await cleanup([HOST], apply=True) == 1)
        check("  ... and only that one", await pending_count() == pending_before - 1)
        r = await c.get("/contacts/outgoing", headers=H(q_tok))
        left = {row["to_uin"] for row in r.json()}
        check("  ... it is gone from /outgoing, requests to people are not",
              copy_uin not in left and nat_uin in left)
        check("a second run finds nothing", await cleanup([HOST], apply=True) == 0)

    await close_redis()
    print(f"\n{'ALL PASS' if fails == 0 else f'{fails} FAIL(S)'}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
