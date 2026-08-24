"""Local-only verification of the `gossip_records` sweep.

`gossip_records` was the last open row in section 2 of the metadata map: the
one table `uin_rows.purge_uin_rows` structurally cannot reach, because it is
keyed by a global Ed25519 signing key rather than a uin, so mirrors of burned
identities were served forever.

It is also a federation mirror OTHER islands resolve against, which is why it
wanted a design and not a horizon. So this file checks what the design SPARES
at least as hard as what it removes, in the same spirit as
`test_retention_sweeps_local.py`:

  spares   a record whose own `ts` is ancient but which somebody resolved
           yesterday. That is the exact shape of the row the mirror exists
           for: a peer whose island has gone dark and who therefore cannot
           republish. Ageing on `ts` would delete it; ageing on demand keeps it
  spares   a row nobody has ever been seen using (`touched_at IS NULL`,
           i.e. written before the tracking shipped). It is STAMPED, so it gets
           a full horizon from today, rather than judged on `updated_at`, which
           is a FIRST-write clock. Judging a horizon on a first-write clock is
           the mistake the prekey sweep shipped and had to fix in .12
  spares   a migrating account's mirror: `signing_key` moves to the new user
           row verbatim, the identity survives, and its contacts on other
           islands still resolve against this record
  removes  a row nobody on this island has mirrored or resolved in the horizon
  removes  the mirror of an account burned HERE, immediately and with no
           horizon at all, because the burn path holds the key it is keyed by

Plus the touch path itself, which is what makes the clock mean anything: a
`PUT` of a byte-identical document and a `GET` both stamp the row, and both are
throttled so a read path does not turn into a write path.

Direct unit test against a throwaway SQLite DB, no HTTP.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_gossip_sweep_local.py
"""
import asyncio
import base64
import json
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_gossip.db"
os.environ["ENV"] = "dev"
os.environ.setdefault("JWT_SECRET", "t" * 64)

for _f in ("test_gossip.db",):
    try:
        os.remove(_f)
    except FileNotFoundError:
        pass

from datetime import datetime, timedelta, timezone  # noqa: E402

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.models.federation import GossipRecord  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers import federation as fed  # noqa: E402
from app.services import gossip_sweep  # noqa: E402
from app.services.uin_rows import (  # noqa: E402
    DROP_ON_REKEY,
    PER_UIN_COLUMNS,
    purge_gossip_mirror,
    purge_uin_rows,
)

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{'' if ok else '  ' + detail}")


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def signed_record(priv: Ed25519PrivateKey, ts: int, homes: list[dict]) -> dict:
    """A §2.3 record the server will actually accept: real signature, real
    canonical bytes. Anything less would test the test."""
    sk = b64(priv.public_key().public_bytes_raw())
    doc = {"v": 1, "ik": b64(b"i" * 32), "sk": sk, "homes": homes, "ts": ts}
    doc["sig"] = b64(priv.sign(fed._record_signed_bytes(doc)))
    return doc


async def row_for(db, sk: str) -> GossipRecord | None:
    return (
        await db.execute(select(GossipRecord).where(GossipRecord.sk == sk))
    ).scalar_one_or_none()


async def main() -> int:
    await init_db()
    now = datetime.now(timezone.utc)
    horizon = gossip_sweep.MAX_IDLE_DAYS

    # ── 1. the touch path ────────────────────────────────────────────────
    print("\n1. a mirror and a resolve both count as use")
    priv = Ed25519PrivateKey.generate()
    sk_live = b64(priv.public_key().public_bytes_raw())
    doc = signed_record(priv, ts=1_700_000_000, homes=[{"host": "is2.rcq.app", "uin": 5}])

    async with SessionLocal() as db:
        await fed.put_gossip_record(doc=doc, db=db)
        row = await row_for(db, sk_live)
        check("a first mirror stamps touched_at", row is not None and row.touched_at is not None)

        # Age the stamp so the throttle cannot mask the next assertion.
        row.touched_at = now - timedelta(hours=6)
        await db.commit()
        before = row.touched_at

        # The re-mirror a client performs on every resolve: byte-identical
        # document, same ts. Nothing about the row's CONTENT changes, which is
        # exactly why `onupdate` alone cannot be trusted here.
        await fed.put_gossip_record(doc=doc, db=db)
        row = await row_for(db, sk_live)
        check(
            "a re-PUT of an IDENTICAL document still counts as use",
            row is not None and row.touched_at > before,
            f"before={before} after={row.touched_at if row else None}",
        )

        row.touched_at = now - timedelta(hours=6)
        await db.commit()
        before = row.touched_at
        got = await fed.get_gossip_record(sk=sk_live, db=db)
        row = await row_for(db, sk_live)
        check("a GET returns the record", got.get("sk") == sk_live)
        check(
            "a GET counts as use (this is the fallback road doing its job)",
            row is not None and row.touched_at > before,
            f"before={before} after={row.touched_at if row else None}",
        )

        # ...but not on every read. A read path that writes every time is a
        # different bug from the one being fixed.
        second = row.touched_at
        await fed.get_gossip_record(sk=sk_live, db=db)
        row = await row_for(db, sk_live)
        check(
            "a second GET within the throttle writes nothing",
            row is not None and row.touched_at == second,
            f"first={second} second={row.touched_at if row else None}",
        )

    # ── 2. the sweep ─────────────────────────────────────────────────────
    print("\n2. the sweep removes the cold and spares the rest")
    cold_priv, warm_priv, dark_priv = (Ed25519PrivateKey.generate() for _ in range(3))
    sk_cold = b64(cold_priv.public_key().public_bytes_raw())
    sk_warm = b64(warm_priv.public_key().public_bytes_raw())
    sk_dark = b64(dark_priv.public_key().public_bytes_raw())
    sk_legacy = b64(Ed25519PrivateKey.generate().public_key().public_bytes_raw())

    async with SessionLocal() as db:
        db.add(GossipRecord(
            sk=sk_cold, doc=json.dumps({"sk": sk_cold}), ts=1_700_000_000,
            touched_at=now - timedelta(days=horizon + 5),
        ))
        db.add(GossipRecord(
            sk=sk_warm, doc=json.dumps({"sk": sk_warm}), ts=1_700_000_000,
            touched_at=now - timedelta(days=1),
        ))
        # The load-bearing spare: an ANCIENT `ts` (the owner has not been able
        # to republish, which is what "their island is dark" looks like) but
        # resolved here yesterday, through the very fallback this row exists
        # to serve.
        db.add(GossipRecord(
            sk=sk_dark, doc=json.dumps({"sk": sk_dark}), ts=1_400_000_000,
            touched_at=now - timedelta(days=2),
        ))
        # Written before the tracking existed: NULL touch, ancient updated_at.
        db.add(GossipRecord(
            sk=sk_legacy, doc=json.dumps({"sk": sk_legacy}), ts=1_700_000_000,
            touched_at=None, updated_at=now - timedelta(days=horizon * 3),
        ))
        await db.commit()

    deleted, stamped = await gossip_sweep.sweep_once()
    check("the cold row was counted as deleted", deleted == 1, f"deleted={deleted}")
    check("the legacy row was counted as stamped", stamped == 1, f"stamped={stamped}")

    async with SessionLocal() as db:
        check("a row nobody has touched in the horizon is gone", await row_for(db, sk_cold) is None)
        check("a row resolved yesterday survives", await row_for(db, sk_warm) is not None)
        dark = await row_for(db, sk_dark)
        check(
            "an ANCIENT ts with a recent touch survives (the dark-island case)",
            dark is not None,
        )
        legacy = await row_for(db, sk_legacy)
        check(
            "a legacy row is STAMPED, not deleted, however old its updated_at",
            legacy is not None and legacy.touched_at is not None,
            f"row={legacy}",
        )

    # A second pass must not now delete what the first one just stamped.
    deleted2, stamped2 = await gossip_sweep.sweep_once()
    check("the pass after the stamp deletes nothing new", deleted2 == 0, f"deleted={deleted2}")
    check("and finds no legacy rows left to stamp", stamped2 == 0, f"stamped={stamped2}")
    async with SessionLocal() as db:
        check(
            "the stamped legacy row is still there a pass later",
            await row_for(db, sk_legacy) is not None,
        )

    # ── 3. burn vs migration ─────────────────────────────────────────────
    print("\n3. a burn takes the mirror; a migration must not")
    burn_priv = Ed25519PrivateKey.generate()
    sk_burn = b64(burn_priv.public_key().public_bytes_raw())
    BURNER, BYSTANDER = 9101, 9102

    async with SessionLocal() as db:
        db.add(User(uin=BURNER, nickname="burner", identity_key="ik", signing_key=sk_burn))
        db.add(GossipRecord(
            sk=sk_burn, doc=json.dumps({"sk": sk_burn}), ts=1_700_000_000, touched_at=now,
        ))
        await db.commit()

    async with SessionLocal() as db:
        # The number-keyed purge alone cannot see it. That is the whole reason
        # this item stayed open, and it is worth a failing test if it silently
        # starts working (the row would then be deleted twice, harmlessly, but
        # the reasoning in two docstrings would be wrong).
        await purge_uin_rows(db, BURNER)
        await db.commit()
        check(
            "purge_uin_rows alone still cannot reach the mirror",
            await row_for(db, sk_burn) is not None,
        )

        user = await db.get(User, BURNER)
        hit = await purge_gossip_mirror(db, user.signing_key)
        await db.commit()
        check("the burn path deletes the mirror by signing key", hit == 1, f"rows={hit}")
        check("and it is gone", await row_for(db, sk_burn) is None)
        check(
            "somebody else's mirror is untouched",
            await row_for(db, sk_warm) is not None,
        )

    # Structural, so a future edit to the rekey lists cannot quietly enrol
    # gossip rows in the migration path. Migrating copies `signing_key`
    # verbatim: the identity survives and its record is still true.
    models_in_rekey = {m for m, _ in PER_UIN_COLUMNS} | {m for m, _ in DROP_ON_REKEY}
    check(
        "GossipRecord is in neither rekey list, so a migration leaves it alone",
        GossipRecord not in models_in_rekey,
    )
    check(
        "purge_gossip_mirror is a no-op without a key",
        await _no_key_is_noop() == 0,
    )

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for f in FAIL:
        print(f"  FAILED: {f}")
    return 1 if FAIL else 0


async def _no_key_is_noop() -> int:
    async with SessionLocal() as db:
        return await purge_gossip_mirror(db, None)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
