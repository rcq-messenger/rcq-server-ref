"""Local-only verification of WHO a group envelope is kept for.

Two reports came out of one rule. `_queueable` skips the offline-queue row for
a member absent longer than OFFLINE_GROUP_DORMANT_DAYS — a real saving on a
1.7k-member group — but it was applied to every envelope type and it never
looked at who we were about to WAKE. So:

  * a returning member's SKDM (the sender-key chain) was dropped, and every
    later broadcast then decrypted to nothing on their phone: no bubble, no
    unread, no sound (#544);
  * a returning member got a "New group message" banner for a message that was
    never written down, opened the group and found it empty (#547).

This pins the corrected rule: sender-key control is kept for everyone, and a
content envelope is kept for anyone we are going to wake.

Runs offline, no DB. NOT part of the prod suite; NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_group_backlog_local.py
"""
import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_group_backlog.db")
os.environ.setdefault("ENV", "dev")

from app.routers.messages import _cls_for, _keep_for, _queueable  # noqa: E402
from app.services.offline_queue_sweep import DORMANT_DAYS  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


now = datetime.now(timezone.utc)
ACTIVE = 5001          # here yesterday
RETURNING = 5002       # away longer than the dormant window, has a push endpoint
GONE = 5003            # away that long and unreachable

members = [
    (ACTIVE, now - timedelta(days=1)),
    (RETURNING, now - timedelta(days=DORMANT_DAYS + 5)),
    (GONE, now - timedelta(days=DORMANT_DAYS + 5)),
]
recipients = [ACTIVE, RETURNING, GONE]
queueable = _queueable(members)
# `group_push_targets` returns {uin: endpoints}; only the keys matter here.
wake = {RETURNING: object()}

print("\n-- the dormant rule itself --")
check("an active member is queueable", ACTIVE in queueable)
check("a long-absent member is not", RETURNING not in queueable and GONE not in queueable)

# Stage 2a: `_keep_for` now branches on the 3-value class, not the type string.
# `_cls_for` is the same ingest-alias map the deposit path applies, so the
# critical types still land as cls 2 (kept for everyone) and content as cls 1.
print("\n-- sender-key control is never dropped (critical class, cls 2) --")
for t in ("skdm", "sknack"):
    keep = _keep_for(recipients, queueable, _cls_for(t), {})
    check(f"{t} (cls {_cls_for(t)}) is kept for every recipient", keep == set(recipients))

print("\n-- content: kept for everyone we wake --")
keep = _keep_for(recipients, queueable, _cls_for("message"), wake)
check("active member kept", ACTIVE in keep)
check("★ member we WAKE is kept even though dormant", RETURNING in keep)
check("dormant member we do not wake is still skipped", GONE not in keep)

print("\n-- nothing else changed --")
check(
    "no wake targets → the plain dormant rule",
    _keep_for(recipients, queueable, _cls_for("message"), {}) == queueable,
)
check(
    "a non-pushable, non-key type keeps the dormant rule",
    _keep_for(recipients, queueable, _cls_for("reaction"), {}) == queueable,
)

# ── the other half of the same rule: the SWEEP ───────────────────────────
#
# Keeping the SKDM at write time is worth exactly one sweep interval unless
# the sweep agrees. `_sweep_dormant` deletes group rows for anyone absent past
# the cutoff, and until this exemption existed that included the chain key we
# had just decided to keep — six hours later #544 was back, with the write-side
# fix still in place and looking correct. Run the real DELETE against a real
# table rather than eyeballing the SQL.
print("\n-- the dormant sweep agrees with the write side --")
import sqlite3  # noqa: E402

from app.services.offline_queue_sweep import _DORMANT_SQL  # noqa: E402

db = sqlite3.connect(":memory:")
# Mixed table: `cls` present on new rows (stage 2a), NULL on the legacy rows the
# migration leaves behind. The sweep spares cls == 2 OR (fallback) envelope_type
# 'skdm', and reaps the rest for a dormant recipient.
db.executescript(
    """
    CREATE TABLE users (uin INTEGER PRIMARY KEY, last_seen TEXT);
    CREATE TABLE offline_group_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        to_uin INTEGER NOT NULL,
        envelope_type TEXT NOT NULL,
        cls INTEGER
    );
    """
)
cutoff = (now - timedelta(days=DORMANT_DAYS)).isoformat()
db.execute("INSERT INTO users VALUES (?,?)", (ACTIVE, (now - timedelta(days=1)).isoformat()))
db.execute("INSERT INTO users VALUES (?,?)", (RETURNING, (now - timedelta(days=DORMANT_DAYS + 5)).isoformat()))
for uin in (ACTIVE, RETURNING):
    for t in ("skdm", "sknack", "gmsg", "message"):
        db.execute(
            "INSERT INTO offline_group_messages (to_uin, envelope_type, cls) VALUES (?,?,?)",
            (uin, t, _cls_for(t)),
        )
# A legacy skdm for the dormant member: cls NULL, spared only by the fallback.
db.execute(
    "INSERT INTO offline_group_messages (to_uin, envelope_type, cls) VALUES (?,?,?)",
    (RETURNING, "skdm", None),
)
db.execute(str(_DORMANT_SQL), {"cutoff": cutoff, "batch": 20_000})

rows_left = list(db.execute("SELECT to_uin, envelope_type, cls FROM offline_group_messages"))
left = {(u, t) for u, t, _ in rows_left}
check("★ a dormant member's SKDM survives the sweep", (RETURNING, "skdm") in left)
check(
    "★ the legacy (cls NULL) skdm survives too, via the envelope_type fallback",
    any(u == RETURNING and t == "skdm" and cl is None for u, t, cl in rows_left),
)
check("their stale content is still reaped", (RETURNING, "gmsg") not in left and (RETURNING, "message") not in left)
check(
    "a new sknack (cls 2) is now spared by the dormant rule — its own short TTL reaps it instead",
    (RETURNING, "sknack") in left,
)
check("an active member loses nothing", len([1 for u, _, _ in rows_left if u == ACTIVE]) == 4)

print("\nALL GROUP-BACKLOG CHECKS PASSED ✅" if not fails else f"\n{fails} CHECK(S) FAILED ❌")
raise SystemExit(1 if fails else 0)
