"""Resident invites: the arithmetic, and the three ways it could quietly leak.

The feature is a counter, so the tests are about counting. Every one of these
guards a way the allowance could refill itself without anybody noticing, which
is the only failure mode that matters: an invite that does not work is a
complaint, and an invite that works five times too often is a flood.
"""
import pathlib
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, '/Users/tager/Documents/RCQ/backend')

from app.models.user import User
from app.routers.invites import _accrued

checks = []


def check(name, cond):
    checks.append((name, cond))
    print(("ok   " if cond else "FAIL ") + name)


NOW = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)


def resident(days_ago, minted=0):
    u = User()
    u.uin = 1000
    u.resident_since = NOW - timedelta(days=days_ago)
    u.invites_minted = minted
    return u


def granted(days_ago, total=5, period=30):
    g, _ = _accrued(resident(days_ago), total=total, period_days=period, now=NOW)
    return g


check("a resident has one the moment they pay", granted(0) == 1)
check("still one the day before the month is up", granted(29) == 1)
check("two when the month has passed", granted(30) == 2)
check("three after two months", granted(61) == 3)
check("five after four months", granted(120) == 5)
check("still five after four YEARS: the cap is a cap", granted(1500) == 5)

# ★ The founder's decision, and the one with the largest number behind it.
free = User()
free.uin = 2000
free.resident_since = None
free.invites_minted = 0
g, nxt = _accrued(free, total=5, period_days=30, now=NOW)
check("somebody who never paid has none, and no clock either", g == 0 and nxt is None)

# Switched off island-wide.
check("total of zero means nobody has any", granted(999, total=0) == 0)

# The clock the client shows.
_, nxt = _accrued(resident(10), total=5, period_days=30, now=NOW)
check("the next one is dated from when they PAID, not from now",
      nxt == (NOW - timedelta(days=10)) + timedelta(days=30))
_, nxt_full = _accrued(resident(400), total=5, period_days=30, now=NOW)
check("no next date once they hold the lot", nxt_full is None)

# A naive-datetime row (SQLite writes them) must not explode.
naive = User()
naive.uin = 3000
naive.resident_since = (NOW - timedelta(days=45)).replace(tzinfo=None)
naive.invites_minted = 0
check("a timezone-naive resident_since still counts", _accrued(naive, total=5, period_days=30, now=NOW)[0] == 2)

src = pathlib.Path('app/routers/invites.py').read_text()

# ⚠⚠ The three leaks. Each of these would ship silently and be found by
# somebody counting accounts, not by anybody counting invites.
check("the allowance is spent by a conditional UPDATE, not read-then-write",
      re.search(r"update\(User\)[\s\S]{0,200}invites_minted < granted", src) is not None)
check("a losing race is refused rather than served", "no_invites_left" in src)
check("revoking does NOT refund the credit (it would be an unlimited reroll)",
      "Does not refund" in src and "invites_minted - 1" not in src)
check("a resident cannot mint an invite carrying a reserved number",
      "uin=None" in src)
check("a suspended account cannot hand out entry", "account_suspended" in src)
check("only a payer may mint", "not_a_resident" in src)

user_src = pathlib.Path('app/models/user.py').read_text()
check("the counter is monotone and documented as such, not a COUNT(*)",
      "MONOTONE" in user_src and "credential_sweep" in user_src)

mig = pathlib.Path('app/routers/migrate.py').read_text()
check("the counter follows a change of number, or a new UIN is a free reset",
      "invites_minted=user.invites_minted" in mig)

auth = pathlib.Path('app/routers/auth.py').read_text()
check("paying grants the resident mark", 'badge="resident" if resident_at else None' in auth)

bad = [n for n, c in checks if not c]
print(f"\n{len(checks) - len(bad)}/{len(checks)} прошло")
sys.exit(1 if bad else 0)
