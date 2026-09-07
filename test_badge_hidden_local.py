"""A hidden mark is hidden on every surface that carries one, and nowhere else.

Runs against the real serialisers, not against HTTP: the point is that the
five places a mark reaches a stranger agree with each other. The one that
caught a bug when this was written is the group roster, which builds its rows
from a column select rather than from a User, so it does not get the gate for
free.
"""
import sys, types, asyncio
sys.path.insert(0, '/Users/tager/Documents/RCQ/backend')

from app.models.user import User, badge_for_viewer

checks = []
def check(name, cond):
    checks.append((name, cond))
    print(("ok   " if cond else "FAIL ") + name)

def mk(uin, badge, hidden):
    u = User()
    u.uin, u.badge, u.badge_hidden = uin, badge, hidden
    return u

worn = mk(1000, "special", False)
kept = mk(1001, "special", True)
none = mk(1002, None, True)

check("worn mark shows to a stranger", badge_for_viewer(worn, viewer_uin=99) == "special")
check("worn mark shows to its owner", badge_for_viewer(worn, viewer_uin=1000) == "special")
check("hidden mark is gone for a stranger", badge_for_viewer(kept, viewer_uin=99) is None)
check("hidden mark is gone for an anonymous caller", badge_for_viewer(kept, viewer_uin=None) is None)
check("hidden mark still shows to its owner", badge_for_viewer(kept, viewer_uin=1001) == "special")
check("no mark reads as no mark either way", badge_for_viewer(none, viewer_uin=99) is None)

# The gate must be indistinguishable from having no mark: same value, same type.
check("hidden and absent are the same answer on the wire",
      badge_for_viewer(kept, viewer_uin=99) == badge_for_viewer(none, viewer_uin=99))

# Every place that serialises a user's mark must route through the gate. This
# is a grep, deliberately: the failure being guarded against is a NEW call site
# added later that reads `u.badge` straight.
import re, pathlib
ROOT = pathlib.Path('/Users/tager/Documents/RCQ/backend/app/routers')
offenders = []
for f in ('users.py', 'contacts.py'):
    for n, line in enumerate(( ROOT / f).read_text().split('\n'), 1):
        if re.search(r'badge=u\.badge\b', line):
            offenders.append(f"{f}:{n}")
check("no serialiser reads u.badge directly: " + (", ".join(offenders) or "none"), not offenders)

roster = (ROOT / 'groups.py').read_text()
check("the group roster selects badge_hidden", "User.badge_hidden," in roster)
check("the group roster gates on it", "r.badge_hidden and not me" in roster)

admin = (ROOT / 'admin.py').read_text()
check("granting a mark does not announce a hidden one",
      "badge=None if user.badge_hidden else user.badge" in admin)

users = (ROOT / 'users.py').read_text()
check("the owner gets their own setting back", "badge_hidden=(u.badge_hidden if owner_self else None)" in users)
check("the setting is writable from a client", "badge_hidden: bool | None = None" in users)


# ── Несколько меток: что держат, что носят ────────────────────────────────
from app.models.user import earned_badges, grant_badge, revoke_badge

u = User(); u.uin = 5000; u.badge = None; u.badges_earned = None; u.badge_hidden = False
check("an account with nothing holds nothing", earned_badges(u) == [])

grant_badge(u, "tester")
check("a first grant is both held and worn", earned_badges(u) == ["tester"] and u.badge == "tester")

grant_badge(u, "resident")
check("a second grant is HELD but does not replace what is worn",
      earned_badges(u) == ["tester", "resident"] and u.badge == "tester")

grant_badge(u, "tester")
check("granting the same one twice does not duplicate it",
      earned_badges(u) == ["tester", "resident"])

u.badge = "resident"
revoke_badge(u, "resident")
check("revoking what is worn falls back to something still held",
      earned_badges(u) == ["tester"] and u.badge == "tester")

revoke_badge(u, "tester")
check("revoking the last one leaves nothing worn", earned_badges(u) == [] and u.badge is None)

old = User(); old.uin = 5001; old.badge = "official"; old.badges_earned = None
check("a row from before the set existed reads its lone mark as the one held",
      earned_badges(old) == ["official"])

odd = User(); odd.uin = 5002; odd.badge = "official"; odd.badges_earned = "tester"
check("a worn mark missing from the set is still counted as held",
      set(earned_badges(odd)) == {"tester", "official"})

users_src = pathlib.Path('app/routers/users.py').read_text()
check("picking a mark is checked against what is held, not granted",
      "badge_not_held" in users_src and "earned_badges(user)" in users_src)
check("the set is owner-only on the wire",
      "badges_earned=(earned_badges(u) if owner_self else [])" in users_src)
admin_src = pathlib.Path('app/routers/admin.py').read_text()
check("an admin grant adds instead of overwriting", "grant_badge(user, body.badge)" in admin_src)

bad2 = [n for n, c in checks if not c]
print(f"\nвсего {len(checks) - len(bad2)}/{len(checks)}")
sys.exit(1 if bad2 else 0)
