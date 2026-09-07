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

bad = [n for n, c in checks if not c]
print(f"\n{len(checks) - len(bad)}/{len(checks)} прошло")
sys.exit(1 if bad else 0)
