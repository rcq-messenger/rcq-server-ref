"""Hall-of-Fame effort stats — how many bug reports a contributor filed and
how many were confirmed as real bugs.

Shared by the public wall (`/public/hof`) and the admin curation list
(`/admin/hof`) so both compute "effort" the same way. A contributor's effort
ring on the wall is driven purely by CONFIRMED bug-bounty reports; abuse
reports against other users — and AUTO-SUBMITTED CRASH reports — never count
toward it.
"""

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.report import Report

# Confirmed-bug count that fills the effort ring to full green. Tuned high on
# purpose: the founder wants a fully-green ring to be rare ("находил баги и они
# признаны багами — таких вряд ли будет"). Bump this if the bar feels too low.
HOF_EFFORT_TARGET = 8

# A bug-bounty report counts as a CONFIRMED bug when the founder resolved it
# (acted on it = it was real), as opposed to dismissing it as not-a-bug.
_CONFIRMED_STATUS = "resolved"

# Auto-submitted crash reports ride the same /reports channel as human bug
# reports (clients prefix the reason with "[<platform> <version>] [CRASH]").
# They are NOT a contributor's deliberate effort, so they must not inflate the
# count or the ring. Mirrors CRASH_MARKER in app/routers/admin.py — keep in sync.
_CRASH_MARKER = "[CRASH]"


async def bug_report_stats(
    db: AsyncSession, uins: list[int]
) -> dict[int, tuple[int, int]]:
    """Map each uin → (total bug-bounty reports filed, confirmed-as-bug count).

    Scoped to `context == "bug_bounty"` and excludes auto crash reports (reason
    carries the [CRASH] marker) so neither plain abuse reports nor crash dumps
    feed the score. uins with no qualifying reports are simply absent from the
    result; callers default them to (0, 0). One grouped query regardless of how
    many uins.
    """
    if not uins:
        return {}
    confirmed_expr = func.coalesce(
        func.sum(case((Report.status == _CONFIRMED_STATUS, 1), else_=0)), 0
    )
    rows = (
        await db.execute(
            select(
                Report.reporter_uin,
                func.count().label("total"),
                confirmed_expr.label("confirmed"),
            )
            .where(
                Report.reporter_uin.in_(uins),
                Report.context == "bug_bounty",
                ~Report.reason.contains(_CRASH_MARKER),
            )
            .group_by(Report.reporter_uin)
        )
    ).all()
    return {r.reporter_uin: (int(r.total), int(r.confirmed)) for r in rows}


def effort_score(confirmed: int) -> float:
    """0..1 ring fill — confirmed bugs toward the target, capped at 1.0."""
    if HOF_EFFORT_TARGET <= 0:
        return 0.0
    return min(confirmed / HOF_EFFORT_TARGET, 1.0)
