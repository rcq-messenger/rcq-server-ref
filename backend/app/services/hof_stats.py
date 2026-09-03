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
from app.models.user import User

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

    ⚠⚠ `hidden_at` IS NOT FILTERED HERE AND MUST NOT BE. A reporter can drop a
    report from their own list (DELETE /reports/mine/{id}); that used to be a
    real DELETE, and since these two numbers are computed live over the rows, it
    was a way to edit your own history: file everything, delete whatever came
    back `dismissed`, and the ratio the podium ranks by only ever improved. The
    delete is a soft delete precisely so that this query keeps seeing the row.
    Adding `Report.hidden_at.is_(None)` to the WHERE below restores the exploit
    exactly.

    Founder-granted credit for reports filed OUTSIDE the in-app form
    (`users.hof_bonus_*`) is added on top, so a tester who does the work in the
    closed tester chat is not shown as having contributed nothing. That credit
    is not derived from anything, which is the point — nobody can earn it by
    filing reports, only the founder can grant it.
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
                # No `hidden_at` clause on purpose. See the docstring: a report
                # the reporter hid from their own list still counts as filed.
            )
            .group_by(Report.reporter_uin)
        )
    ).all()
    stats = {r.reporter_uin: (int(r.total), int(r.confirmed)) for r in rows}

    bonus = (
        await db.execute(
            select(User.uin, User.hof_bonus_reports, User.hof_bonus_confirmed)
            .where(
                User.uin.in_(uins),
                (User.hof_bonus_reports > 0) | (User.hof_bonus_confirmed > 0),
            )
        )
    ).all()
    for uin, extra_total, extra_confirmed in bonus:
        total, confirmed = stats.get(uin, (0, 0))
        stats[uin] = (total + (extra_total or 0), confirmed + (extra_confirmed or 0))
    return stats


def effort_score(confirmed: int) -> float:
    """0..1 ring fill — confirmed bugs toward the target, capped at 1.0."""
    if HOF_EFFORT_TARGET <= 0:
        return 0.0
    return min(confirmed / HOF_EFFORT_TARGET, 1.0)


def podium_score(reports: int, confirmed: int) -> float:
    """Ranking number for the top-three podium. Higher is better; 0 for anyone
    who has never had a bug confirmed.

    `confirmed² / reports` — confirmed bugs weighted by the share of reports
    that turned out to be real. Volume alone must not win, or the way to reach
    the podium is to file everything that crosses your mind and let the
    maintainers sort it out. Founder's own example holds:

        50 filed / 10 confirmed → 100/50  =  2.0
        10 filed /  9 confirmed →  81/10  =  8.1   ← wins, as it should

    Nobody can lose points by filing: a rejected report lowers the ratio but
    `confirmed` never falls, so the score only ever moves up when a bug is
    confirmed. That matters — a scoreboard that punishes reporting would
    quietly teach people not to report.
    """
    if confirmed <= 0 or reports <= 0:
        return 0.0
    return (confirmed * confirmed) / reports
