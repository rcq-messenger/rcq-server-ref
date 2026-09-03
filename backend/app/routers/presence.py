from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import current_uin
from app.models.contact import Contact
from app.models.group import GroupMember
from app.models.user import User
from app.services.connection_manager import manager


async def presence_watchers(db: AsyncSession, uin: int) -> list[int]:
    """Everyone who should receive my presence updates: people who have me in
    their contact list, plus everyone I share a group with — minus anyone I've
    blocked. Used by `/presence/status` and the WebSocket connect/disconnect
    paths so the same audience always gets the same broadcasts."""
    contact_watchers = (
        await db.execute(select(Contact.owner_uin).where(Contact.contact_uin == uin))
    ).scalars().all()

    # Everyone in groups I'm a member of, except myself.
    my_groups = (
        await db.execute(select(GroupMember.group_id).where(GroupMember.uin == uin))
    ).scalars().all()
    group_watchers: list[int] = []
    if my_groups:
        group_watchers = (
            await db.execute(
                select(GroupMember.uin).where(
                    and_(
                        GroupMember.group_id.in_(my_groups),
                        GroupMember.uin != uin,
                    )
                )
            )
        ).scalars().all()

    blocked_by_me = (
        await db.execute(
            select(Contact.contact_uin).where(
                and_(Contact.owner_uin == uin, Contact.blocked == True)  # noqa: E712
            )
        )
    ).scalars().all()
    blocked = set(blocked_by_me)

    return [w for w in set(contact_watchers) | set(group_watchers) if w not in blocked]

router = APIRouter(prefix="/presence", tags=["presence"])

VALID_STATUSES = {"online", "away", "dnd", "invisible", "offline"}


class StatusIn(BaseModel):
    status: str
    status_message: str | None = None


@router.post("/status")
async def set_status(
    body: StatusIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    if body.status not in VALID_STATUSES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid status")
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    # "offline" as a manual pick means "appear offline" — stored as
    # invisible so the `status` column only ever holds a real user-chosen
    # sub-state (online/away/dnd/invisible). A bare "offline" in the
    # column is reserved for legacy rows and is healed on the next WS
    # connect. Online/offline itself is derived from `last_seen` freshness.
    chosen = "invisible" if body.status == "offline" else body.status
    user.status = chosen
    user.status_message = body.status_message
    user.last_seen = datetime.now(timezone.utc)
    await db.commit()

    # Fan out presence to anyone who has this user in their contact list OR
    # shares a group with them — minus anyone they've blocked. Invisible
    # appears as "offline" to others, same as ICQ 2002.
    shown = "offline" if chosen == "invisible" else chosen
    final_watchers = await presence_watchers(db, uin)
    await manager.broadcast(
        list(final_watchers),
        {
            "type": "presence",
            "uin": uin,
            "status": shown,
            "status_message": body.status_message,
        },
    )
    return {"ok": True}
