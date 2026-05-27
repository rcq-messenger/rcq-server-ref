import logging
import os

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import current_uin, issue_token
from app.models.contact import Contact
from app.models.group import Group, GroupMember
from app.models.user import User
from app.routers.groups import _load_group, _members_with_users, _serialize
from app.routers.referrals import record_referral
from app.services.connection_manager import manager
from app.services.uin import allocate_uin

log = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Founder UIN — auto-added bidirectionally to every freshly registered
# tester's contact list. Set RCQ_FOUNDER_UIN=0 in env to disable.
def _founder_uin() -> int:
    raw = os.getenv("RCQ_FOUNDER_UIN", "555555")
    try:
        return int(raw)
    except ValueError:
        return 0


# Founder's beta group — new tester is auto-joined to this group on
# register and notified via WS so the chat shows up immediately. Set
# RCQ_FOUNDER_BETA_GROUP_ID=0 in env to disable.
def _founder_beta_group_id() -> int:
    raw = os.getenv("RCQ_FOUNDER_BETA_GROUP_ID", "0")
    try:
        return int(raw)
    except ValueError:
        return 0


class RegisterIn(BaseModel):
    nickname: str = Field(min_length=1, max_length=64)
    # Long-term X25519 ECDH public key (raw 32-byte, base64). Used by senders
    # to derive the per-message AEAD key.
    identity_key: str
    # Long-term Ed25519 signing public key (raw 32-byte, base64). Used by
    # recipients to authenticate the sealed-sender envelope.
    signing_key: str
    # Optional referral code — the inviter's UIN. Bad value is ignored.
    inviter_uin: int | None = None


class RegisterOut(BaseModel):
    uin: int
    token: str


class SessionOut(BaseModel):
    token: str
    ws_url: str


@router.post("/register", response_model=RegisterOut, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterIn, db: AsyncSession = Depends(get_db)) -> RegisterOut:
    uin = await allocate_uin(db)
    user = User(
        uin=uin,
        nickname=body.nickname,
        identity_key=body.identity_key,
        signing_key=body.signing_key,
    )
    db.add(user)
    await db.commit()

    # Auto-add the founder bidirectionally: new tester gets the team in
    # their list AND the team gets the new tester. iOS ingest does not
    # auto-add unknown senders, so without the reverse row the founder
    # silently wouldn't see incoming messages (push arrives, in-app empty).
    founder_uin = _founder_uin()
    if founder_uin and founder_uin != uin:
        founder = await db.scalar(
            select(User).where(User.uin == founder_uin, User.is_fake == False)  # noqa: E712
        )
        if founder is not None:
            db.add(Contact(owner_uin=uin, contact_uin=founder_uin))
            db.add(Contact(owner_uin=founder_uin, contact_uin=uin))
            await db.commit()

    # Record any referral. Invalid code is rolled back, not raised —
    # must never invalidate the already-committed registration above.
    if body.inviter_uin:
        if await record_referral(db, body.inviter_uin, uin):
            await db.commit()
        else:
            await db.rollback()

    # Auto-join the founder's beta group so the new tester lands directly
    # in the shared chat. Broadcast group_membership_changed so anyone
    # online (including the founder) sees the new member without a refresh.
    beta_group_id = _founder_beta_group_id()
    if beta_group_id:
        group = await db.get(Group, beta_group_id)
        if group is not None:
            db.add(GroupMember(group_id=beta_group_id, uin=uin, role="member"))
            await db.commit()
            members = await _members_with_users(db, beta_group_id)
            g = await _load_group(db, beta_group_id)
            payload = _serialize(g, members).model_dump(mode="json")
            for m in members:
                await manager.send(m.uin, {"type": "group_membership_changed", "group": payload})

    return RegisterOut(uin=uin, token=issue_token(uin))


@router.post("/session", response_model=SessionOut)
async def session(uin: int = Depends(current_uin)) -> SessionOut:
    return SessionOut(token=issue_token(uin), ws_url=f"/ws/{uin}")


@router.delete("/account", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    # Tell every other session connected under this UIN (iOS, web,
    # multi-device) that the account just got burned, so they can
    # wipe local identity and bounce back to login. Without this
    # the second device keeps using a stale token / cached state
    # until next app launch — the user reported this exact bug
    # after burning from web while iOS was open. Fan-out happens
    # *before* the row delete so the WS auth (token still valid)
    # doesn't trip the disconnect path inside the burn itself.
    await manager.broadcast([uin], {"type": "account_burned"})

    # Find groups the user owns + groups they're a member of.
    # Owned groups need to be deleted entirely (burn = total nuke,
    # per founder decision). Member-only groups just need this
    # user's GroupMember row removed so the roster stays clean.
    owned_group_ids: list[int] = (
        await db.execute(
            select(Group.id).where(Group.owner_uin == uin)
        )
    ).scalars().all()

    # Notify members of every owned group so their clients drop the
    # cached group + clear unread + don't render a ghost. Done before
    # delete so we still have GroupMember rows to enumerate.
    for gid in owned_group_ids:
        member_uins = (
            await db.execute(
                select(GroupMember.uin)
                .where(GroupMember.group_id == gid)
                .where(GroupMember.uin != uin)
            )
        ).scalars().all()
        for muin in member_uins:
            await manager.send(muin, {
                "type": "group_deleted",
                "group_id": gid,
                "reason": "owner_burned",
            })

    # Delete owned groups. CASCADE on GroupMember.group_id and
    # Poll.group_id removes those rows automatically.
    if owned_group_ids:
        await db.execute(
            delete(Group).where(Group.id.in_(owned_group_ids))
        )

    # Remove user from groups where they were just a member.
    await db.execute(
        delete(GroupMember).where(GroupMember.uin == uin)
    )

    await db.delete(user)
    await db.commit()
