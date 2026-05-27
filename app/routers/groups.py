from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.contact import Contact
from app.models.group import Group, GroupMember, GroupMessageView
from app.models.user import User
from app.services.connection_manager import manager

router = APIRouter(prefix="/groups", tags=["groups"])

MAX_GROUPS_PER_USER = 5


class GroupOut(BaseModel):
    id: int
    name: str
    # Owner/admin-set free-text description. NULL when unset.
    description: str | None = None
    owner_uin: int
    avatar_seed: int
    # Who can post in the group thread.
    #   "all"        — every member (default)
    #   "owner_only" — broadcast mode; non-owners read-only
    post_policy: str = "all"
    # Closed groups reject `/join` from a stranger — only an
    # owner-initiated invite inserts membership. Open groups
    # (default) keep the self-join + invite-link flow.
    is_closed: bool = False
    # When true, iOS hides the member roster in Group Info from
    # everyone but the owner. Display-only — `members` still ships.
    members_hidden: bool = False
    # Pinned plaintext announcement, owner/admin-editable. NULL when
    # unset. Rendered as a sticky banner above the message list so a
    # brand-new joiner (who can't see encrypted history) at least sees
    # the rules / welcome / link-of-the-day.
    pinned_text: str | None = None
    pinned_at: datetime | None = None
    pinned_by: int | None = None
    # Uploaded avatar (encrypted blob id + per-blob AES key). Both NULL
    # for legacy groups — iOS falls back to the generic glyph.
    avatar_media_id: str | None = None
    avatar_media_key: str | None = None
    created_at: datetime
    members: list["GroupMemberOut"]


class GroupMemberOut(BaseModel):
    uin: int
    nickname: str
    role: str
    # Live presence — online/away/dnd/offline. Invisible is reported as offline,
    # like everywhere else in the API.
    status: str = "offline"
    # Long-term X25519 ECDH public key + Ed25519 signing public key, base64.
    # The client uses these to encrypt-per-recipient when sending into the
    # group (Stage 2 e2ee — every member gets their own ciphertext, the
    # server sees N opaque blobs, never the plaintext).
    identity_key: str
    signing_key: str
    # Stage 3 marker — non-null means this member runs a libsignal client
    # and the sender can ride the v=2 envelope path for them (and a Sender
    # Key distribution for groups). Null means Stage 2 only.
    signal_identity_key: str | None = None


GroupOut.model_rebuild()


class CreateGroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    member_uins: list[int]


class AddMemberIn(BaseModel):
    uin: int


class GroupPatchIn(BaseModel):
    """All-optional partial update. The PATCH endpoint applies only
    the fields the caller actually populated, leaving everything
    else untouched."""
    name: str | None = Field(default=None, min_length=1, max_length=64)
    # Description update. Empty string clears it (mirrors the avatar
    # convention) — None means "leave untouched" for a partial PATCH.
    description: str | None = Field(default=None, max_length=500)
    post_policy: str | None = Field(default=None, pattern="^(all|owner_only)$")
    is_closed: bool | None = None
    members_hidden: bool | None = None
    # Pinned announcement. Empty string clears the pin; None = leave
    # untouched. Plaintext, owner/admin-editable. See model docstring.
    pinned_text: str | None = Field(default=None, max_length=500)
    # Avatar swap. To clear, send empty strings — None means "leave
    # untouched" so a partial PATCH that only flips post_policy
    # doesn't accidentally wipe the avatar.
    avatar_media_id: str | None = Field(default=None, max_length=64)
    avatar_media_key: str | None = Field(default=None, max_length=96)


async def _load_group(db: AsyncSession, group_id: int) -> Group:
    g = await db.get(Group, group_id)
    if g is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such group")
    return g


async def _members_with_users(db: AsyncSession, group_id: int) -> list[GroupMemberOut]:
    rows = (
        await db.execute(
            select(GroupMember, User)
            .join(User, User.uin == GroupMember.uin)
            .where(GroupMember.group_id == group_id)
        )
    ).all()
    out: list[GroupMemberOut] = []
    for m, u in rows:
        # Live presence: only show as their saved status if they currently have
        # a live WebSocket; otherwise force offline. Fake demo users skip this
        # gate so they appear with their seeded status. Invisible always reads
        # as offline so it stays hidden from group-mates.
        if u.is_fake:
            raw_status = u.status
        else:
            # is_online is async now (Redis-backed for cross-worker visibility).
            raw_status = u.status if await manager.is_online(u.uin) else "offline"
        visible = "offline" if raw_status == "invisible" else raw_status
        out.append(GroupMemberOut(
            uin=m.uin,
            nickname=u.nickname,
            role=m.role,
            status=visible,
            identity_key=u.identity_key,
            signing_key=u.signing_key,
            signal_identity_key=u.signal_identity_key,
        ))
    return out


async def _ensure_member(db: AsyncSession, group_id: int, uin: int) -> GroupMember:
    m = await db.scalar(
        select(GroupMember).where(
            and_(GroupMember.group_id == group_id, GroupMember.uin == uin)
        )
    )
    if m is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not a group member")
    return m


async def _ensure_admin(db: AsyncSession, group_id: int, uin: int) -> GroupMember:
    m = await _ensure_member(db, group_id, uin)
    if m.role not in ("owner", "admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin required")
    return m


async def _filter_blocked(
    db: AsyncSession, owner_uin: int, candidates: set[int]
) -> set[int]:
    """Return the subset of `candidates` blocked by `owner_uin`. Used by the
    add-member flow so neither the owner-as-admin nor any other member can
    re-introduce someone the group's creator has banned."""
    if not candidates:
        return set()
    blocked = (
        await db.execute(
            select(Contact.contact_uin).where(
                and_(
                    Contact.owner_uin == owner_uin,
                    Contact.blocked == True,  # noqa: E712
                    Contact.contact_uin.in_(candidates),
                )
            )
        )
    ).scalars().all()
    return set(blocked)


async def _can_invite_to_group(
    db: AsyncSession, *, inviter_uin: int, invitee: User
) -> bool:
    """Apply `invitee.group_invite_policy` to the would-be inviter.
    Owner-self adding themselves through `create_group` is gated
    upstream (you can't be the inviter of yourself in the add-member
    path) so this only runs for outsiders."""
    if inviter_uin == invitee.uin:
        return True
    policy = (invitee.group_invite_policy or "everyone").lower()
    if policy == "everyone":
        return True
    if policy == "nobody":
        return False
    # "contacts" — inviter must be in the invitee's contact list.
    is_contact = (
        await db.scalar(
            select(Contact.id).where(
                and_(
                    Contact.owner_uin == invitee.uin,
                    Contact.contact_uin == inviter_uin,
                    Contact.blocked == False,  # noqa: E712
                )
            )
        )
    ) is not None
    return is_contact


@router.post(
    "",
    response_model=GroupOut,
    status_code=status.HTTP_201_CREATED,
    # 5 owned groups is the hard cap (`MAX_GROUPS_PER_USER`); a
    # rate limit on top stops a user from spam-creating-and-deleting
    # to bypass the cap or to flood join-key generation.
    dependencies=[Depends(rate_limit("groups_create", 10, 3600))],
)
async def create_group(
    body: CreateGroupIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> GroupOut:
    # Cap at MAX_GROUPS_PER_USER per owner. Counts only groups *owned* by the
    # caller — being a member of someone else's group doesn't count.
    owned_count = await db.scalar(
        select(func.count()).select_from(Group).where(Group.owner_uin == uin)
    )
    if (owned_count or 0) >= MAX_GROUPS_PER_USER:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"limit reached: max {MAX_GROUPS_PER_USER} owned groups",
        )

    member_set = set(body.member_uins) | {uin}
    # Validate all members exist
    found_uins = (
        await db.execute(select(User.uin).where(User.uin.in_(member_set)))
    ).scalars().all()
    if set(found_uins) != member_set:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "unknown user in member list")

    # Don't let me create a group that pre-includes anyone I've blocked.
    blocked_initial = await _filter_blocked(db, owner_uin=uin, candidates=member_set - {uin})
    if blocked_initial:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"cannot include blocked users: {sorted(blocked_initial)}",
        )

    # Honour each invitee's group-invite policy. Without this gate
    # the policy could be sidestepped by spinning up a new group and
    # seeding the unwanted member into it on creation.
    invitees = (
        await db.execute(
            select(User).where(User.uin.in_(member_set - {uin}))
        )
    ).scalars().all()
    blocked_by_policy = [
        u.uin for u in invitees
        if not await _can_invite_to_group(db, inviter_uin=uin, invitee=u)
    ]
    if blocked_by_policy:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"these users don't accept group invites from you: {sorted(blocked_by_policy)}",
        )

    group = Group(name=body.name, owner_uin=uin, avatar_seed=hash(body.name) & 0x7FFFFFFF)
    db.add(group)
    await db.flush()

    for member_uin in member_set:
        role = "owner" if member_uin == uin else "member"
        db.add(GroupMember(group_id=group.id, uin=member_uin, role=role))
    await db.commit()
    await db.refresh(group)

    members = await _members_with_users(db, group.id)
    payload = _serialize(group, members)

    # Tell every member their group was created (or they were added).
    for m in members:
        await manager.send(m.uin, {"type": "group_created", "group": payload.model_dump(mode="json")})

    return payload


def _serialize(g: Group, members: list[GroupMemberOut]) -> GroupOut:
    """Single-source serializer so post_policy / entry_price land on
    every payload (list / get / patch / add-member / etc.)."""
    return GroupOut(
        id=g.id,
        name=g.name,
        description=g.description,
        owner_uin=g.owner_uin,
        avatar_seed=g.avatar_seed,
        post_policy=g.post_policy,
        is_closed=g.is_closed,
        members_hidden=g.members_hidden,
        pinned_text=g.pinned_text,
        pinned_at=g.pinned_at,
        pinned_by=g.pinned_by,
        avatar_media_id=g.avatar_media_id,
        avatar_media_key=g.avatar_media_key,
        created_at=g.created_at,
        members=members,
    )


@router.get("", response_model=list[GroupOut])
async def list_groups(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> list[GroupOut]:
    rows = (
        await db.execute(
            select(Group)
            .join(GroupMember, GroupMember.group_id == Group.id)
            .where(GroupMember.uin == uin)
            .order_by(Group.created_at.desc())
        )
    ).scalars().all()
    out: list[GroupOut] = []
    for g in rows:
        members = await _members_with_users(db, g.id)
        out.append(_serialize(g, members))
    return out


class GroupPreviewOut(BaseModel):
    """Lightweight info shown to a non-member who's about to join.
    Carries name + member count + owner nick so the join sheet can
    render the group without exposing membership or message history."""
    id: int
    name: str
    description: str | None = None
    member_count: int
    is_closed: bool = False
    owner_uin: int
    owner_nickname: str | None
    # Avatar fields — same shape as `GroupOut`. Returned to a
    # non-member so the share-card in chat can paint the actual
    # group picture instead of a placeholder glyph. Avatar bytes
    # are an opaque encrypted blob; making them visible here doesn't
    # leak membership or content since the blob can only be
    # decrypted with the key, which is bundled in this same payload.
    avatar_media_id: str | None = None
    avatar_media_key: str | None = None


@router.get(
    "/{group_id}/preview",
    response_model=GroupPreviewOut,
    dependencies=[Depends(rate_limit("group_preview", 120, 60))],
)
async def preview_group(
    group_id: int,
    _viewer_uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> GroupPreviewOut:
    g = await _load_group(db, group_id)
    owner = await db.get(User, g.owner_uin)
    # Ghost-member filter via join with users — same reasoning as the
    # search counter above. Without it, paid-group previews advertised
    # inflated member counts that vanished the moment the user joined.
    member_count = await db.scalar(
        select(func.count(GroupMember.id))
        .join(User, User.uin == GroupMember.uin)
        .where(GroupMember.group_id == group_id)
    )
    return GroupPreviewOut(
        id=g.id,
        name=g.name,
        description=g.description,
        member_count=int(member_count or 0),
        is_closed=g.is_closed,
        owner_uin=g.owner_uin,
        owner_nickname=owner.nickname if owner else None,
        avatar_media_id=g.avatar_media_id,
        avatar_media_key=g.avatar_media_key,
    )


# Must be registered before the `/{group_id}` catch-all so the literal
# segment doesn't get coerced into the int path-parameter and 422'd.
@router.get(
    "/search",
    response_model=list[GroupPreviewOut],
    dependencies=[Depends(rate_limit("groups_search", 60, 60))],
)
async def search_groups(
    q: str,
    limit: int = 20,
    viewer_uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> list[GroupPreviewOut]:
    """Find joinable groups by name substring (or exact id when `q` is
    digits). Used by the iOS Add view to surface foreign groups the
    user could join — same payload shape as `/{group_id}/preview` so
    the rendered row + tap-into-JoinGroupSheet flow doesn't have to
    branch on lookup mode. Caller's own groups are filtered out
    server-side."""
    needle = q.strip()
    if len(needle) < 2:
        return []
    capped = max(1, min(limit, 50))
    clauses = [Group.name.ilike(f"%{needle}%")]
    if needle.isdigit():
        try:
            clauses.append(Group.id == int(needle))
        except ValueError:
            pass
    # Exclude groups the caller is already a member of — those already
    # show up in the local-groups section of the Add view.
    own_group_ids = (
        await db.execute(
            select(GroupMember.group_id).where(GroupMember.uin == viewer_uin)
        )
    ).scalars().all()
    rows = (
        await db.execute(
            select(Group)
            .where(or_(*clauses))
            .where(Group.id.notin_(own_group_ids) if own_group_ids else True)
            .order_by(Group.created_at.desc())
            .limit(capped)
        )
    ).scalars().all()
    if not rows:
        return []
    owner_uins = {g.owner_uin for g in rows}
    owners = (
        await db.execute(select(User).where(User.uin.in_(owner_uins)))
    ).scalars().all()
    owner_nick = {u.uin: u.nickname for u in owners}
    # Join with users so ghost members (rows whose user has been
    # burned/migrated and not yet swept by the legacy cleanup) don't
    # inflate the visible count — testers were seeing "2 members" in
    # search, joining, and finding themselves alone in the room.
    member_count_rows = (
        await db.execute(
            select(GroupMember.group_id, func.count(GroupMember.id))
            .join(User, User.uin == GroupMember.uin)
            .where(GroupMember.group_id.in_([g.id for g in rows]))
            .group_by(GroupMember.group_id)
        )
    ).all()
    counts = {gid: int(c) for gid, c in member_count_rows}
    return [
        GroupPreviewOut(
            id=g.id,
            name=g.name,
            description=g.description,
            member_count=counts.get(g.id, 0),
            is_closed=g.is_closed,
            owner_uin=g.owner_uin,
            owner_nickname=owner_nick.get(g.owner_uin),
            avatar_media_id=g.avatar_media_id,
            avatar_media_key=g.avatar_media_key,
        )
        for g in rows
    ]


@router.get("/{group_id}", response_model=GroupOut)
async def get_group(
    group_id: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> GroupOut:
    await _ensure_member(db, group_id, uin)
    g = await _load_group(db, group_id)
    members = await _members_with_users(db, g.id)
    return _serialize(g, members)


@router.post(
    "/{group_id}/join",
    response_model=GroupOut,
    # Anti-brute-force on paid groups: a script tries every join_key
    # to find one that's free, or tries to repeat-join a paid group
    # to drain a sloppy retry handler. 30/hr is well above any
    # legitimate "tap join, sheet errored, tap again" loop.
    dependencies=[Depends(rate_limit("groups_join", 30, 3600))],
)
async def join_group(
    group_id: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> GroupOut:
    """Self-join. Open groups accept; closed groups require an
    owner-initiated invite via `/members`."""
    g = await _load_group(db, group_id)
    existing = await db.scalar(
        select(GroupMember).where(
            and_(GroupMember.group_id == group_id, GroupMember.uin == uin)
        )
    )
    if existing is not None:
        members = await _members_with_users(db, group_id)
        return _serialize(g, members)

    blocked = await _filter_blocked(db, owner_uin=g.owner_uin, candidates={uin})
    if blocked:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"code": "blocked"},
        )

    if g.is_closed and uin != g.owner_uin:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"code": "group_closed"},
        )

    db.add(GroupMember(group_id=group_id, uin=uin, role="member"))
    await db.commit()

    members = await _members_with_users(db, group_id)
    payload = _serialize(g, members)
    for m in members:
        await manager.send(m.uin, {"type": "group_membership_changed", "group": payload.model_dump(mode="json")})
    return payload


@router.post("/{group_id}/members", response_model=GroupOut)
async def add_member(
    group_id: int,
    body: AddMemberIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> GroupOut:
    # Any current member can pull in friends — admin gate would make tiny groups
    # feel locked in. Owner still controls the block list, which is enforced below.
    await _ensure_member(db, group_id, uin)
    g = await _load_group(db, group_id)
    user = await db.get(User, body.uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")

    # If the group's owner has blocked this user, nobody — not even another
    # admin — can re-introduce them. Mirrors the contact-list block semantics.
    blocked = await _filter_blocked(db, owner_uin=g.owner_uin, candidates={body.uin})
    if blocked:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "the group owner has blocked this user",
        )

    # Honour the invitee's own group-invite policy. "everyone"
    # (default) lets anyone add them; "contacts" requires the
    # *inviter* to already be a contact of the invitee; "nobody"
    # blocks all unsolicited adds. The inviter still has the option
    # of asking the invitee to add themselves later — the policy is
    # only about *unsolicited* drops into a group.
    if not await _can_invite_to_group(db, inviter_uin=uin, invitee=user):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "this user only accepts group invites from their contacts"
            if (user.group_invite_policy or "everyone") == "contacts"
            else "this user does not accept group invites",
        )

    existing = await db.scalar(
        select(GroupMember).where(
            and_(GroupMember.group_id == group_id, GroupMember.uin == body.uin)
        )
    )
    if existing is None:
        db.add(GroupMember(group_id=group_id, uin=body.uin, role="member"))
        await db.commit()

    g = await _load_group(db, group_id)
    members = await _members_with_users(db, group_id)
    payload = _serialize(g, members)
    for m in members:
        await manager.send(m.uin, {"type": "group_membership_changed", "group": payload.model_dump(mode="json")})
    return payload


@router.delete("/{group_id}/members/{member_uin}")
async def remove_member(
    group_id: int,
    member_uin: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    me = await _ensure_member(db, group_id, uin)
    g = await _load_group(db, group_id)
    is_self_leave = member_uin == uin
    if not is_self_leave and me.role not in ("owner", "admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin required")
    if member_uin == g.owner_uin and not is_self_leave:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot remove the owner")

    target = await db.scalar(
        select(GroupMember).where(
            and_(GroupMember.group_id == group_id, GroupMember.uin == member_uin)
        )
    )
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not in group")
    await db.delete(target)
    await db.commit()

    # If the owner leaves and group still has members, hand the crown to the oldest one.
    if member_uin == g.owner_uin:
        next_owner = await db.scalar(
            select(GroupMember).where(GroupMember.group_id == group_id).order_by(GroupMember.joined_at.asc())
        )
        if next_owner is not None:
            next_owner.role = "owner"
            g.owner_uin = next_owner.uin
            await db.commit()
        else:
            await db.delete(g)
            await db.commit()
            return {"deleted": True}

    members = await _members_with_users(db, group_id)
    payload = _serialize(g, members)
    # Notify the remaining members + the just-removed user. The
    # ex-member needs to learn the membership change so their iOS
    # client drops the group from `vm.groups` immediately. Earlier
    # this synthesised a bogus `GroupMemberOut(uin=…, nickname="",
    # role="ex")` to thread the WS broadcast through the same loop —
    # which raised ValidationError under Pydantic v2 because
    # identity_key/signing_key are required fields, and the leave
    # endpoint 500'd. Skip the model entirely and just iterate
    # raw uins.
    notify_uins = {m.uin for m in members}
    notify_uins.add(member_uin)
    for to_uin in notify_uins:
        await manager.send(to_uin, {"type": "group_membership_changed", "group": payload.model_dump(mode="json")})
    return {"deleted": False, "left_uin": member_uin}


@router.patch("/{group_id}", response_model=GroupOut)
async def patch_group(
    group_id: int,
    body: GroupPatchIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> GroupOut:
    # Rename + admin-only fields share one endpoint; the post_policy
    # and entry_price levers are owner-only (they affect everyone's
    # experience), name change is admin-or-better.
    me = await _ensure_member(db, group_id, uin)
    g = await _load_group(db, group_id)

    if body.name is not None:
        if me.role not in ("owner", "admin"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "admin required")
        g.name = body.name
    if body.description is not None:
        # Same admin-or-owner gate as name — it's group metadata.
        # Empty/whitespace-only string clears the description back
        # to NULL so the UI hides the blurb entirely.
        if me.role not in ("owner", "admin"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "admin required")
        cleaned = body.description.strip()
        g.description = cleaned or None
    if body.post_policy is not None:
        if g.owner_uin != uin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "owner only")
        g.post_policy = body.post_policy
    if body.is_closed is not None:
        if g.owner_uin != uin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "owner only")
        g.is_closed = body.is_closed
    if body.members_hidden is not None:
        if g.owner_uin != uin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "owner only")
        g.members_hidden = body.members_hidden
    if body.pinned_text is not None:
        # Owner OR admin can pin / change / clear the announcement.
        # Empty / whitespace-only string clears the pin entirely so
        # the iOS banner disappears.
        if me.role not in ("owner", "admin"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "admin required")
        cleaned = body.pinned_text.strip()
        if cleaned:
            g.pinned_text = cleaned
            g.pinned_at = datetime.now(timezone.utc)
            g.pinned_by = uin
        else:
            g.pinned_text = None
            g.pinned_at = None
            g.pinned_by = None

    # Avatar swap: any admin can change it (matches the name-change
    # gate). Empty string clears. Both fields must move together —
    # the blob is useless without its key and vice versa.
    if body.avatar_media_id is not None or body.avatar_media_key is not None:
        if me.role not in ("owner", "admin"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "admin required")
        new_id = (body.avatar_media_id or "").strip() or None
        new_key = (body.avatar_media_key or "").strip() or None
        # Reject mismatched pairs so the client can't accidentally
        # leave the avatar in a half-set state.
        if (new_id is None) != (new_key is None):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "avatar_media_id and avatar_media_key must be set together",
            )
        g.avatar_media_id = new_id
        g.avatar_media_key = new_key

    await db.commit()
    members = await _members_with_users(db, group_id)
    payload = _serialize(g, members)
    for m in members:
        await manager.send(m.uin, {"type": "group_membership_changed", "group": payload.model_dump(mode="json")})
    return payload


@router.delete("/{group_id}")
async def delete_group(
    group_id: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    g = await _load_group(db, group_id)
    if g.owner_uin != uin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "owner only")
    members = (
        await db.execute(select(GroupMember.uin).where(GroupMember.group_id == group_id))
    ).scalars().all()
    await db.delete(g)
    await db.commit()
    for member_uin in members:
        await manager.send(member_uin, {"type": "group_deleted", "group_id": group_id})
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Group message views (Telegram-style counter under each message)
# ---------------------------------------------------------------------------


class ViewPingIn(BaseModel):
    """Single-message view-ack. iOS fires this when a bubble in a
    closed group enters the viewport for the first time."""
    message_id: str


class ViewCountsIn(BaseModel):
    """Batch fetch — current ChatView's visible window asks for view
    counts of all message IDs at once instead of one round-trip per
    bubble. The map can be partial: missing keys mean zero views."""
    message_ids: list[str]


class ViewCountsOut(BaseModel):
    counts: dict[str, int]


@router.post("/{group_id}/messages/{message_id}/viewed", status_code=status.HTTP_204_NO_CONTENT)
async def mark_message_viewed(
    group_id: int,
    message_id: str,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Record that the caller has seen `message_id` in `group_id`.
    Idempotent: re-posting from the same caller is a no-op. Only
    broadcast-mode groups (post_policy='owner_only') participate in
    the view-count feature — in any-member-can-post groups it would
    feel like surveillance. iOS gates this client-side too; server
    rejects with 404 as a belt-and-suspenders check."""
    g = await db.get(Group, group_id)
    if g is None or g.post_policy != "owner_only":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "broadcast group not found")
    member = await db.scalar(
        select(GroupMember.id).where(
            and_(GroupMember.group_id == group_id, GroupMember.uin == uin)
        )
    )
    if member is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not a member")
    existing = await db.scalar(
        select(GroupMessageView.id).where(
            and_(
                GroupMessageView.group_id == group_id,
                GroupMessageView.message_id == message_id,
                GroupMessageView.viewer_uin == uin,
            )
        )
    )
    if existing is not None:
        return
    db.add(GroupMessageView(
        group_id=group_id,
        message_id=message_id,
        viewer_uin=uin,
        viewed_at=datetime.now(timezone.utc),
    ))
    await db.commit()


@router.post("/{group_id}/view-counts", response_model=ViewCountsOut)
async def view_counts(
    group_id: int,
    body: ViewCountsIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> ViewCountsOut:
    """Aggregate view counts per message in batch. Members of a
    broadcast-mode group (post_policy='owner_only') can query; the
    response is just `{message_id: count}`. Identity of viewers is
    never surfaced. Non-broadcast groups 404."""
    g = await db.get(Group, group_id)
    if g is None or g.post_policy != "owner_only":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "broadcast group not found")
    member = await db.scalar(
        select(GroupMember.id).where(
            and_(GroupMember.group_id == group_id, GroupMember.uin == uin)
        )
    )
    if member is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not a member")
    if not body.message_ids:
        return ViewCountsOut(counts={})
    rows = (await db.execute(
        select(GroupMessageView.message_id, func.count(GroupMessageView.id))
        .where(GroupMessageView.group_id == group_id)
        .where(GroupMessageView.message_id.in_(body.message_ids))
        .group_by(GroupMessageView.message_id)
    )).all()
    return ViewCountsOut(counts={mid: cnt for mid, cnt in rows})
