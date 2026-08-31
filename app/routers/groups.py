"""Groups: create/join/manage, plus the two discovery surfaces.

CLOSED-GROUP DISCOVERABILITY — how the share link became a real capability.

`/{group_id}/preview` is optional-auth on purpose: a cross-island client with
no account on this island still has to render the join card, so possession of
the link is what authorises the read. That reasoning only holds if the link is
unguessable, and originally it was not — group ids are sequential integers, so
the "capability" was a number an attacker could count to. Walking the id space
enumerated every CLOSED group on the island, each with its name and its owner's
UIN and nickname; `/search` leaked the same set by name substring.

Now: `/search` never returns closed groups, and every group carries a
`share_token`. A link is `.../g/<id>?k=<token>`, and a closed group is only
described to a member or to someone presenting the token.

ROLLOUT (this is the part to finish):
Clients build share links themselves, so links already in the wild — and links
made by client builds that predate the token — carry no `k`. Until token-aware
clients ship on iOS, Android and web, a tokenless preview of a closed group
gets a REDACTED card (no name, no owner, no member count) rather than a 404:
enumeration returns nothing worth having, while a legitimate invitee with an
old link still sees that there is a closed group to ask about.
Once those clients are out, set `RCQ_REQUIRE_CLOSED_GROUP_TOKEN=true` and a
tokenless preview becomes an ordinary 404 — indistinguishable from a group that
does not exist, which is the end state.
"""

import os
import base64
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin, current_uin_optional
from app.models.capability import UserCapability
from app.models.contact import Contact
from app.models.group import Group, GroupMember, OfflineGroupMessage
from app.models.group_log import GroupLog, GroupLogCursor, GroupSeq
from app.services.group_log import seed_cursors_on_join
from app.models.user import User, card_openable_fields
from app.services.connection_manager import manager

# Hard-enforce the closed-group share token (404 for a tokenless preview)
# instead of serving the redacted card. Stays FALSE until token-aware
# clients have shipped on iOS, Android and web — see the module docstring.
_REQUIRE_CLOSED_GROUP_TOKEN: bool = (
    os.environ.get("RCQ_REQUIRE_CLOSED_GROUP_TOKEN", "false").strip().lower()
    in {"1", "true", "yes"}
)

# Above this member count the roster stops carrying live presence — see the
# comment in `_members_with_users`. Env-tunable so a self-hoster running one
# big trusted group can raise it.
PRESENCE_ROSTER_LIMIT: int = int(
    os.environ.get("RCQ_PRESENCE_ROSTER_LIMIT", "100")
)


router = APIRouter(prefix="/groups", tags=["groups"])


class GroupOut(BaseModel):
    id: int
    name: str
    # Voluntary catalog: the owner chose to list this room publicly, which is
    # the only reason search may match it (stage 6, founder decision 30.08).
    in_catalog: bool = False
    # Sealed room identity (stage 6 phase 2, docs/group-state-seal-design.md):
    # an opaque blob the members encrypt under the room state key, and its
    # strictly-increasing version. The island stores bytes and does version
    # arithmetic; it cannot read either.
    state_blob: str | None = None
    state_ver: int = 0
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
    # Owner-set content policy: links clickable / files sendable in this
    # group. Client-honored (sealed envelopes are opaque to the server).
    links_allowed: bool = True
    files_allowed: bool = True
    # Slowmode step in seconds (0 = off). Server-enforced for
    # authenticated senders; moderators and the owner are exempt.
    slowmode_sec: int = 0
    # Anti-spam age floor in hours (0 = off): an account younger than this
    # may read but not post. Same enforcement shape as slowmode.
    min_account_age_hours: int = 0
    # Pinned plaintext announcement, owner/admin-editable. NULL when
    # unset. Rendered as a sticky banner above the message list so a
    # brand-new joiner (who can't see encrypted history) at least sees
    # the rules / welcome / link-of-the-day.
    pinned_text: str | None = None
    pinned_at: datetime | None = None
    # (`pinned_by` left the wire and the column on 2026-08-22: the UIN of
    # whoever set the pin, which no client has ever rendered.)
    # Uploaded avatar (encrypted blob id + per-blob AES key). Both NULL
    # for legacy groups — iOS falls back to the generic glyph.
    avatar_media_id: str | None = None
    avatar_media_key: str | None = None
    # Unguessable half of this group's share link. Only ever sent on
    # member-facing payloads (this model is never returned to a non-member),
    # so it behaves like a capability the members hold and can pass on.
    # Clients append it as `?k=` when building an invite link; the preview
    # endpoint requires it before describing a CLOSED group to a stranger.
    share_token: str | None = None
    created_at: datetime
    # How many people are in the group, always present.
    #
    # Exists so a caller can ask for the list WITHOUT the roster and still
    # render "1869 members" — which is the only thing most screens do with a
    # roster they paid a megabyte for.
    member_count: int = 0
    members: list["GroupMemberOut"]


class GroupMemberOut(BaseModel):
    uin: int
    nickname: str
    role: str
    # Granular moderator caps the owner granted this member (subset of
    # delete|members|info). Empty for plain members; the owner implicitly
    # has all. Clients enforce `delete` (sealed sender) + render the toggles.
    permissions: list[str] = []
    # Live presence — online/away/dnd/offline. Invisible is reported as offline,
    # like everywhere else in the API.
    status: str = "offline"
    # Profile picture. Gated by MEMBERSHIP rather than by the contact list:
    # sharing a group is the relationship here, the same one that already
    # exposes the nickname on this row.
    avatar_media_id: str | None = None
    avatar_media_key: str | None = None
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
    # This member's client(s) understand the sender-keys group path (gmsg
    # broadcast + skdm distribution). Senders seal SKDMs to capable members
    # and keep the legacy per-member fan-out for the rest (dual-send).
    sender_keys: bool = False
    # May the caller open THIS member's profile card (founder item 22)? A
    # member list is the first surface the setting names, and it is the one
    # place where the answer cannot simply be "hide the row".
    #
    # ⚠ NOTHING ELSE ON THIS ROW IS GATED, on purpose. The roster has to
    # carry every member's uin and both keys (group ciphertext is sealed per
    # recipient, so a missing member is a member who cannot be written to),
    # and a roster of bare numbers is not a member list anybody can use. The
    # picture stays for the same reason it was added: it is gated by
    # MEMBERSHIP, `/users/{uin}/info` hands it to co-members on the same
    # rule, and the two disagreeing about one person is a bug we already
    # fixed once. So the card policy changes exactly one thing here —
    # whether the name is a link.
    #
    # ⚠ NULL means "this payload has no viewer to answer for", not "yes".
    # Every client helper fails OPEN on absent, which is the right default
    # for a hint whose only job is to avoid drawing a dead link. It is null
    # on the BROADCAST payloads (`group_created`,
    # `group_membership_changed`): those go to every member at once, so a
    # per-viewer verdict computed for whoever triggered the mutation would
    # be a wrong answer for everybody else. The read endpoints
    # (`GET /groups`, `GET /groups/{id}`) fill it, and a client repaints
    # from those.
    profile_openable: bool | None = None


GroupOut.model_rebuild()


class CreateGroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    member_uins: list[int]


class AddMemberIn(BaseModel):
    uin: int


# The slowmode picker every client shows: off, 5s, 10s, 30s, 1min, 5min, 1h.
# 300 and 3600 joined on 29.08: Android 0.151 shipped them in its picker while
# this set still ended at 60, so the two big steps 422'd silently (#809). The
# set grows, never shrinks - a client with the shorter menu simply renders the
# stored number as seconds.
_SLOWMODE_STEPS = {0, 5, 10, 30, 60, 300, 3600}
# Off, 1h, 6h, day, 3 days, week, 30 days.
_AGE_GATE_STEPS = {0, 1, 6, 24, 72, 168, 720}


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
    # Owner-only content policy toggles (clients honor them; the server
    # can't see inside sealed envelopes).
    links_allowed: bool | None = None
    files_allowed: bool | None = None
    # Slowmode step, seconds. Fixed menu of steps rather than a free
    # integer so every client renders the same picker.
    slowmode_sec: int | None = None
    # Voluntary catalog listing. Publishing a room's name is group metadata
    # in the same sense as the name itself, so it shares the admin-or-owner
    # gate ("info") rather than the owner-only one.
    in_catalog: bool | None = None

    # Anti-spam age floor, hours. Fixed menu of steps, same reasoning as
    # slowmode: every client renders the same picker.
    min_account_age_hours: int | None = None

    @field_validator("slowmode_sec")
    @classmethod
    def _slowmode_step(cls, v: int | None) -> int | None:
        if v is not None and v not in _SLOWMODE_STEPS:
            raise ValueError(f"slowmode_sec must be one of {sorted(_SLOWMODE_STEPS)}")
        return v

    @field_validator("min_account_age_hours")
    @classmethod
    def _age_gate_step(cls, v: int | None) -> int | None:
        if v is not None and v not in _AGE_GATE_STEPS:
            raise ValueError(f"min_account_age_hours must be one of {sorted(_AGE_GATE_STEPS)}")
        return v
    # Pinned announcement. Empty string clears the pin; None = leave
    # untouched. Plaintext, owner/admin-editable. See model docstring.
    pinned_text: str | None = Field(default=None, max_length=4096)
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


def _armed_join_stamp(g: Group | None) -> datetime | None:
    """When a new member joined, but ONLY for a room whose anti-spam floor is
    armed, and only to the day (#833, founder 31.08).

    Both halves are the privacy budget: a room nobody armed records nothing,
    and an armed one records "joined on the 27th" rather than the minute a
    relationship began. Floored rather than rounded, so the wait can end up to
    a day short of nominal but never longer than the owner asked for.
    """
    if g is None or (g.min_account_age_hours or 0) <= 0:
        return None
    now = datetime.now(timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


async def _members_with_users(
    db: AsyncSession, group_id: int, *, viewer_uin: int | None = None
) -> list[GroupMemberOut]:
    """The roster. `viewer_uin` is who the payload is FOR, and it is optional
    because most callers here build a payload for everybody at once.

    Pass it on the read endpoints, where exactly one person is asking, and the
    rows come back carrying `profile_openable`. Leave it out on the mutation
    endpoints, whose payload is broadcast to the whole group: a verdict
    computed for the member who pressed the button is not an answer about
    anybody else, and clients treat the absent field as "unknown, draw the
    link" — which is what they did before item 22 existed.
    """
    # ⚠ COLUMNS, not entities. `select(GroupMember, User)` hydrates two ORM
    # objects per member with an identity map behind them: on the flagship
    # roster that is 287ms against 58ms for the same rows read as columns
    # (measured on prod, 2200 members). Nothing below needs a live instance —
    # every field used is listed right here, and the one policy verdict goes
    # through `card_openable_fields` so it cannot drift from the User method.
    rows = (
        await db.execute(
            select(
                GroupMember.uin,
                GroupMember.role,
                GroupMember.permissions,
                User.nickname,
                User.status,
                User.identity_key,
                User.signing_key,
                User.signal_identity_key,
                User.avatar_media_id,
                User.avatar_media_key,
                User.profile_card_policy,
            )
            .join(User, User.uin == GroupMember.uin)
            .where(GroupMember.group_id == group_id)
        )
    ).all()
    # One batched lookup for the sender-keys capability of every member —
    # senders use it to split the dual-send (broadcast vs legacy fan-out).
    capable: set[int] = set(
        (
            await db.execute(
                select(UserCapability.uin).where(
                    UserCapability.uin.in_([r.uin for r in rows]),
                    UserCapability.sender_keys.is_(True),
                )
            )
        ).scalars().all()
    ) if rows else set()
    # One presence lookup for the whole roster. Per-member `is_online` here was
    # a Redis round trip each, so serialising the 1800-member beta group cost
    # 1800 of them, on an endpoint every client polls. Prod was doing ~6900
    # SISMEMBER/s with twenty people online, which was most of the CPU.
    #
    # ⚠ Above PRESENCE_ROSTER_LIMIT members the roster reports everyone as
    # offline instead (2026-08-11). The roster has to carry every member's UIN
    # and keys — group ciphertext is sealed per recipient, so hiding the list
    # would break encryption, not protect anybody. Live presence is different:
    # it is the one field nothing else needs, and in a group the size of the
    # beta one it hands any member who just registered a pollable online/offline
    # feed for ~1900 accounts, which is enough to derive sleep patterns and time
    # zones. Small groups keep the dots: there the roster is people you know,
    # and knowing who is around is the point.
    online = (
        await manager.online_subset(r.uin for r in rows)
        if len(rows) <= PRESENCE_ROSTER_LIMIT
        else set()
    )
    # Card gate (item 22), and the whole design of it is in when this query
    # does NOT run. "everyone" and "nobody" are answerable from the row we
    # already loaded; only "contacts" needs the graph. So look the graph up
    # once for the whole roster, and only when the roster actually holds
    # somebody on "contacts" — which on a group of default accounts is never.
    #
    # Metadata: what is read is the VIEWER'S OWN contact edges, narrowed to
    # people they can already see in this roster, to answer their own request.
    # `GET /contacts` hands them the same edges wholesale. Nothing is written,
    # nothing is logged, and no per-pair state is created — the alternative
    # (computing verdicts at fan-out time) would have had the island evaluate
    # members x viewers relationships on every membership change instead.
    contact_set: set[int] = set()
    if viewer_uin is not None:
        gated = [
            r.uin for r in rows
            if (r.profile_card_policy or "everyone") == "contacts" and r.uin != viewer_uin
        ]
        if gated:
            contact_set = set(
                (
                    await db.scalars(
                        select(Contact.contact_uin).where(
                            Contact.owner_uin == viewer_uin,
                            Contact.contact_uin.in_(gated),
                        )
                    )
                ).all()
            )
    out: list[GroupMemberOut] = []
    for r in rows:
        # Live presence: only show as their saved status if they currently have
        # a live WebSocket; otherwise force offline. Fake demo users skip this
        # Invisible always reads as offline so it stays hidden from group-mates.
        raw_status = r.status if r.uin in online else "offline"
        visible = "offline" if raw_status == "invisible" else raw_status
        out.append(GroupMemberOut(
            uin=r.uin,
            nickname=r.nickname,
            avatar_media_id=r.avatar_media_id,
            avatar_media_key=r.avatar_media_key,
            role=r.role,
            permissions=_perm_list(r.permissions),
            status=visible,
            identity_key=r.identity_key,
            signing_key=r.signing_key,
            signal_identity_key=r.signal_identity_key,
            sender_keys=r.uin in capable,
            profile_openable=(
                None if viewer_uin is None
                else card_openable_fields(
                    r.uin, r.profile_card_policy,
                    viewer_uin=viewer_uin, is_contact=r.uin in contact_set,
                )
            ),
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


# Granular moderator capabilities the owner grants per member:
#   delete  — delete ANY member's message (enforced client-side: sealed sender)
#   members — remove members
#   info    — edit group name / description / avatar / pinned announcement
_GROUP_PERMS = ("delete", "members", "info")


def _perm_list(raw: str | None) -> list[str]:
    """Parse the stored comma-joined permission string to a clean list,
    dropping anything not in the known set."""
    return [p for p in (raw or "").split(",") if p in _GROUP_PERMS]


def _member_can(g: Group, m: GroupMember, perm: str) -> bool:
    """The owner can do everything; any other member needs the granted cap."""
    return m.uin == g.owner_uin or perm in _perm_list(m.permissions)


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
    # No per-user owned-groups cap (removed 2026-06-07 — power users / community
    # organizers legitimately own many). The rate limit below (10/hour) still
    # stops spam-creation and join-key flooding.
    dependencies=[Depends(rate_limit("groups_create", 10, 3600))],
)
async def create_group(
    body: CreateGroupIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> GroupOut:

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

    group = Group(
        name=body.name,
        owner_uin=uin,
        avatar_seed=hash(body.name) & 0x7FFFFFFF,
        # Minted at creation so a group is shareable the moment it exists, and
        # so the token predates any decision to close the group later.
        share_token=secrets.token_urlsafe(16)[:22],
    )
    db.add(group)
    await db.flush()

    for member_uin in member_set:
        role = "owner" if member_uin == uin else "member"
        db.add(GroupMember(group_id=group.id, uin=member_uin, role=role))
    await db.flush()
    for member_uin in member_set:
        await seed_cursors_on_join(db, group.id, member_uin)
    await db.commit()
    await db.refresh(group)

    members = await _members_with_users(db, group.id)
    payload = _serialize(group, members)

    # Tell every member their group was created (or they were added).
    for m in members:
        await manager.send(m.uin, {"type": "group_created", "group": payload.model_dump(mode="json")})

    return payload


# What a serialised member costs on the wire, near enough to price a fan-out
# with: two base64 keys, a nickname and the flags, measured at ~350 bytes.
ROSTER_BYTES_PER_MEMBER = 350

# What ONE `/account/migrate` may publish in group snapshots before the rest of
# its groups fall back to the compact form. The per-group limit below bounds a
# group; this bounds the product of (groups x members x online recipients),
# which is what a migration actually spends. 4 MB is a couple of hundred
# ordinary rooms' worth and cannot stall the cluster; see the ⚠⚠ in
# `broadcast_roster_rekey`.
REKEY_SNAPSHOT_BUDGET_BYTES = 4 * 1024 * 1024

# Above this many members the full group snapshot is too expensive to push.
# It runs about 350 bytes per member and the broadcast sends it once PER
# member, so on the 1750-member beta group a single join turned into roughly
# a gigabyte through the pub/sub channel — which every worker then parses,
# stalling delivery of everything else behind it. Measured 2026-08-03: fanout
# latency spiking to 29 seconds during group churn, which for call signalling
# (no REST fallback) is indistinguishable from the message being lost.
SNAPSHOT_BROADCAST_LIMIT = 100


async def _broadcast_membership(
    group_id: int,
    members: list[GroupMemberOut],
    payload: GroupOut,
    extra_uins: set[int] | None = None,
) -> set[int]:
    """Tell a group that its membership changed.

    Small groups get the whole snapshot, which is what clients upsert
    directly. Large ones get the group id alone: a client that does not know
    the compact form reads `group`, finds nothing and does nothing, picking
    the change up on its next refresh. A slightly stale member list beats
    stalling the whole cluster for seconds.

    Returns who was online at publish time, which every caller but
    `broadcast_roster_rekey` ignores; that one prices its next group with it.
    """
    uins = [m.uin for m in members] + sorted(extra_uins or ())
    if len(members) <= SNAPSHOT_BROADCAST_LIMIT:
        body: dict = {
            "type": "group_membership_changed",
            "group": payload.model_dump(mode="json"),
        }
    else:
        # `owner_uin` rides along even in the compact form, and it is the one
        # field worth the extra bytes: who owns the room is not only a label,
        # it decides which moderator actions a CLIENT honours (the `delete`
        # capability is client-enforced, because sealed sender means the server
        # never learns who deleted what). A big group that learned about a
        # transfer only on its next `GET /groups` went on honouring the FORMER
        # owner's deletes cluster-wide until then.
        body = {
            "type": "group_membership_changed",
            "group_id": group_id,
            "owner_uin": payload.owner_uin,
        }
    return await manager.fanout(uins, body)


async def broadcast_roster_rekey(db: AsyncSession, uin: int) -> list[int]:
    """Tell every group `uin` belongs to that its roster moved under it.

    For `/account/migrate`, which re-keys `Group.owner_uin` and
    `GroupMember.uin` onto the new number and, until 2026-08-23, told nobody
    but the migrating account's own sockets (`account_burned`). Everyone else's
    cached roster kept naming the OLD number, and `POST /messages/group-sealed`
    filters the payload entries against the LIVE roster, so a sender working
    from that cache addressed a copy to a number that no longer exists, the
    island dropped that entry without an error (it cannot error: sealed sender
    means it does not know who is asking) and the migrated member simply never
    got the message. The sender saw a smaller `delivered` count and nothing
    else. It lasted until each sender independently refetched.

    Same event and the same size rule as any other roster change (§7.4.5), so
    no client needs new code: a member who already upserts a
    `group_membership_changed` snapshot picks the new number up at once.

    ⚠ THE FAN-OUT COST, and what was chosen. One migration touches every group
    the account is in, so everything here is per group and multiplies. Three
    decisions hold it down:

      * a group over SNAPSHOT_BROADCAST_LIMIT members never gets the roster
        serialised for it. `_broadcast_membership` would send it the compact
        form anyway, but its callers build the full `GroupOut` first, and on
        the 1750-member flagship group that is a join over the whole roster
        plus a capability lookup plus a presence lookup, all of it paid to send a
        four-key dict. Here the big-group branch reads the member UINs and the
        owner, and nothing else;
      * delivery is `manager.fanout`, which publishes only to the members ONLINE
        at that moment, in one pipelined round trip per group. The bytes scale
        with who is actually connected, not with how big the groups are;
      * nothing is queued for offline members and nothing needs to be. A
        client re-reads its groups on reconnect, which is the same path that
        already covers a nudge missed while the socket was down.

    What a big group's members therefore get is the compact form, which carries
    no roster: they learn the new number on their next `GET /groups`, exactly
    as they do for an ordinary join or leave. That is the accepted trade
    everywhere else in this module and there is no reason for a migration to
    buy a better one at a hundred times the price.

    ⚠⚠ AND THE THREE ARE NOT ENOUGH ON THEIR OWN, because the first of them
    bounds ONE group and this loop multiplies. Nothing caps how many groups an
    account is in (`groups_join` is 30/h and being ADDED is free), and
    `/account/migrate` has no cooldown by default, so an account in 200 groups
    of a hundred members produces two hundred full roster serialisations, each
    published once per online member: on the order of hundreds of megabytes
    into the pub/sub channel that every worker then parses, from a single
    request, repeatable back to back. That is the 2026-08-03 incident again,
    reached by multiplication instead of by size. So the snapshot branch also
    spends from a BUDGET for the whole call (`REKEY_SNAPSHOT_BUDGET_BYTES`),
    priced at what actually went out: bytes per member times members times the
    recipients who were online. Once it is spent every remaining group takes
    the compact branch, whose cost does not depend on the roster at all.

    Returns the group ids it notified, for the caller's log line. Never raises:
    a failed nudge must not turn a committed migration into a 500 (the account
    has already moved), and the fallback is the refresh clients already do.
    """
    gids = (
        await db.execute(select(GroupMember.group_id).where(GroupMember.uin == uin))
    ).scalars().all()
    notified: list[int] = []
    spent = 0
    for gid in gids:
        g = await db.get(Group, gid)
        if g is None:
            # A membership row whose group is gone. Nothing to tell.
            continue
        n = await db.scalar(
            select(func.count()).select_from(GroupMember).where(GroupMember.group_id == gid)
        )
        if (n or 0) <= SNAPSHOT_BROADCAST_LIMIT and spent < REKEY_SNAPSHOT_BUDGET_BYTES:
            members = await _members_with_users(db, gid)
            online = await _broadcast_membership(gid, members, _serialize(g, members))
            spent += ROSTER_BYTES_PER_MEMBER * len(members) * max(len(online), 1)
        else:
            member_uins = (
                await db.execute(
                    select(GroupMember.uin).where(GroupMember.group_id == gid)
                )
            ).scalars().all()
            await manager.fanout(
                [int(u) for u in member_uins],
                {
                    "type": "group_membership_changed",
                    "group_id": gid,
                    "owner_uin": g.owner_uin,
                },
            )
        notified.append(gid)
    return notified


def _serialize(g: Group, members: list[GroupMemberOut], member_count: int | None = None) -> GroupOut:
    """Single-source serializer so post_policy / entry_price land on
    every payload (list / get / patch / add-member / etc.).

    `member_count` is passed separately for the roster-less list, where the
    count is known but the members deliberately are not."""
    return GroupOut(
        id=g.id,
        name=g.name,
        in_catalog=g.in_catalog,
        state_blob=base64.b64encode(g.state_blob).decode() if g.state_blob else None,
        state_ver=g.state_ver or 0,
        description=g.description,
        owner_uin=g.owner_uin,
        avatar_seed=g.avatar_seed,
        post_policy=g.post_policy,
        is_closed=g.is_closed,
        members_hidden=g.members_hidden,
        links_allowed=g.links_allowed,
        files_allowed=g.files_allowed,
        slowmode_sec=g.slowmode_sec,
        min_account_age_hours=g.min_account_age_hours or 0,
        pinned_text=g.pinned_text,
        pinned_at=g.pinned_at,
        avatar_media_id=g.avatar_media_id,
        avatar_media_key=g.avatar_media_key,
        share_token=g.share_token,
        created_at=g.created_at,
        member_count=member_count if member_count is not None else len(members),
        members=members,
    )


# The most expensive read this server serves: it renders every member of every
# group the caller is in, keys included, which on the beta group alone is a
# 700 KB body before compression and seconds of database time.
#
# One account with a client stuck in a boot loop reached roughly 130 of these a
# minute and, with the rest of its boot chain, was two thirds of everything this
# server was doing — the symptom everyone else saw was a slow app and a sluggish
# admin panel. The ceiling here is far above any honest use (an app boot plus
# ordinary refreshes is single digits a minute, and the busiest real account
# measured sat under 30) and exists only so one broken client cannot do that
# again while we find out why it broke.
@router.get(
    "",
    response_model=list[GroupOut],
    dependencies=[Depends(rate_limit("groups_list", 60, 60))],
)
async def list_groups(
    uin: int = Depends(current_uin),
    members: bool = True,
    db: AsyncSession = Depends(get_db),
) -> list[GroupOut]:
    """The caller's groups.

    `?members=0` returns them without the roster, which is what a chat list
    actually needs: a name, a picture and a count. The roster is the expensive
    part — every member with two base64 keys each — and a client that asks for
    it on every poll pays it on every poll. The default stays ON so clients
    already in the field are untouched; new ones opt out and fetch the roster
    from `/groups/{id}` when a group is actually opened.
    """
    rows = (
        await db.execute(
            select(Group)
            .join(GroupMember, GroupMember.group_id == Group.id)
            .where(GroupMember.uin == uin)
            .order_by(Group.created_at.desc())
        )
    ).scalars().all()
    if not members:
        # One grouped count for every group at once rather than a roster query
        # per group.
        ids = [g.id for g in rows]
        counts: dict[int, int] = {}
        if ids:
            counts = dict(
                (
                    await db.execute(
                        select(GroupMember.group_id, func.count())
                        .where(GroupMember.group_id.in_(ids))
                        .group_by(GroupMember.group_id)
                    )
                ).all()
            )
        return [_serialize(g, [], member_count=counts.get(g.id, 0)) for g in rows]
    out: list[GroupOut] = []
    for g in rows:
        # A read for one caller, so the rosters carry their card verdicts.
        roster = await _members_with_users(db, g.id, viewer_uin=uin)
        out.append(_serialize(g, roster))
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
    # 120/min let one caller walk ~7200 group ids an hour. Group ids are
    # SEQUENTIAL and this route is optional-auth, so that was a full catalogue
    # dump — names, member counts and owner identity — for closed groups too,
    # i.e. the same exposure `/search` had, through a second door. Narrowed to
    # a human join flow (a share-link tap previews one group, occasionally a
    # few); anything above this is enumeration, not use.
    #
    # ⚠️ This only shrinks the window, it does not close it: as long as ids are
    # guessable and the share LINK is the whole capability, a patient scan
    # still works. The real fix is an unguessable component in the share link
    # for closed groups; see the note in the module docstring.
    dependencies=[Depends(rate_limit("group_preview", 30, 60))],
)
async def preview_group(
    group_id: int,
    # The unguessable half of the share link (`.../g/<id>?k=<token>`). Supplied
    # by clients that know about it; absent from links shared before the token
    # existed and from older client builds.
    k: str | None = None,
    # Optional auth: the invite LINK is the capability, so a cross-island /
    # not-yet-joined client (no token on this island) can still read the public
    # card (name / avatar / member count / open-closed) to render the join card.
    _viewer_uin: int | None = Depends(current_uin_optional),
    db: AsyncSession = Depends(get_db),
) -> GroupPreviewOut:
    g = await _load_group(db, group_id)
    owner = await db.get(User, g.owner_uin)

    # ── closed-group gate ────────────────────────────────────────────
    # For a CLOSED group we only describe it to someone who has actually been
    # let in: a member, or the holder of the share token. Everyone else is
    # walking sequential ids, which is how the whole catalogue of an island's
    # private communities leaked.
    entitled = True
    if g.is_closed:
        is_member = _viewer_uin is not None and await db.scalar(
            select(GroupMember.id).where(
                GroupMember.group_id == group_id, GroupMember.uin == _viewer_uin
            )
        ) is not None
        has_token = bool(g.share_token) and bool(k) and secrets.compare_digest(k, g.share_token)
        entitled = is_member or has_token

    if not entitled:
        if _REQUIRE_CLOSED_GROUP_TOKEN:
            # Indistinguishable from a group that does not exist — confirming
            # existence is most of the leak.
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such group")
        # Rollout window: links already in the wild carry no token and the
        # shipped clients do not add one yet, so a hard 404 here would break
        # every closed-group invite in flight. Serve a card that still lets a
        # legitimate invitee see there IS a closed group to ask about, minus
        # everything worth harvesting — no name, no description, no owner, no
        # member count, no avatar. Flip RCQ_REQUIRE_CLOSED_GROUP_TOKEN=true
        # once token-aware clients are out.
        return GroupPreviewOut(
            id=g.id,
            name="",
            description=None,
            member_count=0,
            is_closed=True,
            # 0 rather than null: iOS models owner_uin as a non-optional Int,
            # so nulling it fails decoding and breaks the join sheet outright.
            owner_uin=0,
            owner_nickname=None,
            avatar_media_id=None,
            avatar_media_key=None,
        )
    # Ghost-member filter via join with users — same reasoning as the
    # search counter above. Without it, paid-group previews advertised
    # inflated member counts that vanished the moment the user joined.
    member_count = await db.scalar(
        select(func.count(GroupMember.id))
        .join(User, User.uin == GroupMember.uin)
        .where(GroupMember.group_id == group_id)
    )
    # ⚠⚠ The avatar pair goes to MEMBERS ONLY, and the key is why.
    # `avatar_media_key` is the cleartext AES key of the blob, and
    # `GET /media/{id}` has no auth at all, so the pair IS the picture. This
    # endpoint is optional-auth and, for an OPEN group, entitled to everyone
    # (the gate above only guards closed rooms) - which handed the avatar of
    # every open room on the island to an anonymous caller walking sequential
    # ids. The name, the description and the count stay: a join card has to
    # say what you are joining. The avatar falls back to the letter tile every
    # client already draws for the redacted card below.
    viewer_is_member = _viewer_uin is not None and await db.scalar(
        select(GroupMember.id).where(
            GroupMember.group_id == group_id, GroupMember.uin == _viewer_uin
        )
    ) is not None
    return GroupPreviewOut(
        id=g.id,
        name=g.name,
        description=g.description,
        member_count=int(member_count or 0),
        is_closed=g.is_closed,
        owner_uin=g.owner_uin,
        owner_nickname=owner.nickname if owner else None,
        avatar_media_id=g.avatar_media_id if viewer_is_member else None,
        avatar_media_key=g.avatar_media_key if viewer_is_member else None,
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
    # CLOSED groups must never come back from a name search. A closed group is
    # invite-only, and this endpoint is reachable by any registered caller
    # (registration needs no phone/email), so an unfiltered substring match let
    # anyone sweep a dictionary of words and enumerate an island's private
    # communities — together with each one's owner UIN and nickname, i.e. the
    # person to lean on. Android already discarded closed rows client-side
    # (HomeScreen.kt), which is where the intent is documented; iOS did not
    # filter at all, so they rendered in its Add view. Enforced here instead,
    # because the client is not the security boundary.
    #
    # Exact-id lookup keeps working for closed groups: that path is how a
    # share link resolves, and there the LINK is the capability (same rule as
    # `/{group_id}/preview` below).
    # Catalog rows only (stage 6): a room is searchable by name because its
    # owner published it, and for no other reason. The exact-id clause below
    # stays unfiltered - there the LINK is the capability, same rule as
    # preview. Existing open rooms were seeded in_catalog=TRUE on rollout, so
    # nothing the island's users could already find went dark.
    clauses = [
        and_(
            Group.name.ilike(f"%{needle}%"),
            Group.is_closed.is_(False),
            Group.in_catalog.is_(True),
        )
    ]
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
            # Search returns rooms the caller is NOT in, by construction, so
            # the avatar pair is never theirs to hold. Same reasoning as the
            # preview above: the key is the picture, and /media has no auth.
            avatar_media_id=None,
            avatar_media_key=None,
        )
        for g in rows
    ]


@router.get("/{group_id}", response_model=GroupOut)
async def get_group(
    group_id: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
    # ⚠ Returns a pre-serialized Response, NOT a GroupOut — see the comment on
    # the return. `response_model` is kept for the OpenAPI schema only.
) -> Response:
    await _ensure_member(db, group_id, uin)
    g = await _load_group(db, group_id)
    # The member-list screen loads from here, so this is the roster that has
    # to carry `profile_openable`.
    members = await _members_with_users(db, g.id, viewer_uin=uin)
    out = _serialize(g, members)
    # ⚠ End the read transaction BEFORE returning. FastAPI closes a
    # yield-dependency's session only after the LAST BYTE of the response
    # has left, and the flagship room's roster is megabytes that a phone
    # drains for seconds - so this endpoint pinned a pooled connection
    # 'idle in transaction' through the whole transfer (typical 4s on the
    # 31.08 instruments; the same shape as the 25.08 island-wide stall).
    # Every read is done and `out` holds plain values, so nothing after
    # this line touches the session.
    await db.rollback()
    # Serialize HERE rather than handing FastAPI the model. Given a pydantic
    # instance with a `response_model`, FastAPI re-validates the whole object
    # and then walks it again through `jsonable_encoder` — on the flagship
    # roster that is 113ms of pure CPU (measured on prod, 2200 members), and
    # because the event loop is single-threaded per worker it is 113ms during
    # which that worker answers NOBODY. It is the one endpoint here that does
    # enough CPU work to be felt by unrelated requests, which is what the
    # multi-second `worst` on cheap endpoints like /users/me/push-token was.
    # `model_dump_json` alone is 9ms and byte-identical (verified on prod).
    # Returning a Response makes FastAPI skip the duplicate pass entirely.
    return Response(content=out.model_dump_json(), media_type="application/json")


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

    db.add(GroupMember(
        group_id=group_id, uin=uin, role="member", joined_at=_armed_join_stamp(g),
    ))
    await db.flush()
    await seed_cursors_on_join(db, group_id, uin)
    await db.commit()

    members = await _members_with_users(db, group_id)
    payload = _serialize(g, members)
    await _broadcast_membership(group_id, members, payload)
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
        db.add(GroupMember(
            group_id=group_id, uin=body.uin, role="member",
            joined_at=_armed_join_stamp(g),
        ))
        await db.flush()
        await seed_cursors_on_join(db, group_id, body.uin)
        await db.commit()

    g = await _load_group(db, group_id)
    members = await _members_with_users(db, group_id)
    payload = _serialize(g, members)
    await _broadcast_membership(group_id, members, payload)
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
    if not is_self_leave and not _member_can(g, me, "members"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "moderator permission required")
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
    # And drop whatever of this group is still QUEUED for them (#529).
    #
    # Leaving a group used to leave its undelivered backlog in place, and the
    # backlog is what the client turns into notifications when it drains. A
    # fresh install gets a fresh device id, a fresh device has no cursor, and a
    # cursorless device drains from the beginning — so the reporter left RCQ
    # Beta, reinstalled clean, and was met by 460 queued messages replayed as
    # notifications: "уже удалился из этой группы, переустановил приложение
    # начисто — и всё равно они лезут и лезут".
    #
    # They cannot read these anyway once the senders rotate their chain, and a
    # message addressed to a membership that no longer exists is not owed to
    # anyone. The rows for members who STAY are untouched.
    await db.execute(
        delete(OfflineGroupMessage).where(
            and_(
                OfflineGroupMessage.group_id == group_id,
                OfflineGroupMessage.to_uin == member_uin,
            )
        )
    )
    # Stage 5: the same for the room log. The rows sealed to this member go
    # (nobody else can open them), and so do the member's cursors into the
    # room: a membership that no longer exists reads nothing, and a cursor
    # left behind would be a record of how far somebody who left had read.
    await db.execute(
        delete(GroupLog).where(GroupLog.group_id == group_id, GroupLog.to_uin == member_uin)
    )
    await db.execute(
        delete(GroupLogCursor).where(GroupLogCursor.group_id == group_id, GroupLogCursor.uin == member_uin)
    )
    await db.commit()

    # If the owner leaves and group still has members, hand the crown to the oldest one.
    if member_uin == g.owner_uin:
        # ⚠ WHO IS ELIGIBLE is the same question `transfer_owner` answers, and
        # this path used to answer it differently: `order_by(id).first()` over
        # the bare membership rows, with no join to `users` and no look at
        # suspension. Both cases exist in prod:
        #
        #   * a GHOST row (a membership whose account was burned or migrated
        #     and never swept, see the note in `/search`) inherited the room.
        #     `_members_with_users` inner-joins `users`, so that owner is
        #     invisible on every roster while every owner-only lever - caps,
        #     post_policy, is_closed, transfer, delete - 403s for everyone
        #     forever, and an `owner_only` room goes permanently silent.
        #   * a SUSPENDED member inherited it. `authorize_session` refuses
        #     every authenticated request from them, so they cannot exercise
        #     one lever or hand it on: exactly the state `transfer_owner`
        #     refuses with 409 target_suspended.
        #
        # So: the oldest member with a live, un-suspended account. A live but
        # suspended member is the fallback rather than an error, because the
        # alternative is deleting a room whose members may be back tomorrow;
        # only a room with NO live account left is deleted, which is what
        # "everyone is gone" means once the ghosts are discounted.
        eligible = (
            select(GroupMember)
            .join(User, User.uin == GroupMember.uin)
            .where(GroupMember.group_id == group_id)
            .order_by(GroupMember.id.asc())
        )
        next_owner = await db.scalar(
            # Oldest member, by insert order. This used to read `joined_at`,
            # which existed for this one query; `id` is allocated on the same
            # insert and answers it identically without keeping a dated join
            # record for every member of every room.
            eligible.where(User.is_suspended.is_(False))
        ) or await db.scalar(eligible)
        if next_owner is not None:
            next_owner.role = "owner"
            # Same normalisation as `transfer_owner`: an owner row carries no
            # EXPLICIT caps, because the owner's powers are implicit. Left
            # behind, a cap granted to them back when they were a moderator
            # would survive a later transfer away and leave them holding a
            # moderator seat the next owner never issued.
            next_owner.permissions = ""
            g.owner_uin = next_owner.uin
            # One owner, always. Any other row still calling itself owner (a
            # transfer that interleaved with this leave) is demoted here, or
            # the roster would badge two owners while only one of them can
            # use a single owner lever.
            await db.execute(
                update(GroupMember)
                .where(
                    GroupMember.group_id == group_id,
                    GroupMember.uin != next_owner.uin,
                    GroupMember.role == "owner",
                )
                .values(role="member", permissions="")
            )
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
    await _broadcast_membership(
        group_id, members, payload, extra_uins=notify_uins - {m.uin for m in members}
    )
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
        if not _member_can(g, me, "info"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "moderator permission required")
        g.name = body.name
    if body.description is not None:
        # Same admin-or-owner gate as name — it's group metadata.
        # Empty/whitespace-only string clears the description back
        # to NULL so the UI hides the blurb entirely.
        if not _member_can(g, me, "info"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "moderator permission required")
        cleaned = body.description.strip()
        g.description = cleaned or None
    if body.in_catalog is not None:
        if not _member_can(g, me, "info"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "moderator permission required")
        g.in_catalog = body.in_catalog
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
    # Content policy + slowmode: owner-only, like post_policy — they set
    # the rules of the room, not its decoration.
    if body.links_allowed is not None:
        if g.owner_uin != uin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "owner only")
        g.links_allowed = body.links_allowed
    if body.files_allowed is not None:
        if g.owner_uin != uin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "owner only")
        g.files_allowed = body.files_allowed
    if body.min_account_age_hours is not None:
        # The age floor is a rule of the room, like slowmode: owner-only.
        if g.owner_uin != uin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "owner only")
        g.min_account_age_hours = body.min_account_age_hours
    if body.slowmode_sec is not None:
        if g.owner_uin != uin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "owner only")
        g.slowmode_sec = body.slowmode_sec
    if body.pinned_text is not None:
        # Owner OR admin can pin / change / clear the announcement.
        # Empty / whitespace-only string clears the pin entirely so
        # the iOS banner disappears.
        if not _member_can(g, me, "info"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "moderator permission required")
        cleaned = body.pinned_text.strip()
        if cleaned:
            g.pinned_text = cleaned
            g.pinned_at = datetime.now(timezone.utc)
        else:
            g.pinned_text = None
            g.pinned_at = None

    # Avatar swap: any admin can change it (matches the name-change
    # gate). Empty string clears. Both fields must move together —
    # the blob is useless without its key and vice versa.
    if body.avatar_media_id is not None or body.avatar_media_key is not None:
        if not _member_can(g, me, "info"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "moderator permission required")
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
    await _broadcast_membership(group_id, members, payload)
    return payload


class MemberPermsIn(BaseModel):
    # Any subset of {delete, members, info}. Empty list = demote back to a
    # plain member. Unknown entries are rejected.
    permissions: list[str]


class GroupStateIn(BaseModel):
    """One write of the sealed room identity. The blob is opaque to the
    island by construction; the version is the whole concurrency story."""
    state_blob: str = Field(min_length=1)
    state_ver: int = Field(ge=1)


# Deflate-then-AEAD of a sub-kilobyte JSON: 64 KB is forty times the largest
# real room's blob and still nothing next to one avatar. A cap because an
# unreadable column must not become a free blob store.
_STATE_BLOB_CAP = 64 * 1024


@router.patch("/{group_id}/state", response_model=GroupOut)
async def patch_group_state(
    group_id: int,
    body: GroupStateIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> GroupOut:
    """Write the sealed room identity (stage 6 phase 2).

    Single writer with a strictly increasing version: `state_ver` must be
    exactly the stored version plus one, else 409 carrying the current
    version - the vault's #605 rule at room scale. The loser of a race
    re-reads, re-applies its change to the fresh plaintext, and retries;
    nothing is merged on the island because the island cannot read what it
    would be merging.
    """
    me = await _ensure_member(db, group_id, uin)
    g = await _load_group(db, group_id)
    if not _member_can(g, me, "info"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "moderator permission required")
    try:
        blob = base64.b64decode(body.state_blob, validate=True)
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "state_blob is not base64")
    if not blob or len(blob) > _STATE_BLOB_CAP:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "state_blob size out of bounds")
    current = g.state_ver or 0
    if body.state_ver != current + 1:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"stale state_ver: island holds {current}",
        )
    g.state_blob = blob
    g.state_ver = body.state_ver
    await db.commit()
    await db.refresh(g)
    members = await _members_with_users(db, g.id, viewer_uin=uin)
    payload = _serialize(g, members)
    # The same live push a rename gets: every open client re-reads the group
    # and, holding the key, re-renders the new name without a restart.
    await _broadcast_membership(g.id, members, payload)
    return payload


@router.post("/{group_id}/members/{member_uin}/permissions", response_model=GroupOut)
async def set_member_permissions(
    group_id: int,
    member_uin: int,
    body: MemberPermsIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> GroupOut:
    """Owner grants/revokes a member's granular moderator capabilities (any
    subset of delete|members|info — the owner decides which rights each
    moderator gets). OWNER-ONLY on purpose: a moderator can use its caps but
    can't grant caps to others, so there's no escalation chain. The owner's own
    (implicit-all) powers aren't editable here: a cap is not ownership, and
    ownership moves only via `POST /{id}/transfer-owner` or by the owner
    leaving. `delete` is enforced client-side (sealed sender: the
    server never sees who sent or deleted a message); this endpoint just
    publishes the caps every client's roster enforces against."""
    g = await _load_group(db, group_id)
    if g.owner_uin != uin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "owner only")
    unknown = [p for p in body.permissions if p not in _GROUP_PERMS]
    if unknown:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown permissions: {', '.join(unknown)}")
    if member_uin == g.owner_uin:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "the owner already has every permission")
    target = await _ensure_member(db, group_id, member_uin)
    # Dedupe + canonical order, comma-joined for storage.
    canonical = ",".join(p for p in _GROUP_PERMS if p in body.permissions)
    if target.permissions != canonical:
        target.permissions = canonical
        await db.commit()
    members = await _members_with_users(db, group_id)
    payload = _serialize(g, members)
    await _broadcast_membership(group_id, members, payload)
    return payload


class TransferOwnerIn(BaseModel):
    # The member who becomes the owner. Must already be in the group.
    to_uin: int


@router.post(
    "/{group_id}/transfer-owner",
    response_model=GroupOut,
    # Rare and one-way. The ceiling bounds a stolen session rather than pacing
    # a human: nobody hands a group over ten times in an hour.
    dependencies=[Depends(rate_limit("groups_transfer_owner", 10, 3600))],
)
async def transfer_owner(
    group_id: int,
    body: TransferOwnerIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> GroupOut:
    """Hand the group to another member. Owner only, and one way.

    WHY THIS EXISTS. `owner_uin` is the only thing that confers ownership, and
    until now nothing could change it except the owner LEAVING, which promotes
    the oldest member (see `remove_member`): the owner could only hand
    over by walking out, to whoever happened to have joined first. The granular
    caps of §6.6 are not a substitute: `members`/`info`/`delete` let a
    moderator moderate, but every owner-only lever (post_policy, is_closed,
    members_hidden, links/files, slowmode, granting caps, deleting the group)
    reads `g.owner_uin`, and so does the `owner_only` post gate and the
    slowmode exemption in messages.py. There was no way to give those away and
    no way for the owner to get out from under them.

    WHAT MOVES. `Group.owner_uin`, plus the `role` on both member rows so the
    roster every client renders matches. Nothing else: no per-group audit row,
    no "previous owner" column. A transfer is one number changing on one row,
    and a durable record of who used to own which room is exactly the kind of
    metadata the rest of this island has been shedding.

    THE OUTGOING OWNER STAYS, AS A PLAIN MEMBER, WITH NO CAPS. Two halves,
    both deliberate:

    * They stay in the group. Dropping them would make "hand this over" also
      mean "leave", which is a second decision and already has its own endpoint
      (`DELETE /{id}/members/{me}`). Handing over and staying is the ordinary
      case, the founder of a community stepping back to member.
    * Their `permissions` is cleared rather than back-filled with the full set.
      The owner's powers were implicit, so there is nothing to preserve; and a
      cap is a GRANT FROM THE OWNER, which is now somebody else. Leaving the
      ex-owner holding `members`+`info`+`delete` would be a moderator seat the
      new owner never issued and might not notice, on a room they were just
      told they run. If the new owner wants them as a moderator that is one
      call to `/permissions`, made by the person who now has the authority to
      make it.

    The incoming owner's `permissions` is cleared for the same reason it is
    empty on a freshly created group: the owner row carries no explicit caps,
    or a later transfer away would silently leave them holding whatever they
    happened to have been granted before.

    CROSS-ISLAND IS REFUSED, NOT APPROXIMATED. Group membership is local by
    construction: `GroupMember.uin` is a bare number that only means anything
    joined against THIS island's `users` (see `_members_with_users`, which
    drops rows with no local user), `add_member` requires a local `User` row,
    and nothing on the wire (`owner_uin`, the roster, the preview) carries an
    island for a member. So there is no form in which "the owner lives on
    island B" can be expressed, and the explicit `User` lookup below is where
    that is refused: `no_such_user` rather than a group whose owner is a number
    this island cannot resolve. It also catches the ghost row (a member whose
    account was burned or migrated), which would otherwise hand the room to
    nobody.

    Errors, all structured so a client can branch:
      403 {"code": "owner_only"}       caller is not the current owner
      400 {"code": "already_owner"}    target is the caller
      404 {"code": "not_a_member"}     target has no membership row here
      404 {"code": "no_such_user"}     target has no account on this island
      409 {"code": "target_suspended"} target cannot authenticate at all,
                                       so the room would end up unmanageable
    """
    g = await _load_group(db, group_id)
    if g.owner_uin != uin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "owner_only"})
    if body.to_uin == uin:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail={"code": "already_owner"}
        )

    target = await db.scalar(
        select(GroupMember).where(
            and_(GroupMember.group_id == group_id, GroupMember.uin == body.to_uin)
        )
    )
    if target is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail={"code": "not_a_member"}
        )
    target_user = await db.get(User, body.to_uin)
    if target_user is None:
        # See CROSS-ISLAND above. A membership row whose account is not on this
        # island is not a candidate owner, it is a row the roster already hides.
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail={"code": "no_such_user"}
        )
    if target_user.is_suspended:
        # A suspended account is refused by `authorize_session` on every
        # authenticated request, so it could not exercise a single owner lever.
        # The group would have an owner who cannot act and no path back.
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail={"code": "target_suspended"}
        )

    outgoing = await db.scalar(
        select(GroupMember).where(
            and_(GroupMember.group_id == group_id, GroupMember.uin == uin)
        )
    )

    # ⚠ THE MOVE IS CONDITIONAL ON STILL BEING THE OWNER, not on the copy read
    # at the top of this function. Two transfers from one owner's two devices
    # (or a transfer racing the owner's own DELETE /members/{self}) both passed
    # that read under READ COMMITTED, both wrote `owner_uin`, and both stamped
    # role="owner" on their own target: `owner_uin` ended at whichever committed
    # last while the other target kept a role="owner" row forever, so the roster
    # badged two owners and one of them got 403 from every owner lever. Here the
    # second writer matches zero rows (Postgres re-checks the WHERE after the
    # row lock) and is told the truth: somebody else owns the room now.
    moved = await db.execute(
        update(Group)
        .where(Group.id == group_id, Group.owner_uin == uin)
        .values(owner_uin=body.to_uin)
    )
    if moved.rowcount == 0:
        await db.rollback()
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "owner_only"})
    g.owner_uin = body.to_uin
    target.role = "owner"
    target.permissions = ""
    if outgoing is not None:
        # `is None` only for a group whose owner_uin names somebody with no
        # membership row, which nothing writes; tolerated rather than 500'd.
        outgoing.role = "member"
        outgoing.permissions = ""
    # One owner, always: nothing else in this module reconciles `role` against
    # `owner_uin`, so the invariant is restored on the way through.
    await db.execute(
        update(GroupMember)
        .where(
            GroupMember.group_id == group_id,
            GroupMember.uin != body.to_uin,
            GroupMember.role == "owner",
        )
        .values(role="member", permissions="")
    )
    await db.commit()

    members = await _members_with_users(db, group_id)
    payload = _serialize(g, members)
    # Same channel every other group mutation uses (§7.4.5): one
    # `group_membership_changed` carrying the whole GroupOut, which already
    # carries `owner_uin` and the roster with both new roles. Clients that
    # handle a rename handle this with no new code.
    #
    # ⚠ Above SNAPSHOT_BROADCAST_LIMIT members the event carries no roster, so
    # a big group's members learn the new NAME, pin and caps on their next
    # `GET /groups`. Ownership is the exception and rides the compact form too
    # (see `_broadcast_membership`): every other owner-only lever is enforced
    # by the server, which 403s a stale client the moment it uses one, but the
    # moderator `delete` is honoured by the RECEIVING client against its cached
    # roster - sealed sender leaves the server no sender to check - so a stale
    # `owner_uin` is a revoked owner whose deletes still land.
    await _broadcast_membership(group_id, members, payload)
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
    # Stage 5: the room's log, its cursors and its counter go with the room.
    await db.execute(delete(GroupLog).where(GroupLog.group_id == group_id))
    await db.execute(delete(GroupLogCursor).where(GroupLogCursor.group_id == group_id))
    await db.execute(delete(GroupSeq).where(GroupSeq.group_id == group_id))
    await db.delete(g)
    await db.commit()
    for member_uin in members:
        await manager.send(member_uin, {"type": "group_deleted", "group_id": group_id})
    return {"deleted": True}


# ---------------------------------------------------------------------------
# The group read-receipt endpoints lived here until 2026-08-22.
#
# `POST /{id}/messages/{mid}/viewed` and `POST /{id}/view-counts` were backed by
# `group_message_views`: one row per (viewer, group, message), no foreign key,
# no sweep, outliving both the group and the messages it described. That is a
# per-person reading log for every bubble scrolled past in a broadcast room,
# and it bought a "seen by N" number under owner posts on iOS. Four rows in the
# table's lifetime.
#
# An iOS build that still fires them gets a 404 and drops it: the view ping was
# already fire-and-forget, and a missing count renders as no count.
