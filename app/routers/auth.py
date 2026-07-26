import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin, issue_recover_challenge, issue_token, verify_recover_challenge
from app.services import server_settings
from app.models.contact import Contact, ContactRequest
from app.models.invite import Invite
from app.models.group import Group, GroupMember
from app.models.message import OfflineMessage
from app.models.audio_room import AudioRoom, AudioRoomMembership, AudioRoomMute
from app.models.poll import Poll, PollVote
from app.models.story import Story
from app.models.device_token import DeviceToken
from app.models.user import User
from app.routers.groups import _load_group, _members_with_users, _serialize
from app.routers.referrals import record_referral
from app.services.connection_manager import manager
from app.services.uin import allocate_uin

log = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Founder UIN — auto-added bidirectionally to every freshly registered
# tester's contact list. OFF by default now (the old default 555555 was a
# retired RCQ account; a self-host operator should never seed it either).
# Opt in by setting RCQ_FOUNDER_UIN=<uin> in env.
def _founder_uin() -> int:
    raw = os.getenv("RCQ_FOUNDER_UIN", "0")
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
    # Server-join invite token. Required only when this server runs
    # REGISTRATION_POLICY=invite (ignored otherwise).
    invite: str | None = None
    # Best-effort preferred UIN (federation §5a multihoming): a client adding a
    # BACKUP island asks to keep its primary number so the user has one UIN
    # everywhere. Granted only if free on THIS island; otherwise a fresh UIN is
    # minted (uin is per-island and is NOT identity — the key is). A redeemed
    # vanity invite still wins over this.
    desired_uin: int | None = None


class RegisterOut(BaseModel):
    uin: int
    token: str


class SessionOut(BaseModel):
    token: str
    ws_url: str


@router.post(
    "/register",
    response_model=RegisterOut,
    status_code=status.HTTP_201_CREATED,
    # Registration is unauthenticated and mints an identity, so it is the one
    # endpoint an attacker can call for free in a loop. This limiter is
    # DEFENCE IN DEPTH only — the actual vanity-UIN hole is closed by the
    # UIN_MIN/UIN_MAX clamp on `desired_uin` below, not here.
    #
    # Deliberately loose (and keyed by IP, since there is no UIN yet): mobile
    # carriers across the CIS put many subscribers behind one CGNAT address,
    # so a tight cap would turn a launch spike into "can't sign up" for real
    # users. Failing a legitimate registration is a worse outcome than letting
    # someone create a few junk accounts, which invite-only islands gate
    # anyway. Do not tighten this without checking that trade again.
    dependencies=[Depends(rate_limit("auth_register", 20, 3600))],
)
async def register(body: RegisterIn, db: AsyncSession = Depends(get_db)) -> RegisterOut:
    # Invite gate (default-open servers skip this entirely). Validate + consume
    # one use ATOMICALLY: a single UPDATE that only matches an unexpired,
    # not-exhausted code locks the row, so two simultaneous registrations can't
    # both spend the last use. It commits together with the user creation below.
    code = (body.invite or "").strip()
    # A redeemed invite may carry a reserved (vanity) UIN; capture it so the
    # holder gets exactly that number below.
    reserved_uin: int | None = None
    invite_gates = (
        Invite.code == code,
        Invite.used_count < Invite.max_uses,
        or_(Invite.expires_at.is_(None), Invite.expires_at > datetime.now(timezone.utc)),
    )
    if await server_settings.get("registration_policy") == "invite":
        if not code:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "invite_required"})
        consumed = await db.execute(
            update(Invite).where(*invite_gates).values(used_count=Invite.used_count + 1)
        )
        if consumed.rowcount == 0:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "invite_invalid"})
        reserved_uin = await db.scalar(select(Invite.uin).where(Invite.code == code))
    elif code:
        # Open server, but a reserved-UIN invite was supplied → consume it so the
        # holder still gets their vanity number. A plain (uin-less) invite on an
        # open server is simply ignored (registration is already allowed).
        consumed = await db.execute(
            update(Invite)
            .where(*invite_gates, Invite.uin.isnot(None))
            .values(used_count=Invite.used_count + 1)
        )
        if consumed.rowcount > 0:
            reserved_uin = await db.scalar(select(Invite.uin).where(Invite.code == code))

    # A reserved vanity UIN wins when it's still free; then a best-effort
    # desired UIN (multihoming "same number on every island"); otherwise fall
    # back to a random allocation.
    uin = None
    if reserved_uin is not None and await db.scalar(
        select(User.uin).where(User.uin == reserved_uin)
    ) is None:
        uin = reserved_uin
    # `desired_uin` is attacker-controlled on an UNAUTHENTICATED endpoint, so
    # it must be clamped to the same window `allocate_uin` mints from. Without
    # the bound, "any free positive integer" included the 3-6 digit vanity
    # range the shop prices at $199-$999 — free, to anyone, in one request.
    # The multihoming intent (federation §5a: keep your number on a backup
    # island) is preserved: real UINs are all inside this window.
    if (
        uin is None
        and body.desired_uin is not None
        and settings.UIN_MIN <= body.desired_uin <= settings.UIN_MAX
        and await db.scalar(select(User.uin).where(User.uin == body.desired_uin)) is None
    ):
        uin = body.desired_uin
    if uin is None:
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
            # One pipelined fanout to the ONLINE members instead of a sequential
            # per-member send(): on the 1300+ member beta group the old loop was
            # ~2N sequential Redis round-trips IN the register path = ~15s sign-up.
            await manager.fanout(
                [m.uin for m in members],
                {"type": "group_membership_changed", "group": payload},
            )

    return RegisterOut(uin=uin, token=issue_token(uin))


@router.post("/session", response_model=SessionOut)
async def session(uin: int = Depends(current_uin)) -> SessionOut:
    return SessionOut(token=issue_token(uin), ws_url=f"/ws/{uin}")


# ── account recovery (seed-phrase) ──────────────────────────────────────────
# The client's identity IS its keypair (X25519 + Ed25519); the UIN is just the
# server-side handle bound to the public keys. A user who backed up the private
# keys (the "recovery phrase") can re-bind a fresh device to the same UIN by
# proving possession of the private signing key. Two-step, stateless:
#   1) /auth/recover/challenge → a short-lived signed nonce for the pubkey
#   2) /auth/recover → the client's Ed25519 signature over that nonce → token
class RecoverChallengeIn(BaseModel):
    signing_key: str


class RecoverChallengeOut(BaseModel):
    challenge: str


class RecoverIn(BaseModel):
    signing_key: str
    challenge: str
    # base64 Ed25519 signature over the exact challenge string.
    signature: str


@router.post("/recover/challenge", response_model=RecoverChallengeOut)
async def recover_challenge(body: RecoverChallengeIn) -> RecoverChallengeOut:
    sk = body.signing_key.strip()
    if not sk:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "missing_key"})
    return RecoverChallengeOut(challenge=issue_recover_challenge(sk))


@router.post("/recover", response_model=RegisterOut)
async def recover(body: RecoverIn, db: AsyncSession = Depends(get_db)) -> RegisterOut:
    sk = body.signing_key.strip()
    if not verify_recover_challenge(body.challenge, sk):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "invalid_challenge"})
    # Prove key ownership: the Ed25519 signature must verify over the exact
    # challenge string under the claimed public signing key.
    from base64 import b64decode
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(b64decode(sk)).verify(
            b64decode(body.signature), body.challenge.encode()
        )
    except (InvalidSignature, ValueError, TypeError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={"code": "bad_signature"})
    # Find the account bound to this signing key. Small scan at current scale;
    # add an index on users.signing_key when the table grows.
    uin = (
        await db.execute(
            select(User.uin).where(User.signing_key == sk).order_by(User.uin).limit(1)
        )
    ).scalar_one_or_none()
    if uin is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "identity_not_found"})
    return RegisterOut(uin=uin, token=issue_token(uin))


# ── identity key re-issue (in-place rotation) ───────────────────────────────
# Re-key an EXISTING account without changing the UIN. The caller is already
# authenticated (the bearer token proves they own the UIN), so this simply
# rewrites the long-term X25519 identity key + Ed25519 signing key on the user
# row. The client then follows up with POST /keys/bundle to rotate its libsignal
# bundle — which changes the safety number, so contacts get a "safety number
# changed" warning the next time they sync this user's keys. Used when a user
# fears their keys were compromised, or just wants a fresh recovery phrase.
#
# Unlike /auth/recover this needs no signature proof: the JWT already authorises
# the change, and a user can only ever brick their OWN account by uploading a
# pubkey whose private half they don't hold (the client always generates the
# pair locally, so it does). The existing token stays valid; we return a fresh
# one for convenience / parity with register.
class ReissueIn(BaseModel):
    identity_key: str
    signing_key: str


@router.post("/reissue", response_model=RegisterOut)
async def reissue(
    body: ReissueIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> RegisterOut:
    ik = body.identity_key.strip()
    sk = body.signing_key.strip()
    if not ik or not sk:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "missing_key"})
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "user_not_found"})
    user.identity_key = ik
    user.signing_key = sk
    await db.commit()
    return RegisterOut(uin=uin, token=issue_token(uin))


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

    # Wipe every other per-UIN row so a RECYCLED UIN (re-registered, or
    # re-registered after a burn) never inherits the burned owner's
    # data. one_time_prekeys and devices ON DELETE CASCADE off the user
    # row, but these tables key on UIN with no FK cascade — exactly the
    # rows /account migration re-keys. Without this the new owner of a
    # recycled UIN sees the previous owner's contacts, pending requests,
    # queued ciphertext, owned rooms/polls/stories, etc.
    await db.execute(
        delete(Contact).where(or_(Contact.owner_uin == uin, Contact.contact_uin == uin))
    )
    await db.execute(
        delete(ContactRequest).where(
            or_(ContactRequest.from_uin == uin, ContactRequest.to_uin == uin)
        )
    )
    await db.execute(delete(OfflineMessage).where(OfflineMessage.to_uin == uin))
    await db.execute(delete(AudioRoomMembership).where(AudioRoomMembership.uin == uin))
    await db.execute(delete(AudioRoomMute).where(AudioRoomMute.uin == uin))
    await db.execute(delete(AudioRoom).where(AudioRoom.owner_uin == uin))
    await db.execute(delete(PollVote).where(PollVote.voter_uin == uin))
    await db.execute(delete(Poll).where(Poll.creator_uin == uin))
    await db.execute(delete(Story).where(Story.owner_uin == uin))
    await db.execute(delete(DeviceToken).where(DeviceToken.uin == uin))

    await db.delete(user)
    await db.commit()
