import base64
import json
import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import case, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.core.rate_limit import rate_limit
from base64 import b64decode

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.security import (
    bump_uin_epoch,
    cache_uin_epoch,
    carry_device_id,
    current_device_id,
    current_uin,
    device_is_revoked,
    issue_key_challenge,
    issue_recover_challenge,
    issue_token,
    uin_epoch,
    verify_key_challenge,
    verify_recover_challenge,
)
from app.services import server_settings
from app.models.invite import Invite, hash_invite_code
from app.models.group import Group, GroupMember
from app.models.device_token import DeviceToken
from app.models.queue_cursor import QueueCursor
from app.models.user import User
from app.models.vault import VaultSlot
from app.routers.groups import (
    SNAPSHOT_BROADCAST_LIMIT,
    _load_group,
    _members_with_users,
    _serialize,
)
from app.services.connection_manager import manager
from app.services.contact_source import add_edges
from app.services.queue_drain import account_watermark
from app.services.uin import allocate_uin, is_reserved_uin, uin_is_taken
from app.services.uin_rows import purge_gossip_mirror, purge_uin_rows

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


def _pubkey32(value: str, field: str) -> str:
    """A public key must actually be one: base64 of exactly 32 bytes.

    ⚠ This was unvalidated, and it showed. An account exists on the flagship
    holding UIN 2 whose identity_key is the single character "x" — registered
    by hand on 2026-06-15, never used since, and unusable by construction: no
    sender can derive a key to it, so it can never receive a message. It is a
    dead squat on the most valuable number on the island, and the only thing
    that made it possible was that `identity_key: str` accepted anything.

    Padded (44 chars) and unpadded (43) base64 both appear in the live table
    and both decode to 32 bytes, so the test is the decoded LENGTH, not the
    string length.
    """
    raw = value.strip()
    try:
        decoded = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
    except Exception:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"{field} is not base64")
    if len(decoded) != 32:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"{field} must be 32 bytes, got {len(decoded)}",
        )
    return raw


async def _connect_inviter(db: AsyncSession, inviter_uin: int, invitee_uin: int) -> bool:
    """Make the inviter and the newcomer contacts of each other.

    Caller (the /auth/register handler) owns the commit. Returns False and
    writes nothing if the inviter is invalid, because a bad code must never
    block registration.

    This is all that is left of `routers/referrals.record_referral`, which also
    wrote an inviter->invitee row with signup and activation dates that
    deliberately survived a UIN migration. That was a permanent recruitment
    genealogy backing a reward pipeline the code never had, so it went on
    2026-08-22 and the half that does something for the user stayed.
    """
    if inviter_uin == invitee_uin:
        return False
    inviter = await db.scalar(
        select(User).where(
            User.uin == inviter_uin,
            User.is_suspended.is_(False),
        )
    )
    if inviter is None:
        return False
    # Stage 4b: skipped when both accounts keep their list in the vault. In
    # practice the invitee is seconds old here and has advertised nothing, so
    # this writes; it goes through the one helper anyway so there is no write
    # path to `contacts` that a future flip can miss.
    await add_edges(db, invitee_uin, inviter_uin)
    return True


class RegisterIn(BaseModel):
    nickname: str = Field(min_length=1, max_length=64)
    # Long-term X25519 ECDH public key (raw 32-byte, base64). Used by senders
    # to derive the per-message AEAD key.
    identity_key: str
    # Long-term Ed25519 signing public key (raw 32-byte, base64). Used by
    # recipients to authenticate the sealed-sender envelope.
    signing_key: str
    # Whoever's invite link brought this install here, by UIN. Bad value is
    # ignored. It connects the pair as contacts and nothing else: the referral
    # genealogy this used to write went on 2026-08-22, since the reward
    # pipeline its model described was never built and the table held zero rows
    # in the project's life. The field stays because the link still has a job.
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
    # A signed home-island record (federation §2.3, the same document
    # `PUT /federation/island-record` carries) proving `desired_uin` is ALREADY
    # this identity's number somewhere else. Only consulted when the number
    # asked for is a reserved one — see `_owns_uin_elsewhere`.
    home_record: dict | None = None
    # Stable per-INSTALL id, minted by the client on first launch. Optional:
    # clients that predate it get "primary" and the old shared behaviour.
    # See `issue_token` for what it buys.
    device_id: str | None = Field(default=None, max_length=64)
    # Proof that the caller holds the PRIVATE half of `signing_key`: a challenge
    # from POST /auth/register/challenge and an Ed25519 signature over it.
    # Optional on the wire so clients that predate it still register, REQUIRED
    # by the checks below for the two cases where its absence is exploitable.
    challenge: str | None = None
    signature: str | None = None


class RegisterOut(BaseModel):
    uin: int
    token: str


class SessionOut(BaseModel):
    token: str
    ws_url: str


async def _owns_uin_elsewhere(
    db: AsyncSession, uin: int, signing_key: str, offered: dict | None
) -> bool:
    """Does this identity ALREADY hold `uin` on some other island?

    The one question that separates multihoming from squatting, and it has a
    real answer because federation records are self-authenticating: the
    document names `sk` (this identity's Ed25519 signing key) and its `homes`
    (`host`,`uin`) pairs, and it is signed by the private half of `sk`. Nobody
    can forge one for a number they do not already answer to.

    Two sources, both verified the same way. The record the CALLER offers, and
    the one this island already mirrors for that key (`gossip_records`, written
    by any client that resolved and verified the identity — the write path
    verifies the signature before storing, see `routers/federation`). The
    second is what keeps clients that predate `home_record` multihoming onto a
    reserved number: their contacts have almost certainly mirrored the record
    here already.

    ⚠ The signature is re-checked here even for the mirrored row. Verification
    at write time is what makes the table trustworthy today, but this is an
    authorisation decision about a scarce asset, and it costs one Ed25519
    verify to not depend on that.
    """
    from app.models.federation import GossipRecord
    from app.routers.federation import _verify_record_sig

    def names_it(doc) -> bool:
        if not isinstance(doc, dict) or doc.get("sk") != signing_key:
            return False
        homes = doc.get("homes")
        if not isinstance(homes, list):
            return False
        if not any(isinstance(h, dict) and h.get("uin") == uin for h in homes):
            return False
        return _verify_record_sig(doc)

    if names_it(offered):
        return True
    # `doc` is stored as text, and `sk` IS the primary key of the mirror table.
    raw = await db.scalar(select(GossipRecord.doc).where(GossipRecord.sk == signing_key))
    if not raw:
        return False
    try:
        return names_it(json.loads(raw))
    except (ValueError, TypeError):
        return False


class RegisterChallengeIn(BaseModel):
    signing_key: str


class RegisterChallengeOut(BaseModel):
    challenge: str


@router.post(
    "/register/challenge",
    response_model=RegisterChallengeOut,
    dependencies=[Depends(rate_limit("auth_register_challenge", 60, 3600))],
)
async def register_challenge(body: RegisterChallengeIn) -> RegisterChallengeOut:
    """A short-lived nonce to sign at registration, proving the caller holds the
    private half of the signing key they are about to claim.

    Stateless and free of information: it says nothing about whether the key or
    any account exists, so it cannot be used to probe for either.
    """
    return RegisterChallengeOut(challenge=issue_key_challenge(body.signing_key.strip(), "register"))


@router.post(
    "/register",
    response_model=RegisterOut,
    status_code=status.HTTP_201_CREATED,
    # Registration is unauthenticated and mints an identity, so it is the one
    # endpoint an attacker can call for free in a loop.
    #
    # ⚠ This comment used to claim the vanity-UIN hole was "closed by the
    # UIN_MIN/UIN_MAX clamp on `desired_uin` below". There is no UIN_MIN in
    # that check and there deliberately never was — see the note beside it.
    # `desired_uin` accepts ANY free number up to UIN_MAX, including the one
    # and two digit ones the shop refuses to sell, and somebody took UIN 2 that
    # way on 2026-06-15. This limiter is the only thing bounding how MANY, and
    # it bounds nothing about WHICH.
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
    # An account whose keys are not keys is not an account: nobody can seal to
    # it and nothing it signs verifies. Checked before anything is minted, so a
    # junk registration cannot claim a UIN on its way to failing.
    identity_key = _pubkey32(body.identity_key, "identity_key")
    signing_key = _pubkey32(body.signing_key, "signing_key")

    # ⚠⚠ Registration used to take a signing key on the caller's word.
    #
    # A public signing key IS public — /users/{uin}/info hands it out — so
    # anyone could mint a NEW account carrying somebody else's key, ask for a
    # lower number (`desired_uin` has no floor) and thereby own where that
    # person's own seed phrase lands. They never read a message, they hold no
    # private key; the owner simply loses the way back into an account with no
    # email and no phone attached. `/auth/recover` picking the OLDEST claim
    # (2026-08-13) made that race unwinnable, but it left the claim itself free
    # to make: seven signing keys on the flagship are already shared by more
    # than one account, one of them by twelve.
    #
    # So the key must now be PROVEN, exactly the way recovery proves it. The
    # proof is not demanded of everyone yet, because clients that predate it are
    # in people's hands and a hard requirement would lock out every one of them.
    # It IS demanded for the two cases where its absence is what the attack
    # needs:
    #   * the key is already claimed by an existing account — the impersonation
    #     case, and the only way to legitimately re-use a key here is to hold it;
    #   * a specific number is being asked for — multihoming, which a real
    #     client does with its own keys and a squatter cannot.
    # ⏭ Make it unconditional once the fleet has turned over.
    proven = False
    if body.challenge and body.signature:
        if not verify_key_challenge(body.challenge, signing_key, "register"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "invalid_challenge"})
        try:
            Ed25519PublicKey.from_public_bytes(b64decode(signing_key)).verify(
                b64decode(body.signature), body.challenge.encode()
            )
        except (InvalidSignature, ValueError, TypeError):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={"code": "bad_signature"})
        proven = True
    if not proven:
        key_taken = await db.scalar(
            select(User.uin).where(User.signing_key == signing_key).limit(1)
        )
        if key_taken is not None:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail={"code": "key_proof_required"}
            )

    # Invite gate (default-open servers skip this entirely). Validate + consume
    # one use ATOMICALLY: a single UPDATE that only matches an unexpired,
    # not-exhausted code locks the row, so two simultaneous registrations can't
    # both spend the last use. It commits together with the user creation below.
    code = (body.invite or "").strip()
    # ⚠ The `invites.code` COLUMN holds the sha256-hex, not the token (see the
    # model). What the client presents is the raw code, so every lookup here
    # hashes first. A code minted before 2026-08-22 still works: the migration
    # hashed the stored value in place, so the same raw token maps to the same
    # row.
    code_hash = hash_invite_code(code) if code else ""
    # A redeemed invite may carry a reserved (vanity) UIN; capture it so the
    # holder gets exactly that number below.
    reserved_uin: int | None = None
    invite_gates = (
        Invite.code == code_hash,
        Invite.used_count < Invite.max_uses,
        or_(Invite.expires_at.is_(None), Invite.expires_at > datetime.now(timezone.utc)),
    )
    # Stamped in the same atomic UPDATE that spends the use, so an invite whose
    # LAST use this is gets its retention clock started without a second
    # statement that could lose the race. Anything short of the last use leaves
    # the column alone.
    _spent_now = case(
        (Invite.used_count + 1 >= Invite.max_uses, datetime.now(timezone.utc)),
        else_=Invite.spent_at,
    )
    if await server_settings.get("registration_policy") == "invite":
        if not code:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "invite_required"})
        consumed = await db.execute(
            update(Invite)
            .where(*invite_gates)
            .values(used_count=Invite.used_count + 1, spent_at=_spent_now)
        )
        if consumed.rowcount == 0:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "invite_invalid"})
        reserved_uin = await db.scalar(select(Invite.uin).where(Invite.code == code_hash))
    elif code:
        # Open server, but a reserved-UIN invite was supplied → consume it so the
        # holder still gets their vanity number. A plain (uin-less) invite on an
        # open server is simply ignored (registration is already allowed).
        consumed = await db.execute(
            update(Invite)
            .where(*invite_gates, Invite.uin.isnot(None))
            .values(used_count=Invite.used_count + 1, spent_at=_spent_now)
        )
        if consumed.rowcount > 0:
            reserved_uin = await db.scalar(select(Invite.uin).where(Invite.code == code_hash))

    # A reserved vanity UIN wins when it's still free; then a best-effort
    # desired UIN (multihoming "same number on every island"); otherwise fall
    # back to a random allocation.
    #
    # ⚠ "Still free" means free in ALL THREE tables, `users`, `owned_uins` and
    # `invites` (see services/uin.uin_is_taken). This used to read `users`
    # alone, so an invite minted before somebody was granted the same number,
    # or minted on an older build that did not check either, handed a
    # registration a number sitting in a member's collection. When that happens
    # the invite use is already spent, and the registration falls through to a
    # desired or random number rather than failing: refusing here would cost
    # the newcomer their sign-up over an operator's bookkeeping mistake.
    #
    # ⚠⚠ `except_invite` is not optional here. The UPDATE above already spent
    # one use of THIS invite, but a multi-use code (max_uses > 1) is still live
    # afterwards, so without the exclusion the row would report its own
    # redeemer's reserved number as taken and this branch would skip it: the
    # code would be consumed and grant nothing. Any OTHER live invite reserving
    # the same number still counts, which is the case an operator creates by
    # minting twice on an old build.
    uin = None
    if reserved_uin is not None and not await uin_is_taken(
        db, reserved_uin, except_invite=code_hash
    ):
        uin = reserved_uin
    # `desired_uin` is attacker-controlled on an UNAUTHENTICATED endpoint, so it
    # is bounded — but the ceiling is what matters, not a floor at UIN_MIN.
    #
    # A floor of UIN_MIN looks right (it is the window `allocate_uin` mints
    # from) and is wrong in practice: 901 live accounts on the flagship hold
    # numbers BELOW it, 250 of them active in the last month, issued before the
    # range was raised. Since every client sends `desired_uin` only for
    # multihoming (federation §5a — Android Multihome.kt, iOS Multihome.swift,
    # web multihome.ts all pass the user's OWN uin and nothing else), a floor
    # silently downgrades exactly those users: they add a backup island and
    # quietly stop having one number everywhere.
    #
    # The scarce-number worry that motivated a floor is handled elsewhere and
    # better: the shop is gone, and `POST /admin/invites` already refuses to
    # reserve anything outside UIN_MIN..UIN_MAX, so a short number cannot be
    # sold through the supported path regardless. Bulk squatting is bounded by
    # the registration limiter above.
    #
    # The real fix, when vanity numbers become sellable, is to require PROOF of
    # prior tenure rather than a numeric guess: a signed federation
    # island-record (`GET /federation/island-record/{uin}`) already binds a UIN
    # to its holder's keys, so a multihoming client can present one and a
    # squatter cannot.
    #
    # ⚠ Honoured only under `proven`. Refusing the whole registration instead
    # would have been the tidier rule and the wrong one: every client in
    # people's hands today sends `desired_uin` for multihoming (Android
    # Multihome.kt, iOS Multihome.swift, web multihome.ts), so a 403 here would
    # break adding a backup island for everyone who has not updated. Ignoring
    # the request degrades them to a fresh number on the backup island — what
    # they got before multihoming existed — while a squatter, who cannot sign
    # for the key, cannot pick a number at all.
    #
    # ⚠⚠ A HELD number is not free either, and this read `users` alone until
    # 2026-08-23: a number in somebody's collection has no `users` row, so a
    # `desired_uin` naming one was granted. The holder was told (by every
    # client, in as many words) that nobody else could take it. Proving the
    # signing key is no defence here: the squatter proves their OWN key, which
    # says nothing about who holds the number.
    #
    # Nor is a number a live invite RESERVES, for the same reason and with the
    # same silent ending. No `except_invite` on this call, deliberately: if the
    # caller's own invite reserved this number the branch above already granted
    # it, so anything still reserving it here is somebody else's promise.
    #
    # ⚠⚠ And a RESERVED number (short or patterned — see `is_reserved_uin`) is
    # not handed out here at all unless the caller already answers to it
    # somewhere else. This branch was the main way the scarce stock left the
    # island: `desired_uin` exists for multihoming, but nothing tied it to the
    # number the caller already has, so asking for #777 worked exactly as well
    # as asking for your own. Measured 2026-09-01: 563 of 999 three-digit
    # numbers gone, 450 of them on accounts that never came back.
    #
    # Multihoming itself is NOT broken by this: the record that proves prior
    # tenure is the one federation already defines and this island already
    # mirrors for most identities. A client that has none falls through to a
    # fresh number, which is what it got before multihoming existed.
    if (
        uin is None
        and proven
        and body.desired_uin is not None
        and 0 < body.desired_uin <= settings.UIN_MAX
        and not await uin_is_taken(db, body.desired_uin)
        and (
            not is_reserved_uin(body.desired_uin)
            or await _owns_uin_elsewhere(db, body.desired_uin, signing_key, body.home_record)
        )
    ):
        uin = body.desired_uin
    if uin is None:
        uin = await allocate_uin(db)
    user = User(
        uin=uin,
        nickname=body.nickname,
        identity_key=identity_key,
        signing_key=signing_key,
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
            select(User).where(User.uin == founder_uin)
        )
        if founder is not None:
            # ⚠ Stage 4's "features that die" list has this edge on it: it is
            # written for every account that has ever registered, which makes
            # `contacts` a census of the island on top of being a graph, and
            # nobody consented to it. It is NOT dropped here, because the
            # founder's own client does not auto-add unknown senders and would
            # silently stop showing a new tester's first message; the
            # replacement (a room invite carrying the welcome) ships with the
            # drop phase. Until then it goes through the same helper as every
            # other write.
            await add_edges(db, uin, founder_uin)
            await db.commit()

    # Arrived by somebody's invite link: connect the two of them, both
    # directions, so the account exists with a person in it instead of an empty
    # list. Invalid code is rolled back, not raised: it must never invalidate
    # the already-committed registration above.
    if body.inviter_uin:
        if await _connect_inviter(db, body.inviter_uin, uin):
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
            #
            # And on a group this size the payload itself is the problem: the
            # snapshot is ~600 KB, so shipping it to every online member turned
            # each sign-up into tens of megabytes through the pub/sub channel,
            # which every worker parses. Above the limit, send the id alone —
            # nobody is watching a 1750-member roster update live, and the
            # stall it caused was showing up as broken calls.
            await manager.fanout(
                [m.uin for m in members],
                {"type": "group_membership_changed", "group": payload}
                if len(members) <= SNAPSHOT_BROADCAST_LIMIT
                else {"type": "group_membership_changed", "group_id": beta_group_id},
            )

    from app.services.activity_rollup import bump_bg as activity_bump

    activity_bump("reg")
    # Mint under the number's CURRENT epoch: a recycled UIN starts above 0,
    # which is what stops a previous holder's saved bearer from working.
    return RegisterOut(uin=uin, token=issue_token(uin, await uin_epoch(uin), body.device_id))


async def _refuse_revoked_device(uin: int, device_id: str | None) -> None:
    """Guard for every endpoint below that MINTS a session token.

    ⚠ Checking a token on the way IN is not the same as refusing to make a new
    one, and until report #607 this file only ever did the first. The web keeps
    no token on disk: it proves the signing key and mints one at start-up
    (`/auth/refresh`). So disconnecting a browser from the phone denylisted the
    token it was holding and then handed it a fresh one on the next request —
    the session did not even blink, and a reload restored it outright.

    The denylist is the same set `authorize_session` consults, so a revoke now
    means one thing in both directions: this install gets no session, neither
    the one it has nor a new one.
    """
    if await device_is_revoked(uin, device_id):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail={"code": "device_revoked"}
        )


@router.post("/session", response_model=SessionOut)
async def session(
    uin: int = Depends(current_uin),
    device_id: str = Depends(current_device_id),
) -> SessionOut:
    return SessionOut(
        token=issue_token(uin, await uin_epoch(uin), carry_device_id(device_id)),
        ws_url=f"/ws/{uin}",
    )


class ClaimDeviceIn(BaseModel):
    # The install's own id, minted client-side on first launch and kept for
    # the life of the install.
    device_id: str = Field(min_length=8, max_length=64)


@router.post("/device", response_model=SessionOut)
async def claim_device(
    body: ClaimDeviceIn,
    uin: int = Depends(current_uin),
    old_device_id: str = Depends(current_device_id),
    db: AsyncSession = Depends(get_db),
) -> SessionOut:
    """Exchange this session for one that names the install it runs on.

    Every already-installed client holds a token with no `dev` claim, which
    means they all key as "primary": their websockets supersede each other in
    a loop, and they share one offline-queue cursor so the first device to
    drain leaves the others with nothing. They cannot be fixed by re-issuing
    tokens server-side — the client has to say which install it is — so this
    is the upgrade path: call it once after updating, keep the token you get.

    The current cursor is copied onto the new device id, otherwise the install
    would look brand new and be handed the whole queue again (harmless —
    clients dedupe by envelope id — but a pointless re-download of everything
    still on the server).

    ⚠ A LINKED session may not rename itself. `current_uin` already refuses a
    revoked device's bearer, but the id in the registry is the one the phone's
    "disconnect" button acts on: a linked browser that swapped it for a name of
    its own choosing would still be listed as connected and would no longer be
    reachable by the revoke. Nothing does that today (every client claims an
    install id only when its token has none) — this is here so that stays true.
    """
    from app.routers.devices import is_linked_device  # local import: avoid cycle

    await _refuse_revoked_device(uin, body.device_id)
    if body.device_id != old_device_id and await is_linked_device(uin, old_device_id):
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail={"code": "linked_device_cannot_rename"}
        )
    existing = await db.get(QueueCursor, (uin, body.device_id))
    if existing is None:
        old = await db.get(QueueCursor, (uin, old_device_id))
        if old is not None:
            floor_direct, floor_group = old.last_direct_id, old.last_group_id
        else:
            # No "primary" cursor to inherit: start where this account's
            # furthest device got to, never at zero, or the upgrade itself would
            # replay the queue it was written to avoid replaying.
            floor_direct, floor_group = await account_watermark(db, uin)
        db.add(QueueCursor(
            uin=uin,
            device_id=body.device_id,
            last_direct_id=floor_direct,
            last_group_id=floor_group,
            updated_at=datetime.now(timezone.utc),
        ))
        # ⚠⚠ And RETIRE the one it inherited from. The install that was
        # "primary" is this install, under its own name from now on, so the old
        # row is an orphan nothing will ever advance again. Left in place it
        # pins the queue's reap floor: `_reap_below_min` takes the MINIMUM
        # cursor of the account, so every row above that dead watermark is kept
        # for every device of the account until the cursor ages out on its own
        # (7 days superseded, 30 stale). A person who linked a second device on
        # the 29th was still carrying 78 delivered, acknowledged rows on the 1st
        # for no reason at all.
        #
        # Only the inherited one, and only when it really was inherited: a
        # linked device that had no "primary" to copy from (the watermark
        # branch above) must not delete another install's live cursor.
        if old is not None:
            await db.delete(old)
        await db.commit()
    return SessionOut(
        token=issue_token(uin, await uin_epoch(uin), body.device_id),
        ws_url=f"/ws/{uin}",
    )


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
    # The install doing the recovery, so the token it gets back names it (see
    # carry_device_id). Optional: an older client simply gets the unnamed token it
    # used to get, and claims the name on its next start.
    device_id: str | None = Field(default=None, max_length=64)


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
    #
    # ⚠⚠ Ordered by created_at, NOT by uin, and the difference is a hijack.
    #
    # A public signing key is public — /users/{uin}/info hands it out. Ordering
    # by uin let anyone who learned a victim's key register a NEW account
    # carrying it and simply ASK for a lower number (`desired_uin` has no
    # floor), after which the victim's own seed phrase recovered the attacker's
    # empty account instead of theirs, permanently. The attacker never reads a
    # message — they hold no private key — but the owner loses their way back
    # in, which for an account with no email and no phone is the whole of it.
    #
    # Seven signing keys on the flagship are already shared by more than one
    # account (one by twelve), so this tie-break is not hypothetical: it decides
    # real recoveries today. First to claim the key wins, and an attacker cannot
    # claim it before the owner has published it.
    #
    # ⏭ This is a mitigation, not the fix. The fix is to stop accepting a
    # signing key at registration without proof of the matching private key —
    # /auth/recover/challenge already has the machinery.
    # ⚠ COALESCE, and it is the whole repair. `created_at` is a fact about the
    # NUMBER - a migration deliberately does not copy it - so ordering by it
    # alone sent a person to the back of the queue for their own key every time
    # they moved, and handed their recovery to any older row carrying the same
    # key. `identity_created_at` follows the PERSON across a move; rows written
    # before the column existed have NULL and fall back to `created_at`, which
    # for a row that never moved is the same instant.
    first_claim = func.coalesce(User.identity_created_at, User.created_at)
    uin = (
        await db.execute(
            select(User.uin)
            .where(User.signing_key == sk)
            .order_by(first_claim.asc(), User.uin.asc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if uin is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "identity_not_found"})
    # Recovery is the other door into the same room: it mints a session from the
    # signing key alone, so a disconnected install must not be able to walk
    # through it either. A genuine re-install carries a device id the account has
    # never revoked (or none at all) and is unaffected.
    await _refuse_revoked_device(uin, body.device_id)
    return RegisterOut(uin=uin, token=issue_token(uin, await uin_epoch(uin), body.device_id))


# ── session token re-issue (no stored token) ────────────────────────────────
# Same proof as /auth/recover, but the caller says WHICH uin it wants, and gets
# it only if that account really carries the key. It exists so a client does
# not have to keep a 30-day token on disk beside the keys that can mint one:
# the web client now holds no token at all between sessions (see
# docs/web-storage-inventory.md), and asks for one at start-up.
#
# ⚠ /auth/recover cannot do this job. It resolves a key to the OLDEST account
# claiming it, which is the right rule for "I lost everything, take me home"
# and the wrong one here: seven signing keys on the flagship are shared by more
# than one account, and for those a start-up recover would silently hand the
# session to somebody else's uin. Naming the uin removes the ambiguity, and
# gives away nothing — the proof is still possession of the private key, which
# an impersonator who registered a copy of the public one does not have.
class RefreshIn(BaseModel):
    uin: int
    signing_key: str
    challenge: str
    # base64 Ed25519 signature over the exact challenge string.
    signature: str
    device_id: str | None = Field(default=None, max_length=64)


@router.post(
    "/refresh",
    response_model=RegisterOut,
    # Once per start-up per install, plus the odd 401 retry. Keyed by IP (there
    # is no session yet), and loose for the same CGNAT reason as /auth/register.
    dependencies=[Depends(rate_limit("auth_refresh", 60, 3600))],
)
async def refresh(body: RefreshIn, db: AsyncSession = Depends(get_db)) -> RegisterOut:
    sk = body.signing_key.strip()
    if not verify_recover_challenge(body.challenge, sk):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "invalid_challenge"})
    try:
        Ed25519PublicKey.from_public_bytes(b64decode(sk)).verify(
            b64decode(body.signature), body.challenge.encode()
        )
    except (InvalidSignature, ValueError, TypeError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={"code": "bad_signature"})
    owned = (
        await db.execute(
            select(User.uin).where(User.uin == body.uin, User.signing_key == sk).limit(1)
        )
    ).scalar_one_or_none()
    if owned is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "identity_not_found"})
    # ★ The whole point of report #607. Proving the signing key says WHO is
    # asking, never WHERE from, so this is the only thing standing between a
    # disconnected browser and a brand-new session for the same account.
    await _refuse_revoked_device(owned, body.device_id)
    # Same queue-cursor floor as /auth/device. A named install that has no
    # cursor yet (its row was dropped when the session was revoked, or the
    # install id is new) would otherwise be handed the ENTIRE queue on its next
    # drain and notify for all of it.
    if body.device_id:
        if await db.get(QueueCursor, (owned, body.device_id)) is None:
            floor_direct, floor_group = await account_watermark(db, owned)
            db.add(QueueCursor(
                uin=owned,
                device_id=body.device_id,
                last_direct_id=floor_direct,
                last_group_id=floor_group,
                updated_at=datetime.now(timezone.utc),
            ))
            await db.commit()
    return RegisterOut(uin=owned, token=issue_token(owned, await uin_epoch(owned), body.device_id))


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


@router.post(
    "/reissue",
    response_model=RegisterOut,
    dependencies=[Depends(rate_limit("auth_reissue", 10, 3600))],
)
async def reissue(
    body: ReissueIn,
    uin: int = Depends(current_uin),
    device_id: str = Depends(current_device_id),
    db: AsyncSession = Depends(get_db),
) -> RegisterOut:
    ik = body.identity_key.strip()
    sk = body.signing_key.strip()
    if not ik or not sk:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "missing_key"})
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "user_not_found"})
    if user.identity_key == ik and user.signing_key == sk:
        # ⚠ THE SAME KEYS ARE NOT A ROTATION, and this route is destructive
        # enough that "do it again" has to be free. The documented flow is
        # read the slots, call this, write them back under the new derivation,
        # and a retry of a call that actually succeeded (a gateway timeout on
        # the reply, a double tap) would otherwise land AFTER the republish:
        # the vault delete below would take out the slots the client had just
        # rewritten, and `vault_reset` would tell every other session that a
        # derivation which has not moved is retired. Nothing to change and
        # nothing to announce, so only the token is reissued.
        return RegisterOut(
            uin=uin, token=issue_token(uin, await uin_epoch(uin), carry_device_id(device_id))
        )
    user.identity_key = ik
    user.signing_key = sk
    # The vault (stage 4a) is sealed under, and its slots named by, keys the
    # first-party clients derive from the identity being retired here. Every
    # slot would be unreachable under the new derivation, and ciphertext
    # under a key the user just declared compromised has no business staying,
    # so the account's vault goes in the same transaction. The client reads
    # its slots BEFORE calling this and writes them back AFTER.
    #
    # ⚠ A HARD DELETE, deliberately, and NOT the tombstone-at-version+1 that
    # `DELETE /vault/{slot}` leaves. That difference is load-bearing for the
    # device that did not rotate: it holds the retired `identity_priv`, so it
    # keeps deriving the OLD slot names, and reading one at version 0 when it
    # remembers version 12 is what trips its rollback floor and stops it. A
    # tombstone would answer "version 13, nothing there", which reads as an
    # ordinary empty slot, and the device would cheerfully republish its whole
    # contact list under the retired name, sealed with the retired key. The
    # ABA hazard the tombstone rule exists for is covered here by the same
    # floor: the recreated slot counts from 1 again, which is below it.
    await db.execute(delete(VaultSlot).where(VaultSlot.uin == uin))
    await db.commit()

    # ...and the account's OTHER sessions are told, which until 2026-08-23 they
    # were not: this route emptied the vault and announced nothing at all. What
    # a second device saw was a slot name reading 404 with version 0, which is
    # byte for byte what a slot NOBODY HAS EVER WRITTEN reads, so it concluded
    # "fresh account, publish what I have", wrote its own cached list as
    # version 1 under the OLD derivation, and the rotating device then wrote
    # version 2 over it from its own copy. Two devices, silently
    # un-publishing each other: the #605 shape the version rule exists to
    # prevent, walked in through the one door the version rule cannot watch.
    #
    # ⚠ WHY NOT `vault_changed`. That frame names one slot and one version, and
    # both of those change here. The names are derived from `identity_priv`
    # (§4.9), so after this call the account's slots are not "at a new version",
    # they are at NEW NAMES: a per-slot nudge would send a device off to re-read
    # a name that will never exist again, and the versions it carried would be
    # the retired derivation's. What actually happened is one account-level
    # event, so it gets one account-level frame.
    #
    # ⚠ The rotating install is skipped by name, exactly as `vault._nudge`
    # skips a writer and for the same reason: it is the device that is about to
    # write the state back, and it must not be told to drop the copy it is
    # holding. "primary" is the ABSENCE of a name rather than a device, so an
    # unnamed rotator is NOT skipped and hears its own reset. That is why the
    # frame means "the island's copy is gone and your derivation is retired,
    # re-derive and republish" and never "wipe what you have": a client that
    # reads it as a wipe loses the only remaining copy the moment it rotates
    # from an unnamed install.
    #
    # No queue and no replay, like every other socket nudge: a device that was
    # offline learns the same thing the same way it always did, by re-reading
    # its slots on reconnect and finding them gone.
    await manager.send(
        uin,
        {"type": "vault_reset", "reason": "identity_reissued"},
        except_device=carry_device_id(device_id),
    )
    return RegisterOut(
        uin=uin, token=issue_token(uin, await uin_epoch(uin), carry_device_id(device_id))
    )


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

    # Delete owned groups. CASCADE on GroupMember.group_id removes those rows
    # automatically. (`polls.group_id` used to be named here too. Polls were
    # removed on 2026-08-23; the orphaned table still carries its physical FK
    # on Postgres, so it keeps cascading, but nothing in the app depends on
    # that either way. See the block in core/db.py.)
    if owned_group_ids:
        await db.execute(
            delete(Group).where(Group.id.in_(owned_group_ids))
        )

    # Remove user from groups where they were just a member.
    await db.execute(
        delete(GroupMember).where(GroupMember.uin == uin)
    )

    # Wipe every other per-UIN row so a RECYCLED UIN (re-registered, or
    # re-registered after a burn) never inherits the burned owner's data.
    # one_time_prekeys and devices ON DELETE CASCADE off the user row, but a
    # long tail of tables key on UIN with no FK cascade.
    #
    # The list lives in `app/services/uin_rows.py`, shared with the migration
    # path so the two can no longer drift: this block and that one were both
    # hand-maintained and both had gaps (queued GROUP ciphertext, the queue
    # drain cursor, capabilities and the signed federation record were missed
    # here, along with several per-feature tables that have since been
    # deleted outright).
    await purge_uin_rows(db, uin)
    # ⚠ The one row `purge_uin_rows` structurally cannot reach, and it needs
    # the KEY rather than the number. `gossip_records` is this island's MIRROR
    # of some identity's signed home-island record, keyed by the global Ed25519
    # `sk`; anybody may write one, and for a burned account it kept serving
    # "this identity lives at these islands under these numbers" forever. The
    # key is `user.signing_key` on the row about to be deleted, so it has to be
    # read HERE, before `db.delete(user)` below. Mirrors of the same record on
    # OTHER islands are out of reach from here; `services/gossip_sweep` ages
    # those out on demand.
    await purge_gossip_mirror(db, user.signing_key)
    await db.execute(delete(DeviceToken).where(DeviceToken.uin == uin))

    # The number goes back into circulation, so retire every token minted for
    # THIS holder: otherwise a saved bearer keeps authenticating as whoever
    # gets the number next (see app/models/uin_epoch.py).
    new_epoch = await bump_uin_epoch(db, uin)

    await db.delete(user)
    await db.commit()
    await cache_uin_epoch(uin, new_epoch)
