import base64
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy import case, delete, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import log_identity, settings
from app.core.db import get_db
from app.core.rate_limit import enforce_rate_limit, rate_limit, island_ceiling
from base64 import b64decode

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.guest_policy import ALLOW, guest
from app.core.security import (
    _bearer,
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
from sqlalchemy.exc import IntegrityError
from app.models.invite import Invite, hash_invite_code
from app.models.uin_sale import SpentVoucher
from app.services import uin_voucher
from app.models.group import Group, GroupMember
from app.models.device_token import DeviceToken
from app.models.queue_cursor import QueueCursor
from app.models.user import User, earned_badges, grant_badge
from app.models.vault import VaultSlot
from app.core import guest_policy
from app.routers.groups import (
    SNAPSHOT_BROADCAST_LIMIT,
    _armed_join_stamp,
    _broadcast_membership,
    _load_group,
    _members_with_users,
    _serialize,
)
from app.services import guest_accounts, guest_proof
from app.services.account_delete import purge_account
from app.services.group_log import seed_cursors_on_join
from app.services.island_hosts import island_hosts
from app.services.connection_manager import manager
from app.services.contact_source import add_edges
from app.services.key_owner import uin_for_signing_key
from app.services.queue_drain import account_watermark, upsert_cursor
from app.services.uin import allocate_uin, is_reserved_uin, uin_is_taken
from app.services.uin_rows import purge_gossip_mirror, purge_uin_rows
from app.models.retired_signing_key import RetiredSigningKey
from app.services import reissue_proof

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
    #: True when the account this token opens is a guest copy (spec
    #: 2026-09-15): it takes part in rooms here and nothing else. A client
    #: that sees it on its own primary session hides contacts, calls and the
    #: rest, and must never adopt the island as a backup home on the strength
    #: of such a reply. Defaults False, so every reply older than guests, and
    #: every native account, reads exactly as before. `RefreshOut` inherits it.
    guest: bool = False


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


def _invite_gates(code_hash: str) -> tuple:
    """WHERE clauses for "this invite can still be spent". Used inside the one
    atomic UPDATE that spends a use, by registration and by guest settle
    alike, so the two doors cannot disagree about what a live invite is."""
    return (
        Invite.code == code_hash,
        Invite.used_count < Invite.max_uses,
        or_(Invite.expires_at.is_(None), Invite.expires_at > datetime.now(timezone.utc)),
    )


def _invite_spent_now():
    """The `spent_at` value for that UPDATE. Stamped in the same statement that
    spends the use, so an invite whose LAST use this is gets its retention
    clock started without a second statement that could lose the race.
    Anything short of the last use leaves the column alone."""
    return case(
        (Invite.used_count + 1 >= Invite.max_uses, datetime.now(timezone.utc)),
        else_=Invite.spent_at,
    )


class RegisterChallengeIn(BaseModel):
    signing_key: str


class RegisterChallengeOut(BaseModel):
    challenge: str


@router.post(
    "/register/challenge",
    response_model=RegisterChallengeOut,
    dependencies=[
        Depends(rate_limit("auth_register_challenge", 60, 3600, fail_closed=True)),
        Depends(rate_limit("auth_register_challenge_net", 240, 3600, fail_closed=True, by_subnet=True)),
    ],
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
    # Three caps, because 2026-09-01 showed that one is not a cap. Per address
    # as before; per /24 or /64, because 28 addresses inside one rented machine
    # is not 28 actors; and the island's own ceiling, which is the only one a
    # rotating source cannot walk around. All three fail closed: an account is
    # minted here, and minting must stop when the bookkeeping stops.
    dependencies=[
        Depends(rate_limit("auth_register", 20, 3600, fail_closed=True)),
        Depends(rate_limit("auth_register_net", 60, 3600, fail_closed=True, by_subnet=True)),
        Depends(island_ceiling(
            "auth_register",
            lambda: settings.REGISTER_CEILING_PER_MINUTE,
            lambda: settings.REGISTER_CEILING_PER_HOUR,
        )),
    ],
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
    invite_gates = _invite_gates(code_hash)
    _spent_now = _invite_spent_now()
    policy = await server_settings.get("registration_policy")
    # ⚠⚠ PAID ENTRY RIDES THE INVITE FIELD, on purpose. An entry voucher and an
    # invite answer the same question — "may this person have an account here"
    # — and every client already has one box for that answer, on four
    # platforms and in seven languages. Giving payment its own field would have
    # meant a second box beside the first, asking people to know which of two
    # credentials they are holding, which is exactly the confusion the gateway
    # key was just renamed to avoid.
    #
    # An invite still works on a paid island, and that is deliberate: it is how
    # the operator lets somebody in without charging them, and later how a
    # resident spends one of their own.
    #
    # The voucher is tried FIRST and only when it looks like one, so a plain
    # invite never pays the cost of a signature check.
    resident_at: datetime | None = None
    # How this account is getting in, for `users.entered_via`. Starts as a
    # walk-in and is overwritten by whichever credential actually opens the
    # door below. ⚠ Stamped on EVERY registration, including on an open
    # island, because NULL in that column means "registered before the column
    # existed" and the free invite drip (routers/invites.py) reads it that
    # way: a fresh walk-in left NULL would look like a legacy account.
    entered_via = "open"
    # ⚠⚠ NOT gated on the policy. A voucher is money that has already changed
    # hands, so it is redeemed whenever one is presented and it verifies, even
    # on an island whose door happens to be open. The alternative was tried on
    # paper and is indefensible: somebody buys entry, the operator has not
    # flipped the island to paid yet, and the island takes the voucher, records
    # nothing, and lets them in as an ordinary stranger. They paid to be a
    # resident and `resident_since` would be NULL for ever.
    #
    # The POLICY decides whether a voucher is REQUIRED. That is a different
    # question and it is answered below.
    if code:
        try:
            nonce = uin_voucher.verify_entry(
                code, expect_host=str(await server_settings.get("island_host") or "")
            )
        except uin_voucher.VoucherError as e:
            # Not a voucher, or not one for us. A malformed string still has a
            # chance of being an invite, so fall through and let the invite gate
            # answer; anything that names another island or has been tampered
            # with is refused here and now.
            if e.code in ("voucher_other_island", "voucher_expired"):
                raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": e.code}) from None
        else:
            # Signed by the till. Now the second question, which the signature
            # cannot answer: has it been redeemed already. One row, nonce as the
            # primary key, exactly as a number sale does it.
            db.add(SpentVoucher(nonce=nonce))
            try:
                await db.flush()
            except IntegrityError:
                await db.rollback()
                raise HTTPException(
                    status.HTTP_409_CONFLICT, detail={"code": "voucher_spent"}
                ) from None
            resident_at = datetime.now(timezone.utc)
            entered_via = "voucher"
            code = ""  # spent as a voucher; do not also spend it as an invite

    if policy in ("invite", "paid") and resident_at is None:
        if not code:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail={"code": "invite_required" if policy == "invite" else "entry_required"},
            )
        consumed = await db.execute(
            update(Invite)
            .where(*invite_gates)
            .values(used_count=Invite.used_count + 1, spent_at=_spent_now)
        )
        if consumed.rowcount == 0:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "invite_invalid"})
        entered_via = "invite"
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
            # A row was spent, so this is an invited entry even though the door
            # was open: it is the consumed ROW that decides, not the policy.
            entered_via = "invite"
            reserved_uin = await db.scalar(select(Invite.uin).where(Invite.code == code_hash))

    # ⚠⚠ A KEY THAT ALREADY HOLDS A GUEST ROW HERE BECOMES THAT ROW, NEVER A
    # SECOND ONE (spec 2026-09-15, 9.2). The door has just said yes (voucher,
    # invite or open), so this person may live here, and they already have an
    # account here: the guest copy, with its number and its rooms. Inserting a
    # new row instead would leave two rows for one key, and recovery follows
    # the OLDER claim, so their own phrase would land in the guest copy and
    # never reach the account they paid for. A hostile member could arrange
    # that on purpose by owner-adding somebody's public key before they buy
    # entry. Only under `proven`: an unproven registration for a key that is
    # taken was already refused above with `key_proof_required`.
    if proven:
        guest_row = await guest_accounts.row_for_key(
            db, reissue_proof.decode_key32(signing_key), guests_only=True
        )
        if guest_row is not None:
            return await _convert_guest_on_register(
                db,
                uin=guest_row.uin,
                identity_key=identity_key,
                resident_at=resident_at,
                reserved_uin=reserved_uin,
                device_id=body.device_id,
            )

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
        # NULL unless an entry voucher was redeemed a few dozen lines up. An
        # invite, even on a paid island, does not make somebody a resident:
        # they were let in, they did not buy their way in, and the two are
        # different facts about the same person.
        resident_since=resident_at,
        # Which credential opened the door, decided above. Never NULL from
        # here on: NULL is reserved for rows older than the column.
        entered_via=entered_via,
        # ⚠ The mark comes with the money. Two paths grant one without an
        # operator, this one and `POST /residency/redeem` for an account that
        # already exists, and both do it off a spent voucher and nothing else.
        # It is a slug the clients have never
        # heard of, which is deliberate and safe: every client draws an unknown
        # kind from the island's own `badge_labels`, so naming and colouring it
        # is an island setting rather than four client releases.
        #
        # Both columns: what they hold, and what they wear. A brand new account
        # wears it because there is nothing else to wear.
        badge="resident" if resident_at else None,
        badges_earned="resident" if resident_at else None,
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


async def _convert_guest_on_register(
    db: AsyncSession,
    *,
    uin: int,
    identity_key: str,
    resident_at: datetime | None,
    reserved_uin: int | None,
    device_id: str | None,
) -> RegisterOut:
    """The in-place conversion of section 9.2, after the door said yes.

    ⚠ Nothing is committed before the refusals below. The voucher nonce (flushed)
    and the invite use (UPDATE) are still inside this transaction, so a refusal
    rolls both back and the person keeps their code.
    """
    if reserved_uin is not None:
        # An invite that carries its own number cannot be applied to a row that
        # already has one, and quietly spending it on the guest's number would
        # throw away what the invite was for.
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "invite_has_number"})
    # A plain registration mints a new account, which no install can have been
    # disconnected from. This hands out a session for an EXISTING one, so it is
    # a mint in the #607 sense and asks the denylist like recover does.
    try:
        await _refuse_revoked_device(uin, device_id)
    except Exception:
        await db.rollback()
        raise
    user = await db.get(User, uin)
    guest_accounts.clear_guest_columns(user)
    # The key holder's own request, proven by the signature above; an adder's
    # guess at their identity key is replaced here.
    user.identity_key = identity_key
    if resident_at is not None:
        user.resident_since = resident_at
        grant_badge(user, "resident")
    user.last_seen = datetime.now(timezone.utc)
    # ⚠⚠ EVERY BEARER MINTED BEFORE THIS REQUEST DIES, in the same commit as
    # the conversion (review 2026-09-15). This hands a resident's session to
    # whoever proved the key, and nobody showed a bearer. A guest row can reach
    # a key by rotation without anyone proving the new private key (see
    # `retire_bearers_before_proof`): a free copy parked on the payer's public
    # key would otherwise become a paid resident its rotator is still signed
    # into. An honest guest's other devices re-prove the key once.
    epoch = await guest_accounts.retire_bearers_before_proof(db, uin, always=True)
    await db.commit()
    await guest_accounts.bearers_retired(uin, epoch)
    await guest_accounts.after_conversion(db, uin)
    # No founder edge, no inviter edge, no beta room: this is not a new
    # account, and it already has the rooms it chose.
    return RegisterOut(uin=uin, token=issue_token(uin, await uin_epoch(uin), device_id), guest=False)


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
@guest(ALLOW)
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
@guest(ALLOW)
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
        # Upsert, not INSERT: the client may well be retrying this call (it keeps
        # the token it gets, so a lost answer means a second attempt with the same
        # device id), and a plain insert made that retry a 500 on
        # `queue_cursors_pkey`. On conflict the row's marks are left where they
        # are, which is right: whoever created it in between seeded it themselves.
        # Only `updated_at` moves, so the row does not look abandoned.
        await upsert_cursor(
            db, uin, body.device_id,
            seed_direct=floor_direct, seed_group=floor_group,
        )
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
    #
    # ⚠⚠ The order itself (COALESCE of identity_created_at and created_at, then
    # uin) lives in services/key_owner.py and nowhere else. /federation/uin-for-key
    # must pick the SAME row, because a group owner adds whatever it returns and
    # the member later recovers into whatever this returns; when the two sorted
    # differently, the member recovered into an account outside the group.
    uin = await uin_for_signing_key(db, sk)
    if uin is None:
        # ⚠⚠ Not every missing key is a burned account. A key this island
        # retired in a rotation still opens nothing, but the account behind it
        # is alive, and `identity_not_found` is the word every client wipes on.
        # See `_rotated_account`.
        rotated = await _rotated_account(db, sk)
        if rotated is not None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, detail={"code": "identity_rotated", "uin": rotated}
            )
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "identity_not_found"})
    # Recovery is the other door into the same room: it mints a session from the
    # signing key alone, so a disconnected install must not be able to walk
    # through it either. A genuine re-install carries a device id the account has
    # never revoked (or none at all) and is unaffected.
    await _refuse_revoked_device(uin, body.device_id)
    guest = await _claim_seat_on_proof(db, uin)
    return RegisterOut(
        uin=uin, token=issue_token(uin, await uin_epoch(uin), body.device_id), guest=guest
    )


async def _claim_seat_on_proof(db: AsyncSession, uin: int) -> bool:
    """Section 4.5: a proof of the signing key opens an unclaimed seat, and the
    reply says whether the account is a guest. Returns that flag.

    ⚠ Recover and refresh DO claim seats, although they prove only the signing
    key and cannot repair a wrong identity key the adder supplied. Refusing
    would make every owner-add unusable for every client that predates
    `/auth/guest` (critic disposition, section 18); new clients call
    `/auth/guest` first, which repairs the key.

    One primary-key read for a native account, which is every recovery on an
    island without guests. The UPDATE runs only for a seat.

    ⚠⚠ The same read carries `key_unproven_since`: when a reissue moved a guest
    row onto this key and nobody has proven it since, this proof is the first,
    and every bearer minted before it dies here, BEFORE the caller mints its
    own token (`guest_accounts.retire_bearers_before_proof`, review
    2026-09-15). Without it the key holder would share the row with whoever
    rotated it.
    """
    row = (
        await db.execute(
            select(User.guest_status, User.key_unproven_since).where(User.uin == uin)
        )
    ).first()
    status_now = row.guest_status if row is not None else None
    if row is not None and row.key_unproven_since is not None:
        epoch = await guest_accounts.retire_bearers_before_proof(db, uin)
        if epoch is not None:
            await db.commit()
            await guest_accounts.bearers_retired(uin, epoch)
    if status_now == guest_policy.STATUS_ADDED:
        # No `mark_guest`: a seat is in the guest set already, and stays there.
        if await guest_accounts.claim_seat(db, uin):
            await db.commit()
            await guest_accounts.announce_rooms(db, uin)
            await guest_policy.bump_stat("guest_claim")
        status_now = await db.scalar(select(User.guest_status).where(User.uin == uin))
    return status_now is not None


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
class RefreshOut(RegisterOut):
    """`uin` + `token`, plus the one field that stops a second device from
    deleting itself.

    ⚠⚠ `moved_from` is set when the number asked for no longer exists and the
    key resolved to one account instead: the person moved, and this device is
    the one that was not in their hand at the time. Before this, that device
    got `identity_not_found`, which every client reads as "the account was
    burned" - so a phone left in a drawer wiped its own copy of the chats
    because its owner bought a shorter number on their laptop.

    A client that does not know the field still sees a different `uin` in the
    answer and can refuse it, which is what the web one does. It ends up where
    it started, retrying, rather than erasing anything.
    """

    moved_from: int | None = None


class RefreshIn(BaseModel):
    uin: int
    signing_key: str
    challenge: str
    # base64 Ed25519 signature over the exact challenge string.
    signature: str
    device_id: str | None = Field(default=None, max_length=64)


@router.post(
    "/refresh",
    response_model=RefreshOut,
    # Once per start-up per install, plus the odd 401 retry. Keyed by IP (there
    # is no session yet), and loose for the same CGNAT reason as /auth/register.
    #
    # ⚠ 60 an hour was the whole address's budget, and a browser keeps no
    # token on disk: it mints on every page load (it minted TWICE until
    # web 2026-09-26). One phone reloading the page a few dozen times, or a
    # handful of people behind one carrier NAT, and the address was out for an
    # hour, every call after that going out tokenless (#1041). The address
    # ceiling is now an abuse ceiling, and the per-account budget below, taken
    # only AFTER the signature checks out, is the one a real person meets.
    dependencies=[Depends(rate_limit("auth_refresh", 240, 3600))],
)
async def refresh(body: RefreshIn, db: AsyncSession = Depends(get_db)) -> RefreshOut:
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
    moved_from: int | None = None
    if owned is None:
        # ⚠⚠ The number is not there. Two very different reasons, and answering
        # both with "identity_not_found" is what made a second device delete a
        # live account: the owner MOVED (bought a shorter number on another
        # device, took a free one, was granted one) and this install is still
        # asking about the number they left. The account is alive; only its
        # name changed.
        #
        # The proof is unchanged - the signature above already showed
        # possession of the private key - so resolving by key alone grants
        # nothing `/auth/recover` would not grant the same caller. Two guards
        # keep it narrow:
        #
        #   * the number asked for must be VACANT. If somebody else answers as
        #     it now, this is not a move, and handing over a different account
        #     would be answering a question nobody asked;
        #   * the key must resolve to EXACTLY ONE account. Seven keys on the
        #     flagship are carried by more than one, and picking a winner among
        #     them is how a device ends up in a stranger's account. Ambiguity
        #     goes to recovery, where a person is looking at the screen.
        still_there = await db.scalar(select(User.uin).where(User.uin == body.uin))
        ambiguous = False
        if still_there is None:
            candidates = (
                await db.execute(select(User.uin).where(User.signing_key == sk).limit(2))
            ).scalars().all()
            if len(candidates) == 1:
                owned = int(candidates[0])
                moved_from = int(body.uin)
            elif len(candidates) > 1:
                # ⚠⚠ REFUSED, BUT NOT ABSENT, AND THE DIFFERENCE DECIDES WHETHER
                # A LIVE ACCOUNT IS ERASED. This branch means the number is
                # vacant AND this key answers for more than one account, so we
                # will not pick a winner. Until today it left by the same door
                # as "no such identity", and every client reads that one word
                # as "the account was burned, wipe the local copy". A phone
                # that was switched OFF while its owner moved to a new number
                # therefore erased a living account on its next launch, and
                # only for the people whose key is shared, who are exactly the
                # people the guard exists to protect.
                #
                # Same 404, different word, so an older client is no worse off
                # than it is today and a newer one can hold still and send its
                # owner to recovery, where a person is looking at the screen.
                ambiguous = True
    if owned is None:
        if not ambiguous:
            # ⚠⚠ The third reason the number is not there under this key: its
            # owner changed keys on another device. Same shape as the move
            # above, same stakes: answered `identity_not_found`, the device
            # erases a live account. The uin is the account's CURRENT number,
            # which a move after the rotation may have changed.
            rotated = await _rotated_account(db, sk)
            if rotated is not None:
                raise HTTPException(
                    status.HTTP_404_NOT_FOUND,
                    detail={"code": "identity_rotated", "uin": rotated},
                )
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail={"code": "identity_ambiguous" if ambiguous else "identity_not_found"},
        )
    # Per account, and only once the key has been proved: a stranger cannot
    # spend somebody else's budget, and the account holder can only spend
    # their own (#1041).
    await enforce_rate_limit(f"uin:{owned}", "auth_refresh_uin", 120, 3600)
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
            # Upsert for the same reason as /auth/device above: two refreshes of
            # one install can land at once (a reconnect racing a foreground
            # refresh), and the loser of a plain INSERT was a 500.
            await upsert_cursor(
                db, owned, body.device_id,
                seed_direct=floor_direct, seed_group=floor_group,
            )
            await db.commit()
    guest = await _claim_seat_on_proof(db, owned)
    return RefreshOut(
        uin=owned,
        token=issue_token(owned, await uin_epoch(owned), body.device_id),
        moved_from=moved_from,
        guest=guest,
    )


# ── identity key re-issue (in-place rotation) ───────────────────────────────
# Re-key an EXISTING account without changing the UIN. The caller is already
# authenticated (the bearer token proves they own the UIN), so this simply
# rewrites the long-term X25519 identity key + Ed25519 signing key on the user
# row. The client then follows up with POST /keys/bundle to rotate its libsignal
# bundle — which changes the safety number, so contacts get a "safety number
# changed" warning the next time they sync this user's keys. Used when a user
# fears their keys were compromised, or just wants a fresh recovery phrase.
#
# Until 2026-09-15 this took no signature proof: the JWT alone authorised the
# change, on the theory that a user can only brick their OWN account. The theory
# missed the token thief (spec F3, critic 2). A stolen bearer could rotate the
# row to keys of its own and lock the owner out, and since nothing here touched
# the epoch, the thief's session also outlived the owner's rotation.
#
# So a change can now carry a proof signed by the OLD signing key over exactly
# what changes, bound to this island and this number (services/reissue_proof).
# A signed change bumps the epoch, which kills every older token; the rotating
# caller gets a fresh one. And the retired key is recorded, so the account's
# other devices hear `identity_rotated` from /auth/refresh and /auth/recover
# instead of the `identity_not_found` they wipe on.
#
# GRACE MODE. A missing proof is still accepted, counted and logged, because
# every client in people's hands today sends none. The operator setting
# `reissue_require_proof` turns that into a 403; the spec's release order says
# when (30 days at zero unsigned, and the signing builds as the minimum).
class ReissueIn(BaseModel):
    identity_key: str
    signing_key: str
    # ── the optional `rcq-reissue-v1` proof ────────────────────────────────
    # All six or none. Optional on the wire so an old client's body still
    # parses; checked by hand below rather than by pydantic, so a broken proof
    # gets the documented 400 code instead of a generic 422.
    proof_v: int | None = None
    #: The island the client believes it is talking to. Checked against this
    #: island's own name, never trusted: see `_reissue_hosts`.
    host: str | None = Field(default=None, max_length=260)
    #: The key being replaced. Redundant with the row on purpose: a client that
    #: signed against a key the island no longer holds gets a distinct 409 it
    #: can act on, instead of a bad-signature 403 it cannot tell from forgery.
    old_signing_key: str | None = None
    ts: int | None = None
    #: 16 random bytes, base64url, no padding (22 characters).
    nonce: str | None = None
    #: Ed25519 by the OLD signing key over `reissue_proof.proof_bytes`, standard base64.
    signature: str | None = None


_PROOF_FIELDS = ("proof_v", "host", "old_signing_key", "ts", "nonce", "signature")
# The daily counters live 40 days so the "30 consecutive days at zero" the
# require switch waits for can be read straight off Redis.
_STAT_TTL_SECONDS = 40 * 24 * 60 * 60
# Longer than the whole acceptance window (ts +/- REISSUE_PROOF_SKEW_SECONDS),
# so a nonce cannot be spent a second time while its ts is still acceptable.
_NONCE_TTL_SECONDS = 1800


async def _bump_reissue_stat(name: str) -> None:
    """INCR `stat:<name>:<YYYYMMDD>` (UTC). Best-effort: a counter must never
    fail a key change. No uin in the key: these count HOW rotations happen on
    the island, and a per-account tally would be a rotation log."""
    try:
        from app.core.redis import get_redis

        redis = await get_redis()
        key = f"stat:{name}:{datetime.now(timezone.utc):%Y%m%d}"
        pipe = redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, _STAT_TTL_SECONDS)
        await pipe.execute()
    except Exception:  # noqa: BLE001
        pass


async def _claim_reissue_nonce(key: str) -> bool:
    """SET NX the replay guard. True when this is the first use.

    ⚠ Deliberately NOT best-effort, unlike the counters: a proof with no
    replay guard behind it is a proof anyone who saw it once can spend again
    inside its window. Raises when Redis is unreachable and the caller answers
    503, so the client retries the identical request later.
    """
    from app.core.redis import get_redis

    redis = await get_redis()
    return bool(await redis.set(key, "1", nx=True, ex=_NONCE_TTL_SECONDS))


async def _release_reissue_nonce(key: str) -> None:
    """Give a nonce back when the change it guarded did not commit.

    Without this a commit failure after the guard was claimed turns the
    client's IDENTICAL resend (the spec's lost-reply rule) into a 409
    `reissue_replayed` for a change that never happened.
    """
    try:
        from app.core.redis import get_redis

        await (await get_redis()).delete(key)
    except Exception:  # noqa: BLE001
        pass


# The host set a proof may name moved to `services/island_hosts.py` when the
# guest proof (`rcq-guest-v1`) needed the same answer: two proofs that bind
# "this island" must agree on what this island is called.
_reissue_hosts = island_hosts


def _key_bytes_or_none(value: str | None) -> bytes | None:
    """The 32 raw bytes of a stored key, or None for a value that is not one.

    Stored keys predate validation (an account on the flagship holds "x"), so a
    row's own key is decoded defensively rather than trusted to parse.
    """
    try:
        return reissue_proof.decode_key32(value or "")
    except ValueError:
        return None


async def _rotated_account(db: AsyncSession, signing_key: str) -> int | None:
    """The live account that retired `signing_key` in a rotation, or None.

    Both callers verified a signature under this key first, so only a holder
    of the OLD private key ever learns the answer. "Live" is checked here and
    not trusted to the marker: a burn deletes the marker (uin_rows), but a
    number recycled by some other path must not make a stranger's account the
    answer.
    """
    raw = _key_bytes_or_none(signing_key)
    if raw is None:
        return None
    row = await db.get(RetiredSigningKey, hashlib.sha256(raw).hexdigest())
    if row is None:
        return None
    alive = await db.scalar(select(User.uin).where(User.uin == row.uin))
    return int(alive) if alive is not None else None


async def _signing_key_taken_by(db: AsyncSession, raw: bytes, uin: int) -> set[int]:
    """Other accounts on this island whose signing key is `raw`.

    Both spellings, because padded and unpadded base64 both sit in the live
    table and `uin_for_signing_key` matches verbatim: a check on one spelling
    would let the other one through to the very lookup it protects.
    """
    padded = base64.b64encode(raw).decode()
    rows = await db.scalars(
        select(User.uin).where(
            User.signing_key.in_((padded, padded.rstrip("="))), User.uin != uin
        )
    )
    return {int(u) for u in rows}


async def _retire_signing_key(db: AsyncSession, old_raw: bytes, uin: int, signed: bool) -> None:
    """Record `old_raw` as retired by `uin`. The caller owns the commit.

    ⚠ ONE ROW PER KEY, and a key can be on more than one account here: seven
    signing keys on the flagship are, from before registration demanded proof.
    So a second rotation of the same key has to decide whose marker it is. A
    SIGNED rotation proved the private key and always takes it. An unsigned one
    proved only a token, which a squatter holding a copy of somebody's public
    key also has, so it may not move a marker off another LIVE account: that
    would send the real owner's other devices to the squatter's number.
    """
    sk_hash = hashlib.sha256(old_raw).hexdigest()
    now = datetime.now(timezone.utc)
    row = await db.get(RetiredSigningKey, sk_hash)
    if row is None:
        db.add(RetiredSigningKey(sk_hash=sk_hash, uin=uin, rotated_at=now))
        return
    if (
        signed
        or row.uin == uin
        or await db.scalar(select(User.uin).where(User.uin == row.uin)) is None
    ):
        row.uin = uin
        row.rotated_at = now


@router.post(
    "/reissue",
    response_model=RegisterOut,
    dependencies=[Depends(rate_limit("auth_reissue", 10, 3600))],
)
@guest(ALLOW)
async def reissue(
    body: ReissueIn,
    request: Request,
    uin: int = Depends(current_uin),
    device_id: str = Depends(current_device_id),
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> RegisterOut:
    # a) Keys that are not keys are refused before anything is looked at. This
    # used to accept any non-empty string, which is how an account came to hold
    # "x" (see `_pubkey32`); a rotation onto such a key bricks the account.
    try:
        ik = _pubkey32(body.identity_key, "identity_key")
        sk = _pubkey32(body.signing_key, "signing_key")
    except HTTPException:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "bad_key"}) from None
    new_ik_raw = reissue_proof.decode_key32(ik)
    new_sk_raw = reissue_proof.decode_key32(sk)
    # b)
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "user_not_found"})
    require_proof = bool(await server_settings.get("reissue_require_proof"))
    # c) Compared as decoded bytes, so a retry that spells the same key with or
    # without padding is still "the same keys" and not a second rotation.
    if (
        _key_bytes_or_none(user.identity_key) == new_ik_raw
        and _key_bytes_or_none(user.signing_key) == new_sk_raw
    ):
        # ⚠ THE SAME KEYS ARE NOT A ROTATION, and this route is destructive
        # enough that "do it again" has to be free. The documented flow is
        # read the slots, call this, write them back under the new derivation,
        # and a retry of a call that actually succeeded (a gateway timeout on
        # the reply, a double tap) would otherwise land AFTER the republish:
        # the vault delete below would take out the slots the client had just
        # rewritten, and `vault_reset` would tell every other session that a
        # derivation which has not moved is retired. Nothing to change and
        # nothing to announce, so only the token is reissued.
        #
        # ⚠⚠ But "only the token" was itself a hole (critic 2): the row's
        # current public keys are served by the open key card, so ANY valid
        # bearer could post them here and walk away with a brand-new session,
        # for ever, including after the owner rotated because of that very
        # theft. Once the switch is on, the branch hands back the bearer it
        # was shown and mints nothing. A genuine lost-reply retry does not need
        # a fresh token: after a SIGNED rotation the old bearer is stale and
        # never reaches this line, and the client probes /auth/refresh with the
        # new key instead.
        if require_proof:
            return RegisterOut(uin=uin, token=creds.credentials if creds else "")
        await _bump_reissue_stat("reissue_samekeys")
        return RegisterOut(
            uin=uin, token=issue_token(uin, await uin_epoch(uin), carry_device_id(device_id))
        )

    # ⚠⚠ A key change may not adopt a signing key another account here holds.
    # /auth/register has refused that since 2026-08 (`key_proof_required`), and
    # this route was the door left open: the key card hands out anyone's public
    # key, a bearer posts it here, and because a rotation leaves created_at and
    # identity_created_at alone, an OLDER account wins `uin_for_signing_key`
    # from then on. Recovery with the victim's own phrase lands in the
    # attacker's row, and /federation/uin-for-key sends group owners there.
    # The old-key proof does not close it (it proves the key being REPLACED,
    # which the attacker holds for its own row), so the check stands on its own,
    # in grace mode and after the flip alike.
    # Honest rotations mint fresh random keys and never collide.
    taken_by = await _signing_key_taken_by(db, new_sk_raw, uin)

    signed = False
    nonce_key: str | None = None
    if any(getattr(body, f) is not None for f in _PROOF_FIELDS):
        # d) A proof was offered, so it is judged, switch or no switch. ⚠ A
        # present-but-bad proof is NEVER waved through as "unsigned": that
        # would let a forger downgrade a refusal into grace-mode acceptance
        # simply by sending garbage instead of nothing.
        try:
            if (
                body.proof_v is None
                or body.ts is None
                or not body.host
                or not body.old_signing_key
                or not body.nonce
                or not body.signature
            ):
                raise ValueError("missing field")
            host = reissue_proof.canonical_host(body.host)
            if not host:
                raise ValueError("empty host")
            old_sk_raw = reissue_proof.decode_key32(body.old_signing_key)
            nonce_raw = reissue_proof.decode_nonce(body.nonce)
            sig_raw = reissue_proof.decode_signature(body.signature)
        except ValueError:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, detail={"code": "reissue_proof_malformed"}
            ) from None
        if body.proof_v != reissue_proof.VERSION:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "reissue_proof_version"})
        allowed, from_header = await _reissue_hosts(request)
        if from_header:
            await _bump_reissue_stat("reissue_host_from_header")
        if host not in allowed:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "reissue_wrong_host"})
        if _key_bytes_or_none(user.signing_key) != old_sk_raw:
            raise HTTPException(
                status.HTTP_409_CONFLICT, detail={"code": "reissue_old_key_mismatch"}
            )
        now = int(time.time())
        if abs(now - int(body.ts)) > settings.REISSUE_PROOF_SKEW_SECONDS:
            # `now` so the client can rebuild the proof against the island's
            # clock once, rather than guessing how far off its own is.
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, detail={"code": "reissue_clock_skew", "now": now}
            )
        signed_bytes = reissue_proof.proof_bytes(
            host, uin, old_sk_raw, new_ik_raw, new_sk_raw, int(body.ts), nonce_raw
        )
        try:
            Ed25519PublicKey.from_public_bytes(old_sk_raw).verify(sig_raw, signed_bytes)
        except (InvalidSignature, ValueError):
            # 403, never 401: every client answers 401 by refreshing its token
            # and trying again, and a forged proof must not start that loop.
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail={"code": "reissue_bad_signature"}
            ) from None
        if taken_by:
            # The one collision that is legitimate: a person's duplicate rows on
            # this island, following each other in a rotation cascade onto the
            # same new keys. It is recognised by the marker the FIRST of those
            # rotations left: the key this caller just proved it holds was
            # retired by the very row that now carries the new key. Nobody else
            # can meet that: the marker names a row that once held this private
            # key, and the signature above proves the caller holds it too.
            # Signed only; an unsigned change proves nothing about the old key.
            marker = await db.get(RetiredSigningKey, hashlib.sha256(old_sk_raw).hexdigest())
            if marker is None or int(marker.uin) not in taken_by:
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN, detail={"code": "key_proof_required"}
                )
        # Claimed LAST, after everything that can refuse, so a request refused
        # for any other reason does not burn its nonce and the client can fix
        # and resend it. Keyed by the canonical spelling: the same 16 bytes
        # spelled with different trailing bits must hit the same guard.
        nonce_key = (
            f"rin:{hashlib.sha256(old_sk_raw).hexdigest()[:16]}:"
            f"{reissue_proof.canonical_nonce(nonce_raw)}"
        )
        try:
            fresh = await _claim_reissue_nonce(nonce_key)
        except Exception:  # noqa: BLE001
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, detail={"code": "reissue_unavailable"}
            ) from None
        if not fresh:
            # ⚠ Means "possibly applied", not "attack": the first copy may
            # have committed and its reply been lost. The client probes
            # /auth/refresh with the NEW key rather than giving up.
            raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "reissue_replayed"})
        signed = True
    else:
        # e) No proof.
        if require_proof:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail={"code": "reissue_proof_required"}
            )
        if taken_by:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "key_proof_required"})
        # The number the require switch waits on, and the line that says a
        # token alone just rewrote an account's keys. The uin is behind
        # RCQ_LOG_IDENTITIES like every other log line that names a person.
        await _bump_reissue_stat("reissue_unsigned")
        log.warning("[reissue] unsigned key change uin=%s", log_identity(uin))

    # f) Apply.
    retired_raw = _key_bytes_or_none(user.signing_key)
    user.identity_key = ik
    user.signing_key = sk
    # ⚠⚠ A GUEST row moved onto a new signing key is marked "not proven since".
    # Nothing above proves the NEW private key, and `_signing_key_taken_by`
    # refuses only keys another row already holds, so a free guest copy can be
    # parked on a stranger's public key before that stranger ever comes here.
    # The first request that proves the key clears the mark and bumps the
    # epoch (`guest_accounts.retire_bearers_before_proof`), so the rotator's
    # bearers, this reply's included, die at that moment (review 2026-09-15).
    # An honest rotator holds the key and simply re-proves it once.
    #
    # ⏭ Native rows are not marked. The same parking works with a native row
    # on an open island and predates guest copies; guest copies only made it
    # free on paid islands, where the conversion made it worth money.
    if user.guest_status is not None and retired_raw != new_sk_raw:
        user.key_unproven_since = datetime.now(timezone.utc)
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
    new_epoch: int | None = None
    try:
        await db.execute(delete(VaultSlot).where(VaultSlot.uin == uin))
        # The marker behind `identity_rotated`, written for signed and unsigned
        # changes alike: an old device holding the retired key has to hear
        # "rotated" whichever way the change was authorised. Only when the
        # signing key actually changed; an identity-key-only change retires
        # nothing that /auth/refresh could be asked about.
        if retired_raw is not None and retired_raw != new_sk_raw:
            await _retire_signing_key(db, retired_raw, uin, signed)
        # ⚠⚠ A SIGNED change bumps the epoch, so every token minted before it
        # dies, the thief's included (critic 2); this caller gets a fresh one
        # below. An UNSIGNED change does not, deliberately: the old sibling
        # clients still in the field answer a 401 by re-proving a key that no
        # longer matches, and would reach their wipe path sooner. Those are
        # exactly the clients that send no proof, so the two stay paired until
        # the require switch retires both.
        if signed:
            new_epoch = await bump_uin_epoch(db, uin)
        await db.commit()
    except Exception:
        if nonce_key is not None:
            await _release_reissue_nonce(nonce_key)
        raise
    if new_epoch is not None:
        await cache_uin_epoch(uin, new_epoch)
    if signed:
        await _bump_reissue_stat("reissue_signed")

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
    # ⚠ The epoch bump kills old tokens at the NEXT handshake, and a socket
    # opened before it stays up regardless: a thief's live socket would keep
    # receiving everything. So a signed change closes every socket of the
    # account, the caller's included (a stolen phone token names the same
    # "primary" device the owner's phone does). AFTER `vault_reset`, and on the
    # same channel, so the other sessions hear it before they are closed. An
    # unsigned change leaves tokens alive by design (see the bump above), so
    # there is nothing to evict.
    if new_epoch is not None:
        await manager.kick_uin(uin)
    # Minted under the epoch this change produced, read from the bump itself
    # rather than back from the cache, so a Redis blip between the write-through
    # and this line cannot hand the rotating device a token that is stale on
    # arrival.
    epoch = new_epoch if new_epoch is not None else await uin_epoch(uin)
    return RegisterOut(uin=uin, token=issue_token(uin, epoch, carry_device_id(device_id)))


@router.delete("/account", status_code=status.HTTP_204_NO_CONTENT)
@guest(ALLOW)
async def delete_account(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    # The whole sequence (tell this account's other sessions, delete the rooms
    # it owns, leave the rest, every per-UIN row, the gossip mirror, the push
    # tokens, the epoch bump, the row, and the guest mark after the commit)
    # lives in `services/account_delete.py` since 2026-09-15, because the guest
    # sweep, the operator's "Delete guest copy" and the rollback hold have to
    # delete a row exactly the way a burn does (spec 2026-09-15, 8.4). A burn
    # is the one caller that announces `account_burned`: the person asked for
    # it, so their other devices wipe and go back to login.
    if await purge_account(db, uin, "owner_burned", announce_burn=True) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")


# ── guest copies (spec 2026-09-15, sections 4 and 9.1) ──────────────────────
# A person whose account lives on another island takes part in a room here
# without coming through the door. Their copy is a row with `guest_status` set,
# created ONLY together with its first membership, and restricted to rooms (see
# app/core/guest_policy.py). Nothing about their home island is sent or stored.
#
# Two requests: a challenge, then a proof over the island, the room, both keys
# and that challenge (`rcq-guest-v1`, services/guest_proof.py). A key that
# already has a row here gets a session for THAT row whatever the admission
# settings say, so turning admission off never locks out existing copies.
class GuestChallengeIn(BaseModel):
    signing_key: str = Field(max_length=128)


class GuestChallengeOut(BaseModel):
    challenge: str


@router.post(
    "/guest/challenge",
    response_model=GuestChallengeOut,
    dependencies=[
        Depends(rate_limit("auth_guest_challenge", 60, 3600, fail_closed=True)),
        Depends(rate_limit("auth_guest_challenge_net", 240, 3600, fail_closed=True, by_subnet=True)),
    ],
)
async def guest_challenge(body: GuestChallengeIn) -> GuestChallengeOut:
    """A 120 s challenge for a guest proof, bound to `typ="guest"` and to the
    key exactly as sent. The typ keeps it apart from the register and recover
    challenges in both directions. Says nothing about whether the key or any
    account exists."""
    return GuestChallengeOut(challenge=issue_key_challenge(body.signing_key.strip(), "guest"))


class GuestIn(BaseModel):
    #: Proof layout version. Anything but 1 is 400 `guest_proof_version`, not a
    #: 422, so a client from the future can tell "update the island" apart
    #: from "my request is broken".
    v: int
    #: The island as the client dialled it; canonicalised, then checked against
    #: this island's own names (`island_hosts`), never trusted.
    host: str = Field(min_length=1, max_length=253)
    #: The room on THIS island, never a client-side alias.
    group_id: int = Field(gt=0)
    nickname: str = Field(min_length=1, max_length=64)
    identity_key: str = Field(max_length=128)
    signing_key: str = Field(max_length=128)
    challenge: str = Field(max_length=2048)
    #: Ed25519 over `guest_proof.proof_bytes`, standard base64.
    signature: str = Field(max_length=128)
    device_id: str | None = Field(default=None, max_length=64)


class GuestOut(BaseModel):
    uin: int
    token: str
    #: False only when the key resolved to a NATIVE account here (a backup
    #: home, or a copy made while the door was open): the caller gets that
    #: account, unrestricted.
    guest: bool
    #: True when this request created the row (201). False for an existing row
    #: (200), claimed or not.
    created: bool


@router.post(
    "/guest",
    response_model=GuestOut,
    status_code=status.HTTP_201_CREATED,
    # Its own buckets and its own island ceiling, NOT `auth_register`'s: a
    # flood of free guest mints must not 429 the people standing at the door
    # with a paid voucher (section 4.4). All fail closed, because this mints
    # identities.
    dependencies=[
        Depends(rate_limit("auth_guest", 10, 3600, fail_closed=True)),
        Depends(rate_limit("auth_guest_day", 30, 86400, fail_closed=True)),
        Depends(rate_limit("auth_guest_net", 30, 3600, fail_closed=True, by_subnet=True)),
        Depends(island_ceiling(
            "guest_mint",
            lambda: settings.GUEST_CEILING_PER_MINUTE,
            lambda: settings.GUEST_CEILING_PER_HOUR,
        )),
    ],
)
async def guest_join(
    body: GuestIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> GuestOut:
    """Section 4.4, in its order. The order is the design: everything that can
    be refused without state is refused first, the challenge is spent before
    any token exists, existing rows are answered before the admission switch
    is read, and the room is checked before anything is written."""
    # 1. Shape.
    if body.v != guest_proof.VERSION:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "guest_proof_version"})
    identity_key = _pubkey32(body.identity_key, "identity_key")
    signing_key = _pubkey32(body.signing_key, "signing_key")
    ik_raw = reissue_proof.decode_key32(identity_key)
    sk_raw = reissue_proof.decode_key32(signing_key)
    try:
        sig_raw = reissue_proof.decode_signature(body.signature)
    except ValueError:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail={"code": "guest_proof_malformed"}
        ) from None

    # 2. A guest challenge for this key, unexpired. A register or recover
    # challenge fails here by its typ.
    if not verify_key_challenge(body.challenge, signing_key, "guest"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "invalid_challenge"})

    # 3. This island.
    host = reissue_proof.canonical_host(body.host)
    allowed, from_header = await island_hosts(request)
    if from_header:
        await guest_policy.bump_stat("guest_host_from_header")
    if not host or host not in allowed:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "guest_wrong_host"})

    # 4. The signature over island, room, both keys and challenge. A request
    # whose ik or group_id was swapped after signing fails HERE, as a bad
    # signature, which is exactly what it is.
    try:
        signed = guest_proof.proof_bytes(host, body.group_id, ik_raw, sk_raw, body.challenge)
        Ed25519PublicKey.from_public_bytes(sk_raw).verify(sig_raw, signed)
    except (InvalidSignature, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={"code": "bad_signature"}) from None

    # 5. Single use, before any token. Given back only when a commit fails.
    guard = await guest_accounts.claim_challenge(body.challenge)

    # 6. Rows that already exist for this key.
    existing = await guest_accounts.row_for_key(db, sk_raw)
    if existing is not None:
        response.status_code = status.HTTP_200_OK
        return await _guest_existing_row(
            db, existing, identity_key=identity_key, ik_raw=ik_raw,
            device_id=body.device_id, guard=guard,
        )
    rotated = await _rotated_account(db, signing_key)
    if rotated is not None:
        # The same answer recover gives, and clients must never wipe on it.
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail={"code": "identity_rotated", "uin": rotated}
        )

    # 7. Only now the operator's switch: it governs NEW rows.
    if not await guest_policy.admission_open():
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "guest_closed"})

    # 8. The room, before any write.
    g = await db.get(Group, body.group_id)
    if g is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "group_not_found"})
    if g.is_closed:
        # The existing code and meaning: a closed room needs an add by a member.
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "group_closed"})
    if g.allow_guests is False:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "guest_room_closed"})
    await guest_accounts.refuse_full_room(db, g)
    await guest_accounts.spend_room_budget(g.id)

    # 9. Create lock, and resolve again under it: a concurrent request for the
    # same key may have inserted between step 6 and here.
    lock = await guest_accounts.acquire_create_lock(sk_raw)
    try:
        existing = await guest_accounts.row_for_key(db, sk_raw)
        if existing is not None:
            response.status_code = status.HTTP_200_OK
            return await _guest_existing_row(
                db, existing, identity_key=identity_key, ik_raw=ik_raw,
                device_id=body.device_id, guard=guard,
            )

        # 10. The row and its first membership, in ONE transaction. There is no
        # such thing as a guest row without a room: nothing to sweep later.
        now = datetime.now(timezone.utc)
        uin = await allocate_uin(db)
        db.add(User(
            uin=uin,
            nickname=body.nickname,
            identity_key=identity_key,
            signing_key=signing_key,
            entered_via="guest",
            guest_status=guest_policy.STATUS_PROVEN,
            guest_since=now,
            # Backdated to one day short of the dormant window: content is
            # stored for about a day before the first poll (section 8.3).
            last_seen=now - guest_policy.mint_backdate(),
            resident_since=None,
            badge=None,
        ))
        await db.flush()
        db.add(GroupMember(
            group_id=g.id, uin=uin, role="member", joined_at=_armed_join_stamp(g),
        ))
        await db.flush()
        await seed_cursors_on_join(db, g.id, uin)
        try:
            # BEFORE the commit, and not best effort (guest_policy docstring).
            await guest_policy.mark_guest(uin)
        except guest_policy.GuestCacheUnavailable:
            await db.rollback()
            await guest_accounts.release_key(guard)
            raise guest_policy.guest_unavailable_error() from None
        try:
            await db.commit()
        except Exception:
            await db.rollback()
            await guest_policy.unmark_guest(uin)
            await guest_accounts.release_key(guard)
            raise
    finally:
        await guest_accounts.release_create_lock(lock)

    # 11. After the commit. Deliberately NOT here: the founder edge, the
    # inviter edge and the beta-room auto-join a registration gets. A guest
    # has no relationships on this island and no rooms it did not choose.
    g = await _load_group(db, g.id)
    members = await _members_with_users(db, g.id)
    await _broadcast_membership(g.id, members, _serialize(g, members))
    await guest_policy.bump_stat("guest_mint")
    from app.services.activity_rollup import bump_bg as activity_bump

    activity_bump("guest")
    # 12.
    return GuestOut(
        uin=uin,
        token=issue_token(uin, await uin_epoch(uin), body.device_id),
        guest=True,
        created=True,
    )


async def _guest_existing_row(
    db: AsyncSession,
    row: "guest_accounts.KeyRow",
    *,
    identity_key: str,
    ik_raw: bytes,
    device_id: str | None,
    guard: str,
) -> GuestOut:
    """Section 4.4 step 6: a proof for a key that already has a row here.

    * native: a session for it, and nothing else changes. This is every backup
      home and every copy that walked in while the door was open.
    * unclaimed seat: claimed, and its identity key set to the proven one,
      because the adder's copy of it may be stale or wrong.
    * proven guest: a session, and the identity key repaired if it differs.
      An identity-key-only change proven by the same signing key.
    """
    await _refuse_revoked_device(row.uin, device_id)
    # ⚠⚠ First, and for every kind of row: when a reissue parked this row on the
    # key and nobody has proven it since, this proof kills every bearer minted
    # before it (review 2026-09-15). "Bump when the claim changes something"
    # would not do: the rotator chooses the identity key too, and sets it to
    # the holder's own, so nothing below changes. A row settled after the
    # rotation is native by now and still carries the mark, hence before the
    # native branch.
    epoch = await guest_accounts.retire_bearers_before_proof(db, row.uin)
    if epoch is not None:
        try:
            await db.commit()
        except Exception:
            await db.rollback()
            await guest_accounts.release_key(guard)
            raise
        await guest_accounts.bearers_retired(row.uin, epoch)
    if row.guest_status is None:
        return GuestOut(
            uin=row.uin,
            token=issue_token(row.uin, await uin_epoch(row.uin), device_id),
            guest=False,
            created=False,
        )
    changed = claimed = False
    if row.guest_status == guest_policy.STATUS_ADDED:
        try:
            await guest_policy.mark_guest(row.uin)
        except guest_policy.GuestCacheUnavailable:
            await guest_accounts.release_key(guard)
            raise guest_policy.guest_unavailable_error() from None
        claimed = changed = await guest_accounts.claim_seat(db, row.uin, identity_key=identity_key)
    if not claimed and _key_bytes_or_none(row.identity_key) != ik_raw:
        result = await db.execute(
            update(User)
            .where(User.uin == row.uin, User.guest_status.is_not(None))
            .values(identity_key=identity_key)
            .execution_options(synchronize_session=False)
        )
        changed = (result.rowcount or 0) == 1
    if changed:
        try:
            await db.commit()
        except Exception:
            await db.rollback()
            await guest_accounts.release_key(guard)
            raise
        # Senders re-read keys and re-issue sender keys to the new identity key.
        await guest_accounts.announce_rooms(db, row.uin)
        if claimed:
            await guest_policy.bump_stat("guest_claim")
    # Read back rather than assumed: a settle racing this request may have made
    # the row native a moment ago, and the reply must not call it a guest.
    status_now = await db.scalar(select(User.guest_status).where(User.uin == row.uin))
    return GuestOut(
        uin=row.uin,
        token=issue_token(row.uin, await uin_epoch(row.uin), device_id),
        guest=status_now is not None,
        created=False,
    )


class GuestSettleIn(BaseModel):
    #: An entry voucher or an invite, in the one box every client already has.
    #: Absent on an open island, where settling is free.
    code: str | None = Field(default=None, max_length=512)


class GuestSettleOut(BaseModel):
    uin: int
    #: Set only when a voucher paid for it. An invite lets somebody live here
    #: without making them a resident, exactly as at registration.
    resident_since: datetime | None = None
    badge: str | None = None
    badges_earned: list[str] = []


@router.post(
    "/guest/settle",
    response_model=GuestSettleOut,
    dependencies=[Depends(rate_limit("guest_settle", 10, 3600, fail_closed=True))],
)
@guest(ALLOW)
async def guest_settle(
    body: GuestSettleIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> GuestSettleOut:
    """Section 9.1: a guest becomes a resident of THIS row, with its number and
    its rooms. The token does not change, because guestness is never in it.

    Suspended accounts never get here: `authorize_session` refuses them.
    """
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "user_not_found"})
    if user.guest_status is None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "not_a_guest"})
    badge_before = user.badge
    now = datetime.now(timezone.utc)
    code = (body.code or "").strip()
    if code:
        # Tried exactly as registration tries it: a voucher first, and only
        # when it looks like one; a voucher naming another island or expired
        # is refused outright; anything else may still be an invite.
        nonce: str | None = None
        try:
            nonce = uin_voucher.verify_entry(
                code, expect_host=str(await server_settings.get("island_host") or "")
            )
        except uin_voucher.VoucherError as e:
            if e.code in ("voucher_other_island", "voucher_expired"):
                raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": e.code}) from None
        if nonce is not None:
            db.add(SpentVoucher(nonce=nonce))
            try:
                await db.flush()
            except IntegrityError:
                await db.rollback()
                raise HTTPException(
                    status.HTTP_409_CONFLICT, detail={"code": "voucher_spent"}
                ) from None
            user.resident_since = now
            grant_badge(user, "resident")
        else:
            code_hash = hash_invite_code(code)
            # ⚠ BEFORE anything is consumed. An invite that reserves a number
            # is a promise of that number, and a guest row already has one.
            if await db.scalar(select(Invite.uin).where(Invite.code == code_hash)) is not None:
                raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "invite_has_number"})
            consumed = await db.execute(
                update(Invite)
                .where(*_invite_gates(code_hash))
                .values(used_count=Invite.used_count + 1, spent_at=_invite_spent_now())
            )
            if consumed.rowcount == 0:
                raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "invite_invalid"})
    else:
        # ⚠⚠ STRICT, and it is the difference between a paid island and a free
        # one for a few seconds after a worker boots. `get` on a cold worker
        # whose database blinked serves the CODE default, which is "open", and
        # this branch would then settle a guest for nothing on a paid island.
        # Refusing with 503 costs one retry.
        try:
            policy = await server_settings.get_strict("registration_policy")
        except server_settings.SettingsUnavailable:
            raise guest_policy.guest_unavailable_error() from None
        if policy != "open":
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail={"code": "invite_required" if policy == "invite" else "entry_required"},
            )
    guest_accounts.clear_guest_columns(user)
    await db.commit()
    await guest_accounts.after_conversion(db, uin)
    if user.badge != badge_before:
        from app.routers.users import _announce_rename  # local: users imports widely

        await _announce_rename(db, uin, user.nickname, badge=None if user.badge_hidden else user.badge)
    return GuestSettleOut(
        uin=uin,
        resident_since=user.resident_since,
        badge=user.badge,
        badges_earned=earned_badges(user),
    )
