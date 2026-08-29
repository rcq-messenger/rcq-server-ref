"""The contact graph, and stage 4 of the core-metadata plan.

Stage 4a (2026-08-23) gave every account a vault (SPEC 4.9) and all four
clients started mirroring their contact list into the `contacts` slot. Stage
4b adds the per-install `vault_contacts` mark (SPEC 2.12,
`services/contact_source`) and the batch read that replaces the `/contacts`
JOIN (`POST /users/lookup`, SPEC 4.10). Nothing about the WRITES in this
router changes yet, and that is the correction the review made:

  * every accept still records both directed rows, for every pair. The
    island stops writing them at the DROP, together with the five rules that
    read them and with the client halves that replace those rules; a freeze
    on its own turns a brand-new mutual contact into a stranger for calls,
    room invites, presence, last_seen and the picture, and lets a sibling
    install still on the 4a mirror tombstone the pair out of the shared
    vault slot. `services/contact_source` carries the long version and the
    one flag that flips it.
  * `GET /contacts` is untouched and stays untouched. It serves every row
    that exists, for everyone, which is what keeps the plan's invariant that
    "at no point is a contact list only in one place".
  * Removals land as they always did. `DELETE /contacts/{uin}` and the block
    toggle are unchanged: a relationship that has ended has to stop granting
    calls and room invites.
  * The CONSENT flow is untouched from end to end. Requests, the 202, the
    `contact_request` / `contact_response` frames, `/pending`, `/outgoing`
    and the cross-island `contactreq` envelope of federation §5f all behave
    identically -- consent is a short-lived record with a reader on both
    sides, not a relationship ledger, and stage 4 keeps it.

⚠ One consequence lands at the drop and is the honest cost of it rather than
a bug: with no row, `POST /contacts/request` can no longer answer "already in
your contact list" with a 409, because the island no longer knows. It will
open a fresh request instead, and the client hides its Add button off its own
vault list. Marked at the call site.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.contact import Contact, ContactRequest
from app.models.user import User, card_openable_for_viewer, visible_status, coarse_last_seen
from app.services.apns import send_to_user as apns_send, should_push_for
from app.services.connection_manager import manager
from app.services.contact_source import add_edges
from app.services.unifiedpush import send_to_user as up_send

router = APIRouter(prefix="/contacts", tags=["contacts"])


class ContactRow(BaseModel):
    uin: int
    nickname: str
    status: str
    status_message: str | None = None
    blocked: bool = False
    identity_key: str
    signing_key: str
    # Stage 3 marker — non-null means peer has uploaded a libsignal bundle
    # and we should ride v=2 envelopes for them. Null = Stage 2 only.
    signal_identity_key: str | None = None
    # Gender icon hint, gated by `gender_visibility`. The viewer
    # is always a mutual contact here (the row literally exists
    # because they're in our list), so "contacts" visibility
    # passes too. "nobody" / null still hides.
    gender: str | None = None
    # Gated by the contact's `last_seen_visibility`. Viewer is a
    # mutual contact, so "everyone" and "contacts" both pass;
    # "nobody" / null hide. Null when contact is currently online
    # (status field already reflects that) or when hidden.
    last_seen: datetime | None = None
    # Whether WE may place a call to this contact, per THEIR call_policy. The
    # viewer is always a mutual contact here, so "contacts" passes too — only
    # "nobody" hides the call buttons. The server still enforces the policy on
    # the call_offer itself; this just keeps the UI honest.
    callable: bool = True
    # Whether WE may open THIS contact's profile card, per THEIR
    # `profile_card_policy` (founder item 22). Exact twin of `callable`
    # above and computed the same way: the viewer is a mutual contact by
    # construction on this row, so "everyone" and "contacts" both pass and
    # only "nobody" turns the name into plain text.
    #
    # ⚠ The FIELDS on this row are deliberately NOT gated by the card
    # policy. Every one of them (nickname, status, status_message, gender,
    # last_seen, picture) is a contact-LIST field with its own rule, shown
    # on a screen the viewer built by deliberately adding this person. Item
    # 22 is about being found on surfaces nobody chose to appear on; a
    # contact list is the opposite of one. What the flag changes here is
    # whether the row is a link.
    profile_openable: bool = True
    # Profile picture. The viewer is always a mutual contact on this row, which
    # is exactly the relationship the picture is handed out for, so it needs no
    # gate of its own here.
    avatar_media_id: str | None = None
    avatar_media_key: str | None = None


class RequestRow(BaseModel):
    id: int
    from_uin: int
    nickname: str
    state: str


class OutgoingRow(BaseModel):
    id: int
    to_uin: int
    nickname: str
    state: str  # pending | declined


class AddRequestIn(BaseModel):
    to_uin: int


class RespondIn(BaseModel):
    request_id: int
    accept: bool


@router.get("", response_model=list[ContactRow])
async def list_contacts(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> list[ContactRow]:
    """Every row the island still holds for this account.

    Unchanged by stage 4 so far and deliberately so: an account that has
    moved its list into the vault keeps reading its rows here, and an install
    of it that has NOT moved reads them too. The replacement a moved client
    renders from is its own vault slot plus `POST /users/lookup` (SPEC 4.10);
    this endpoint goes when the rows do, not before.
    """
    rows = (
        await db.execute(
            select(Contact, User)
            .join(User, User.uin == Contact.contact_uin)
            .where(Contact.owner_uin == uin)
        )
    ).all()
    out: list[ContactRow] = []
    for c, u in rows:
        # Online is DERIVED from `last_seen` freshness (heartbeat-backed)
        # — robust against a killed client that never wrote "offline".
        # Fakes are decoration and keep their stored status; `visible_status`
        # handles both and maps invisible → offline for the viewer.
        live_status = visible_status(u)
        # Gender visibility tri-state. The viewer here is a
        # mutual contact (row only exists because the contact
        # graph is symmetric in our model), so "everyone" and
        # "contacts" both pass; "nobody" / null hide.
        gender_visible: str | None = None
        if u.gender:
            vis = (u.gender_visibility or "nobody").lower()
            if vis in ("everyone", "contacts"):
                gender_visible = u.gender
        # last_seen visibility — viewer is a mutual contact, so
        # "everyone" and "contacts" both pass; "nobody"/null hide.
        # Online users return null (the live status field already
        # tells the client they're here right now).
        last_seen_visible: datetime | None = None
        if live_status == "offline":
            vis = (u.last_seen_visibility or "everyone").lower()
            if vis in ("everyone", "contacts") and u.last_seen is not None:
                # A7: the hour, not the minute. See coarse_last_seen.
                last_seen_visible = coarse_last_seen(u.last_seen)
        out.append(
            ContactRow(
                uin=u.uin,
                nickname=u.nickname,
                status=live_status,
                status_message=u.status_message,
                avatar_media_id=u.avatar_media_id,
                avatar_media_key=u.avatar_media_key,
                blocked=c.blocked,
                identity_key=u.identity_key,
                signing_key=u.signing_key,
                signal_identity_key=u.signal_identity_key,
                gender=gender_visible,
                last_seen=last_seen_visible,
                callable=(u.call_policy or "everyone") != "nobody",
                # `is_contact=True` is not an assumption: this row exists
                # because the caller owns a contact edge to `u`. No lookup.
                profile_openable=card_openable_for_viewer(
                    u, viewer_uin=uin, is_contact=True
                ),
            )
        )
    return out


@router.post(
    "/request",
    status_code=status.HTTP_202_ACCEPTED,
    # Spam guard: prevents one user from blasting friend requests
    # at every UIN. 30/hr is well above the most prolific human
    # use (adding a few people from search) but stops a script in
    # its tracks.
    dependencies=[Depends(rate_limit("contact_request", 30, 3600))],
)
async def send_request(
    body: AddRequestIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Send a friend request, idempotent across all the legacy states.

    Cases handled:
      * self-add → 400
      * unknown target → 404
      * already a mutual contact → 409 (the client should hide its Add button)
      * an existing pending request from us → no-op, return it
      * an existing declined/expired request from us → reopen as pending
      * a pending request from them to us → auto-accept (mutual desire to connect)

    The previous version blindly INSERTed a new row, which slammed the unique
    `(from_uin, to_uin)` constraint as soon as any prior row existed in any state.
    """
    if body.to_uin == uin:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot add yourself")
    target = await db.get(User, body.to_uin)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")

    # ⚠ At the drop this check finds nothing for a pair that lives only in
    # the vault, so a re-add will open a fresh request rather than answering
    # 409: the island cannot tell an old friend from a stranger any more,
    # which is the point, and the client suppresses its own Add button off
    # the list it holds. Until then every accepted pair still has rows and
    # this answers exactly as it always did.
    already_contact = await db.scalar(
        select(Contact.id).where(
            and_(Contact.owner_uin == uin, Contact.contact_uin == body.to_uin)
        )
    )
    if already_contact is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "already in your contact list")

    # If they already sent us a pending request, treat our send as an acceptance.
    reverse = await db.scalar(
        select(ContactRequest).where(
            and_(ContactRequest.from_uin == body.to_uin, ContactRequest.to_uin == uin, ContactRequest.state == "pending")
        )
    )
    if reverse is not None:
        # Accepted requests are not kept as history: once the two Contact rows
        # exist they are the relationship, and nothing reads an accepted
        # request afterwards (both list endpoints exclude the state, no client
        # compares against it). Keeping them left a permanent "A asked B on
        # date D" on the island for no reader — 515 such rows going back to
        # April, before this. The row is marked here and swept an hour later;
        # see the note in respond() for why not inline.
        reverse_id, reverse_from = reverse.id, reverse.from_uin
        reverse.state = "accepted"
        reverse.resolved_at = datetime.now(timezone.utc)
        # The single writer of a contact edge (`services/contact_source`),
        # which is also where the drop will one day stop writing. The consent
        # flow itself is untouched either way -- what the two of them just
        # agreed to is carried by this response and by the WS event below,
        # not by the rows.
        await add_edges(db, reverse.from_uin, reverse.to_uin)
        await db.commit()
        delivered = await manager.send(
            reverse_from,
            {"type": "contact_response", "request_id": reverse_id, "accepted": True, "to_uin": uin},
        )
        if not delivered and await should_push_for(
            reverse_from,
            kind="contact_response_accepted",
            sender_uin=uin,
        ):
            # Mutual-add auto-accept landed for someone offline —
            # fire a push so they see "X accepted your request" on
            # their next wake. thread-id "peer-<UIN>" routes the
            # tap straight into the new chat.
            # ⚠ No name in the wake. The banner used to be titled with the
            # ACCEPTER'S NICKNAME, which handed Apple and the Android
            # distributor a real person's name tied to a device token
            # (metadata-map-2026-08-22 §1.6, the sender-name half). The
            # requester already knows who they asked, and `notif_kind` is
            # what the client localizes the line from.
            push_args = dict(
                alert_body="accepted your contact request",
                thread_id=f"peer-{uin}",
                notif_kind="contact_response_accepted",
            )
            await apns_send(reverse_from, **push_args)
            # Android rides UnifiedPush, not APNs — without this an Android
            # user simply never heard about a contact request or an accept.
            await up_send(reverse_from, **push_args)
        # ⚠ Every field below the delete comes from the locals captured above:
        # the row is gone from the session, and touching the instance here
        # would raise on a refresh rather than answer.
        return {"id": reverse_id, "state": "accepted", "auto": True}

    existing = await db.scalar(
        select(ContactRequest).where(
            and_(ContactRequest.from_uin == uin, ContactRequest.to_uin == body.to_uin)
        )
    )
    if existing is not None:
        if existing.state == "pending":
            return {"id": existing.id, "state": "pending"}
        if existing.state == "accepted":
            # Stale row left after a removal — reopen.
            existing.state = "pending"
            await db.commit()
        else:
            # declined or any other terminal state — reopen.
            existing.state = "pending"
            await db.commit()
        sender = await db.get(User, uin)
        sender_nick = sender.nickname if sender else str(uin)
        delivered = await manager.send(
            body.to_uin,
            {
                "type": "contact_request",
                "request_id": existing.id,
                "from_uin": uin,
                "from_nickname": sender_nick,
            },
        )
        if not delivered and await should_push_for(
            body.to_uin, kind="contact_request", sender_uin=uin,
        ):
            # The requester is a STRANGER, so there is nothing local for the
            # client to fill the name in from and the banner stays generic
            # until the app is opened. That is the cost, and it is the right
            # way round: a stranger's nickname on a third party's wire is
            # exactly the pairing this stage exists to stop.
            push_args = dict(
                alert_body="wants to add you as a contact",
                thread_id="pending",
                notif_kind="contact_request",
            )
            await apns_send(body.to_uin, **push_args)
            await up_send(body.to_uin, **push_args)
        return {"id": existing.id, "state": "pending"}

    req = ContactRequest(from_uin=uin, to_uin=body.to_uin, state="pending")
    db.add(req)
    await db.commit()
    await db.refresh(req)
    sender = await db.get(User, uin)
    sender_nick = sender.nickname if sender else str(uin)
    delivered = await manager.send(
        body.to_uin,
        {
            "type": "contact_request",
            "request_id": req.id,
            "from_uin": uin,
            "from_nickname": sender_nick,
        },
    )
    if not delivered and await should_push_for(
        body.to_uin, kind="contact_request", sender_uin=uin,
    ):
        # Generic banner, same reasoning as the reopen path above.
        push_args = dict(
            alert_body="wants to add you as a contact",
            thread_id="pending",
            notif_kind="contact_request",
        )
        await apns_send(body.to_uin, **push_args)
        await up_send(body.to_uin, **push_args)
    return {"id": req.id, "state": "pending"}


@router.get("/pending", response_model=list[RequestRow])
async def pending(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> list[RequestRow]:
    rows = (
        await db.execute(
            select(ContactRequest, User)
            .join(User, User.uin == ContactRequest.from_uin)
            .where(and_(ContactRequest.to_uin == uin, ContactRequest.state == "pending"))
        )
    ).all()
    return [
        RequestRow(id=r.id, from_uin=r.from_uin, nickname=u.nickname, state=r.state)
        for r, u in rows
    ]


@router.get("/outgoing", response_model=list[OutgoingRow])
async def outgoing(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> list[OutgoingRow]:
    """Requests WE sent that are still pending, plus ones the recipient
    DECLINED. Declined rows surface here because there's no push telling the
    sender "X declined you" — the client shows them in the outgoing list so
    the user can see the outcome and dismiss (DELETE /outgoing) them. The
    recipient is never told from here that they were the one who declined.
    Accepted requests are dropped from the list (the peer is already a
    mutual contact, visible in the normal contact list)."""
    rows = (
        await db.execute(
            select(ContactRequest, User)
            .join(User, User.uin == ContactRequest.to_uin)
            .where(
                and_(
                    ContactRequest.from_uin == uin,
                    ContactRequest.state.in_(("pending", "declined")),
                )
            )
        )
    ).all()
    return [
        OutgoingRow(id=r.id, to_uin=r.to_uin, nickname=u.nickname, state=r.state)
        for r, u in rows
    ]


@router.delete("/outgoing/{to_uin}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_outgoing(
    to_uin: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Cancel/revoke a contact request WE sent (state pending), or dismiss a
    DECLINED one out of our outgoing list. Deleting a still-pending row pulls
    the request out of the recipient's incoming list too: a WS
    `contact_request_cancelled` nudges them if they're online, otherwise
    their next /contacts/pending simply won't include it, and a stale
    accept/decline against the now-gone row 404s harmlessly."""
    req = await db.scalar(
        select(ContactRequest).where(
            and_(ContactRequest.from_uin == uin, ContactRequest.to_uin == to_uin)
        )
    )
    if req is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such request")
    rid = req.id
    was_pending = req.state == "pending"
    await db.delete(req)
    await db.commit()
    if was_pending:
        await manager.send(
            to_uin,
            {"type": "contact_request_cancelled", "request_id": rid, "from_uin": uin},
        )


@router.post("/respond")
async def respond(
    body: RespondIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    req = await db.get(ContactRequest, body.request_id)
    if req is None or req.to_uin != uin:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such request")
    if req.state != "pending":
        return {"state": req.state}
    req_id, req_from = req.id, req.from_uin
    if body.accept:
        # Mutual contact rows so both sides see each other in their list. Those
        # two rows ARE the relationship; the request row is spent the moment
        # they exist and is swept shortly after (services/contact_request_sweep).
        #
        # ⚠ Marked, not deleted here. Deleting inline makes a second tap on
        # Accept — a slow network and an impatient finger — answer 404 for a
        # request that in fact succeeded, and the web client raises an error
        # banner on any exception. The sweep's short delay costs an hour of
        # retention and keeps the endpoint idempotent, which is the better
        # trade for a row that used to live forever.
        await add_edges(db, req.from_uin, req.to_uin)
        req.state = "accepted"
        req.resolved_at = datetime.now(timezone.utc)
        state = "accepted"
    else:
        # ⚠⚠ A DECLINED row is NOT history and must not be swept away with the
        # accepted ones: it is the only way the sender ever learns they were
        # declined. GET /contacts/outgoing serves exactly pending+declined, no
        # push is sent for a decline on purpose, and all three clients render
        # that state ("Declined", with a Dismiss that DELETEs the row). Drop it
        # and the request silently reverts to looking like it was never sent.
        #
        # Stamped all the same, since 2026-08-22. Un-stamped is not the same as
        # un-swept: without a resolution clock the row was immortal, so "A
        # asked, B said no" outlived the two accounts' interest in it by years.
        # The stamp gives the long horizon in `contact_request_sweep` something
        # honest to measure from, and it is the refusal's own clock, not the
        # request's.
        req.state = "declined"
        req.resolved_at = datetime.now(timezone.utc)
        state = "declined"
    await db.commit()
    delivered = await manager.send(
        req_from,
        {"type": "contact_response", "request_id": req_id, "accepted": body.accept, "to_uin": uin},
    )
    # Only push for ACCEPTED responses; declined responses are
    # silent (the requester probably doesn't want a banner saying
    # "X declined your friend request"). Tap routes to the freshly-
    # opened chat with the accepter.
    if not delivered and body.accept and await should_push_for(
        req_from, kind="contact_response_accepted", sender_uin=uin,
    ):
        # Same as the auto-accept path above: no name in the wake.
        push_args = dict(
            alert_body="accepted your contact request",
            thread_id=f"peer-{uin}",
            notif_kind="contact_response_accepted",
        )
        await apns_send(req_from, **push_args)
        await up_send(req_from, **push_args)
    return {"state": state}


@router.delete("/{contact_uin}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_contact(
    contact_uin: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """ICQ-style mutual remove. Caller drops the contact AND the peer's
    row pointing back at the caller goes with it, so the peer's iOS
    contact list refreshes them out.

    ⚠ Stage 4 keeps this endpoint alive on purpose, and a client that has
    moved its list into the vault must keep calling it for as long as its
    rows exist: the five server-side rules that read them (callability, the
    group invite policy, the block filter, the card gate, avatar and
    last_seen) would otherwise go on granting a stranger what an ex-contact
    had. A pair that never had rows 404s here, and the client is expected to
    treat that as done rather than as a failure (iOS `ContactService.remove`
    swallows exactly this code) -- the removal then lives only in the vault.
    A WS `contact_removed` event
    notifies the peer if they're online so the change is immediate
    rather than waiting for their next /contacts refresh. The actual
    spam-block (silently dropping the peer's future sealed messages)
    is enforced client-side on the caller via RemovedContactsStore —
    sealed sender means the server can't filter by sender."""
    own = await db.scalar(
        select(Contact).where(
            and_(Contact.owner_uin == uin, Contact.contact_uin == contact_uin)
        )
    )
    if own is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not in list")
    await db.delete(own)
    # Reverse row, if any. Silent if the peer never had us as a contact.
    reverse = await db.scalar(
        select(Contact).where(
            and_(Contact.owner_uin == contact_uin, Contact.contact_uin == uin)
        )
    )
    if reverse is not None:
        await db.delete(reverse)
    await db.commit()
    # Fan out the change if the peer is online so they refresh without
    # waiting on /contacts.
    if reverse is not None:
        await manager.send(contact_uin, {
            "type": "contact_removed",
            "peer_uin": uin,
        })


@router.post("/{contact_uin}/block")
async def block_contact(
    contact_uin: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    rows = await db.execute(
        select(Contact).where(
            and_(Contact.owner_uin == uin, Contact.contact_uin == contact_uin)
        )
    )
    contact = rows.scalar_one_or_none()
    if contact is None:
        # ⚠ Stage 4b: a pair with no row cannot be blocked here, because the
        # flag is a column ON the row and creating one would be exactly the
        # new edge the phase stops writing. The block lives in the caller's
        # vault and their client honours it; what is lost server-side is the
        # group-add filter (`_filter_blocked` in routers/groups.py), which
        # stage 4's own "features that die" list already names. It goes pair
        # by pair as pairs move, never all at once.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not in list")
    contact.blocked = not contact.blocked
    await db.commit()
    return {"blocked": contact.blocked}
