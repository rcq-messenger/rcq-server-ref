from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.contact import Contact, ContactRequest
from app.models.user import User, visible_status
from app.services.apns import send_to_user as apns_send, should_push_for
from app.services.connection_manager import manager

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


class RequestRow(BaseModel):
    id: int
    from_uin: int
    nickname: str
    state: str


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
                last_seen_visible = u.last_seen
        out.append(
            ContactRow(
                uin=u.uin,
                nickname=u.nickname,
                status=live_status,
                status_message=u.status_message,
                blocked=c.blocked,
                identity_key=u.identity_key,
                signing_key=u.signing_key,
                signal_identity_key=u.signal_identity_key,
                gender=gender_visible,
                last_seen=last_seen_visible,
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
        reverse.state = "accepted"
        db.add_all([
            Contact(owner_uin=reverse.from_uin, contact_uin=reverse.to_uin),
            Contact(owner_uin=reverse.to_uin, contact_uin=reverse.from_uin),
        ])
        await db.commit()
        delivered = await manager.send(
            reverse.from_uin,
            {"type": "contact_response", "request_id": reverse.id, "accepted": True, "to_uin": uin},
        )
        if not delivered and await should_push_for(
            reverse.from_uin,
            kind="contact_response_accepted",
            sender_uin=uin,
        ):
            # Mutual-add auto-accept landed for someone offline —
            # fire a push so they see "X accepted your request" on
            # their next wake. thread-id "peer-<UIN>" routes the
            # tap straight into the new chat.
            accepter = await db.get(User, uin)
            await apns_send(
                reverse.from_uin,
                alert_title=accepter.nickname if accepter else f"#{uin}",
                alert_body="accepted your contact request",
                thread_id=f"peer-{uin}",
                notif_kind="contact_response_accepted",
            )
        return {"id": reverse.id, "state": "accepted", "auto": True}

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
            await apns_send(
                body.to_uin,
                alert_title=sender_nick,
                alert_body="wants to add you as a contact",
                thread_id="pending",
                notif_kind="contact_request",
            )
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
    if not delivered:
        await apns_send(
            body.to_uin,
            alert_title=sender_nick,
            alert_body="wants to add you as a contact",
            thread_id="pending",
        )
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
    req.state = "accepted" if body.accept else "declined"
    if body.accept:
        # Mutual contact rows so both sides see each other in their list.
        db.add_all([
            Contact(owner_uin=req.from_uin, contact_uin=req.to_uin),
            Contact(owner_uin=req.to_uin, contact_uin=req.from_uin),
        ])
    await db.commit()
    delivered = await manager.send(
        req.from_uin,
        {"type": "contact_response", "request_id": req.id, "accepted": body.accept, "to_uin": uin},
    )
    # Only push for ACCEPTED responses; declined responses are
    # silent (the requester probably doesn't want a banner saying
    # "X declined your friend request"). Tap routes to the freshly-
    # opened chat with the accepter.
    if not delivered and body.accept and await should_push_for(
        req.from_uin, kind="contact_response_accepted", sender_uin=uin,
    ):
        accepter = await db.get(User, uin)
        await apns_send(
            req.from_uin,
            alert_title=accepter.nickname if accepter else f"#{uin}",
            alert_body="accepted your contact request",
            thread_id=f"peer-{uin}",
            notif_kind="contact_response_accepted",
        )
    return {"state": req.state}


@router.delete("/{contact_uin}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_contact(
    contact_uin: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """ICQ-style mutual remove. Caller drops the contact AND the peer's
    row pointing back at the caller goes with it, so the peer's iOS
    contact list refreshes them out. A WS `contact_removed` event
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
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not in list")
    contact.blocked = not contact.blocked
    await db.commit()
    return {"blocked": contact.blocked}
