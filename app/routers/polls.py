"""Group polls.

Design: the QUESTION and OPTION LABELS travel inside the encrypted
`.poll` chat envelope (groups already broadcast group chat messages
to all members). The server stores only structural shape
(`num_options`, `single_choice`, `anonymous`) and per-option vote
tallies indexed by `option_index`. Admin reading the DB sees who
voted for `option 2` but cannot reconstruct what option 2 was — that
context is only in the (encrypted) envelope the iOS clients received.

Flow:
1. iOS calls `POST /groups/{group_id}/polls` with structural params,
   gets back `poll_id`.
2. iOS sends an in-band group chat envelope `kind = "poll"` with
   the encrypted JSON `{poll_id, question, options[], single_choice,
   anonymous}` to all peers via the normal `/groups/.../broadcast`
   path.
3. Members tap an option → `POST /polls/{poll_id}/vote {option_index}`.
4. Anyone fetches results via `GET /polls/{poll_id}` — returns
   counts per index. For anonymous polls voter_uins are stripped;
   for non-anonymous, the caller sees who voted for what.
5. Creator (or, future, group admin) can `POST /polls/{poll_id}/close`.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.group import GroupMember
from app.models.poll import Poll, PollVote

router = APIRouter(prefix="/polls", tags=["polls"])
group_polls_router = APIRouter(prefix="/groups", tags=["polls"])

# Catalog caps. 2..10 options matches Telegram + WhatsApp; longer
# ballots usually mean the user wanted a list, not a poll.
MIN_OPTIONS: int = 2
MAX_OPTIONS: int = 10


# ── DTOs ────────────────────────────────────────────────────────────


class CreatePollIn(BaseModel):
    """Server is intentionally blind to the question and option text
    — those travel encrypted in the chat envelope. We only need the
    shape + flags to validate votes."""
    message_id: str = Field(..., min_length=1, max_length=36)
    num_options: int = Field(..., ge=MIN_OPTIONS, le=MAX_OPTIONS)
    single_choice: bool = True
    anonymous: bool = False


class CreatePollOut(BaseModel):
    poll_id: int
    created_at: datetime


class VoteIn(BaseModel):
    option_index: int = Field(..., ge=0)


class OptionTallyOut(BaseModel):
    option_index: int
    count: int
    # Populated only for non-anonymous polls. iOS surfaces these as
    # "Nick, Nick2, +3 more" under each option.
    voter_uins: list[int] = []


class PollOut(BaseModel):
    poll_id: int
    group_id: int
    creator_uin: int
    message_id: str
    num_options: int
    single_choice: bool
    anonymous: bool
    closed_at: datetime | None
    created_at: datetime
    tallies: list[OptionTallyOut]
    total_votes: int
    # Caller's own selected indices — drives the iOS "you voted X"
    # state. For anonymous polls this is still returned to the
    # caller themselves (they need to know what they ticked).
    my_votes: list[int]


# ── helpers ─────────────────────────────────────────────────────────


async def _ensure_group_member(db: AsyncSession, group_id: int, uin: int) -> GroupMember:
    m = await db.scalar(
        select(GroupMember).where(
            and_(GroupMember.group_id == group_id, GroupMember.uin == uin)
        )
    )
    if m is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not a group member")
    return m


async def _hydrate_poll_out(db: AsyncSession, poll: Poll, caller_uin: int) -> PollOut:
    rows = (await db.execute(
        select(PollVote).where(PollVote.poll_id == poll.id)
    )).scalars().all()

    by_option: dict[int, list[int]] = {i: [] for i in range(poll.num_options)}
    my_votes: list[int] = []
    for v in rows:
        if 0 <= v.option_index < poll.num_options:
            by_option[v.option_index].append(v.voter_uin)
        if v.voter_uin == caller_uin:
            my_votes.append(v.option_index)

    tallies = [
        OptionTallyOut(
            option_index=i,
            count=len(by_option[i]),
            # Strip voter_uins for anonymous polls — except caller
            # themselves, surfaced via `my_votes`. For non-anonymous
            # polls return the list so the iOS bubble can render
            # "Nick, Nick2, +N more" attribution.
            voter_uins=[] if poll.anonymous else by_option[i],
        )
        for i in range(poll.num_options)
    ]

    return PollOut(
        poll_id=poll.id,
        group_id=poll.group_id,
        creator_uin=poll.creator_uin,
        message_id=poll.message_id,
        num_options=poll.num_options,
        single_choice=poll.single_choice,
        anonymous=poll.anonymous,
        closed_at=poll.closed_at,
        created_at=poll.created_at,
        tallies=tallies,
        total_votes=sum(len(v) for v in by_option.values()),
        my_votes=sorted(set(my_votes)),
    )


# ── create ──────────────────────────────────────────────────────────


@group_polls_router.post(
    "/{group_id}/polls",
    response_model=CreatePollOut,
    status_code=status.HTTP_201_CREATED,
    # Single tester drowning a group with 50 polls is the abuse
    # vector; 10/hr is generous for legitimate use.
    dependencies=[Depends(rate_limit("polls_create", 10, 3600))],
)
async def create_poll(
    group_id: int,
    body: CreatePollIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> CreatePollOut:
    await _ensure_group_member(db, group_id, uin)
    poll = Poll(
        group_id=group_id,
        creator_uin=uin,
        message_id=body.message_id,
        num_options=body.num_options,
        single_choice=body.single_choice,
        anonymous=body.anonymous,
    )
    db.add(poll)
    await db.commit()
    await db.refresh(poll)
    return CreatePollOut(poll_id=poll.id, created_at=poll.created_at)


# ── vote ────────────────────────────────────────────────────────────


@router.post(
    "/{poll_id}/vote",
    response_model=PollOut,
    # Generous — UI may bounce on connection blip and re-fire; cap
    # just stops a script from spamming the votes table.
    dependencies=[Depends(rate_limit("polls_vote", 60, 60))],
)
async def vote(
    poll_id: int,
    body: VoteIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> PollOut:
    poll = await db.get(Poll, poll_id)
    if poll is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such poll")
    if poll.closed_at is not None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"code": "poll_closed", "closed_at": poll.closed_at.isoformat()},
        )
    if not (0 <= body.option_index < poll.num_options):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail={"code": "option_out_of_range", "num_options": poll.num_options},
        )
    await _ensure_group_member(db, poll.group_id, uin)

    # Existing vote(s) for this caller on this poll.
    existing = (await db.execute(
        select(PollVote).where(
            and_(PollVote.poll_id == poll_id, PollVote.voter_uin == uin)
        )
    )).scalars().all()

    if poll.single_choice:
        # Re-vote replaces. If the caller re-clicks the SAME option,
        # treat it as a toggle off (matches the iOS bubble UX).
        already_for_same = next((v for v in existing if v.option_index == body.option_index), None)
        if already_for_same is not None and len(existing) == 1:
            await db.execute(delete(PollVote).where(PollVote.id == already_for_same.id))
        else:
            for v in existing:
                await db.execute(delete(PollVote).where(PollVote.id == v.id))
            db.add(PollVote(poll_id=poll_id, voter_uin=uin, option_index=body.option_index))
    else:
        # Multi-choice: toggle the specific option. Other options'
        # votes stay.
        already = next((v for v in existing if v.option_index == body.option_index), None)
        if already is not None:
            await db.execute(delete(PollVote).where(PollVote.id == already.id))
        else:
            db.add(PollVote(poll_id=poll_id, voter_uin=uin, option_index=body.option_index))

    await db.commit()
    await db.refresh(poll)
    return await _hydrate_poll_out(db, poll, uin)


# ── close ───────────────────────────────────────────────────────────


@router.post("/{poll_id}/close", response_model=PollOut)
async def close_poll(
    poll_id: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> PollOut:
    poll = await db.get(Poll, poll_id)
    if poll is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such poll")
    if poll.creator_uin != uin:
        # Future: also allow group owner/admin. v1 = creator only.
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only the creator can close")
    if poll.closed_at is None:
        poll.closed_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(poll)
    return await _hydrate_poll_out(db, poll, uin)


# ── read ────────────────────────────────────────────────────────────


@router.get("/{poll_id}", response_model=PollOut)
async def get_poll(
    poll_id: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> PollOut:
    poll = await db.get(Poll, poll_id)
    if poll is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such poll")
    await _ensure_group_member(db, poll.group_id, uin)
    return await _hydrate_poll_out(db, poll, uin)


@router.get("/by_message/{message_id}", response_model=PollOut)
async def get_poll_by_message(
    message_id: str,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> PollOut:
    """Lookup a poll by the chat envelope's UUID. Used by iOS to
    recover the server-side `poll_id` for `.poll` rows that pre-date
    the local CoreData `pollID` column — they reload with `pollID=nil`
    after an app relaunch and the bubble can't otherwise reach the
    Close / vote endpoints. The envelope id ⇄ poll mapping is 1:1
    (`Poll.message_id` is the UUID of the chat envelope that
    announced the poll), so this resolves without ambiguity.
    """
    poll = await db.scalar(select(Poll).where(Poll.message_id == message_id))
    if poll is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such poll")
    await _ensure_group_member(db, poll.group_id, uin)
    return await _hydrate_poll_out(db, poll, uin)
