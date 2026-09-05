import base64
import hashlib
import secrets
import hmac
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import String, and_, case, cast, delete, false, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.contact import Contact
from app.models.group import GroupMember
from app.core.db import get_db
from app.core.rate_limit import enforce_cost_budget, rate_limit
from app.core.security import current_device_id, current_uin
from app.models.capability import UserCapability
from app.models.device_token import DeviceToken
from app.models.user import POLICY_VALUES, User, card_openable_for_viewer, visible_status, coarse_last_seen
from app.services.connection_manager import manager
from app.services.contact_source import mark_vault_device, unmark_vault_device

router = APIRouter(prefix="/users", tags=["users"])

# HoF avatar limits. Stored inline in the DB as a data-URI and served publicly
# only for approved members, so keep it small (≈256 KB of image → ~350 KB
# base64 → ~360 KB with the prefix). Animated GIF is allowed (the wall is the
# website, where browsers animate it natively).
_HOF_AVATAR_MIMES = {"image/gif", "image/png", "image/jpeg", "image/webp"}
_HOF_AVATAR_MAX_CHARS = 360_000


def _validate_hof_avatar(raw: str) -> str:
    """Accept only a `data:image/{gif|png|jpeg|webp};base64,<b64>` URI under the
    size cap, with a base64 body that actually decodes. Returns the normalized
    string to store; raises 400 otherwise."""
    if len(raw) > _HOF_AVATAR_MAX_CHARS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "hof_avatar too large")
    if not raw.startswith("data:") or ";base64," not in raw:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "hof_avatar must be a base64 image data-URI")
    header, b64 = raw.split(";base64,", 1)
    mime = header[len("data:"):].strip().lower()
    if mime not in _HOF_AVATAR_MIMES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "hof_avatar unsupported image type")
    try:
        decoded = base64.b64decode(b64, validate=True)
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "hof_avatar invalid base64")
    if not decoded:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "hof_avatar empty")
    return f"data:{mime};base64,{b64}"


class PublicUser(BaseModel):
    uin: int
    nickname: str
    first_name: str | None = None
    last_name: str | None = None
    age: int | None = None
    gender: str | None = None
    city: str | None = None
    country: str | None = None
    about: str | None = None
    interests: list[str] = []
    homepage: str | None = None
    status: str
    status_message: str | None = None
    identity_key: str
    signing_key: str
    # NULL-able Stage 3 signals. Non-null `signal_identity_key` means this
    # user has uploaded a libsignal key bundle and the sender should ride
    # the v=2 envelope path (X3DH + Double Ratchet inside our existing
    # outer ECIES tunnel). Null means Stage 2 only — fall back to v=1.
    signal_identity_key: str | None = None
    signal_registration_id: int | None = None
    # Last-seen ISO timestamp, filtered by the target user's
    # `last_seen_visibility` setting:
    #   "everyone"  → always returned
    #   "contacts"  → only when the caller is a mutual contact
    #   "nobody"    → never returned
    # When suppressed the field is null on the wire; the iOS client
    # treats null as "hidden by privacy setting" and renders just the
    # status icon without a precise "Last seen" timestamp.
    last_seen: datetime | None = None
    # Owner-only echo of the visibility setting so the user can show
    # their current choice in Settings without a separate fetch.
    # Always null in third-party `from_model_for_viewer` calls — only
    # populated for `me`.
    last_seen_visibility: str | None = None
    # Same owner-only mirror for the gender visibility and group
    # invite policy controls. Third-party callers see null.
    gender_visibility: str | None = None
    group_invite_policy: str | None = None
    # Owner-only mirror of the call-policy setting. iOS / web
    # clients hide every call-related affordance when this is
    # `"nobody"` — there's no server-side gate yet, just a UI
    # contract; users who silenced calls don't see Call buttons in
    # any chat header.
    call_policy: str | None = None
    # Owner-only mirror of the read-receipts setting. Enforced
    # client-side at send-time inside `MessageService` — server is
    # blind to the decision because the receipt envelope is
    # sealed-sender. Always null for third-party callers.
    read_receipts_visibility: str | None = None
    # Owner-only mirror of the profile-card visibility setting.
    # Same tri-state as the others; null for third-party callers.
    profile_visibility: str | None = None
    # Owner-only mirror of "who may OPEN my card" (founder item 22).
    # Same tri-state, same owner-only rule as every policy above it: this
    # field tells you about YOURSELF and never about a peer. Whether a
    # PEER's card may be opened is `profile_openable` below.
    profile_card_policy: str | None = None
    # The per-viewer verdict, and the only half of item 22 a client can act
    # on: may THIS caller open THIS person's card? The twin of `callable`
    # on a contact row, and it exists for the same reason — a policy that
    # belongs to somebody else can only reach a client as an answer the
    # island already computed, never as the raw setting.
    #
    # Always present on this endpoint (it is the card route; it always has
    # viewer context). `true` for a self-fetch. Clients that predate the
    # field ignore it and simply get a card with nothing on it, which is
    # the belt to this suspenders.
    profile_openable: bool | None = None
    # "Stay visible after leaving", removed on 2026-08-23 with the columns
    # behind it (models/user.py says why). The COLUMNS are gone; these two keys
    # are not, and they are pinned to a constant off rather than dropped from
    # the response, for the same reason `hood` / `stories` / `nearby` are
    # pinned False on /server/info instead of disappearing: a missing key is
    # not the same message as an explicit one.
    #
    # ⚠⚠ Dropping them was tried first and was wrong. The shipped iOS Privacy
    # screen seeds its toggle from `UserDefaults` and only ever writes that
    # cache from `if let v = p.presencePersistent`, so an ABSENT key reads as
    # "keep what I have" and the toggle stays ON forever on every iPhone that
    # had it enabled: the picker under it stays, the contact-list countdown
    # keeps ticking, and each tap PUTs a field this server now ignores and gets
    # a 200 back. A privacy screen telling somebody they are visible when
    # presence is pure `last_seen` freshness is worse than a dead switch.
    # A literal `false` makes that `if let` fire and the toggle fall to off.
    #
    # Constants, never assigned from the model: there is no column left to read
    # and no per-viewer answer to give. A PUT that still carries them is
    # accepted and ignored (see UpdateMeIn).
    presence_persistent: bool = False
    presence_ttl_minutes: int | None = None
    # Owner-only mirror of the Hall-of-Fame opt-in (consent to be
    # considered). Approval is a separate founder-only flag, never
    # echoed here. Null for third-party callers.
    hof_opt_in: bool | None = None
    # Owner-only echo of the uploaded HoF avatar data-URI so the client can
    # preview its current image (incl. before approval). Null for third parties.
    hof_avatar: str | None = None
    # Profile picture. Handed out only to people with an established
    # relationship (see the model): a mutual contact, or yourself. Group
    # co-members get it through GroupMemberOut instead, which is gated by
    # membership rather than by the contact list.
    avatar_media_id: str | None = None
    avatar_media_key: str | None = None

    @classmethod
    def from_model_for_viewer(
        cls,
        u: User,
        viewer_uin: int,
        is_contact: bool,
        shares_group: bool = False,
    ) -> "PublicUser":
        last_seen = _last_seen_for_viewer(u, viewer_uin=viewer_uin, is_contact=is_contact)
        gender = _gender_for_viewer(u, viewer_uin=viewer_uin, is_contact=is_contact)
        owner_self = viewer_uin == u.uin
        # ── The card gate (founder item 22) ──────────────────────────────
        # Costs nothing: `is_contact` was already computed above this call
        # for last_seen, gender and the picture, so the island evaluates no
        # relationship it was not evaluating before this field existed.
        openable = card_openable_for_viewer(u, viewer_uin=viewer_uin, is_contact=is_contact)
        # Profile gate — applied to first_name, last_name, age, city,
        # country, about, interests, homepage, status_message.
        # Identity-level fields (nickname, uin, keys, status,
        # equipped_pet) always pass through; chat + crypto would
        # break otherwise. `gender` already has its own gate above,
        # but ALSO falls under profile_visibility — if profile is
        # hidden, gender is hidden regardless of its own setting.
        #
        # `and openable` is the second half of item 22, and it is the half
        # that survives a client which ignores `profile_openable`: a card
        # nobody may open is served with nothing on it. The two settings
        # compose one way only — the card gate can hide what
        # profile_visibility would have shown, never the reverse.
        profile_visible = (
            _profile_visible_for_viewer(u, viewer_uin=viewer_uin, is_contact=is_contact)
            and openable
        )
        # `last_seen` is a card field too, and it is the one field with its
        # own tri-state, so be explicit: a shut-out viewer gets nothing here
        # even when `last_seen_visibility` is "everyone". Nothing is lost by
        # it — a contact still reads the timestamp off their contact list,
        # which `GET /contacts` serves on its own relationship rule.
        if not openable:
            last_seen = None
        # A picture is not part of the profile card gate: it follows the
        # relationship, not the "who may see my details" setting. Strangers get
        # nothing here regardless of how open the rest of the profile is.
        #
        # Sharing a group IS such a relationship, and the server already acts on
        # it: `GroupMemberOut` hands the picture to co-members. Leaving it out
        # here made the two disagree about the same person — their avatar in the
        # member list, a blank flower on their profile one tap away. Reported
        # from the desktop, but it was never a client bug: every client asks
        # this endpoint and every client showed the same hole.
        avatar_ok = owner_self or is_contact or shares_group
        return cls(
            uin=u.uin,
            nickname=u.nickname,
            avatar_media_id=u.avatar_media_id if avatar_ok else None,
            avatar_media_key=u.avatar_media_key if avatar_ok else None,
            first_name=u.first_name if profile_visible else None,
            last_name=u.last_name if profile_visible else None,
            age=u.age if profile_visible else None,
            gender=gender if profile_visible else None,
            city=u.city if profile_visible else None,
            country=u.country if profile_visible else None,
            about=u.about if profile_visible else None,
            interests=([t for t in (u.interests or "").split(",") if t]
                       if profile_visible else []),
            homepage=u.homepage if profile_visible else None,
            # Self-view returns the raw user-chosen status (online/away/dnd/
            # invisible) so the iOS Status picker re-hydrates correctly on
            # app relaunch. `visible_status()` folds invisible → offline
            # AND offlines a user whose last_seen has gone stale — both
            # are correct for OTHER viewers but make a freshly-launched
            # self-view think their chosen sub-state is gone.
            status=(u.status if owner_self else visible_status(u)),
            status_message=u.status_message if profile_visible else None,
            identity_key=u.identity_key,
            signing_key=u.signing_key,
            signal_identity_key=u.signal_identity_key,
            signal_registration_id=u.signal_registration_id,
            last_seen=last_seen,
            last_seen_visibility=(u.last_seen_visibility if owner_self else None),
            gender_visibility=(u.gender_visibility if owner_self else None),
            profile_visibility=(u.profile_visibility if owner_self else None),
            profile_card_policy=(u.profile_card_policy if owner_self else None),
            profile_openable=openable,
            group_invite_policy=(u.group_invite_policy if owner_self else None),
            call_policy=(u.call_policy if owner_self else None),
            read_receipts_visibility=(u.read_receipts_visibility if owner_self else None),
            hof_opt_in=(u.hof_opt_in if owner_self else None),
            hof_avatar=(u.hof_avatar if owner_self else None),
        )

    @classmethod
    def from_model(cls, u: User, *, viewer_uin: int | None = None, is_contact: bool = False) -> "PublicUser":
        # Legacy entry point — used by /users/search where we can't
        # cheaply gate every result against the contact graph. Search
        # results never include last_seen; viewers see the precise
        # timestamp once they actually open the user's info page.
        #
        # Profile-visibility cuts conservatively here: only "everyone"
        # ships the optional profile fields. Search hits for
        # "contacts"-restricted users still surface (so a contact can
        # find them via nickname) but the row reveals only nickname
        # + uin — full data is unveiled once they tap into the
        # /users/{uin}/info endpoint that has viewer context.
        #
        # `viewer_uin` / `is_contact` arrived with the card gate (item 22).
        # A search row IS a surface that opens a card, so it has to carry
        # the verdict; the caller resolves `is_contact` for the whole page
        # in one query, and only when the page actually contains somebody on
        # "contacts" (see `search`). Defaulting to the anonymous answer
        # keeps every other caller of this classmethod correct.
        visible = (u.profile_visibility or "everyone") == "everyone"
        openable = card_openable_for_viewer(u, viewer_uin=viewer_uin, is_contact=is_contact)
        # Same composition as `from_model_for_viewer`: the card gate can
        # take away what profile_visibility would have given, never add.
        visible = visible and openable
        return cls(
            uin=u.uin,
            nickname=u.nickname,
            profile_openable=openable,
            first_name=u.first_name if visible else None,
            last_name=u.last_name if visible else None,
            age=u.age if visible else None,
            gender=u.gender if visible else None,
            city=u.city if visible else None,
            country=u.country if visible else None,
            about=u.about if visible else None,
            interests=([t for t in (u.interests or "").split(",") if t]
                       if visible else []),
            homepage=u.homepage if visible else None,
            status=u.status,
            status_message=u.status_message if visible else None,
            identity_key=u.identity_key,
            signing_key=u.signing_key,
            signal_identity_key=u.signal_identity_key,
            signal_registration_id=u.signal_registration_id,
        )


def _last_seen_for_viewer(u: User, *, viewer_uin: int, is_contact: bool) -> datetime | None:
    """Apply the target user's `last_seen_visibility` rule against
    the viewer. Owner always sees their own timestamp regardless of
    the setting — the rule is only about *outsiders*, and an outsider
    gets the HOUR, not the minute (A7, coarse_last_seen)."""
    if viewer_uin == u.uin:
        return u.last_seen
    visibility = u.last_seen_visibility or "everyone"
    if visibility == "everyone":
        return coarse_last_seen(u.last_seen)
    if visibility == "contacts" and is_contact:
        return coarse_last_seen(u.last_seen)
    return None


def _profile_visible_for_viewer(u: User, *, viewer_uin: int, is_contact: bool) -> bool:
    """Apply the target user's `profile_visibility` rule. Same shape
    as the other visibility gates — owner always sees their own
    profile; outsiders are filtered by the setting."""
    if viewer_uin == u.uin:
        return True
    visibility = u.profile_visibility or "everyone"
    if visibility == "everyone":
        return True
    if visibility == "contacts" and is_contact:
        return True
    return False


def _gender_for_viewer(u: User, *, viewer_uin: int, is_contact: bool) -> str | None:
    """Same shape as `_last_seen_for_viewer` but for gender. Default
    here is "nobody" rather than "everyone" — gender is opt-in to
    surface, opt-out for last-seen."""
    if u.gender is None:
        return None
    if viewer_uin == u.uin:
        return u.gender
    visibility = u.gender_visibility or "nobody"
    if visibility == "everyone":
        return u.gender
    if visibility == "contacts" and is_contact:
        return u.gender
    return None


class ProfileUpdate(BaseModel):
    nickname: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    age: int | None = None
    gender: str | None = None
    city: str | None = None
    country: str | None = None
    about: str | None = None
    interests: list[str] | None = None
    homepage: str | None = None
    status_message: str | None = None
    # "everyone" | "contacts" | "nobody". Validated server-side; the
    # iOS Settings picker enforces the valid set.
    last_seen_visibility: str | None = None
    gender_visibility: str | None = None
    profile_visibility: str | None = None
    # Who may OPEN my card (founder item 22). Distinct from
    # `profile_visibility` above: that one blanks the optional FIELDS and
    # still lets an empty card open, this one decides whether the card is
    # served at all and whether other clients draw the name as a link.
    #
    # ⚠ Until 2026-08-23 this key was simply absent, and `extra="ignore"`
    # meant every shipped client's Privacy screen PUT it, got a 200 and
    # changed nothing. iOS and web ship the tri-state picker; Android ships
    # the same idea as one switch and maps off → "nobody", on → "everyone".
    profile_card_policy: str | None = None
    group_invite_policy: str | None = None
    call_policy: str | None = None
    read_receipts_visibility: str | None = None
    # ⚠ `presence_persistent` and `presence_ttl_minutes` were REMOVED from this
    # model on 2026-08-23, deliberately without a 400 replacing them. Every
    # shipped iOS and Android build still PUTs the toggle from its Privacy
    # screen, and those builds stay in the field for weeks; rejecting the body
    # would fail the whole profile save (nickname, avatar, every other privacy
    # tri-state travelling in the same request), not just the dead field.
    # Pydantic's default `extra="ignore"` drops the two keys, so those clients
    # keep getting a 200 and the value goes nowhere. Do NOT put an
    # `extra="forbid"` config on this model.
    # Hall-of-Fame consent toggle. User opts in; the founder approves
    # separately (admin-only). `hof_approved` is NOT settable here.
    hof_opt_in: bool | None = None
    # Optional public HoF avatar as a data-URI. Empty string clears it.
    # Validated (mime allow-list + base64 + size cap) in update_me.
    hof_avatar: str | None = None
    # Profile picture: the id + key of an already-uploaded encrypted blob.
    # Both empty strings clear it; leaving them unset leaves the picture
    # alone, so a PATCH that only changes a nickname cannot wipe it. Same
    # convention as a group's avatar.
    avatar_media_id: str | None = Field(default=None, max_length=64)
    avatar_media_key: str | None = Field(default=None, max_length=96)


@router.get(
    "/search",
    response_model=list[PublicUser],
    # Anti-scraping: legit users open the search a few times a
    # session, scripts pull pages-per-second. 60/min is generous
    # for human use.
    dependencies=[Depends(rate_limit("users_search", 60, 60))],
)
async def search(
    q: str = Query(min_length=1),
    limit: int = Query(20, le=100),
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> list[PublicUser]:
    raw = q.strip()
    like = f"%{raw.lower()}%"
    # Search matches a NAME or a number, which is what the clients promise in
    # the field's own label ("name, UIN or group"). It used to also match city,
    # country and interests, and that was wrong twice over (#518):
    #
    #  * It broke the promise. Typing `av` returned somebody whose only `av` is
    #    in "Moscow avenue", with nothing on the row to explain why they are in
    #    the list.
    #  * Worse, it matched fields the SAME request then refuses to return.
    #    `PublicUser.from_model` blanks every optional field for a user whose
    #    profile is not "everyone", so a hidden profile still answered questions
    #    about itself through the result set: type a guess, see whether they
    #    appear. "У него скрыта информация о себе? Если скрыта, то почему по ней
    #    ищет и выдаёт?" — exactly right, and it applied to the real name too.
    #
    # So: nickname always (it is identity, never hidden, and it is the "name"
    # people search by), first/last name only while the profile is public.
    profile_public = or_(
        User.profile_visibility.is_(None),
        User.profile_visibility == "everyone",
    )
    text_clause = or_(
        User.nickname.ilike(like),
        and_(profile_public, User.first_name.ilike(like)),
        and_(profile_public, User.last_name.ilike(like)),
    )
    # `#123` is how a UIN is written everywhere in this product — in a bubble
    # header, in a profile, in a chat. Typing it into search therefore means
    # THIS number, not "anything containing 123", and it used to mean neither:
    # the `#` fell through to the text clause, which then matched `%#123%`
    # against nicknames and cities and found nothing at all.
    if raw.startswith("#") and raw[1:].isdigit():
        clause = User.uin == int(raw[1:])
    elif raw.isdigit():
        # A bare number still searches both ways: somebody who types 1990 may
        # want the number or may want it in a nickname, and we cannot tell.
        #
        # ⚠ It also has to match numbers that CONTAIN those digits. The rank
        # below has had a tier for "uin contains the query" since #525, but no
        # such row could ever reach it: this clause only admitted the exact
        # number and text matches, so searching 123 never surfaced 51234 and
        # the tier ranked an empty set (#883).
        clause = or_(
            User.uin == int(raw),
            cast(User.uin, String).like(f"%{raw}%"),
            text_clause,
        )
    else:
        clause = text_clause
    # ORDER, and it is not a nicety (#524, #525). A single letter matches 123
    # accounts on this island; `LIMIT 20` with no ORDER BY returns whichever
    # twenty Postgres happens to reach first, so searching "L" did not find the
    # user named "Li" while "Li" did — the row was never missing, it was
    # twenty-first. Founder: "выдавать сначала отсортированных друзей, потом
    # совпавший полностью номер, потом номера содержащие введённое число,
    # затем блок по нику, потом блок по имени и фамилии".
    #
    # A subquery for "is this person already my contact" rather than a join:
    # the ordering must not multiply rows, and a contact row that does not
    # exist must not drop the person from the results.
    my_contacts = select(Contact.contact_uin).where(Contact.owner_uin == me)
    exact_uin = int(raw[1:]) if raw.startswith("#") and raw[1:].isdigit() else (
        int(raw) if raw.isdigit() else None
    )
    # ⚠ Being a contact is no longer a TIER of its own, it is the tiebreaker
    # INSIDE a tier (#869). It used to outrank every kind of match: a friend
    # whose name merely contained the text stood above a stranger whose name
    # STARTED with it, so typing the first letters of a name you can see on
    # screen did not put that name first, and the search read as broken. The
    # rule "friends first" is kept exactly where it was meant to apply — among
    # people who matched equally well — and match quality decides between
    # tiers, which is also what the group filter and the mention picker have
    # always done. One reporter found all three and asked for one rule.
    #
    # Prefix covers the real name too, on the same public-profile condition as
    # [text_clause]: a person searching "Ser" for Sergey should not have to
    # know whether that is the nickname or the first name.
    prefix = f"{raw.lower()}%"
    # A query that is nothing but digits is a query about NUMBERS, so numbers
    # come first and the names that happen to contain those digits follow
    # (#883). Anything with a letter in it keeps the old order, where a name
    # match is what the person meant.
    name_tiers = (
        (func.lower(User.nickname) == raw.lower(), 1),
        (
            or_(
                User.nickname.ilike(prefix),
                and_(profile_public, User.first_name.ilike(prefix)),
                and_(profile_public, User.last_name.ilike(prefix)),
            ),
            2,
        ),
        (User.nickname.ilike(like), 3),
    )
    exact_tier = (User.uin == exact_uin, 0) if exact_uin is not None else (false(), 0)
    if raw.isdigit():
        uin_contains = cast(User.uin, String).like(f"%{raw}%")
        rank = case(
            exact_tier,
            (uin_contains, 1),
            *((cond, tier + 1) for cond, tier in name_tiers),
            else_=5,
        )
    else:
        rank = case(exact_tier, *name_tiers, else_=5)
    # False sorts before True, so contacts lead their own tier.
    contact_last = case((User.uin.in_(my_contacts), 0), else_=1)
    # Never include the caller in their own search results — Add-to-contacts on
    # self would 400, and "find people" silently shouldn't list me anyway.
    # Suspended accounts stay out of the directory. models/user.py has claimed
    # "their /users/search results are filtered out" since the flag was added;
    # this is the line that makes the claim true.
    rows = (
        await db.execute(
            select(User)
            .where(clause)
            .where(User.uin != me)
            .where(User.is_suspended.is_(False))
            .order_by(rank, contact_last, func.lower(User.nickname), User.uin)
            .limit(limit)
        )
    ).scalars().all()
    # Card gate (item 22). A search row is a surface that opens a card, so it
    # has to carry `profile_openable` — and "contacts" is the only value that
    # needs the graph to answer. So ask the graph ONLY when this page actually
    # contains somebody on "contacts", and then ask once for the whole page
    # instead of once per row. On the overwhelmingly common page (everybody on
    # the default) this adds no query at all.
    #
    # Metadata: the set being read is the CALLER'S OWN contact list, restricted
    # to uins already in their hands. `GET /contacts` hands them the same set
    # wholesale, so the island learns nothing here it does not already store,
    # and it writes nothing down.
    contact_set: set[int] = set()
    gated = [u.uin for u in rows if (u.profile_card_policy or "everyone") == "contacts"]
    if gated:
        contact_set = set(
            (
                await db.scalars(
                    select(Contact.contact_uin).where(
                        and_(Contact.owner_uin == me, Contact.contact_uin.in_(gated))
                    )
                )
            ).all()
        )
    return [
        PublicUser.from_model(u, viewer_uin=me, is_contact=u.uin in contact_set)
        for u in rows
    ]


# ── Stage 4b: POST /users/lookup ──────────────────────────────────────────
# A batch of `GET /users/{uin}/info`, and deliberately nothing more.
#
# It exists because stage 4 takes the contact list off the island. Today a
# client renders its list from `GET /contacts`, which JOINs the caller's
# `contacts` rows onto `users` and returns nickname, keys, status, picture
# and the two policy verdicts in one request. When the rows go, the JOIN goes
# with them and the client is left holding a list of numbers it read out of
# its own vault. This is how it turns those numbers back into rows.
#
# HOW MANY UINS THE ISLAND MAY SEE AT ONCE. 256 is not a privacy number, it
# is a cost number: the per-uin endpoint is capped at 180/min, and 120
# batches of 256 an hour is the same order of work. The privacy of this
# endpoint does not come from the cap.
MAX_LOOKUP_UINS = 256
# Resolved uins per account per day. The named risk on a batch read of the
# directory is bulk harvesting, not one person's contact list: at 50k a day a
# scraper needs a new account every 50k numbers, which registration already
# prices.
LOOKUP_DAILY_UINS = 50_000
# ⚠ The budget is charged in whole quanta, never in exact uins. The counter
# behind `enforce_cost_budget` is a per-account number that lives in Redis
# for 24 hours, so charging `len(wanted)` would write the caller's render-set
# SIZE into it on every refresh -- |contacts(A)|, sampled live, from the one
# endpoint built to take the contact graph out of storage. Rounded up, the
# key holds a bucket count instead. 64 keeps the daily ceiling meaningful
# (781 full batches) while making a list of 3 and a list of 60 the same
# charge.
LOOKUP_COST_QUANTUM = 64


class LookupIn(BaseModel):
    # ⚠ A body, never a query string: a uin in a URL is a uin in an access
    # log, and this list is the most sensitive thing a client sends.
    uins: list[int] = Field(min_length=1, max_length=MAX_LOOKUP_UINS)

    @field_validator("uins")
    @classmethod
    def _ascending(cls, v: list[int]) -> list[int]:
        """Strictly ascending, enforced rather than requested.

        ⚠ A client that passes its rendered list straight through sends it in
        DISPLAY order, which is most-recent-conversation first, and that is
        "who A talks to most" written into the request body -- the exact fact
        this endpoint is built not to carry. The island sees the body as sent,
        before any of the code below turns it into a set, so a SHOULD in the
        spec is a property nobody enforces. Ascending also means no repeats,
        which is why the handler's de-duplication is a belt to this.
        """
        if any(b <= a for a, b in zip(v, v[1:])):
            raise ValueError("uins must be strictly ascending")
        return v


class LookupRow(BaseModel):
    """A contact-list row, gated as if the caller had asked for this one
    person by number.

    Exactly the `ContactRow` fields of SPEC 4.2 minus `blocked`. That
    omission is the point rather than an oversight: whether you have blocked
    somebody is yours, it lives in your vault, and an island that answers it
    is keeping the negative half of the graph after giving up the positive
    half."""

    uin: int
    nickname: str
    status: str
    status_message: str | None = None
    identity_key: str
    signing_key: str
    signal_identity_key: str | None = None
    gender: str | None = None
    last_seen: datetime | None = None
    # UI hint only, computed the way `_caller_allowed` in routers/ws.py
    # computes it. The ring itself is still gated server-side there.
    #
    # ⚠ ANSWERED ONLY FOR A CONTACT, True for everybody else, and that is not
    # laziness. `PublicUser` has no such field and returns `call_policy` as
    # null to every non-self viewer, so a real verdict here for an arbitrary
    # uin would be a bit of a third party's call settings that no other
    # endpoint gives: 256 strangers classified per request into "accepts
    # calls from anyone" and "does not". `GET /contacts` computes it for
    # contacts and only for contacts, and this matches that exactly. For a
    # stranger, True means what clients already do today -- show the button,
    # let the island refuse the ring.
    #
    # ⚠ At the drop this settles at True for every row, and that is the
    # right end state rather than an accident: `is_contact` is False for
    # everyone once the table is gone, `_caller_allowed` becomes "let it
    # ring, the callee's client refuses", and a client draws the button and
    # handles the refusal. The alternative, answering `policy != "nobody"`
    # for the whole batch, would hand a caller 256 people's call settings at
    # exactly the moment the island stops being able to tell which of them
    # it is allowed to describe.
    callable: bool = True
    profile_openable: bool = True
    avatar_media_id: str | None = None
    avatar_media_key: str | None = None


class LookupOut(BaseModel):
    users: list[LookupRow]


@router.post(
    "/lookup",
    response_model=LookupOut,
    # Per ACCOUNT, and never per looked-up uin. A limiter keyed on the
    # numbers in the body would write the caller's contact list into Redis
    # one key at a time, which is how sealed sender was defeated once already
    # (metadata-map-2026-08-22 §1.1). `bucket_name` HMACs even this.
    dependencies=[Depends(rate_limit("users_lookup", 120, 3600))],
)
async def lookup(
    body: LookupIn,
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> LookupOut:
    """Resolve a batch of uins the caller already holds into list rows.

    THE RULE. For every uin in the batch this answers exactly what
    `GET /users/{uin}/info` would answer the same caller: same visibility
    gates, same card gate, same picture rule, evaluated per row. It is one
    round trip instead of N, and it is not a second way in. If a field is
    hidden from you one at a time it is hidden from you here.

    WHAT THE ISLAND LEARNS, PLAINLY. That this account asked about these
    numbers, at this moment. That is the same SHAPE of knowledge
    `GET /contacts` handed over -- a set of uins attached to an account --
    and stage 4 is not honest about removing the contact graph if the
    replacement posts it back on every boot. So, precisely:

      * it is a SUPERSET of a contact list, not a contact list. The batch is
        the caller's render set: contacts, group co-members, strangers who
        wrote first, a number typed into search a minute ago. Sending nothing
        but the contact list is a client choice, not something this endpoint
        forces.
      * ⚠ PADDING DOES NOT HIDE A NUMBER FROM THE ISLAND, only from a reader
        of the request. The island runs the query, so it knows exactly which
        of the numbers asked about resolved; chaff made of unknown or
        suspended uins falls out of its own answer. Only chaff naming LIVE
        accounts is indistinguishable from real interest, and that kind
        charges budget like any other read, so a client padding 3x reaches
        the daily 429 three times sooner. The identical omission below is a
        property of the RESPONSE (a miss, a suspension and a stranger look
        the same to whoever gets the answer), not a defence against the
        island.
      * the ORDER carries nothing, because the island refuses any other one:
        `LookupIn` requires strictly ascending uins and the answer comes back
        in the same order. A client's own list ordering ("who I talk to
        most") therefore cannot ride along in the body.
      * it writes no ROW and no log line: the path holds no digits so the
        access-log redactor has nothing to mask, and the body is never
        logged. It does write the two limiter keys, and they are the honest
        residue: `rl:users_lookup:<hmac(account)>` holds one timestamp per
        request for an hour, which is a refresh-activity trace for an account
        that may be hiding its presence, and `rlc:users_lookup_uins:` holds a
        24-hour running total charged in quanta of [LOOKUP_COST_QUANTUM] so
        that it is a count of reads and not a live measure of the caller's
        list size. Both are keyed by an HMAC of the ACCOUNT and never by a
        looked-up number -- keying a limiter on the numbers in the body is
        how sealed sender was defeated once already (metadata-map §1.1).
      * it says nothing about the reverse direction. "Who holds A in their
        list" is the question the table could answer and this cannot: an
        account that never calls this is never named by anyone else's call.

    ⚠ IT NAMES THE CALLER, AND FOR NOW IT HAS TO. Stage 3 took the session
    token OFF the key lookups (`routers/keys.py`) precisely so the island
    would stop recording "A is about to talk to B" under A's identity, and
    this endpoint hands back `identity_key` / `signing_key` /
    `signal_identity_key` for a batch, with a session. The reason is the
    per-viewer gating below -- the card gate, the picture, `last_seen`,
    `gender` all need to know who is asking, and today they resolve real
    `contacts` rows. When those rows drop, `contact_set` is empty by
    construction and the only gate left needing an identity is the
    group-co-member picture rule, which `GET /groups/{id}/members` already
    serves. THAT is the moment this moves to `current_uin_optional` plus an
    `X-Deposit-Token` like the key routes, and it is a field-level change
    rather than a wire break, which is why the shape here is already the
    shape it needs then.

    ⚠ BOTH BOUNDS ARE FAIL-SOFT. `rate_limit` and `enforce_cost_budget` log a
    warning and allow the request when Redis is unreachable (island-wide
    policy, `core/rate_limit`), so during a Redis outage this endpoint has no
    ceiling at 256 uins a request. The same outage lifts the per-uin cap on
    `/users/{uin}/info` too, but there it leaves a scraper at one number per
    request; here it leaves it at 256. Not fixed by failing closed, which
    would make the contact list the one screen that dies with Redis.

    What it therefore still gives an island that decides to watch: a live,
    repeatable, per-account interest set, and its changes over time if it
    keeps snapshots. That is a real residue and it is smaller than the table
    it replaces, not zero.
    """
    # De-duplicated, self dropped (the caller has `/users/me` and the
    # owner-self view differs on every gate), non-positive dropped.
    wanted = {u for u in body.uins if u > 0 and u != me}
    if not wanted:
        return LookupOut(users=[])
    # Rounded UP to a whole quantum, never the exact count; see the note on
    # [LOOKUP_COST_QUANTUM]. Charged before the query, so a padded batch pays
    # for what it asks about rather than for what came back.
    charged = -(-len(wanted) // LOOKUP_COST_QUANTUM) * LOOKUP_COST_QUANTUM
    await enforce_cost_budget(
        f"uin:{me}", "users_lookup_uins", charged, LOOKUP_DAILY_UINS, 86400
    )
    rows = (
        await db.execute(
            select(User)
            .where(User.uin.in_(wanted))
            .where(User.is_suspended.is_(False))
            .order_by(User.uin)
        )
    ).scalars().all()
    if not rows:
        return LookupOut(users=[])
    found = [u.uin for u in rows]
    # The caller's OWN edges, narrowed to numbers already in their hands.
    # `GET /contacts` hands them the same edges wholesale; nothing is learned
    # here that the island does not already store, and nothing is written.
    # ⚠ When the rows drop this set is empty and every "contacts"-scoped
    # field in the answer closes. That is the correct end state, not a bug:
    # the island stops being able to tell a contact from a stranger, and the
    # settings that said "contacts" become the recipient's client's job.
    contact_set = set(
        (
            await db.scalars(
                select(Contact.contact_uin).where(
                    and_(Contact.owner_uin == me, Contact.contact_uin.in_(found))
                )
            )
        ).all()
    )
    shares = set(
        (
            await db.scalars(
                select(GroupMember.uin).where(
                    GroupMember.uin.in_(found),
                    GroupMember.group_id.in_(
                        select(GroupMember.group_id).where(GroupMember.uin == me)
                    ),
                )
            )
        ).all()
    )
    out: list[LookupRow] = []
    for u in rows:
        is_contact = u.uin in contact_set
        openable = card_openable_for_viewer(u, viewer_uin=me, is_contact=is_contact)
        # Same composition as PublicUser.from_model_for_viewer: the card gate
        # can hide what profile_visibility would have shown, never the reverse.
        profile_visible = (
            _profile_visible_for_viewer(u, viewer_uin=me, is_contact=is_contact)
            and openable
        )
        last_seen = _last_seen_for_viewer(u, viewer_uin=me, is_contact=is_contact)
        if not openable:
            last_seen = None
        gender = _gender_for_viewer(u, viewer_uin=me, is_contact=is_contact)
        policy = (u.call_policy or "everyone").lower()
        out.append(
            LookupRow(
                uin=u.uin,
                nickname=u.nickname,
                status=visible_status(u),
                status_message=u.status_message if profile_visible else None,
                identity_key=u.identity_key,
                signing_key=u.signing_key,
                signal_identity_key=u.signal_identity_key,
                gender=gender if profile_visible else None,
                last_seen=last_seen,
                callable=(policy != "nobody") if is_contact else True,
                profile_openable=openable,
                # The picture follows the relationship, not the card setting,
                # exactly as on `/users/{uin}/info`.
                avatar_media_id=(u.avatar_media_id if (is_contact or u.uin in shares) else None),
                avatar_media_key=(u.avatar_media_key if (is_contact or u.uin in shares) else None),
            )
        )
    return LookupOut(users=out)


@router.get(
    "/{uin}/info",
    response_model=PublicUser,
    # `/search` was capped against scraping from day one and this was not, which
    # left the whole directory walkable one UIN at a time by anyone holding a
    # single account. Every client call site is user-driven — opening a profile,
    # resolving one unknown sender, the `#911` exact lookup — and group fan-out
    # reads keys from the roster, not from here, so no legitimate path loops
    # over this endpoint. 180/min is far above human use and turns enumeration
    # into something that needs many accounts, which registration limits price.
    dependencies=[Depends(rate_limit("users_info", 180, 60))],
)
async def info(
    uin: int,
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> PublicUser:
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    is_contact: bool
    if me == user.uin:
        is_contact = False  # field not used in owner-self path
        shares_group = False
    else:
        is_contact = (
            await db.scalar(
                select(Contact.id).where(
                    and_(Contact.owner_uin == me, Contact.contact_uin == user.uin)
                )
            )
        ) is not None
        shares_group = (
            await db.scalar(
                select(GroupMember.id)
                .where(GroupMember.uin == user.uin)
                .where(
                    GroupMember.group_id.in_(
                        select(GroupMember.group_id).where(GroupMember.uin == me)
                    )
                )
                .limit(1)
            )
        ) is not None
    return PublicUser.from_model_for_viewer(
        user, viewer_uin=me, is_contact=is_contact, shares_group=shares_group,
    )


async def _announce_rename(db: AsyncSession, uin: int, nickname: str) -> None:
    """Tell everyone holding this user as a contact that the name changed.

    A NEW packet type rather than a field bolted onto `presence`: presence has
    a visibility rule behind it (an invisible user is broadcast as offline, and
    only to `presence_watchers`), and a name has none — every contact already
    reads it from the roster. Keeping them separate means neither one has to
    borrow the other's audience.

    Additive, like `call_unreachable` before it: a client that does not know
    the type ignores it and keeps picking the name up on its next roster pull,
    which is exactly today's behaviour. Best-effort, offline contacts likewise.
    """
    owners = (
        await db.scalars(
            select(Contact.owner_uin)
            .where(Contact.contact_uin == uin)
            .where(Contact.blocked == False)  # noqa: E712
        )
    ).all()
    packet = {"type": "contact_renamed", "uin": uin, "nickname": nickname}
    for owner_uin in set(owners):
        await manager.send(owner_uin, packet)


@router.put("/me", response_model=PublicUser)
async def update_me(
    body: ProfileUpdate,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> PublicUser:
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    data = body.model_dump(exclude_unset=True)
    if "interests" in data and data["interests"] is not None:
        data["interests"] = ",".join(data["interests"])
    if "last_seen_visibility" in data:
        if data["last_seen_visibility"] not in ("everyone", "contacts", "nobody"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid last_seen_visibility")
    if "gender_visibility" in data:
        if data["gender_visibility"] not in ("everyone", "contacts", "nobody"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid gender_visibility")
    if "profile_visibility" in data:
        if data["profile_visibility"] not in ("everyone", "contacts", "nobody"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid profile_visibility")
    if "profile_card_policy" in data:
        if data["profile_card_policy"] not in POLICY_VALUES:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid profile_card_policy")
    if "group_invite_policy" in data:
        if data["group_invite_policy"] not in ("everyone", "contacts", "nobody"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid group_invite_policy")
    if "call_policy" in data:
        if data["call_policy"] not in ("everyone", "contacts", "nobody"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid call_policy")
    if "read_receipts_visibility" in data:
        if data["read_receipts_visibility"] not in ("everyone", "contacts", "nobody"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid read_receipts_visibility")
    if "gender" in data and data["gender"] is not None:
        if data["gender"] not in ("male", "female", "other"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid gender")
    if "hof_avatar" in data:
        # Empty/blank string clears the avatar; otherwise it must be a small
        # base64 image data-URI of an allowed type. Stored inline + served
        # publicly only once approved, so cap it hard and validate the bytes.
        raw = (data["hof_avatar"] or "").strip()
        if not raw:
            data["hof_avatar"] = None
        else:
            data["hof_avatar"] = _validate_hof_avatar(raw)
    if "avatar_media_id" in data or "avatar_media_key" in data:
        # The pair used to have to arrive whole. It no longer does, and the
        # asymmetry is the profile-key migration (docs/profile-key-design.md):
        #
        #   * id WITHOUT key is the NEW shape. The blob is sealed under the
        #     owner's profile key, which their contacts receive over E2E and
        #     this island never sees. We store the id, serve the id, and cannot
        #     open the picture - which is the whole point, because today we can:
        #     the key sits in this row next to the uin and the nickname, and a
        #     seized island decrypts every face it holds.
        #   * id WITH key is the OLD shape, still accepted so that clients
        #     which predate the migration keep working. Phase 3 nulls these.
        #   * key WITHOUT id is still nonsense and still refused.
        #
        # Clearing both is still how a client removes the picture.
        new_id = (data.get("avatar_media_id") or "").strip() or None
        new_key = (data.get("avatar_media_key") or "").strip() or None
        if new_id is None and new_key is not None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "avatar_media_key without avatar_media_id"
            )
        data["avatar_media_id"] = new_id
        # An id arriving alone REPLACES whatever key we held: the new blob is
        # sealed under a key we were not given, so keeping the old one would
        # leave a key that opens nothing pointing at a picture it cannot.
        data["avatar_media_key"] = new_key
    # (The `presence_ttl_minutes` allow-list check stood here until 2026-08-23.
    # It guarded a column that no longer exists; the key cannot reach `data` at
    # all now, because `ProfileUpdate` no longer declares it and unknown keys
    # are dropped before we get here.)
    renamed = "nickname" in data and data["nickname"] != user.nickname
    for key, value in data.items():
        setattr(user, key, value)
    await db.commit()
    await db.refresh(user)
    # Tell contacts the name changed. Nothing did, and nothing ever has: the
    # only per-user packet on the socket is `presence`, which carries status
    # and status message and not the name, so a rename reached the other side
    # whenever their client next happened to re-read the whole roster. From
    # the outside that is "he changed his nickname and it took a while, at
    # what point is it supposed to update?" — reported, and the honest answer
    # was "at no particular point". Best-effort: an offline contact reads the
    # new name on their next roster pull exactly as before.
    if renamed:
        await _announce_rename(db, uin, user.nickname)
    # Owner-self path — `from_model_for_viewer` echoes the visibility
    # back so Settings can show the active choice.
    return PublicUser.from_model_for_viewer(
        user, viewer_uin=uin, is_contact=False,
    )


# What a push address may be, and it is the INDEX that decides: `token` is
# indexed and carries the (uin, token) unique constraint, so the value has to
# stay inside a btree entry (models/device_token.py). Refused here rather than
# by the database, because the database's answer is a 500 and a client that
# retries it on every launch for ever — which is exactly what one person's
# 344-character UnifiedPush endpoint did from 2026-09-01 until the column was
# widened. Well above any real endpoint; a value over it is a broken
# distributor, and it deserves to be told so.
MAX_PUSH_TOKEN_LEN = 1024


class PushTokenIn(BaseModel):
    token: str
    platform: str = "ios"  # "ios" | "ios-voip"
    # Stable per-install id (client Keychain, survives reinstall). Optional so
    # pre-device-id clients keep working via the legacy (uin, token) upsert.
    device_id: str | None = None


@router.post("/me/push-token", status_code=status.HTTP_204_NO_CONTENT)
async def register_push_token(
    body: PushTokenIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Register an APNs device token for this account. Idempotent — if the
    same (uin, token) row already exists, we just bump `last_seen` so we
    can later prune ones that haven't been refreshed in months.

    Uses Postgres `INSERT ... ON CONFLICT DO UPDATE` so two parallel
    registrations of the same (uin, token) — which iOS does at boot,
    once from `didRegisterForRemoteNotificationsWithDeviceToken` and
    once from the explicit refresh in `AppState.boot` — both succeed
    with a 204 instead of one of them blowing up on the unique
    constraint and bubbling a 500 back to the client (which then gives
    up and never retries)."""
    if not body.token.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "empty token")
    if len(body.token) > MAX_PUSH_TOKEN_LEN:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            {"code": "token_too_long", "max": MAX_PUSH_TOKEN_LEN, "got": len(body.token)},
        )
    now = datetime.now(timezone.utc)
    device_id = (body.device_id or "").strip() or None
    # Upsert on the existing (uin, token) constraint either way — an app
    # UPDATE keeps the same APNs token, so this just refreshes last_seen (and
    # backfills device_id on the first device-id-aware launch). A reinstall
    # mints a NEW token, so this INSERTs a fresh row; the stale-token cleanup
    # below then drops the OLD row for the same physical device.
    stmt = (
        pg_insert(DeviceToken)
        .values(
            uin=uin, token=body.token, platform=body.platform,
            device_id=device_id, created_at=now, last_seen=now,
        )
        .on_conflict_do_update(
            index_elements=["uin", "token"],
            # Clear any recorded push failure: the client is demonstrably alive
            # and re-registering, so the old verdict is stale. The next failed
            # wake re-records it.
            set_={
                "platform": body.platform, "device_id": device_id, "last_seen": now,
                "push_last_error": None,
            },
        )
    )
    await db.execute(stmt)
    if device_id:
        # Drop any other token previously registered by THIS device (same
        # uin+device_id+platform) under a different token — a reinstall reuses
        # the Keychain device_id but gets a new APNs token, so without this the
        # old token row lingers and double-pushes until APNs 410s it.
        await db.execute(
            delete(DeviceToken).where(and_(
                DeviceToken.uin == uin,
                DeviceToken.device_id == device_id,
                DeviceToken.platform == body.platform,
                DeviceToken.token != body.token,
            ))
        )
        # And the rows from BEFORE device ids existed, which nothing has ever
        # cleaned. The rule above only matches rows carrying the same id, and
        # `device_id == NULL` is never true in SQL, so every reinstall from that
        # era left a row behind for good: 1378 of 1828 registrations had no
        # device id, the heaviest testers held sixteen and seventeen endpoints
        # each, and every single wake published to all of them.
        #
        # ⚠ Nothing else can find these. A UnifiedPush publish to a topic with
        # no subscriber SUCCEEDS — ntfy has no idea anybody was meant to be
        # listening — so the permanent-failure pruning in the sender never fires
        # for them. They are only knowable by what they lack.
        #
        # Safe because a device that still runs re-registers on every launch,
        # which upserts its row and backfills the id. So no id AND not seen in a
        # week means a device that has neither reinstalled nor started since
        # device ids shipped. The staleness window is what protects a genuine
        # second device still running a pre-0.84 build.
        await db.execute(
            delete(DeviceToken).where(and_(
                DeviceToken.uin == uin,
                DeviceToken.platform == body.platform,
                DeviceToken.device_id.is_(None),
                DeviceToken.last_seen < now - timedelta(days=7),
            ))
        )
    await db.commit()


class PushHealthRow(BaseModel):
    platform: str
    # Host only — never the full endpoint URL. The path segment IS the wake
    # secret for a UnifiedPush topic, and this response travels to a client
    # that already knows its own endpoint anyway.
    host: str | None = None
    last_error: str | None = None
    last_ok: datetime | None = None
    registered_at: datetime


class PushHealthOut(BaseModel):
    devices: list[PushHealthRow]


@router.get("/me/push-health", response_model=PushHealthOut)
async def push_health(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> PushHealthOut:
    """What the server's last wake attempt did, per registered device.

    Android push rides a third-party distributor (ntfy, …) the user chose,
    and when that distributor stops accepting wakes — ntfy.sh answers `507`
    once the topic has no connected subscriber, `429` once the rate bucket
    behind the subscriber's NAT is drained — the user's experience is simply
    "notifications stopped", with nothing anywhere to explain it. The client
    reads this to say so out loud in the notification settings."""
    rows = (
        await db.execute(
            select(
                DeviceToken.platform, DeviceToken.token, DeviceToken.push_last_error,
                DeviceToken.push_last_ok, DeviceToken.created_at,
            ).where(DeviceToken.uin == uin)
        )
    ).all()
    out: list[PushHealthRow] = []
    for platform, token, last_error, last_ok, created_at in rows:
        host: str | None = None
        if platform == "android-up" and "://" in token:
            host = token.split("://", 1)[1].split("/", 1)[0]
        out.append(PushHealthRow(
            platform=platform, host=host, last_error=last_error,
            last_ok=last_ok, registered_at=created_at,
        ))
    return PushHealthOut(devices=out)


@router.delete("/me/push-token", status_code=status.HTTP_204_NO_CONTENT)
async def delete_push_token(
    body: PushTokenIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Drop an APNs token (logout / burn). Tokens also auto-prune when
    Apple returns 410 Gone, so this is best-effort cleanup."""
    await db.execute(
        delete(DeviceToken).where(
            and_(DeviceToken.uin == uin, DeviceToken.token == body.token)
        )
    )
    await db.commit()


class CapabilitiesIn(BaseModel):
    # Sender-keys group path (`gmsg` broadcast + `skdm` distribution).
    # Advertised once per app start by clients that ship it; the
    # /messages/group-broadcast fan-out only targets capable accounts and
    # group member lists expose the flag so senders know who still needs
    # the legacy per-member fan-out. Optional so future flags can ride the
    # same endpoint without old clients clearing them.
    sender_keys: bool | None = None
    # Stage 4b: THIS INSTALL keeps its contact list in the vault (SPEC 4.9)
    # and no longer reads `GET /contacts` as the truth. Per DEVICE, unlike
    # `sender_keys` above, and stored in `contact_vault_devices` rather than
    # on this row: an account whose phone updated first must keep receiving
    # contact rows for its still-old desktop, or a person added on the phone
    # would silently never appear on the desktop. False unmarks this install,
    # which is the way back out of a rolled-back release.
    vault_contacts: bool | None = None


@router.post("/me/capabilities", status_code=status.HTTP_204_NO_CONTENT)
async def set_capabilities(
    body: CapabilitiesIn,
    uin: int = Depends(current_uin),
    device_id: str = Depends(current_device_id),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Upsert this account's client-capability flags. Idempotent — clients
    fire it on every start without tracking whether they already did."""
    if body.vault_contacts is not None:
        if body.vault_contacts:
            await mark_vault_device(db, uin, device_id)
        else:
            await unmark_vault_device(db, uin, device_id)
        await db.commit()
    if body.sender_keys is None:
        return
    # No timestamp. Clients fire this on every app start, so stamping the row
    # made it a second last-seen clock nobody read (unmapped 2026-08-22).
    stmt = (
        pg_insert(UserCapability)
        .values(uin=uin, sender_keys=body.sender_keys)
        .on_conflict_do_update(
            index_elements=["uin"],
            set_={"sender_keys": body.sender_keys},
        )
    )
    await db.execute(stmt)
    await db.commit()


class PushPreferencesOut(BaseModel):
    contact_requests: bool
    trades_from_contacts: bool
    trades_from_strangers: bool
    muted_uins: list[int]
    muted_group_ids: list[int]


class PushPreferencesIn(BaseModel):
    contact_requests: bool | None = None
    trades_from_contacts: bool | None = None
    trades_from_strangers: bool | None = None
    muted_uins: list[int] | None = None
    muted_group_ids: list[int] | None = None


def _hydrate_push_prefs(prefs: dict | None) -> PushPreferencesOut:
    """Apply defaults to NULL or partial JSON. Mirror of the
    `_pref` helper in apns.py — kept in sync deliberately so the
    iOS settings page sees the same defaults the push-fire path
    enforces."""
    from app.services.apns import PUSH_PREFERENCE_DEFAULTS
    src = prefs or {}
    return PushPreferencesOut(
        contact_requests=src.get("contact_requests", PUSH_PREFERENCE_DEFAULTS["contact_requests"]),
        trades_from_contacts=src.get("trades_from_contacts", PUSH_PREFERENCE_DEFAULTS["trades_from_contacts"]),
        trades_from_strangers=src.get("trades_from_strangers", PUSH_PREFERENCE_DEFAULTS["trades_from_strangers"]),
        muted_uins=src.get("muted_uins", PUSH_PREFERENCE_DEFAULTS["muted_uins"]),
        muted_group_ids=src.get("muted_group_ids", PUSH_PREFERENCE_DEFAULTS["muted_group_ids"]),
    )


@router.get("/me/push-preferences", response_model=PushPreferencesOut)
async def get_push_preferences(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> PushPreferencesOut:
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    return _hydrate_push_prefs(user.push_preferences)


@router.put("/me/push-preferences", response_model=PushPreferencesOut)
async def set_push_preferences(
    body: PushPreferencesIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> PushPreferencesOut:
    """Partial update — fields left out of the body keep their
    existing value. Lets the iOS Notifications settings flip a
    single toggle without re-shipping the whole map."""
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    current = dict(user.push_preferences or {})
    if body.contact_requests is not None:
        current["contact_requests"] = body.contact_requests
    if body.trades_from_contacts is not None:
        current["trades_from_contacts"] = body.trades_from_contacts
    if body.trades_from_strangers is not None:
        current["trades_from_strangers"] = body.trades_from_strangers
    if body.muted_uins is not None:
        # De-duplicate + sort for a stable on-the-wire shape.
        # iOS posts the full list whenever a contact is muted /
        # unmuted, so we don't bother with delta semantics here.
        current["muted_uins"] = sorted(set(body.muted_uins))
    if body.muted_group_ids is not None:
        current["muted_group_ids"] = sorted(set(body.muted_group_ids))
    user.push_preferences = current
    await db.commit()
    return _hydrate_push_prefs(current)


class TurnCredentialsOut(BaseModel):
    urls: list[str]
    username: str
    credential: str
    ttl: int


@router.get("/me/turn-credentials", response_model=TurnCredentialsOut)
async def turn_credentials(uin: int = Depends(current_uin)) -> TurnCredentialsOut:
    """Mint short-lived TURN credentials for `uin`. Implements the
    "TURN REST API" auth pattern (draft-uberti-behave-turn-rest):
    coturn's `static-auth-secret` is shared between us and the TURN
    daemon; we sign `<unix_expiry>:<opaque>` with HMAC-SHA1 and the daemon
    validates the same signature on the wire.

    ⚠ The second half of the username used to be the account number. coturn
    with `use-auth-secret` only needs the timestamp prefix; everything after
    the colon is free text it logs on every allocation. So a seized or
    compelled TURN host held a complete log of who called and when, keyed by
    account, although the database keeps nothing about calls at all
    (metadata map 1.7). A fresh random tag per issuance gives the TURN host
    a per-call pseudonym that it cannot join back to an account; the only
    party that ever knew the pair (this handler) does not write it down.

    No-ops to an empty list when TURN isn't configured (dev environments
    without coturn). The iOS client treats an empty `urls` list as
    "STUN-only" and proceeds with the call — works on permissive
    networks, fails behind symmetric NATs."""
    if not settings.TURN_HOST or not settings.TURN_SECRET:
        return TurnCredentialsOut(urls=[], username="", credential="", ttl=0)

    expiry = int(time.time()) + settings.TURN_TTL_SECONDS
    username = f"{expiry}:{secrets.token_hex(8)}"
    digest = hmac.new(
        settings.TURN_SECRET.encode("utf-8"),
        username.encode("utf-8"),
        hashlib.sha1,
    ).digest()
    credential = base64.standard_b64encode(digest).decode("ascii")

    # UDP first (lowest latency), TCP fallback for hostile networks that
    # block UDP entirely (corporate, captive portals).
    urls = [
        f"turn:{settings.TURN_HOST}:3478?transport=udp",
        f"turn:{settings.TURN_HOST}:3478?transport=tcp",
    ]
    # TURN-over-TLS (turns:) — the path that survives DPI/UDP-blocking on
    # hostile mobile networks (e.g. RU CGNAT), where plain UDP and plain-TCP:3478
    # are exactly what gets dropped, leaving symmetric-NAT peers with no relay
    # candidate (call UI "connects" on the SDP answer but no media ever flows).
    # On 443 the allocation is indistinguishable from ordinary HTTPS. Emitted
    # only when the operator has configured coturn to actually listen with TLS
    # (see deploy docs); listed last so clients still prefer the cheaper UDP path
    # when it works.
    if settings.TURN_TLS_PORT:
        urls.append(f"turns:{settings.TURN_HOST}:{settings.TURN_TLS_PORT}?transport=tcp")
    return TurnCredentialsOut(
        urls=urls,
        username=username,
        credential=credential,
        ttl=settings.TURN_TTL_SECONDS,
    )
