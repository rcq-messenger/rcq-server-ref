import base64
import hashlib
import hmac
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import and_, delete, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.contact import Contact
from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.device_token import DeviceToken
from app.models.user import User, visible_status

router = APIRouter(prefix="/users", tags=["users"])


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
    # Owner-only mirror of the persistent-presence opt-in. When TRUE,
    # the owner's chosen `status` keeps broadcasting to contacts even
    # after their WS goes stale. Null for third-party callers.
    presence_persistent: bool | None = None
    # Optional TTL (minutes) for `presence_persistent`. NULL/0 =
    # forever; >0 = visible for N minutes past last_seen.
    presence_ttl_minutes: int | None = None

    @classmethod
    def from_model_for_viewer(
        cls,
        u: User,
        viewer_uin: int,
        is_contact: bool,
    ) -> "PublicUser":
        last_seen = _last_seen_for_viewer(u, viewer_uin=viewer_uin, is_contact=is_contact)
        gender = _gender_for_viewer(u, viewer_uin=viewer_uin, is_contact=is_contact)
        owner_self = viewer_uin == u.uin
        # Profile gate — applied to first_name, last_name, age, city,
        # country, about, interests, homepage, status_message.
        # Identity-level fields (nickname, uin, keys, status,
        # equipped_pet) always pass through; chat + crypto would
        # break otherwise. `gender` already has its own gate above,
        # but ALSO falls under profile_visibility — if profile is
        # hidden, gender is hidden regardless of its own setting.
        profile_visible = _profile_visible_for_viewer(u, viewer_uin=viewer_uin, is_contact=is_contact)
        return cls(
            uin=u.uin,
            nickname=u.nickname,
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
            group_invite_policy=(u.group_invite_policy if owner_self else None),
            call_policy=(u.call_policy if owner_self else None),
            read_receipts_visibility=(u.read_receipts_visibility if owner_self else None),
            presence_persistent=(u.presence_persistent if owner_self else None),
            presence_ttl_minutes=(u.presence_ttl_minutes if owner_self else None),
        )

    @classmethod
    def from_model(cls, u: User) -> "PublicUser":
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
        visible = (u.profile_visibility or "everyone") == "everyone"
        return cls(
            uin=u.uin,
            nickname=u.nickname,
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
    the setting — the rule is only about *outsiders*."""
    if viewer_uin == u.uin:
        return u.last_seen
    visibility = u.last_seen_visibility or "everyone"
    if visibility == "everyone":
        return u.last_seen
    if visibility == "contacts" and is_contact:
        return u.last_seen
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
    group_invite_policy: str | None = None
    call_policy: str | None = None
    read_receipts_visibility: str | None = None
    # Opt-in toggle. When TRUE the server keeps broadcasting the user's
    # chosen `status` (online/away/dnd) to contacts even after the WS
    # goes stale — see `effective_status()` in models/user.py.
    presence_persistent: bool | None = None
    # Optional TTL cap (minutes) for `presence_persistent`. Pass 0 (or
    # NULL) for "forever". Server validates against a small allow-list
    # so we don't accept arbitrary precision the UI can't render.
    presence_ttl_minutes: int | None = None


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
    like = f"%{q.lower()}%"
    text_clause = or_(
        User.nickname.ilike(like),
        User.first_name.ilike(like),
        User.last_name.ilike(like),
        User.city.ilike(like),
        User.country.ilike(like),
        User.interests.ilike(like),
    )
    if q.isdigit():
        clause = or_(User.uin == int(q), text_clause)
    else:
        clause = text_clause
    # Never include the caller in their own search results — Add-to-contacts on
    # self would 400, and "find people" silently shouldn't list me anyway.
    rows = (
        await db.execute(
            select(User).where(clause).where(User.uin != me).limit(limit)
        )
    ).scalars().all()
    return [PublicUser.from_model(u) for u in rows]


@router.get("/{uin}/info", response_model=PublicUser)
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
    else:
        is_contact = (
            await db.scalar(
                select(Contact.id).where(
                    and_(Contact.owner_uin == me, Contact.contact_uin == user.uin)
                )
            )
        ) is not None
    return PublicUser.from_model_for_viewer(
        user, viewer_uin=me, is_contact=is_contact,
    )


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
    if "presence_ttl_minutes" in data and data["presence_ttl_minutes"] is not None:
        # Allowlist matches the iOS picker options so we don't accept
        # arbitrary values from a poked client. 0 = forever; the rest
        # are 30 min / 1 h / 3 h / 8 h / 24 h.
        allowed = {0, 30, 60, 180, 480, 1440}
        if data["presence_ttl_minutes"] not in allowed:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid presence_ttl_minutes")
    for key, value in data.items():
        setattr(user, key, value)
    await db.commit()
    await db.refresh(user)
    # Owner-self path — `from_model_for_viewer` echoes the visibility
    # back so Settings can show the active choice.
    return PublicUser.from_model_for_viewer(
        user, viewer_uin=uin, is_contact=False,
    )


class PushTokenIn(BaseModel):
    token: str
    platform: str = "ios"  # "ios" | "ios-voip"


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
    now = datetime.now(timezone.utc)
    stmt = (
        pg_insert(DeviceToken)
        .values(uin=uin, token=body.token, platform=body.platform, created_at=now, last_seen=now)
        .on_conflict_do_update(
            index_elements=["uin", "token"],
            set_={"platform": body.platform, "last_seen": now},
        )
    )
    await db.execute(stmt)
    await db.commit()


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
    daemon; we sign `<unix_expiry>:<uin>` with HMAC-SHA1 and the daemon
    validates the same signature on the wire.

    No-ops to an empty list when TURN isn't configured (dev environments
    without coturn). The iOS client treats an empty `urls` list as
    "STUN-only" and proceeds with the call — works on permissive
    networks, fails behind symmetric NATs."""
    if not settings.TURN_HOST or not settings.TURN_SECRET:
        return TurnCredentialsOut(urls=[], username="", credential="", ttl=0)

    expiry = int(time.time()) + settings.TURN_TTL_SECONDS
    username = f"{expiry}:{uin}"
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
    return TurnCredentialsOut(
        urls=urls,
        username=username,
        credential=credential,
        ttl=settings.TURN_TTL_SECONDS,
    )
