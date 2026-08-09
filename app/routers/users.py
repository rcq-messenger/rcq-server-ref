import base64
import hashlib
import hmac
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.contact import Contact
from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.capability import UserCapability
from app.models.device_token import DeviceToken
from app.models.user import User, visible_status

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
    # Owner-only mirror of the persistent-presence opt-in. When TRUE,
    # the owner's chosen `status` keeps broadcasting to contacts even
    # after their WS goes stale. Null for third-party callers.
    presence_persistent: bool | None = None
    # Optional TTL (minutes) for `presence_persistent`. NULL/0 =
    # forever; >0 = visible for N minutes past last_seen.
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
        # A picture is not part of the profile card gate: it follows the
        # relationship, not the "who may see my details" setting. Strangers get
        # nothing here regardless of how open the rest of the profile is.
        avatar_ok = owner_self or is_contact
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
            group_invite_policy=(u.group_invite_policy if owner_self else None),
            call_policy=(u.call_policy if owner_self else None),
            read_receipts_visibility=(u.read_receipts_visibility if owner_self else None),
            presence_persistent=(u.presence_persistent if owner_self else None),
            presence_ttl_minutes=(u.presence_ttl_minutes if owner_self else None),
            hof_opt_in=(u.hof_opt_in if owner_self else None),
            hof_avatar=(u.hof_avatar if owner_self else None),
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
        # The pair only makes sense whole: an id without a key is a blob
        # nobody can open, and a key without an id points at nothing. Sending
        # both blank is how a client removes the picture.
        new_id = (data.get("avatar_media_id") or "").strip() or None
        new_key = (data.get("avatar_media_key") or "").strip() or None
        if (new_id is None) != (new_key is None):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "avatar_media_id and avatar_media_key go together"
            )
        data["avatar_media_id"] = new_id
        data["avatar_media_key"] = new_key
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


@router.post("/me/capabilities", status_code=status.HTTP_204_NO_CONTENT)
async def set_capabilities(
    body: CapabilitiesIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Upsert this account's client-capability flags. Idempotent — clients
    fire it on every start without tracking whether they already did."""
    if body.sender_keys is None:
        return
    now = datetime.now(timezone.utc)
    stmt = (
        pg_insert(UserCapability)
        .values(uin=uin, sender_keys=body.sender_keys, updated_at=now)
        .on_conflict_do_update(
            index_elements=["uin"],
            set_={"sender_keys": body.sender_keys, "updated_at": now},
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
