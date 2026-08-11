from datetime import datetime, timedelta, timezone

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class User(Base):
    __tablename__ = "users"

    uin: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    nickname: Mapped[str] = mapped_column(String(64), index=True)
    # Long-term X25519 public key for ECDH (32-byte raw, base64). Used as the
    # recipient half of every per-message ephemeral key agreement.
    identity_key: Mapped[str] = mapped_column(Text)
    # Long-term Ed25519 public key (32-byte raw, base64). Senders sign every
    # ciphertext with their corresponding private key; the signature is
    # carried inside the encrypted payload (sealed-sender style) and verified
    # by the recipient against the value the server reports here.
    signing_key: Mapped[str] = mapped_column(Text)

    # ── Stage 3 libsignal material (additive on top of the Stage 2 keys above).
    # NULL until the user upgrades to a Stage 3 client and uploads a key bundle
    # via POST /keys/bundle. Stage 3 senders treat NULL here as "recipient is
    # still on Stage 2", and fall back to the v=1 ECIES envelope path. Once
    # populated, both sides ride the v=2 hybrid envelope: outer Stage 2 ECIES
    # tunnel still hides the sender from the server, inner libsignal session
    # delivers Double Ratchet + post-compromise security. See README in
    # backend/docs once we write it; for now `RCQ/Services/CryptoService.swift`
    # is the canonical wire-format spec.
    #
    # Base64 of the 33-byte libsignal IdentityKey (Curve25519 with leading
    # type byte). Distinct from `identity_key` above which is RCQ's own raw
    # X25519 ECDH pubkey — different format, different keypair, different
    # purpose. Both stay populated on a Stage 3 user.
    signal_identity_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    # libsignal `registrationId` (uint32 in [1, 16380]). Fixed per device for
    # the lifetime of the identity; rotates only on a fresh bootstrap.
    signal_registration_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Active signed-prekey: id is whatever the client picked, public is the
    # Curve25519 pub (33 bytes b64), signature is over `public` with the
    # client's libsignal IdentityKey. Senders verify the signature on receipt
    # before running X3DH so a malicious server can't substitute keys
    # undetected (modulo trust-on-first-use of the IdentityKey itself).
    signed_prekey_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    signed_prekey_public: Mapped[str | None] = mapped_column(Text, nullable=True)
    signed_prekey_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    signed_prekey_uploaded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # libsignal v0.93+ runs PQXDH (X3DH + Kyber) — every PreKeyBundle now
    # carries a Kyber pre-key in addition to the EC signed pre-key. We
    # ship a single, periodically-rotated, "last-resort" Kyber pre-key
    # rather than a one-time pool. Reuse of last-resort Kyber prekeys is
    # acceptable (forward secrecy comes from the EC ephemeral; Kyber
    # contributes post-quantum hardness which doesn't degrade with reuse).
    # Public is base64 of the serialized KEMPublicKey, signature is over
    # `public` with the identity key.
    kyber_prekey_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kyber_prekey_public: Mapped[str | None] = mapped_column(Text, nullable=True)
    kyber_prekey_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    kyber_prekey_uploaded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Set true by an admin via /admin/users/{uin}/ban after a Reports-queue
    # review. Suspended UINs:
    #   - cannot send 1:1 / group messages (sealed-sender path checks before
    #     queueing/relaying)
    #   - cannot post Hood / Stories
    #   - cannot create or join audio rooms / random chat
    #   - their /users/search results are filtered out
    # Profile + receive paths stay open so a suspended user can still see
    # what was sent to them before the ban (no rage-quit through chat
    # disappearance).
    is_suspended: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    # Hall of Fame. `hof_opt_in` is set by the user from their client (consent
    # to be considered). `hof_approved` is set by the founder from the admin
    # console — only the founder decides who actually appears. Both true → the
    # user shows on the public /hof wall (nickname + uin).
    hof_opt_in: Mapped[bool] = mapped_column(Boolean, default=False)
    hof_approved: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    # Optional public HoF avatar as a data-URI (see db.py note). Served only
    # for approved members; NULL falls back to the initial-letter circle.
    hof_avatar: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Uploaded profile picture, same model as a group's: the blob at
    # `/media/{avatar_media_id}` is AES-encrypted and `avatar_media_key` is the
    # base64 key handed to whoever is allowed to see it. Both NULL = no picture,
    # clients fall back to the status glyph they have always drawn.
    #
    # Who may see it is deliberately NARROWER than the rest of the profile: a
    # picture is handed to people you have a relationship with (mutual
    # contacts, and members of a group you are in), never to a stranger who
    # merely found you in search, in Random, or in Nearby, and never on a
    # contact request you have not accepted — otherwise an incoming request
    # becomes a channel for pushing an image onto someone's screen.
    avatar_media_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    avatar_media_key: Mapped[str | None] = mapped_column(String(96), nullable=True)
    # Founder-assigned rating tier — which flower shows next to the member on
    # the wall: "bronze" | "silver" | "gold". Independent of the auto-computed
    # bug-report effort ring; this is the founder's manual "thank you" for
    # people who helped (not all of them report bugs). Defaults to "gold" so
    # the existing all-gold wall looks unchanged until the founder grades.
    hof_tier: Mapped[str] = mapped_column(String(8), default="gold")
    # Credit for bug reports filed OFF the in-app form. Some of the most
    # useful testers never touch it — they report in the closed tester chat,
    # in comments, by voice — so the computed counters read 0 next to a gold
    # flower and the wall understates exactly the people it exists to thank.
    # These are ADDED to the counts derived from real `reports` rows.
    #
    # A separate column rather than synthesised report rows on purpose: fake
    # rows would show up on that person's own "My reports" screen as
    # submissions they never filed, land in the admin queue, and distort the
    # resolved-this-week stats.
    hof_bonus_reports: Mapped[int] = mapped_column(Integer, default=0)
    hof_bonus_confirmed: Mapped[int] = mapped_column(Integer, default=0)

    first_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    age: Mapped[int | None] = mapped_column(Integer, nullable=True)
    gender: Mapped[str | None] = mapped_column(String(16), nullable=True)
    city: Mapped[str | None] = mapped_column(String(64), nullable=True)
    country: Mapped[str | None] = mapped_column(String(64), nullable=True)
    about: Mapped[str | None] = mapped_column(Text, nullable=True)
    interests: Mapped[str | None] = mapped_column(Text, nullable=True)  # comma-joined tags
    homepage: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status_message: Mapped[str | None] = mapped_column(String(255), nullable=True)

    status: Mapped[str] = mapped_column(String(16), default="offline")
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    # Last-seen visibility per ICQ tradition. "everyone" → /users/{uin}/info
    # always returns the timestamp; "contacts" → only callers who have a
    # mutual contact row see it; "nobody" → never returned.
    #
    # ⚠ Default was "everyone" (parity with the era when last_seen was
    # unconditional) until 2026-08-11. A prod snapshot then showed 2801 of
    # 2923 accounts still sitting on it, i.e. the setting existed and nobody
    # found it. An open last_seen plus an open group roster let any freshly
    # registered account poll the whole base and derive sleep patterns and
    # time zones without sending a single message, which is the one signal
    # that leaks continuously and cannot be end-to-end encrypted because we
    # are its source. Strangers now get nothing; contacts still see it.
    last_seen_visibility: Mapped[str] = mapped_column(String(16), default="contacts")
    # Profile-card visibility. Same {"everyone","contacts","nobody"}
    # tri-state. Gates the optional profile fields (first_name,
    # last_name, age, city, country, about, interests, homepage,
    # status_message) on `/users/{uin}/info` for outsiders. Always-
    # visible identity stays on the wire regardless: nickname, uin,
    # identity_key, signing_key, signal_*, status, equipped_pet —
    # those are needed for crypto + chat routing. Default "everyone"
    # keeps the historical open-profile UX; users worried about
    # surfacing their personal info to strangers flip it to
    # "contacts" or "nobody".
    profile_visibility: Mapped[str] = mapped_column(String(16), default="everyone")
    # Gender visibility — same {"everyone","contacts","nobody"}
    # tri-state as last-seen. Default "nobody" because gender is
    # optional info that the user opts in to surfacing, unlike
    # last-seen which has a long ICQ-era history of "default
    # public, can hide".
    gender_visibility: Mapped[str] = mapped_column(String(16), default="nobody")
    # Group invite policy. Same tri-state. Default "contacts" since
    # 2026-08-11 (was "everyone"): being pulled into a group by a
    # stranger both delivers unsolicited content and exposes the UIN
    # to every other member of that group. Invite links still work for
    # people who are not contacts yet, so the growth path is intact.
    group_invite_policy: Mapped[str] = mapped_column(String(16), default="contacts")
    # Who can propose a trade to me. Same tri-state as the other
    # privacy controls. "everyone" — any user can send a trade
    # offer; "contacts" — only mutual contacts can; "nobody" —
    # trade endpoint refuses with 403. Default "everyone" so the
    # trade system feels open by default; users worried about
    # spam can dial it down. The setting is enforced server-side
    # in `propose_trade`.
    trade_policy: Mapped[str] = mapped_column(String(16), default="everyone")
    # Who can call me (voice / video). Same tri-state. "nobody" hides
    # every call-affordance in the caller's UI and refuses incoming WS
    # call_offer events at the server.
    #
    # ⚠ This comment used to claim "everyone" and "contacts" were
    # equivalent because signalling was gated on the contact graph
    # anyway. That is false: `_caller_allowed` in routers/ws.py returns
    # True immediately on "everyone", so any stranger holding the number
    # could ring. That matters more than spam — WebRTC hands the peer
    # your ICE candidates, i.e. your real IP, and no amount of transport
    # obfuscation covers it. Default is "contacts" since 2026-08-11.
    call_policy: Mapped[str] = mapped_column(String(16), default="contacts")
    # Read-receipts visibility — gates whether iOS sends a
    # `.readReceipt` envelope when the user opens a chat. Same tri-
    # state as the other privacy controls. "everyone" → always sent
    # (current behaviour); "contacts" → only mutual contacts get
    # receipts; "nobody" → never sent. Pure iOS gate at send time —
    # the server doesn't see who would have received what (the
    # envelope is sealed-sender), so enforcement is client-side only.
    # The server still ferries the setting back to the owner so
    # Settings can render the current state. Default "contacts" since
    # 2026-08-11: a read receipt to a stranger confirms "this person is
    # holding their phone right now", which is the same presence leak as
    # last_seen, only finer-grained.
    read_receipts_visibility: Mapped[str] = mapped_column(String(16), default="contacts")
    # (The pre-pivot social-reputation columns were removed here; the
    # 2026-05-27 pivot cut that feature. Existing deployments may still
    # carry unused `reputation`/`reputation_visibility` columns — the ORM
    # simply doesn't map them.)
    # Per-user push notification preferences. JSON shape:
    #   {
    #     "contact_requests": bool,         # default true
    #     "trades_from_contacts": bool,     # default true
    #     "trades_from_strangers": bool,    # default false (anti-spam)
    #     "muted_uins": [int]               # silenced senders for the
    #                                       #   3 non-sealed event types
    #                                       #   (contact_request,
    #                                       #   trade_received,
    #                                       #   contact_response_accepted)
    #   }
    # Missing keys read as defaults via `_pref(...)`. Sealed-sender
    # messages (1:1 + group) can't be filtered server-side because
    # the server doesn't know the sender UIN — those keep the
    # existing "always push when offline" behaviour and the user
    # mutes them via iOS system settings.
    push_preferences: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Distinct-calendar-day activity counter, bumped once per UTC day
    # on WS connect. Drives referral activation (3 days = "active").
    # `last_active_day` is the YYYY-MM-DD string of the last bump so
    # a same-day reconnect does not double-count.
    active_days: Mapped[int] = mapped_column(Integer, default=0)
    last_active_day: Mapped[str | None] = mapped_column(String(10), nullable=True)
    # Opt-in flag: when TRUE, the user's chosen `status` keeps being
    # broadcast to contacts even after the WS goes stale. Lets people
    # appear "around" with their selected status (online/away/dnd) when
    # the app is killed. Default FALSE keeps the historical behaviour
    # where killing the app shows the user as offline.
    presence_persistent: Mapped[bool] = mapped_column(Boolean, default=False)
    # Optional TTL for `presence_persistent`. NULL/0 = no cap, the
    # user stays "visible" forever after exit. >0 = stay visible for
    # N minutes past `last_seen`, then revert to offline. Lets the
    # user pick "show me as online for the next hour" without leaving
    # themselves visible indefinitely after they put the phone down.
    presence_ttl_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


# ── Presence ────────────────────────────────────────────────────────
# "online" is DERIVED from `last_seen` freshness — never trusted from the
# stored `status` column. A killed / crashed / force-quit client can't be
# relied on to write "offline", so the old design left users stuck online
# forever. Instead a live client refreshes `last_seen` via the WS ping
# heartbeat (~25s); when it stops, the user goes offline purely by
# staleness — no disconnect handler has to fire. The `status` column is
# trusted ONLY for the user-chosen sub-states (away / dnd / invisible).
PRESENCE_FRESHNESS_SECONDS = 60


def _as_aware(dt: datetime) -> datetime:
    """Coerce a naive datetime to UTC. PostgreSQL TIMESTAMPTZ round-trips as
    tz-aware, but SQLite (the self-host / dev path) drops the tzinfo on read —
    comparing such a value against `datetime.now(timezone.utc)` raises
    "can't compare offset-naive and offset-aware". Treat naive as UTC (that's
    what we wrote). No-op on already-aware values, so Postgres is unaffected."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def presence_is_fresh(last_seen: datetime | None) -> bool:
    """True if `last_seen` is recent enough to count as a live connection."""
    if last_seen is None:
        return False
    return _as_aware(last_seen) > datetime.now(timezone.utc) - timedelta(seconds=PRESENCE_FRESHNESS_SECONDS)


def effective_status(user: "User") -> str:
    """The real presence state. Fake users are decoration (no live
    connection) so their stored status is used verbatim. For real users a
    stale `last_seen` means offline regardless of what `status` says;
    while fresh, a user-chosen away/dnd/invisible is honoured, otherwise
    online.

    `presence_persistent` opts the user OUT of the staleness check —
    their chosen `status` is broadcast regardless of WS liveness. The
    implicit "offline" default (which only appears when status was never
    explicitly set) is mapped to "online" so a persistent user without
    a deliberate pick still shows as around. Anyone who wants to look
    offline picks `invisible`, which `visible_status` reduces to
    `offline` for other viewers.
    """
    if user.presence_persistent:
        # TTL gate (when set): persistent presence expires after N
        # minutes past last_seen. NULL/0 = forever (legacy behaviour).
        ttl = user.presence_ttl_minutes or 0
        within_ttl = (
            ttl == 0
            or (
                user.last_seen is not None
                and _as_aware(user.last_seen)
                > datetime.now(timezone.utc) - timedelta(minutes=ttl)
            )
        )
        if within_ttl:
            chosen = user.status or "offline"
            return "online" if chosen == "offline" else chosen
        # TTL expired → fall through to staleness check, which will
        # render the user offline.
    if not presence_is_fresh(user.last_seen):
        return "offline"
    if user.status in ("away", "dnd", "invisible"):
        return user.status
    return "online"


def visible_status(user: "User") -> str:
    """`effective_status` as seen by OTHER users — invisible reads as
    offline, ICQ-style."""
    s = effective_status(user)
    return "offline" if s == "invisible" else s
