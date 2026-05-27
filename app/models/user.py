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
    # Flagged on seeded demo users. Their stored `status` is reported as-is
    # without consulting `manager.is_online`, so they can appear online/away/dnd
    # even though no real WebSocket is connected for them.
    is_fake: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
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
    # mutual contact row see it; "nobody" → never returned. Default
    # "everyone" for parity with the existing behaviour where last_seen
    # was always shipped (back when the column was unconditional).
    last_seen_visibility: Mapped[str] = mapped_column(String(16), default="everyone")
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
    # Group invite policy. Same tri-state. Default "everyone" so
    # group-invite UX stays unchanged for users who never touch
    # the setting; users worried about invite spam can flip it
    # to "contacts" or "nobody".
    group_invite_policy: Mapped[str] = mapped_column(String(16), default="everyone")
    # Who can propose a trade to me. Same tri-state as the other
    # privacy controls. "everyone" — any user can send a trade
    # offer; "contacts" — only mutual contacts can; "nobody" —
    # trade endpoint refuses with 403. Default "everyone" so the
    # trade system feels open by default; users worried about
    # spam can dial it down. The setting is enforced server-side
    # in `propose_trade`.
    trade_policy: Mapped[str] = mapped_column(String(16), default="everyone")
    # Who can call me (voice / video). Same tri-state. "everyone"
    # / "contacts" both allow calls (the call-signalling path is
    # gated on the contact graph anyway, so they're effectively
    # equivalent for now); "nobody" hides every call-affordance
    # in the caller's UI and refuses incoming WS call_offer
    # events at the server. Default "everyone".
    call_policy: Mapped[str] = mapped_column(String(16), default="everyone")
    # Read-receipts visibility — gates whether iOS sends a
    # `.readReceipt` envelope when the user opens a chat. Same tri-
    # state as the other privacy controls. "everyone" → always sent
    # (current behaviour); "contacts" → only mutual contacts get
    # receipts; "nobody" → never sent. Pure iOS gate at send time —
    # the server doesn't see who would have received what (the
    # envelope is sealed-sender), so enforcement is client-side only.
    # The server still ferries the setting back to the owner so
    # Settings can render the current state.
    read_receipts_visibility: Mapped[str] = mapped_column(String(16), default="everyone")
    # Social reputation counter. Other users can spend jettons (min 5)
    # to grant +N reputation; the spent jettons are burned outright
    # (full sink, no transfer to the recipient). Lives on the user
    # row so it transfers verbatim through account migration just like
    # any other profile field. Default 0 for every existing row.
    reputation: Mapped[int] = mapped_column(BigInteger, default=0)
    # Tri-state visibility for the reputation counter — same shape as
    # `profile_visibility`. "everyone" → counter is in /users/{uin}/info
    # for any caller; "contacts" → only mutual contacts see the value;
    # "nobody" → counter is suppressed on the wire for outsiders.
    # Note: visibility ONLY gates display of the counter — the
    # /reputation/grant endpoint accepts grants regardless of the
    # target's visibility setting (you can still donate even if you
    # can't see the running total). Default "everyone".
    reputation_visibility: Mapped[str] = mapped_column(String(16), default="everyone")
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


def presence_is_fresh(last_seen: datetime | None) -> bool:
    """True if `last_seen` is recent enough to count as a live connection."""
    if last_seen is None:
        return False
    return last_seen > datetime.now(timezone.utc) - timedelta(seconds=PRESENCE_FRESHNESS_SECONDS)


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
    if user.is_fake:
        return user.status
    if user.presence_persistent:
        # TTL gate (when set): persistent presence expires after N
        # minutes past last_seen. NULL/0 = forever (legacy behaviour).
        ttl = user.presence_ttl_minutes or 0
        within_ttl = (
            ttl == 0
            or (
                user.last_seen is not None
                and user.last_seen
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
