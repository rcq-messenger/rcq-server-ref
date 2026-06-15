# Closed-island access tokens — design v2

Status: DESIGN v2 (hardened after an adversarial security review; v1 was
`redesign`-gated — the Caddy gate was invalid, the Redis fail-mode unsafe, redeem
could mint unbounded tokens, client stamping was incomplete, and web-chat was
locked out. All folded in below.)

Goal: a self-hoster runs a **fully private island** — invisible to scanners (the
masquerade decoy is preserved), reachable only by holders of an **admin-issued
access token** that is **per-person, one-time-redeemable (can't be reshared) and
revocable**. Also lets an invited outsider on another island message a member of
the closed island.

## Background (unchanged): two independent gates
1. **Network gate** — can your client reach the API at all? Today: Caddy static
   match `X-RCQ-Auth: {$RCQ_AUTH_TOKEN}` else decoy 200
   (`deploy/Caddyfile.masquerade.compose`). One shared, unrevocable, reshareable
   token. THIS is what we upgrade.
2. **Membership gate** — can you create an account? `REGISTRATION_POLICY=invite`,
   unchanged. Messaging a member from outside needs only the NETWORK gate (sealed
   deposit is account-less).

## Token kinds (`access_tokens` table)
- **invite** — one-time (`max_uses=1`). Passes the gate until redeemed; first
  connect redeems it → a device token; then consumed → resharing is useless.
- **device** — durable, minted ONLY by `/gate/redeem` from an invite, bound to a
  client-chosen random `device_id`, revocable. Stamped on every later request.
- **standing** — durable admin token for a known person/bot/relay
  (`max_uses=NULL` = unlimited), revocable, used directly (no redeem, no mint).
- **env master** — legacy `.env` `RCQ_AUTH_TOKEN`, matched in-process for
  back-compat (see §Env master). Unrevocable bypass → recommend UNSET once
  per-user tokens are adopted.

### Table DDL
```
access_tokens(
  id            int pk,
  token_hash    varchar(64) NOT NULL,              -- sha256-hex of raw; raw shown once, never stored
  kind          varchar(16) NOT NULL,              -- invite|device|standing
  label         varchar(128),
  device_id     varchar(64),                       -- set on device rows
  parent_id     int,                               -- invite a device row was minted from
  max_uses      int,                               -- invite=1; standing=NULL(unlimited)
  uses          int NOT NULL default 0,
  expires_at    timestamptz,
  revoked       bool NOT NULL default false,
  created_at    timestamptz NOT NULL,
  last_used_at  timestamptz
)
UNIQUE INDEX ON access_tokens(token_hash)
UNIQUE INDEX ON access_tokens(device_id) WHERE device_id IS NOT NULL  -- idempotency key for redeem ON CONFLICT
```
Added via `init_db` additive add-list (Postgres) like every other table.

## Gate: Caddy raw reverse_proxy subrequest → `/gate/check` (NOT forward_auth)
`forward_auth` sugar will NOT accept `@name`/`handle_response` blocks
(`caddy validate` rejects it). Hand-write the raw subrequest with an **inverted
status split**: grant ONLY on an explicit 2xx; EVERYTHING else (1xx/3xx/4xx/5xx,
dial errors) → the decoy. Pin **Caddy ≥ 2.9.0** (the method-GET / body-not-
consumed / copy-header fixes for auth subrequests, issues #6610/#5430).

```caddyfile
{$RCQ_DOMAIN} {
  route {
    # --- network gate: ask /gate/check, decoy on anything but a 2xx grant ---
    reverse_proxy app:8000 {
      method GET
      rewrite /gate/check
      header_up X-RCQ-Auth {http.request.header.X-RCQ-Auth}
      header_up -Connection        # force a WS upgrade back to a plain GET subrequest
      header_up -Upgrade
      @ok status 2xx
      handle_response @ok { }      # empty -> control falls through to the real proxy below
      @gate_fail status 1xx 3xx 4xx 5xx
      handle_response @gate_fail {
        root * /srv/decoy
        rewrite * /index.html
        file_server
        header { Strict-Transport-Security "max-age=31536000; includeSubDomains"
                 X-Content-Type-Options nosniff; Referrer-Policy no-referrer; -Server }
      }
    }
    # --- reached ONLY on a 2xx grant ---
    reverse_proxy app:8000 {
      header_up X-Forwarded-For {remote_host}
      header_up X-Real-IP {remote_host}
      header_up X-Forwarded-Proto https
    }
  }
}
```
The gated docker profile ALSO sets `RCQ_DOCS_DISABLED=1` (app disables
`/docs`+`/openapi.json` — the loudest fingerprint) and puts `RCQ_AUTH_TOKEN` in
the **app** env (not just Caddy — see §Env master).

**Build gate (step 0, before any other work):** `caddy validate` must pass, and a
6-path proof must show byte-identical decoy for: no token / wrong token / revoked
token / `/gate/check` 5xx (app down) / dial failure / a random path — AND a
VALID-token real 404 (e.g. `POST /messages/sealed` bogus uin) returns the app's
JSON 404 (proves grants pass through), AND a VALID-token WS stays up while a
no-token WS gets the decoy 200 (not a hung 426).

## `/gate/check` (subrequest target; hot path — DB-read at worst, never DB-write)
Algorithm, in order:
1. **env master**: `secrets.compare_digest(header, app_env_RCQ_AUTH_TOKEN)` in
   process (compare_digest — low-entropy operator secret = timing oracle with
   `==`). Match → 200.
2. **cache**: read a short-TTL (30–60s) per-hash cache entry
   `{expires_at, revoked, kind, max_uses, uses}` and re-evaluate IN-PROCESS every
   request: grant iff
   `revoked=false AND (expires_at IS NULL OR expires_at>now) AND (max_uses IS NULL OR uses<max_uses)`.
   (NULL `max_uses` = unlimited standing — the bare `uses<max_uses` wrongly
   rejects it.)
3. **cache miss OR any Redis exception** → single indexed
   `SELECT ... WHERE token_hash=?`; populate the cache; apply the same predicate.
   **FAIL-CLOSED**: 401→decoy only if the DB also denies/unreachable. NEVER
   `return 200` in an `except` — a Redis blip must not open the island, and an
   uncaught 5xx would decoy-lock EVERYONE.
4. The DB lookup is sha256-hex equality on a UNIQUE index (256-bit preimage-
   resistant → no compare_digest needed; document why). compare_digest is used
   ONLY for the raw env-master compare.
5. Response is **content-free** (status only, empty body, `-Server`, no Set-
   Cookie, no RCQ headers) so even an authed observer learns nothing.
6. Failure path adds a fixed min-response-time / small jitter floor (the
   subrequest can't be timing-identical to a pure-Caddy static file — see
   security property #2, downgraded).
7. **`last_used_at`** (telemetry only, never on the auth decision): on a pass,
   `SET gate:lru:<hash> 1 NX EX 300`; only when NX succeeds do an out-of-band
   `UPDATE last_used_at`. Bounds writes to ~1/token/5min (the per-worker pool is
   tiny — pool_size≈2 — a per-request write would saturate it).
8. **Rate-limit** `gate_check` (generous) via the existing per-IP limiter; the
   limiter must be fail-soft and a 429 must render as the decoy (no
   status/timing divergence from wrong-token).
- **Revoke latency bound** = cache TTL (≤60s) even if the immediate cache-bust is
  lost.

## `/gate/redeem` (behind the gate; invite → durable device token) — invariants
Body `{device_id: <client random 16B hex>}`. Auth = a token that already passed
`/gate/check`.
- **INVARIANT**: a device row is INSERTed ONLY when the presented token is
  `kind=='invite'` AND `uses<max_uses`. For `device`/`standing`/`env-master`:
  return the presented token **verbatim**, NO insert, NO `uses` mutation, NO
  `gate:active` write (else one standing token + fresh random device_ids = an
  unbounded device-token factory, each child surviving the parent's revocation).
- **Order (kills the double-consume TOCTOU)** in ONE transaction:
  1. `INSERT device row ... ON CONFLICT (device_id) DO NOTHING` FIRST.
  2. Run the invite consume `UPDATE access_tokens SET uses=uses+1 WHERE
     token_hash=h AND uses<max_uses AND NOT revoked` (rowcount check, NO
     RETURNING — mirror the proven `auth.py:103-107` pattern) ONLY when step 1
     created a new row.
  3. If the device row already existed (`ON CONFLICT` no-op) → return its token,
     do NOT consume (idempotent retry).
  - NO `await` on Redis/network between the consume and the commit; do the
    `gate:active` SADD/cache-populate AFTER commit (a Redis failure must not roll
    back a committed consume).
- Per-parent **child cap** (defensive bound on device rows per invite).
- Tight **rate-limit** `gate_redeem`; a redeem with a garbage token is denied by
  the gate (decoy), not a distinct 401.
- Response is content-free besides `{token}` on success.

## Revocation cascade
Revoking a parent **invite** cascades: revoke + cache-evict ALL `device` rows
with that `parent_id` (else "revoke Alice's invite" leaves Alice's redeemed
device working). Admin list shows parent→child; support "revoke device by
device_id/label" too. Test: redeem→device works→revoke invite→device hits decoy
within the TTL bound.

## Admin endpoints (operator-only, behind existing admin auth)
- `POST /admin/access-tokens {kind, label, expires_at?, max_uses?}` → `{token}`
  (raw shown ONCE).
- `GET /admin/access-tokens` → list: id, label, kind, uses/max, created,
  last_used, revoked, parent_id, a hash PREFIX for display — NEVER the raw token
  or full hash.
- `POST /admin/access-tokens/{id}/revoke` (cascades for invites).
- Self-host console (`admin_console.py`): "Access tokens" panel — generate
  (default one-time invite), list+status, copy-once, revoke. Harmless when the
  gate is off.

## Clients (iOS + Android + web) — blanket stamping, not an endpoint list
- **Per-HOST access-token store** (`{host → token}`), separate from the account
  JWT. The SINGLE source of truth for ALL foreign-host roles: contact islands,
  OWN multihome **backup** islands, AND §5c **visited-group** islands (backup /
  visited hosts can also be gated). `MultihomeStore` + `VisitedIslandsStore`
  entries gain an optional `accessToken`.
- **Blanket transport rule**: EVERY outbound HTTP/WS to host H stamps
  `X-RCQ-Auth` from the store iff a (non-empty) token exists for H. Enumerating
  endpoints is a trap — any unstamped call to a gated host gets 200 decoy HTML
  the client misparses as null.
  - iOS: a shared `CrossIslandHTTP` helper injecting host→token on the bare
    `URLSession` calls in CrossIslandSender / CrossIslandGroups / Multihome
    (covers /federation/keys, /federation/uin-for-key, /federation/island-record,
    /federation/gossip-record, /auth/register guest, /groups, /groups/{id}/
    preview|join, /messages/sealed, /messages/group-sealed, /messages/queue,
    /media PUT). Own island already stamps `serverToken` via APIClient.
  - Android: an OkHttp Interceptor on `CrossIslandSender` clients AND every
    per-host `RcqApi("https://$host")` — **RcqApi has NO X-RCQ-Auth path today**;
    add it alongside the Bearer header (RcqApi.kt ~953-1045). Android also has NO
    own-island token plumbing → add it.
- **Empty token = absent header** (trim→empty→nil at every entry point; a host
  with no token sends NO header so PUBLIC islands are unchanged).
- **Where the user enters it**: own-island add-account token field (iOS has it;
  Android add); NEW "Access token" field in add-contact / add-by-uin@host (both).
- **Redeem-on-entry, with the open-host fallback**: only attempt `/gate/redeem`
  when the user actually supplied a token for that host. A clean **404** = no
  gate → ignore the pasted token, proceed (don't break adding contacts on
  api.rcq.app and every public island). A **200 decoy / non-JSON** body with a
  token present = surface "this island needs a valid access token". Never
  "redeem-failed → block entry" blanket.
- **web-chat = NATIVE-ONLY for gated islands** (decision): a browser cannot send
  a custom header on the WS upgrade (RCQ WS already uses a `token` query param
  for the JWT, but the GATE is at Caddy on the upgrade), and the browser's CORS
  preflight (OPTIONS) never carries X-RCQ-Auth → it would hit the decoy and break
  every cross-origin call. So web shows "this island requires the mobile/desktop
  app". (A query-param gate-token + a Caddy OPTIONS-passthrough is possible but
  weakens the masquerade — explicitly NOT done in v2.)

## Env master (back-compat — must be done right)
The app NEVER reads `RCQ_AUTH_TOKEN` today (Caddy-only var). The new Caddyfile
stops referencing it, so unless the **uvicorn process** also has it,
single-token deployments are HARD-locked-out on Caddyfile swap. Mandate:
`RCQ_AUTH_TOKEN` in the APP env (docker-compose + README + bare-metal), a startup
log line confirming it's active, `secrets.compare_digest`. Document that leaving
it set = a permanent unrevocable reshareable bypass sitting in front of the
DB/revocation machinery → recommend operators adopting per-user tokens UNSET it.

## Security properties (hardened)
1. No bypass: the gate is host-wide (every path incl. /health, /server/info,
   /docs, /openapi.json, /ws, /, random → decoy when unauthed). Disable
   /docs+/openapi in the gated profile. Test matrix asserts byte-identical decoy.
2. Decoy: byte-identical status+headers+body to the static decoy; timing is
   **similar within ~1–5ms** (the subrequest overhead is irreducible — downgraded
   from "indistinguishable"; jitter floor caps the tell). The gate response never
   reaches an UNAUTHED client; for an authed client both /gate/* are content-free.
3. Redeem: atomic single-consumer, idempotent retry, no unbounded mint, one
   transaction, Redis after commit.
4. Revocation: takes effect ≤ cache TTL; invite→device cascade.
5. Hot path: FAIL-CLOSED with DB fallback; no per-request DB write
   (NX-gated last_used_at); Redis is a cache, DB is truth.
6. Tokens: sha256-only at rest; raw shown once; `X-RCQ-Auth`/raw tokens NEVER
   logged (grep test); admin bodies return no raw/full-hash.
7. Open-island/no-token path: strict no-op (no header, no /gate overhead).
8. Residual risk: env-master = legacy unrevocable bypass; recommend UNSET.
9. Rate-limit /gate/check (generous) + /gate/redeem (tight); 429 → decoy.
10. Ops: forward-style gate masks 5xx as decoy → a backend fault looks "fine" to
    the operator. MUST pair with /health + 5xx alerting (already a TODO) +
    distinct server-side error logging on the gate error path.

## Build order
0. **Caddyfile**: hand-write + `caddy validate` + the 6-path decoy proof + the
   valid-token-404 + WS proof. FIRST — the whole mechanism rested on a false
   assumption.
1. Backend: table + `/gate/check` + `/gate/redeem` + admin endpoints + Redis
   short-TTL metadata cache + rate-limit + env-master + /docs-disable + grep-no-
   token-log test. curl-test against a local gated compose.
2. Clients: per-host store + blanket stamping (iOS helper / Android interceptor +
   RcqApi path) + Multihome/Visited accessToken + add-account(Android)/add-contact
   token fields + redeem-with-open-host-fallback. web = native-only message.
3. Console: access-tokens panel.
4. Docs: `docs/private-island.md` + README + website /faq + /servers.
5. Release: Android v0.61 + iOS TF (+ web build for the native-only notice).
