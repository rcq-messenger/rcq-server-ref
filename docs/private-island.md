# Running a fully private (closed) island

RCQ federates by ADDRESS (`uin@host`) — anyone who knows your island's host can
reach it. That's the default and it's fine for a public/community island. If you
want a **fully private island** — invisible to scanners and reachable ONLY by
people you give access to — turn on the **masquerade gate**.

A closed island has two independent doors:

1. **Network gate** (this doc) — can a client reach the API at all? With the
   masquerade on, every request must carry a valid `X-RCQ-Auth` token or it gets
   a decoy "landing page" (a scanner can't even tell it's RCQ).
2. **Membership gate** — can someone create an account? Set
   `REGISTRATION_POLICY=invite` (separate; see the invites panel in the admin
   console). Messaging a member from another island only needs door #1.

> Closed islands are **native-only** (iOS / Android / desktop). A web browser
> can't attach the gate header to its WebSocket upgrade or CORS preflight, so
> web-chat can't reach a gated island.

## Two ways to run the gate

### A. One shared token (simplest)
Use `deploy/Caddyfile.masquerade.compose`. Caddy matches a single
`X-RCQ-Auth: $RCQ_AUTH_TOKEN`; everything else gets the decoy. No app changes.
Good for a tiny trusted group, but the token is shared, can't be revoked per
person, and anyone you give it to can re-share it.

### B. Per-user, one-time, revocable tokens (recommended)
Use `deploy/Caddyfile.masquerade-tokens.compose`. Caddy asks the backend
`/gate/check` on every request; you mint **per-person tokens** in the admin
console and **revoke** them individually. A **one-time invite** is consumed by
the first device that uses it, so a re-posted invite stops working.

Requires **Caddy ≥ 2.9**.

## Enable option B

1. Add to your `.env` (next to `docker-compose.yml`):
   ```
   RCQ_DOCS_DISABLED=1
   # optional legacy master token; prefer leaving it UNSET and using per-user
   # tokens. If set, it MUST be visible to the APP container (below), and it is a
   # permanent, unrevocable, reshareable bypass.
   # RCQ_AUTH_TOKEN=<openssl rand -hex 32>
   ```
   Make sure `RCQ_DOCS_DISABLED` (and `RCQ_AUTH_TOKEN` if you use it) are in the
   **app** service's environment, not just Caddy's.
2. Drop a generic `./decoy/index.html` (a plain "coming soon" / blog page — see
   the README masquerade note) and bind-mount it: `- ./decoy:/srv/decoy:ro`.
3. Point Caddy at the tokens Caddyfile:
   `- ./deploy/Caddyfile.masquerade-tokens.compose:/etc/caddy/Caddyfile`
4. `docker compose up -d`.

**Validate before relying on it** (Caddy ≥ 2.9):
```
caddy validate --adapter caddyfile --config deploy/Caddyfile.masquerade-tokens.compose
```
Then, against the live island, confirm the gate behaves (all should look like
the static decoy except the last two):
```
curl -s -o /dev/null -w '%{http_code}\n' https://<host>/server/info                 # no token  -> 200 decoy HTML
curl -s -H 'X-RCQ-Auth: wrong' https://<host>/server/info | head -c 40              # wrong     -> decoy HTML
curl -s -H "X-RCQ-Auth: <valid>" https://<host>/server/info | head -c 40            # valid     -> real JSON
curl -s -i -H "X-RCQ-Auth: <valid>" https://<host>/health                           # valid     -> real 200
```

## Mint, give out, and revoke tokens

Admin console → **Access tokens** (`https://<host>/admin/console`, HTTP-Basic):
- **One-time invite** — hand to one person; consumed on first use.
- **Standing** — multi-use (a bot/bridge); revoke anytime.
- The full token is shown **once** on creation — copy it then.
- **Revoke** kills a token immediately (a revoked invite also kills the device
  token it minted). Worst-case propagation is ~60s (the gate's cache TTL).

(API equivalents: `POST/GET /admin/access-tokens`, `POST /admin/access-tokens/{id}/revoke`.)

## How people connect

Give the person the token out of band (Signal / in person). In the RCQ app:
- **Joining your closed island** (their own account here): Add account → enter
  the host → paste the token in **Access token**.
- **Messaging a member from another island**: Add contact → `uin@host` → paste
  the token in **Access token**.

The app redeems a one-time invite into a durable per-device token automatically;
from then on it stamps `X-RCQ-Auth` on every request to your host.

## Notes / limits (v1)
- web-chat is not supported on a gated island (native only).
- Multihoming a *backup* island that is itself gated is not yet wired (the
  primary 1:1 + own-account + cross-island-group paths are).
- The gate masks backend 5xx as the decoy, so a server fault looks "fine" from
  outside — pair a closed island with `/health` + 5xx alerting.
- Leaving `RCQ_AUTH_TOKEN` set keeps a permanent unrevocable bypass in front of
  the per-user tokens; unset it once you've issued per-user tokens.

See `docs/closed-island-access-design.md` for the full design + threat model.
