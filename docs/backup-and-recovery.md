# Backing up and recovering an island

Short version: **back up Postgres, the media directory, `.env` and `certs/` on
a cron, off the box, encrypted.** That is enough to recover an island after a
dead disk or a lost droplet, under the same identity. Everything below is
optional hardening on top of that.

Do NOT confuse this with RCQ's **per-user backup island** (multihoming): that is
a client feature where a *user* mirrors their own mailbox to a second island.
Islands never replicate each other and never talk. This document is about an
*operator* protecting their own island's data.

## What an island stores

- **Postgres** (the compose `postgres` service): users, contacts, group
  membership, the offline queue (ciphertext, deleted on ACK), reports. The
  accounts live here; the island's own identity does not (the next two items).
- **`.env`**: `JWT_SECRET` (every session token is signed with it; a new one
  logs every device out), the database password, the TLS mode and the
  address. Not in git, not in Postgres.
- **`certs/`**, on an island without a certificate authority
  (`RCQ_TLS_MODE=fingerprint`): `island.key` IS the island's identity. Every
  user's app pins the certificate it signs, and a re-issued one is a new
  fingerprint that every user gets a red banner for and has to accept
  ([tls-without-a-ca.md](tls-without-a-ca.md), "Rotating the certificate": a
  lost key is a rotation). Nothing regenerates it; only a copy brings it back.
  Empty but for `.gitkeep` on a CA island, where Caddy obtains its certificate
  again on its own.
- **Media directory** (`RCQ_MEDIA_DIR`, default `./media/uploads`): E2E-encrypted
  blobs (`{id}.bin`). Losing it only loses old attachments; identities survive.
- **Sites directory** (`RCQ_SITES_DIR`, default `./sites`): `.rcq` site
  bundles. ⚠ The only PUBLIC bytes on the island - back them up like a web
  root. Losing it loses somebody's pages, and nobody else has a copy: the
  bundle lives here, not in a client. The rows in Postgres (name, owner, the
  signed manifest) are useless without the files beside them.
- Redis is a cache (rate limits, WS routing) — disposable, do not back it up.

## Minimum backup (every island, including a $6 droplet)

A nightly `pg_dump` + a media rsync, pushed somewhere off the box (object
storage, another host), and a DATED copy of the identity beside them.
Example cron on the host:

```sh
#!/bin/bash
# /etc/cron.daily/rcq-backup  (chmod +x)
# pipefail: without it the dump line reports gzip's status, and a pg_dump
# that fails writes an empty rcq-DATE.sql.gz every night with exit 0.
set -eo pipefail
STAMP=$(date +%F)
DEST=/var/backups/rcq
mkdir -p "$DEST" && chmod 700 "$DEST"
# The island's identity and its secrets, dated and never pruned. A single
# mirrored copy is overwritten by the next run: after a re-issued
# certificate (install.sh issues one when it finds certs/ empty) or a
# rewritten .env, within a day no copy held the old island.key, the one
# file nothing regenerates. A few kilobytes each; tar keeps the 0600.
tar -C /opt/rcq-server -cf "$DEST/identity-$STAMP.tar" .env certs
chmod 600 "$DEST/identity-$STAMP.tar"
# DB dump from the compose postgres service
docker compose -f /opt/rcq-server/docker-compose.yml exec -T postgres \
  pg_dump -U rcq rcq | gzip > "$DEST/rcq-$STAMP.sql.gz"
# Media (encrypted blobs)
rsync -a --delete /opt/rcq-server/media/ "$DEST/media/"
# Keep 14 daily dumps
ls -1t "$DEST"/rcq-*.sql.gz | tail -n +15 | xargs -r rm -f
# Then push $DEST off-box, e.g. rclone copy "$DEST" remote:rcq-backups
# (copy never deletes there, and the dated names never overwrite)
```

⚠ `$DEST` now holds the island's key and secrets. Encrypt it before it leaves
the box (`rclone` with a crypt remote, or `age`), to a place only you can read.

### Restore

On the new box, in this order. The order is the whole point: `install.sh`
writes a fresh `.env` when it finds none (a new `JWT_SECRET`, every device
logged out) and, on a fingerprint island, issues a new certificate when it
finds none, which is the rotation above. It also clones into
`/opt/rcq-server` only when that directory does not exist yet, so the two
files cannot be put there ahead of it: `git clone` refuses a directory that
is not empty, and the installer stops at its clone.

1. The checkout, by hand:
   `git clone https://github.com/rcq-messenger/rcq-server-ref.git /opt/rcq-server`
2. The identity into it, from the copy made BEFORE whatever was lost (after
   a lost `certs/`, the newest copy that still holds the old `island.key`;
   the dates exist for this):
   `tar -C /opt/rcq-server -xpf "$DEST/identity-YYYY-MM-DD.tar"`
   That puts `.env` and `certs/` back under their own names, 0600.
3. The database, before the app has created empty tables in it. From
   `/opt/rcq-server`: `docker compose up -d postgres`, then
   `docker compose exec -T postgres pg_isready -U rcq` until it says
   accepting connections, then
   `gunzip -c "$DEST/rcq-YYYY-MM-DD.sql.gz" | docker compose exec -T postgres psql -U rcq rcq`
4. The media back into `RCQ_MEDIA_DIR`:
   `rsync -a "$DEST/media/" /opt/rcq-server/media/`
5. `bash /opt/rcq-server/install.sh`: it finds the checkout and pulls, keeps
   the `.env` and `certs/` it finds, and brings the rest of the stack up.

Clients reconnect to the same address and see their history: the keys live on
the devices, so a restored DB plus the same domain, plus the same `certs/` on
a fingerprint island, is a full recovery.

## The flagship (managed Postgres)

`api.rcq.app` runs on **DigitalOcean managed Postgres**, which already does
automated daily backups + point-in-time-recovery, so a separate `pg_dump` is
not required there. If the *app* droplet dies, redeploy the app pointing at the
same managed cluster — no data loss. Media and `.env` still need their own
backup (both are on the droplet disk; move media to object storage when it
grows).

## Optional: hot standby + DNS failover (large islands only)

If you want **zero-downtime** failover (not just no-data-loss), run a second
server as a Postgres streaming replica and point a low-TTL DNS record at it; on
a primary outage, repromote the replica and flip DNS. Clients keep the same
hostname and reconfigure nothing.

This is classic infrastructure DR (Postgres replication + DNS), entirely outside
the RCQ app — RCQ does not replicate islands server-to-server. It is overkill
for a small or hobby island; the nightly dump above is the right call there.
Reach for this only when an hour of downtime actually costs you something.
