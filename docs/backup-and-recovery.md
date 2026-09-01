# Backing up and recovering an island

Short version: **back up Postgres + the media directory on a cron, off the
box.** That is enough to recover an island after a dead disk or a lost droplet.
Everything below is optional hardening on top of that.

Do NOT confuse this with RCQ's **per-user backup island** (multihoming): that is
a client feature where a *user* mirrors their own mailbox to a second island.
Islands never replicate each other and never talk. This document is about an
*operator* protecting their own island's data.

## What an island stores

- **Postgres** (the compose `db` service): users, contacts, group membership,
  the offline queue (ciphertext, deleted on ACK), reports. This is the only
  stateful thing that matters for identity continuity.
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
storage, another host). Example cron on the host:

```sh
# /etc/cron.daily/rcq-backup  (chmod +x)
#!/bin/sh
set -e
STAMP=$(date +%F)
DEST=/var/backups/rcq
mkdir -p "$DEST"
# DB dump from the compose db container
docker compose -f /opt/rcq-server/docker-compose.yml exec -T db \
  pg_dump -U rcq rcq | gzip > "$DEST/rcq-$STAMP.sql.gz"
# Media (encrypted blobs)
rsync -a --delete /opt/rcq-server/media/ "$DEST/media/"
# Keep 14 daily dumps
ls -1t "$DEST"/rcq-*.sql.gz | tail -n +15 | xargs -r rm -f
# Then push $DEST off-box, e.g. rclone copy "$DEST" remote:rcq-backups
```

Restore: `gunzip -c rcq-YYYY-MM-DD.sql.gz | docker compose exec -T db psql -U rcq rcq`
into a fresh stack, drop the media back into `RCQ_MEDIA_DIR`, `up -d`. Clients
reconnect to the same hostname and see their history (the keys live on the
devices, so a restored DB plus the same domain is a full recovery).

## The flagship (managed Postgres)

`api.rcq.app` runs on **DigitalOcean managed Postgres**, which already does
automated daily backups + point-in-time-recovery, so a separate `pg_dump` is
not required there. If the *app* droplet dies, redeploy the app pointing at the
same managed cluster — no data loss. Media still needs its own backup (it is on
the droplet disk, move it to object storage when it grows).

## Optional: hot standby + DNS failover (large islands only)

If you want **zero-downtime** failover (not just no-data-loss), run a second
server as a Postgres streaming replica and point a low-TTL DNS record at it; on
a primary outage, repromote the replica and flip DNS. Clients keep the same
hostname and reconfigure nothing.

This is classic infrastructure DR (Postgres replication + DNS), entirely outside
the RCQ app — RCQ does not replicate islands server-to-server. It is overkill
for a small or hobby island; the nightly dump above is the right call there.
Reach for this only when an hour of downtime actually costs you something.
