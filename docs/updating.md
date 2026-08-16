# Keeping your island up to date

Your island is a checkout of this repository plus a few containers. Updating it
is a `git pull` and a rebuild — but remembering to do that, forever, is the part
that does not survive contact with real life. So there is a script, and a timer
that runs the script, and both are **off until you turn them on**.

An island that pulls code by itself is a trust decision. It is yours, not ours.

## Why it matters more than it sounds

Releases here are mostly not features. They are the fixes an island cannot
diagnose on its own. Two from a single day, 2026-08-16:

* Registration on an island answered **500 to everybody** because a column the
  model had dropped was still `NOT NULL` in that database. Nobody could create
  an account there, and it was noticed by a user, not by us.
* Group messages were broken on **every SQLite island** because a timestamp
  comparison worked on Postgres and threw on SQLite.

Neither is visible from the outside. Both are fixed by updating.

## Update now, by hand

```bash
/opt/rcq-server/deploy/rcq-update.sh          # update if behind, then restart
/opt/rcq-server/deploy/rcq-update.sh --check  # say what would happen, change nothing
```

What it does, in order: refuses to touch a checkout with local changes, fetches
`main`, **dumps the database** (Postgres islands; keeps the last five dumps in
`state/`), fast-forwards, rebuilds the app container, and then waits up to two
minutes for `/health` to answer. The result is written to
`state/update-status.json` and appended to `state/update.log`.

⚠ It does **not** roll back on failure. Rolling the code back does not roll the
database back, and doing that unattended is how a bad minute becomes lost data.
You get the dump, the log line, and the old container still running.

## Update on its own, daily

```bash
cp /opt/rcq-server/deploy/rcq-update.{service,timer} /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now rcq-update.timer
```

Check on it:

```bash
systemctl list-timers rcq-update.timer     # when it next runs
journalctl -u rcq-update -n 50             # what happened last time
cat /opt/rcq-server/state/update-status.json
```

Turn it off again:

```bash
systemctl disable --now rcq-update.timer
```

The timer fires once a day with up to four hours of random delay. That delay is
not cosmetic: without it every island on earth would fetch the same repository
in the same second after a release, and the ones behind a censored network
would be the ones that time out.

## If you would rather not

Perfectly reasonable — plenty of operators want to read a diff before it runs on
their users' data. The admin console keeps telling you when a release is out
(the version line at the top), and the two commands above are the whole job.
An air-gapped island can switch even the check off with `RCQ_UPDATE_CHECK=false`
in `.env`.
