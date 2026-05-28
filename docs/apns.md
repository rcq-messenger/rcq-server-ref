# APNs setup for self-hosted RCQ

iOS push notifications are optional. Without APNs the server still
delivers every message — clients pull queued messages on the next
WebSocket reconnect (foreground app, lock-screen unlock, or scheduled
background fetch). What you lose is the lock-screen alert when the app
is fully suspended or killed.

If you want push, you'll need:

1. An Apple Developer Program membership ($99/year).
2. An APNs Auth Key (`.p8` file).
3. Three identifiers from your Apple Developer account: Key ID, Team ID,
   Bundle ID.
4. A decision about `production` vs `sandbox` APNs environment.

The whole walkthrough is ~10 minutes once you have the developer
account. The `.p8` key is generated once, lives only on your server,
and never touches the iOS client.

## 1. Generate the `.p8` key

Apple's APNs key replaces the older per-app push certificate. One key
works for every app under the same Team ID, and it doesn't expire.

1. Open https://developer.apple.com/account/resources/authkeys/list
2. Click **"+"** (Create a new key).
3. Give it a name like `RCQ self-host APNs`. Tick
   **"Apple Push Notifications service (APNs)"**.
4. Continue → Register → **Download**. You get one shot at this file —
   if you lose it, you regenerate the key. Save it somewhere safe
   (password manager, encrypted backup).
5. On the same page Apple shows the **Key ID** (10 chars,
   e.g. `ABCD1234EF`). Note it down — you'll need it as `APNS_KEY_ID`.

## 2. Find your Team ID

Top-right of https://developer.apple.com/account — directly under your
name, the 10-char string (e.g. `1A2B3C4D5E`) is your Team ID. Use it as
`APNS_TEAM_ID`.

## 3. Find or register a Bundle ID

If you're running the unmodified RCQ iOS client (the public
`rcq-messenger/rcq-ios` repo) against your own server, you'll be
rebuilding the app with your own provisioning profile and your own
Bundle ID. The Bundle ID you registered for that build is what goes
into `APNS_BUNDLE_ID`.

If you haven't registered one yet:

1. Open https://developer.apple.com/account/resources/identifiers/list
2. Click **"+"** → App IDs → App → Continue.
3. Pick a Bundle ID like `com.yourname.rcq`.
4. Tick **"Push Notifications"** under Capabilities.
5. Continue → Register.

Set `APNS_BUNDLE_ID` to exactly the string you registered.

## 4. Pick the right environment

* `APNS_ENVIRONMENT=production` → `api.push.apple.com`. Use this for
  builds installed via TestFlight or the App Store.
* `APNS_ENVIRONMENT=sandbox` → `api.sandbox.push.apple.com`. Use this
  for Xcode debug builds installed directly on a device (development
  signing).

Same `.p8` key works for both environments — you flip the env var,
restart the server, and the next push goes to the other path.

If pushes silently don't arrive, environment mismatch is the first
thing to check. Apple's response is the same shape either way, so the
sender thinks the push succeeded — it just lands in `/dev/null` on the
wrong APNs path.

## 5. Wire it into the server

### 5a. Drop the `.p8` next to `docker-compose.yml`

```
rcq-server-ref/
├── apns.p8                    ← here
├── docker-compose.yml
├── .env
└── ...
```

The repo's `.gitignore` already excludes `*.p8`, so you won't
accidentally commit it. Treat the key like a production credential
anyway — anyone with it can push notifications to any user of any app
under your Team ID.

### 5b. Uncomment the volume mount

Open `docker-compose.yml`, find the `app:` service `volumes:` block,
and uncomment this line:

```yaml
# - ./apns.p8:/keys/apns.p8:ro
```

so it becomes:

```yaml
- ./apns.p8:/keys/apns.p8:ro
```

The `:ro` suffix mounts it read-only inside the container.

### 5c. Fill in `.env`

```
APNS_KEY_ID=ABCD1234EF
APNS_TEAM_ID=1A2B3C4D5E
APNS_BUNDLE_ID=com.yourname.rcq
APNS_KEY_PATH=/keys/apns.p8
APNS_ENVIRONMENT=production
```

`APNS_KEY_PATH` is the path **inside the container**, not on the host.
That's why the mount target is `/keys/apns.p8` regardless of where the
host file lives.

### 5d. Restart

```
docker compose up -d
```

(or `docker compose restart app` if everything else is already up).

## 6. Verify

Send yourself a message from a second account. The receiving device
should get a lock-screen alert within a couple of seconds.

If nothing arrives:

* `docker compose logs app | grep -i apns` — the sender logs every push
  attempt and the APNs response code. The most common failures:
  * `BadDeviceToken` → device token registered against a different
    Bundle ID or environment. Verify `APNS_BUNDLE_ID` matches the iOS
    build, and `APNS_ENVIRONMENT` matches how the iOS build was
    installed (TestFlight = production, Xcode-direct = sandbox).
  * `Forbidden` → wrong `APNS_KEY_ID` / `APNS_TEAM_ID`, or the key was
    revoked in the Developer Console.
  * `Unregistered` → the device uninstalled the app or revoked
    notifications. Normal; the server prunes that token.

* If `grep` returns nothing, the push pipeline never tried. Confirm
  `APNS_KEY_PATH` resolves inside the container:
  `docker compose exec app ls -la /keys/apns.p8`.

## Disabling APNs

Leave any of `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_BUNDLE_ID`, or
`APNS_KEY_PATH` empty in `.env`. The sender no-ops cleanly — your users
still get messages on the next WebSocket connect, just without iOS
alert pushes. You can also leave the volume mount commented out.

## What about VoIP push (incoming calls)?

The same `.p8` key handles VoIP pushes too. The server uses the
`liveactivity` and `voip` topics off the same Bundle ID and key. No
extra config needed for calls — once 1:1 messaging push works, calls
work.
