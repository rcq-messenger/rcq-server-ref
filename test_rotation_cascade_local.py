"""A key rotation that crosses islands: what the copies elsewhere do.

Why this exists. Changing the recovery phrase rewrote the keys on the home
island and stopped there, so every copy of the identity on another island -- a
backup home, a guest copy made to join one room -- kept the old keys and the
old phrase still opened them (report #986). The fix is one signed
`rcq-reissue-v1` proof per island, and the only way to know it works is to
watch two islands do it.

This is the SERVER half, on the wire, in the order a client walks it: a home
account on A, a copy of the same identity on B, a rotation on each, and then
the questions that matter -- does the old key still open the copy, does the new
one, is it still the same number there. It also pins the answers the client
branches on: the proof is bound to ONE island, a stranger's proof is refused,
an absent identity says so, the bearer dies with the rotation, and repeating a
rotation that already happened is a 200 rather than an error.

Like `test_cross_island_local.py` it needs two live islands:

    DATABASE_URL="sqlite+aiosqlite:///./test_rot_a.db" \
        .venv/bin/uvicorn app.main:app --port 8099
    DATABASE_URL="sqlite+aiosqlite:///./test_rot_b.db" \
        .venv/bin/uvicorn app.main:app --port 8098
    PYTHONPATH=. .venv/bin/python test_rotation_cascade_local.py

The second half needs island B to admit guests, which it does by flipping two
of its own settings in its database and waiting out the settings cache. It puts
them back the way it found them on the way out.
"""
import base64, json, os, secrets, sqlite3, sys, time, urllib.error, urllib.request

from app.services import reissue_proof, guest_proof  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

A = "http://127.0.0.1:8099"    # home island
B = "http://127.0.0.1:8098"    # the island holding the copy
# ⚠ What the client DIALLED, which is what the proof names and what the island
# checks against its own name. With `island_host` unset an island reads its
# name off the Host header, so these two have to be the addresses above.
A_HOST = "127.0.0.1:8099"
B_HOST = "127.0.0.1:8098"

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"ok   {name}")
    else:
        fail += 1
        print(f"FAIL {name} {extra}")


def call(base, path, body=None, token=None, method=None, host=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method or ("POST" if data else "GET"))
    req.add_header("Content-Type", "application/json")
    # ⚠ The Host header IS the island's name here: with island_host unset the
    # island reads its own name off it, which is what a client dialling
    # 127.0.0.1:8099 makes it see.
    req.add_header("Host", host or "")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw[:200]}


def b64(raw):
    return base64.b64encode(raw).decode()


class Key:
    def __init__(self, seed=None):
        self.seed = seed or secrets.token_bytes(32)
        self.sk = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.signing_pub = self.sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        self.identity_pub = secrets.token_bytes(32)   # X25519 half, opaque here

    def sign(self, msg):
        return b64(self.sk.sign(msg))


# The guest phase at the end leaves island B closed; start every run from open.
# ⚠ Island B's own database, beside this file: the same path the header tells
# you to start it with. Absolute paths to somebody's laptop have no business in
# a published test (19.09 audit).
_ISL_B = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_rot_b.db")
_con = sqlite3.connect(_ISL_B)
for _k, _v in (("registration_policy", "open"), ("guest_admission", "off")):
    _con.execute("insert into server_settings(key, value, updated_at) values(?,?,datetime('now')) "
                 "on conflict(key) do update set value=excluded.value", (_k, _v))
_con.commit()
_con.close()
time.sleep(7)

print("== a room on B for the guest half")
_rk = Key()
st, _owner = call(B, "/auth/register", {
    "nickname": "room-owner", "identity_key": b64(_rk.identity_pub),
    "signing_key": b64(_rk.signing_pub),
}, host=B_HOST)
check("an account on B to own the room", st in (200, 201), f"{st} {_owner}")
st, _room = call(B, "/groups", {"name": "stand room", "member_uins": []},
                 token=_owner["token"], host=B_HOST)
check("an open room on B", st in (200, 201) and _room.get("id"), f"{st} {_room}")
room_on_b = _room.get("id")

old = Key()
print("\n== home account on A")
st, me = call(A, "/auth/register", {
    "nickname": "cascade-tester",
    "identity_key": b64(old.identity_pub),
    "signing_key": b64(old.signing_pub),
}, host=A_HOST)
check("registered on the home island", st in (200, 201) and me.get("uin"), f"{st} {me}")
home_uin, home_token = me["uin"], me["token"]

print("\n== a copy of the SAME identity on B")
# ⚠ On an OPEN island there are no guests: the same keys register natively and
# that row IS the copy this device would hold (VisitedIslandsStore). The guest
# flavour of the same copy is exercised at the end, on a closed island.
st, copy = call(B, "/auth/register", {
    "nickname": "cascade-tester",
    "identity_key": b64(old.identity_pub),
    "signing_key": b64(old.signing_pub),
}, host=B_HOST)
check("the copy exists on B", st in (200, 201) and copy.get("uin"), f"{st} {copy}")
copy_uin, copy_token = copy["uin"], copy["token"]
check("the copy has its OWN number there", copy_uin != home_uin, f"{copy_uin} == {home_uin}")
print(f"     home {home_uin} on A, copy {copy_uin} on B")

print("\n== the rotation: home first, then the copy (what rotateEverywhere does)")
new = Key()


def reissue(base, host, uin, token, signer, new_keys, ts=None, nonce_raw=None):
    ts = ts or int(__import__("time").time())
    nonce_raw = nonce_raw or secrets.token_bytes(16)
    msg = reissue_proof.proof_bytes(
        host, uin, signer.signing_pub, new_keys.identity_pub, new_keys.signing_pub, ts, nonce_raw,
    )
    return call(base, "/auth/reissue", {
        "identity_key": b64(new_keys.identity_pub),
        "signing_key": b64(new_keys.signing_pub),
        "proof_v": reissue_proof.VERSION,
        "host": host,
        "old_signing_key": reissue_proof.canonical_key(signer.signing_pub),
        "ts": ts,
        "nonce": reissue_proof.canonical_nonce(nonce_raw),
        "signature": signer.sign(msg),
    }, token=token, host=host), (ts, nonce_raw)


(st, out), _ = reissue(A, A_HOST, home_uin, home_token, old, new)
check("the home island takes the rotation", st == 200, f"{st} {out}")

# ⚠ The heart of #986: the SAME new keys, a DIFFERENT proof, bound to B and to
# the number the copy has there.
(st, out2), (ts_b, nonce_b) = reissue(B, B_HOST, copy_uin, copy_token, old, new)
check("★ the copy on the other island takes it too", st == 200, f"{st} {out2}")

print("\n== the old phrase, right after the rotation")
st, ch_old = call(B, "/auth/recover/challenge", {"signing_key": b64(old.signing_pub)}, host=B_HOST)
if st == 200:
    st, out_old = call(B, "/auth/recover", {
        "signing_key": b64(old.signing_pub), "challenge": ch_old["challenge"],
        "signature": old.sign(ch_old["challenge"].encode()),
    }, host=B_HOST)
else:
    out_old = ch_old
check("★ the OLD key no longer opens the copy on B", st in (403, 404), f"{st} {out_old}")
print(f"     (B answers {st} {json.dumps(out_old)[:90]})")

st, ch_new = call(B, "/auth/recover/challenge", {"signing_key": b64(new.signing_pub)}, host=B_HOST)
st, fresh = call(B, "/auth/recover", {
    "signing_key": b64(new.signing_pub), "challenge": ch_new["challenge"],
    "signature": new.sign(ch_new["challenge"].encode()),
}, host=B_HOST)
check("★ the NEW key opens it, and it is the same number",
      st == 200 and fresh.get("uin") == copy_uin, f"{st} {fresh}")
live_token = fresh.get("token")

st, ch_a = call(A, "/auth/recover/challenge", {"signing_key": b64(old.signing_pub)}, host=A_HOST)
if st == 200:
    st, out_a = call(A, "/auth/recover", {
        "signing_key": b64(old.signing_pub), "challenge": ch_a["challenge"],
        "signature": old.sign(ch_a["challenge"].encode()),
    }, host=A_HOST)
else:
    out_a = ch_a
check("the OLD key no longer opens the home account either", st in (403, 404), f"{st} {out_a}")

print("\n== what the token does, and what the proof refuses")
# ⚠ THE TOKEN USED FOR A REISSUE DIES WITH IT. A retry whose first reply was
# lost comes back with a bearer the island has already retired, so it gets 401
# and never reaches the proof at all: 401 is "your token is stale", not "your
# key is stale" (ReissueCascade.classify).
(st, stale), _ = reissue(B, B_HOST, copy_uin, copy_token, old, new, ts=ts_b, nonce_raw=nonce_b)
check("★ the token that rotated an island is dead afterwards", st == 401, f"{st} {stale}")

# ⚠ The SAME change again, with a live token: 200, because the keys it is being
# asked to set are the ones the island already holds. That is what makes a lost
# reply harmless, and why the client reads 2xx as done. It mints a new bearer,
# so the old one dies here too.
(st, replayed), _ = reissue(B, B_HOST, copy_uin, live_token, old, new, ts=ts_b, nonce_raw=nonce_b)
check("★ repeating a rotation that already happened is a 200, not an error",
      st == 200, f"{st} {replayed}")
live_token = replayed.get("token", live_token)

# A proof bound to the OTHER island, sent here: the binding that stops one
# proof from rotating every copy.
third = Key()
bad_ts = int(__import__("time").time())
bad_nonce_raw = secrets.token_bytes(16)
msg_for_a = reissue_proof.proof_bytes(
    A_HOST, copy_uin, new.signing_pub, third.identity_pub, third.signing_pub, bad_ts, bad_nonce_raw)
st, out4 = call(B, "/auth/reissue", {
    "identity_key": b64(third.identity_pub), "signing_key": b64(third.signing_pub),
    "proof_v": reissue_proof.VERSION, "host": A_HOST,
    "old_signing_key": reissue_proof.canonical_key(new.signing_pub),
    "ts": bad_ts, "nonce": reissue_proof.canonical_nonce(bad_nonce_raw), "signature": new.sign(msg_for_a),
}, token=live_token, host=B_HOST)
check("★ a proof made for the home island is refused by B", st in (400, 403), f"{st} {out4}")
print(f"     (it answers {st} {json.dumps(out4)[:120]})")

# A proof signed by a key this island does not hold: the answer the client maps
# to DIFFERENT_KEY and re-checks with the new key before believing.
stranger = Key()
(st, out4b), _ = reissue(B, B_HOST, copy_uin, live_token, stranger, third)
check("a proof signed by a key the island does not hold is refused",
      st in (400, 403, 409), f"{st} {out4b}")
print(f"     (it answers {st} {json.dumps(out4b)[:120]})")

# An account that is not there at all: the answer the client reads as GONE.
ghostie = Key()
st, ghost = call(B, "/auth/recover/challenge", {"signing_key": b64(ghostie.signing_pub)}, host=B_HOST)
if st == 200:
    st, ghost = call(B, "/auth/recover", {
        "signing_key": b64(ghostie.signing_pub), "challenge": ghost["challenge"],
        "signature": ghostie.sign(ghost["challenge"].encode()),
    }, host=B_HOST)
check("an identity with no row here answers 'not found'", st in (400, 403, 404), f"{st} {ghost}")
print(f"     (it answers {st} {json.dumps(ghost)[:120]})")

print("\n== the same thing again, but the copy is a GUEST row")
# A guest row is the interesting one: `key_unproven_since` is set by a reissue
# and every bearer minted before the new key is proven has to die (guest
# accounts, review 2026-09-15). If that path refused the rotation, a paid or
# invite island would keep the old phrase working for ever.
db = _ISL_B
con = sqlite3.connect(db)
for k, v in (("registration_policy", "paid"), ("guest_admission", "on")):
    con.execute("insert into server_settings(key, value, updated_at) values(?,?,datetime('now')) "
                "on conflict(key) do update set value=excluded.value", (k, v))
con.commit()
con.close()
time.sleep(7)   # the settings cache

gid = room_on_b
g_old = Key()
st, me2 = call(A, "/auth/register", {
    "nickname": "guest-tester", "identity_key": b64(g_old.identity_pub),
    "signing_key": b64(g_old.signing_pub),
}, host=A_HOST)
check("a second home account on A", st in (200, 201), f"{st} {me2}")
st, ch = call(B, "/auth/guest/challenge", {"signing_key": b64(g_old.signing_pub)}, host=B_HOST)
check("island B issues a guest challenge", st == 200 and ch.get("challenge"), f"{st} {ch}")
gbytes = guest_proof.proof_bytes(B_HOST, gid, g_old.identity_pub, g_old.signing_pub, ch["challenge"])
st, guest = call(B, "/auth/guest", {
    "v": guest_proof.VERSION, "host": B_HOST, "group_id": gid,
    "nickname": "guest-tester", "identity_key": b64(g_old.identity_pub),
    "signing_key": b64(g_old.signing_pub), "challenge": ch["challenge"],
    "signature": g_old.sign(gbytes),
}, host=B_HOST)
check("the guest copy exists on B", st in (200, 201) and guest.get("uin"), f"{st} {guest}")
if guest.get("uin"):
    g_uin, g_token = guest["uin"], guest["token"]
    g_new = Key()
    (st, out), _ = reissue(A, A_HOST, me2["uin"], me2["token"], g_old, g_new)
    check("the home half of the second rotation", st == 200, f"{st} {out}")
    (st, out), _ = reissue(B, B_HOST, g_uin, g_token, g_old, g_new)
    check("★ a GUEST copy takes the rotation", st == 200, f"{st} {out}")
    st, ch5 = call(B, "/auth/recover/challenge", {"signing_key": b64(g_old.signing_pub)}, host=B_HOST)
    if st == 200:
        st, out = call(B, "/auth/recover", {
            "signing_key": b64(g_old.signing_pub), "challenge": ch5["challenge"],
            "signature": g_old.sign(ch5["challenge"].encode()),
        }, host=B_HOST)
    check("★ the old key no longer opens the guest copy", st in (403, 404), f"{st} {out}")
    st, ch6 = call(B, "/auth/recover/challenge", {"signing_key": b64(g_new.signing_pub)}, host=B_HOST)
    st, out = call(B, "/auth/recover", {
        "signing_key": b64(g_new.signing_pub), "challenge": ch6["challenge"],
        "signature": g_new.sign(ch6["challenge"].encode()),
    }, host=B_HOST)
    check("★ the new key opens it, same number", st == 200 and out.get("uin") == g_uin, f"{st} {out}")
    con = sqlite3.connect(db)
    row = list(con.execute("select guest_status, key_unproven_since from users where uin=?", (g_uin,)))
    con.close()
    check("the guest row is marked proven and carries no unproven key",
          row and row[0][0] == "proven" and row[0][1] is None, f"{row}")

# Put island B back the way it was found.
con = sqlite3.connect(_ISL_B)
for k, v in (("registration_policy", "open"), ("guest_admission", "off")):
    con.execute("insert into server_settings(key, value, updated_at) values(?,?,datetime('now')) "
                "on conflict(key) do update set value=excluded.value", (k, v))
con.commit()
con.close()

print(f"\n{ok}/{ok + fail} passed")
sys.exit(1 if fail else 0)
