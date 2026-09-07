"""Paid entry: what the signature protects, and what it deliberately does not.

The voucher is a bearer token. Everything here is about the two questions that
are NOT the same question: did the till sign this, and has anybody spent it.
The first is answered by `verify_entry`, the second by a row, and a test that
only checked the first would pass while the island handed out free accounts.
"""
import base64, json, sys, time
sys.path.insert(0, '/Users/tager/Documents/RCQ/backend')

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.services import uin_voucher as V

checks = []
def check(name, cond):
    checks.append((name, cond)); print(("ok   " if cond else "FAIL ") + name)

key = Ed25519PrivateKey.generate()
pub = base64.b64encode(key.public_key().public_bytes_raw()).decode()
V.public_key_b64 = lambda: pub          # the island trusts this till

def mint(host="api.rcq.app", nonce="n" * 32, ttl=3600, kind="entry", v=V.VERSION):
    exp = int(time.time()) + ttl
    body = V.entry_signed_bytes(host=host, nonce=nonce, exp=exp)
    doc = {"v": v, "kind": kind, "host": host, "nonce": nonce, "exp": exp,
           "sig": base64.b64encode(key.sign(body)).decode()}
    return base64.b64encode(json.dumps(doc).encode()).decode()

def refused(voucher, host="api.rcq.app"):
    try:
        V.verify_entry(voucher, expect_host=host); return None
    except V.VoucherError as e:
        return e.code

check("a good voucher verifies and returns its nonce",
      V.verify_entry(mint(), expect_host="api.rcq.app") == "n" * 32)
check("the host is matched case-insensitively",
      V.verify_entry(mint(host="API.RCQ.APP"), expect_host="api.rcq.app") == "n" * 32)

# ★ The one that matters: a voucher bought on a cheap island must not open this one.
check("a voucher for another island is refused",
      refused(mint(host="cheap.example")) == "voucher_other_island")
check("...and the refusal names the reason, so a client can say it",
      refused(mint(host="cheap.example")) not in (None, "bad_voucher"))

check("an expired voucher is refused", refused(mint(ttl=-10)) == "voucher_expired")
check("a voucher good for a year is refused (we bound the window, not the till)",
      refused(mint(ttl=400 * 24 * 3600)) == "bad_voucher")

# Cross-kind confusion: a number voucher must not be spendable as entry.
num = base64.b64encode(json.dumps({
    "v": V.VERSION, "uin": 777, "nonce": "m" * 32, "exp": int(time.time()) + 3600,
    "sig": base64.b64encode(key.sign(V.signed_bytes(uin=777, nonce="m" * 32,
                                                    exp=int(time.time()) + 3600))).decode(),
}).encode()).decode()
check("a voucher for a NUMBER cannot be spent as entry", refused(num) == "bad_voucher")
check("a voucher of an invented kind is refused", refused(mint(kind="entry2")) == "bad_voucher")
check("a voucher of a future version is refused, not guessed at", refused(mint(v=V.VERSION + 1)) == "bad_voucher")

# Tampering: the host is inside the signature, so editing it must not survive.
doc = json.loads(base64.b64decode(mint()))
doc["host"] = "cheap.example"
tampered = base64.b64encode(json.dumps(doc).encode()).decode()
check("editing the host after signing is caught", refused(tampered, host="cheap.example") == "bad_voucher")

check("a short nonce is refused (replay protection needs room)", refused(mint(nonce="abc")) == "bad_voucher")
check("garbage is refused", refused("not-a-voucher") == "bad_voucher")

# An island that does not know its own name cannot check the only field that matters.
check("an island with no configured host refuses everything", refused(mint(), host="") == "sales_disabled")
saved, V.public_key_b64 = V.public_key_b64, lambda: None
check("an island with no till key refuses everything", refused(mint()) == "sales_disabled")
V.public_key_b64 = saved

# The wiring: registration must consult the right things.
import pathlib, re
auth = pathlib.Path('app/routers/auth.py').read_text()
check("registration redeems the voucher itself", "verify_entry(" in auth)
check("the host comes from settings, never from the request",
      "island_host" in auth and "x-forwarded-host" not in auth.lower())
check("a redeemed nonce is recorded", "SpentVoucher(nonce=nonce)" in auth)
check("a replay is a conflict, not a free account", 'code": "voucher_spent"' in auth)
check("a spent voucher is not then spent again as an invite", 'code = ""' in auth)
check("an invite still opens a paid island", 'policy in ("invite", "paid")' in auth)
# ★ The money question, and the one that would have been silent: a voucher is
# paid for BEFORE the operator necessarily closes the door, so redeeming it
# must not depend on the door being closed. Otherwise somebody buys entry to an
# open island and `resident_since` stays NULL for ever.
import re as _re
_body = auth[auth.index("resident_at: datetime | None = None"):]
_body = _body[:_body.index("if policy in (")]
check("a voucher is redeemed whatever the door policy says",
      _re.search(r"^\s*if code:", _body, _re.M) is not None
      and 'policy == "paid" and code' not in _body)
check("residency is stamped on the account", "resident_since=resident_at" in auth)
mig = pathlib.Path('app/routers/migrate.py').read_text()
check("residency survives a change of number", "resident_since=user.resident_since" in mig)

bad = [n for n, c in checks if not c]
print(f"\n{len(checks) - len(bad)}/{len(checks)} прошло")
sys.exit(1 if bad else 0)
