"""Paid entry: what the signature protects, and what it deliberately does not.

The voucher is a bearer token. Everything here is about the two questions that
are NOT the same question: did the till sign this, and has anybody spent it.
The first is answered by `verify_entry`, the second by a row, and a test that
only checked the first would pass while the island handed out free accounts.

The second half covers the question the till asks BEFORE any of that, the
signed `entry_payout` document (`POST /entry/payout-target`): the island must
answer its own till about its own door and nobody else about anything. When
`node` is on PATH the document is also signed with the Worker's own
canonicalisation, the way `test_till_interop_local.py` does for numbers.

Run: .venv/bin/python test_entry_voucher_local.py   (from RCQ/backend)
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

# ── The till's question: what does entry cost here and where is it paid ──────
#
# ★ Same shape of proof as the voucher: the till signs the island's name into
# the question, and the island answers only when the name is its own.
print()

def mint_q(host="api.rcq.app", ttl=300, kind="entry_payout", v=V.VERSION, sign_host=None):
    exp = int(time.time()) + ttl
    body = V.entry_payout_signed_bytes(host=sign_host if sign_host is not None else host, exp=exp)
    doc = {"v": v, "kind": kind, "host": host, "exp": exp,
           "sig": base64.b64encode(key.sign(body)).decode()}
    return base64.b64encode(json.dumps(doc).encode()).decode()

def refused_q(request, host="api.rcq.app"):
    try:
        V.verify_entry_payout(request, expect_host=host); return None
    except V.VoucherError as e:
        return e.code

check("the till's payout question round-trips and returns the host it signed",
      V.verify_entry_payout(mint_q(), expect_host="api.rcq.app") == "api.rcq.app")
check("the host in the question is matched case-insensitively",
      V.verify_entry_payout(mint_q(host="API.RCQ.APP"), expect_host="api.rcq.app") == "API.RCQ.APP")
# ★ The one that matters: a till pointed at the wrong island gets nothing.
check("a question about another island is refused by name",
      refused_q(mint_q(host="cheap.example")) == "voucher_other_island")
check("editing the host after signing is a bad signature, not another island",
      refused_q(mint_q(host="cheap.example", sign_host="api.rcq.app"), host="cheap.example") == "bad_voucher")
check("a stale question is refused", refused_q(mint_q(ttl=-5)) == "voucher_expired")
check("a question good for a day is refused (short-lived by our clock, not the till's)",
      refused_q(mint_q(ttl=24 * 3600)) == "voucher_expired")
check("an entry VOUCHER is not accepted as the payout question", refused_q(mint()) == "bad_voucher")
check("a NUMBER payout question is not accepted as the entry one",
      refused_q(base64.b64encode(json.dumps({
          "v": V.VERSION, "kind": "payout", "uin": 4477, "exp": int(time.time()) + 300,
          "sig": base64.b64encode(key.sign(V.payout_signed_bytes(uin=4477, exp=int(time.time()) + 300))).decode(),
      }).encode()).decode()) == "bad_voucher")
_entry_q = mint_q()
_as_voucher = None
try:
    V.verify_entry(_entry_q, expect_host="api.rcq.app")
except V.VoucherError as e:
    _as_voucher = e.code
check("and the payout question can never be spent as an entry voucher", _as_voucher == "bad_voucher")
check("a question of a future version is refused", refused_q(mint_q(v=V.VERSION + 1)) == "bad_voucher")
check("an island with no configured host answers nobody", refused_q(mint_q(), host="") == "sales_disabled")
saved, V.public_key_b64 = V.public_key_b64, lambda: None
check("an island with no till key answers nobody", refused_q(mint_q()) == "sales_disabled")
V.public_key_b64 = saved
# A stranger's till (a key this island does not trust) learns nothing, and in
# particular does not learn WHICH host we are by being told "other island".
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _K
_stranger = _K.generate()
_exp = int(time.time()) + 300
_sdoc = {"v": V.VERSION, "kind": "entry_payout", "host": "cheap.example", "exp": _exp,
         "sig": base64.b64encode(_stranger.sign(V.entry_payout_signed_bytes(host="cheap.example", exp=_exp))).decode()}
check("a stranger's till is refused without being told which island this is",
      refused_q(base64.b64encode(json.dumps(_sdoc).encode()).decode()) == "bad_voucher")

# The same bytes from the Worker's own serialiser (uins.js `canonical`), so a
# space or a key order that differs between the two languages fails HERE and
# not after somebody has paid.
import shutil, subprocess, tempfile, os
if shutil.which("node"):
    from cryptography.hazmat.primitives import serialization
    pkcs8 = base64.b64encode(key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())).decode()
    tmp = tempfile.mkdtemp(prefix="rcq-entry-")
    script = os.path.join(tmp, "sign.mjs")
    with open(script, "w") as fh:
        fh.write(r"""
const priv = process.argv[2], nowS = Number(process.argv[3]);
const key = await crypto.subtle.importKey('pkcs8', Buffer.from(priv, 'base64'), { name: 'Ed25519' }, false, ['sign']);
function canonical(doc) {
  const keys = Object.keys(doc).sort();
  return new TextEncoder().encode('{' + keys.map((k) => JSON.stringify(k) + ':' + JSON.stringify(doc[k])).join(',') + '}');
}
async function sign(doc) {
  const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', key, canonical(doc)));
  return Buffer.from(JSON.stringify({ ...doc, sig: Buffer.from(sig).toString('base64') })).toString('base64');
}
process.stdout.write(JSON.stringify({
  q: await sign({ v: 1, kind: 'entry_payout', host: 'api.rcq.app', exp: nowS + 300 }),
  other: await sign({ v: 1, kind: 'entry_payout', host: 'cheap.example', exp: nowS + 300 }),
}));
""")
    r = subprocess.run(["node", script, pkcs8, str(int(time.time()))], capture_output=True, text=True)
    if r.returncode != 0:
        check("node could sign the payout question (" + r.stderr.strip()[:200] + ")", False)
    else:
        signed = json.loads(r.stdout)
        check("the Worker's canonical bytes verify on the island (payout question)",
              refused_q(signed["q"]) is None)
        check("...and the Worker's question about another island is refused by name",
              refused_q(signed["other"]) == "voucher_other_island")
    shutil.rmtree(tmp, ignore_errors=True)
else:
    print("skip node is not on PATH; the cross-language check did not run")

# The wiring: the endpoint exists, answers the till, and is not gated on the
# number shop.
entry = pathlib.Path('app/routers/entry.py').read_text()
main = pathlib.Path('app/main.py').read_text()
check("the island exposes POST /entry/payout-target", '"/payout-target"' in entry and 'prefix="/entry"' in entry)
check("it verifies the signed question against the island's own host",
      "verify_entry_payout(" in entry and "island_host" in entry)
check("price comes from the console setting, wallets from the same map numbers use",
      "entry_price_cents" in entry and "operator_addresses()" in entry)
check("zero price is not_for_sale and no wallet is no_payout",
      '"not_for_sale"' in entry and '"no_payout"' in entry)
check("entry sells with the number shop closed", "Depends(require_shop_open)" not in entry)
check("the router is mounted", "app.include_router(entry.router)" in main)
srv = pathlib.Path('app/routers/server.py').read_text()
check("/server/info publishes till_url and terms_url, empty by default",
      'till_url: str = ""' in srv and 'terms_url: str = ""' in srv)
check("till_url is https only", "_https_only(eff[\"uin_till_url\"])" in srv)

bad = [n for n, c in checks if not c]
print(f"\n{len(checks) - len(bad)}/{len(checks)} прошло")
sys.exit(1 if bad else 0)
