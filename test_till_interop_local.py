"""Local-only proof that the till and the island agree BYTE FOR BYTE.

⚠⚠ This is the failure that only shows up in production. The voucher is a
signature over a canonical JSON document, and the two halves that build that
document are written in different languages by different hands: Python's
`json.dumps(sort_keys=True, separators=(",", ":"))` on the island, a hand-rolled
sorted-key serialiser in the Cloudflare Worker. One space, one different key
order, one number formatted differently, and every signature the till produces
is refused by the island - after the money has already moved.

So this test does not check the Python against itself. It runs NODE with the
Worker's own canonicalisation, signs both documents the till can send (a
voucher and a hold request), and verifies them with the island's verifier.

Needs `node` on PATH. NOT deployed, and it touches no database.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_till_interop_local.py
"""
import base64
import json
import os
import shutil
import subprocess
import tempfile
import time

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


# The Worker's canonicalisation, copied from deploy/console-worker/uins.js. If
# that file changes shape, this string is what has to change with it.
NODE_SIGN = r"""
import fs from 'fs';
const priv = process.argv[2], out = process.argv[3];
const key = await crypto.subtle.importKey(
  'pkcs8', Buffer.from(priv, 'base64'), { name: 'Ed25519' }, false, ['sign']);
function canonical(doc) {
  const keys = Object.keys(doc).sort();
  return new TextEncoder().encode(
    '{' + keys.map((k) => JSON.stringify(k) + ':' + JSON.stringify(doc[k])).join(',') + '}');
}
async function sign(doc) {
  const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', key, canonical(doc)));
  return Buffer.from(JSON.stringify({ ...doc, sig: Buffer.from(sig).toString('base64') }))
    .toString('base64');
}
const nowS = Number(process.argv[4]);
fs.writeFileSync(out, JSON.stringify({
  voucher: await sign({ v: 1, uin: 4477, nonce: 'a1b2c3d4e5f60718293a', exp: nowS + 3600 }),
  big: await sign({ v: 1, uin: 987654321, nonce: 'z'.repeat(64), exp: nowS + 3600 }),
  hold: await sign({ v: 1, kind: 'hold', uin: 4477, hold_id: 'inv_0f1e2d3c4b5a6978', exp: nowS + 300 }),
  release: await sign({ v: 1, kind: 'release', uin: 4477, hold_id: 'inv_0f1e2d3c4b5a6978', exp: nowS + 300 }),
}));
"""


def main() -> int:
    if shutil.which("node") is None:
        print("node is not on PATH - this test cannot run")
        return 1

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    k = Ed25519PrivateKey.generate()
    pkcs8 = base64.b64encode(k.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())).decode()
    os.environ["RCQ_UIN_VOUCHER_PUBKEY"] = base64.b64encode(k.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    from app.services import uin_voucher

    tmp = tempfile.mkdtemp(prefix="rcq-till-")
    script, out = f"{tmp}/sign.mjs", f"{tmp}/out.json"
    with open(script, "w") as fh:
        fh.write(NODE_SIGN)
    r = subprocess.run(["node", script, pkcs8, out, str(int(time.time()))],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  FAIL  node could not sign: {r.stderr.strip()[:400]}")
        return 1
    signed = json.loads(open(out).read())

    print("\nWhat the till signs, the island accepts:")
    try:
        nonce = uin_voucher.verify(signed["voucher"], expect_uin=4477)
        check(f"a voucher crosses the language boundary ({nonce})", nonce == "a1b2c3d4e5f60718293a")
    except uin_voucher.VoucherError as e:
        check(f"a voucher crosses the language boundary ({e.code})", False)
    try:
        uin_voucher.verify(signed["big"], expect_uin=987654321)
        check("  ... and so does the longest number and nonce we allow", True)
    except uin_voucher.VoucherError as e:
        check(f"  ... and so does the longest number and nonce we allow ({e.code})", False)
    try:
        got = uin_voucher.verify_hold(signed["hold"])
        check(f"a hold request does too {got}",
              got == ("hold", 4477, "inv_0f1e2d3c4b5a6978", got[3]))
    except uin_voucher.VoucherError as e:
        check(f"a hold request does too ({e.code})", False)
    try:
        got = uin_voucher.verify_hold(signed["release"])
        check("  and so does a release", got[0] == "release")
    except uin_voucher.VoucherError as e:
        check(f"  and so does a release ({e.code})", False)

    print("\nAnd the documents stay strangers to each other:")
    try:
        uin_voucher.verify(signed["hold"], expect_uin=4477)
        check("⚠ a HOLD request is not accepted as a voucher", False)
    except uin_voucher.VoucherError:
        check("⚠ a HOLD request is not accepted as a voucher", True)
    try:
        uin_voucher.verify_hold(signed["voucher"])
        check("⚠ a VOUCHER is not accepted as a hold request", False)
    except uin_voucher.VoucherError:
        check("⚠ a VOUCHER is not accepted as a hold request", True)

    shutil.rmtree(tmp, ignore_errors=True)
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
