"""Publish a `.rcq` site from a directory on the island itself.

The ordinary path for a site is the API: a client signs a manifest with the
owner's key and PUTs the bundle. This tool is the operator's path, for the
island's own pages (a front page, a status page, the operator's notice board)
and for the first sites before the clients grow a publisher.

It does the same work the client would, in the same order, so a bundle
published here is indistinguishable from one published through the API:

    manifest = {v, name, version, key, files{path: sha256}, title?}
    sig      = Ed25519(canonical_json(manifest without sig))

⚠ The signing key is the SITE's, not the island's. Keep it off the island in
the long run: a key that lives next to the bytes it signs proves nothing about
who wrote them. It is here because the island's own pages are the island's to
sign, and the file is generated with 0600.

    python -m app.tools.publish_site --name blog --dir ./pages --uin 100001 \
        --key ~/.rcq-site-blog.key --title "Notes" --listed

Run it from the backend root in the server's venv (it needs DATABASE_URL and
the same RCQ_SITES_DIR the app uses).
"""

import argparse
import asyncio
import base64
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from app.core.db import SessionLocal
from app.models.site import Site
from app.routers.sites import MAX_BUNDLE_BYTES, MAX_FILE_BYTES, MAX_FILES, SITES_ROOT, _NAME_RE, _TYPES


def _canonical(obj: dict) -> bytes:
    """Byte-identical to the clients' `canonicalJSON` (spec §2.2)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _load_key(path: Path) -> Ed25519PrivateKey:
    if path.exists():
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(path.read_text().strip()))
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    path.write_text(base64.b64encode(raw).decode())
    os.chmod(path, 0o600)
    print(f"new signing key written to {path}")
    return key


def _collect(root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.name.startswith("."):
            continue
        rel = p.relative_to(root).as_posix()
        if p.suffix.lower() not in _TYPES:
            raise SystemExit(f"{rel}: type not allowed in a bundle ({sorted(_TYPES)})")
        body = p.read_bytes()
        if len(body) > MAX_FILE_BYTES:
            raise SystemExit(f"{rel}: over the {MAX_FILE_BYTES} byte file limit")
        files[rel] = body
    if "index.html" not in files:
        raise SystemExit("a bundle needs an index.html")
    if len(files) > MAX_FILES:
        raise SystemExit(f"more than {MAX_FILES} files")
    if sum(len(b) for b in files.values()) > MAX_BUNDLE_BYTES:
        raise SystemExit(f"over the {MAX_BUNDLE_BYTES} byte bundle limit")
    return files


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--uin", type=int, required=True)
    ap.add_argument("--key", required=True, help="Ed25519 private key file (created if missing)")
    ap.add_argument("--title", default=None)
    ap.add_argument("--listed", action="store_true")
    args = ap.parse_args()

    name = args.name.strip().lower()
    if not _NAME_RE.match(name):
        raise SystemExit("name must be [a-z0-9-], up to 32 characters")

    files = _collect(Path(args.dir).resolve())
    key = _load_key(Path(args.key).expanduser())
    pub = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()

    async with SessionLocal() as db:
        existing = await db.get(Site, name)
        # ⚠ The key may not change under a name that readers have pinned. The
        # API refuses this too; the operator's path must not be the loophole.
        if existing is not None and existing.owner_key != pub:
            raise SystemExit(f"{name} is pinned to another key ({existing.owner_key[:12]}…)")
        version = (existing.version + 1) if existing else 1

        manifest: dict = {
            "v": 1,
            "name": name,
            "version": version,
            "key": pub,
            "files": {rel: hashlib.sha256(body).hexdigest() for rel, body in files.items()},
        }
        if args.title:
            manifest["title"] = args.title
        manifest["sig"] = base64.b64encode(key.sign(_canonical(manifest))).decode()

        # Written beside the live bundle and swapped, so a reader never sees
        # half a version.
        staging = SITES_ROOT / f".staging-{name}"
        shutil.rmtree(staging, ignore_errors=True)
        for rel, body in files.items():
            dest = staging / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(body)
        live = SITES_ROOT / name
        previous = SITES_ROOT / f".previous-{name}"
        shutil.rmtree(previous, ignore_errors=True)
        if live.exists():
            live.rename(previous)
        staging.rename(live)
        shutil.rmtree(previous, ignore_errors=True)

        now = datetime.now(timezone.utc)
        blob = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        total = sum(len(b) for b in files.values())
        if existing is None:
            db.add(Site(
                name=name, owner_uin=args.uin, owner_key=pub, version=version,
                manifest=blob, size_bytes=total, title=args.title,
                listed=bool(args.listed), created_at=now, updated_at=now,
            ))
        else:
            existing.version = version
            existing.manifest = blob
            existing.size_bytes = total
            existing.title = args.title
            existing.listed = bool(args.listed)
            existing.updated_at = now
        await db.commit()

    print(f"{name}.rcq v{version}: {len(files)} files, {total} bytes, key {pub[:12]}…")


if __name__ == "__main__":
    asyncio.run(main())
