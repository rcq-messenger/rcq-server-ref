"""Self-host invite-minting CLI.

For operators running rcq-server-ref with ``REGISTRATION_POLICY=invite`` who
don't go through the web-admin / console.rcq.app. Run from the backend root
(same venv/env the server uses, so it sees DATABASE_URL):

    python -m app.tools.mint_invite --host chat.example.com --uses 5 --ttl 7d --label "Acme HR"

Prints the invite code and the ``rcq://server/<host>?invite=<code>`` URL to drop
into a QR. ``--ttl`` accepts ``7d`` / ``12h`` / ``30m`` (or a bare number = hours);
omit it for a never-expiring invite. List/revoke via the /admin/invites API or
straight SQL on the ``invites`` table (whose ``code`` column holds the sha256
of the token, not the token; see app/models/invite.py).
"""

import argparse
import asyncio
import secrets
from datetime import datetime, timedelta, timezone

from app.core.db import SessionLocal
from app.models.invite import Invite, hash_invite_code

_UNITS = {"d": 86_400, "h": 3_600, "m": 60, "s": 1}


def _parse_ttl_seconds(s: str | None) -> int | None:
    if not s:
        return None
    s = s.strip().lower()
    if s and s[-1] in _UNITS:
        return int(float(s[:-1]) * _UNITS[s[-1]])
    return int(float(s) * 3_600)  # bare number = hours


async def _mint(args: argparse.Namespace) -> None:
    secs = _parse_ttl_seconds(args.ttl)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(seconds=secs) if secs else None
    )
    code = secrets.token_urlsafe(16)
    async with SessionLocal() as db:
        db.add(
            Invite(
                # The island stores the hash; this print is the only place the
                # token itself ever exists outside the operator's clipboard.
                code=hash_invite_code(code),
                label=args.label,
                max_uses=args.uses,
                expires_at=expires_at,
            )
        )
        await db.commit()

    print("⚠ copy the code now: the island stores only its hash and")
    print("  cannot show it again. Losing it means minting a new invite.")
    print(f"invite code: {code}")
    print(f"max uses:    {args.uses}")
    print(f"expires:     {expires_at.isoformat() if expires_at else 'never'}")
    if args.host:
        print(f"join url:    rcq://server/{args.host}?invite={code}")
        print(f"             https://{args.host}/join?invite={code}")
    else:
        print("(pass --host <your-domain> for the rcq://server/... join URL)")


def main() -> None:
    p = argparse.ArgumentParser(description="Mint a server-join invite token.")
    p.add_argument("--host", default="", help="this server's public host (for the join URL)")
    p.add_argument("--uses", type=int, default=1, help="max registrations (default 1)")
    p.add_argument("--ttl", default=None, help="time to live, e.g. 7d / 12h / 30m (default: never)")
    p.add_argument("--label", default=None, help="optional note shown in the admin list")
    asyncio.run(_mint(p.parse_args()))


if __name__ == "__main__":
    main()
