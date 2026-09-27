"""Clear pending contact requests addressed to BACKUP copies (#1054).

Before the refusal in `routers/contacts.send_request` existed, a request to
somebody's backup mailbox was written and then never read by anyone: the owner
drains only the message queue there (federation §5a.3). Those rows sit at
"pending" in the requester's outgoing list forever. On 2026-09-27 that was 2
rows on is2 and 0 on the flagship.

A new client already shows such a row with the home address and a button to
add it (`home` on `GET /contacts/outgoing`), so the rows are worth keeping
until the clients that read `home` are out; after that this drops what is
left. Deleting is what the requester's own Cancel does: the row leaves their
outgoing list, and the addressee never saw it.

The copy test is `services/backup_copy.home_from_doc`, the same one the island
runs on every request, signature check included. Plain SQL cannot verify a
signature, which is why this is a script.

    python -m app.tools.backup_copy_requests --host is2.rcq.app                 # dry run
    python -m app.tools.backup_copy_requests --host is2.rcq.app --apply

`--host` is this island's name as the records spell it, repeatable (is2 has
two). The CDN fronts from FRONT_ALIAS_HOSTS are added on their own. Prints
counts only, never a number or a name.
"""

import argparse
import asyncio

from sqlalchemy import delete, select

from app.core.config import settings
from app.core.db import SessionLocal
from app.models.contact import ContactRequest
from app.models.federation import HomeIslandRecord
from app.models.user import User
from app.services import reissue_proof
from app.services.backup_copy import home_from_doc


async def run(hosts: list[str], apply: bool) -> int:
    own = {reissue_proof.canonical_host(h) for h in hosts if h.strip()}
    own |= {reissue_proof.canonical_host(h) for h in settings.FRONT_ALIAS_HOSTS.split(",") if h.strip()}
    async with SessionLocal() as db:
        rows = (
            await db.execute(
                select(ContactRequest.id, User, HomeIslandRecord.doc)
                .join(User, User.uin == ContactRequest.to_uin)
                .join(HomeIslandRecord, HomeIslandRecord.uin == ContactRequest.to_uin)
                .where(ContactRequest.state == "pending")
            )
        ).all()
        ids = [rid for rid, user, doc in rows if home_from_doc(doc, user, own) is not None]
        print(f"pending requests with a record: {len(rows)}; addressed to backup copies: {len(ids)}")
        if not ids or not apply:
            if ids:
                print("dry run: nothing deleted (pass --apply)")
            return len(ids)
        await db.execute(delete(ContactRequest).where(ContactRequest.id.in_(ids)))
        await db.commit()
        print(f"deleted {len(ids)}")
        return len(ids)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--host", action="append", required=True, help="this island's name, repeatable")
    p.add_argument("--apply", action="store_true", help="delete; without it, only count")
    args = p.parse_args()
    asyncio.run(run(args.host, args.apply))


if __name__ == "__main__":
    main()
