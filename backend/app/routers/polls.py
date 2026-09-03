"""Group polls, removed on 2026-08-23 (founder decision, item 14a).

WHY THEY WENT. A poll was only half end-to-end encrypted. The question and the
option labels rode the encrypted `.poll` chat envelope and this server never
saw them, but `poll_votes` held (poll_id, voter_uin, option_index, created_at)
in the clear for EVERY poll, the ones marked anonymous included: anonymity was
a filter in the response builder, never a property of the stored row, and the
model admitted as much in its own docstring right up to the release that
deleted it. Worse, `polls.creator_uin` sat next to `polls.message_id`, the UUID
of the encrypted group envelope that announced the poll, so for that one
message the island learned the author by name. That is sealed sender defeated
by a side table.
`docs/core-metadata-plan.md` had already reached the same verdict: cut it.

WHY THIS FILE STILL EXISTS. Every client in the field still has the poll
composer, and none of them gate it on anything: `polls` was never a key in
`GET /server/info`. It is one now, pinned False (see routers/server.py), but no
shipped build reads it, so this release is the first thing a poll composer ever
hears about the removal, and it hears it by calling. Deleting the routes would
make that a routing 404, which is indistinguishable from "no such poll id" and
from a typo in the path. People Nearby was cut that way in August and the
result was worse than a dead button. So the paths answer, deliberately, with
410 Gone and a machine-readable code.

WHAT A SHIPPED CLIENT DOES WITH THE ANSWER, which is why 410 is enough. On iOS,
`PollService.refresh` and `.lookupByMessage` swallow the error and return nil,
so the bubble draws its question, every option and a zero next to each, with no
progress bars and no "you voted" marks. That reads as a poll whose results are
no longer being counted, which is exactly what it is: no blank bubble, no
spinner that never resolves. `vote` and `close` throw and surface the existing
`poll.error.vote` string, and creating one fails at the Create button rather
than half-succeeding and leaving a poll envelope nobody can tally.

⚠ Android 0.146 is worse and nothing here can improve it. `ChatScreen` closes
the composer BEFORE it sends and wraps the call in a bare `runCatching` with no
failure branch, so the 410 is swallowed whole: the dialog dismisses, no bubble
appears, no toast, no error row, and the likeliest next move is to file the same
poll again. The good half still holds (the envelope fan-out is never reached, so
there is no orphan bubble). This is the case the `polls` capability in
routers/server.py exists for, and it only starts helping one Android release
from now, which is the argument for shipping that key today rather than with
whatever removes this file.

WHEN TO DELETE THIS FILE. The metrics middleware records the route TEMPLATE, so
`/polls/{rest:path}` and `/groups/{group_id}/polls` each get their own row in the
admin request table. Once both have sat at zero for a release or two, the field
has updated, and this tombstone and the two orphaned tables (see the block in
`core/db.py`) can go in the same change.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

router = APIRouter(prefix="/polls", tags=["polls"])
group_polls_router = APIRouter(prefix="/groups", tags=["polls"])

# Same shape as `core/feature_gate`'s disabled-feature body, so a client that
# already knows how to read one knows how to read this. `feature_removed` is a
# distinct code from `feature_disabled` on purpose: disabled is an operator
# toggle that can come back, removed never does.
_GONE_DETAIL = {"code": "feature_removed", "feature": "polls"}

_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]

# Kept out of the OpenAPI schema: /docs is the loudest "this is RCQ"
# fingerprint an island has, and a tombstone is not an API anyone should build
# against. Old clients hard-code the paths, they do not discover them.
_HIDDEN = {"include_in_schema": False}


def _gone() -> None:
    # 410 rather than 404 because Gone is the one status that says "this path
    # was real and is not coming back": a client can stop retrying, and nothing
    # confuses it with the 404 the old router itself returned for an unknown
    # poll id.
    raise HTTPException(status.HTTP_410_GONE, detail=_GONE_DETAIL)


@router.api_route("/{rest:path}", methods=_METHODS, **_HIDDEN)
async def polls_gone(rest: str) -> None:
    """Everything the removed router served under /polls: `/{poll_id}`,
    `/{poll_id}/vote`, `/{poll_id}/close`, `/by_message/{message_id}`. One
    catch-all rather than four stubs so a path that was missed here cannot
    still fall through to a bare 404.

    Unauthenticated on purpose. The old endpoints required a session token, but
    answering 401 first would tell a client with an expired token to go and
    refresh it for a feature that no longer exists.
    """
    _gone()


@group_polls_router.post("/{group_id}/polls", **_HIDDEN)
async def create_poll_gone(group_id: int) -> None:
    """Poll creation. Its own route rather than another catch-all so composer
    traffic shows up separately from bubble refreshes in the request metrics,
    which is the signal for when this file can go."""
    _gone()
