"""Server-side gate for operator-toggleable features.

A `require_feature("nearby_enabled")` dependency attached to a router makes
every route under it 404 when the operator has turned that feature off in the
admin console (Features tab). The 404 (rather than 403) makes a disabled feature
look simply absent — cleaner, and consistent with a masquerade/closed island
not advertising what it doesn't run. The flag is ALSO advertised via
/server/info so a cooperating client hides the tab; this dependency enforces it
regardless of client version.
"""
from fastapi import HTTPException, status

from app.services import server_settings


def require_feature(key: str):
    async def _gate() -> None:
        if not await server_settings.get_bool(key):
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                detail={"code": "feature_disabled", "feature": key},
            )
    return _gate
