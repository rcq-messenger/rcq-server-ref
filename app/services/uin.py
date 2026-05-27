import secrets

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.user import User


async def allocate_uin(db: AsyncSession) -> int:
    """Allocate a free UIN in the legacy ICQ range. ICQ used 6–9 digit numbers — we
    follow the same shape so the feel is right.
    """
    for _ in range(100):
        candidate = secrets.randbelow(settings.UIN_MAX - settings.UIN_MIN) + settings.UIN_MIN
        registered = await db.scalar(select(User.uin).where(User.uin == candidate))
        if registered is not None:
            continue
        return candidate
    raise RuntimeError("UIN allocation exhausted")
