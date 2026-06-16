from datetime import datetime, timezone

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class ServerSetting(Base):
    """Operator-set runtime override for a single server setting.

    The island's baseline config still comes from `.env` (app/core/config.py),
    read once at startup. This table holds ONLY the keys an operator changed
    from the admin console — an absent row means "use the env/code default".
    The effective value (override ?? default) is resolved by
    `app.services.server_settings`, which is what `/server/info` and the feature
    routers consult, so a toggle takes effect without editing `.env` or
    restarting. Values are stored as strings and parsed per the typed registry
    in the service (bool -> "true"/"false", int -> "5", str -> raw).
    """

    __tablename__ = "server_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
