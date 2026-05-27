"""Demo / fake users so the contact list and search don't look empty during
development. Seeded once at startup if no fakes exist; idempotent thereafter.

Each fake gets:
  * A unique random UIN in the same range as real users.
  * Random base64 bytes for `identity_key` and `signing_key`, so the column
    NOT NULL constraints are satisfied. They aren't real X25519 / Ed25519
    keys — fakes don't decrypt anything because they don't have clients.
  * A varied status (`online`/`away`/`dnd`/`invisible`/`offline`) and an
    optional status message — distribution is biased toward "online" so the
    list looks lively.
  * A handful of profile fields (city, age, about) so the directory feels
    populated when the user opens search.

Real users see fakes alongside real users in `/users/search`. They can add
fakes as contacts; messages will queue server-side forever (no client to
deliver to). That's acceptable for demo. The user can `clearAll` chat history
or burn the account to reset.
"""
from __future__ import annotations

import base64
import secrets

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import SessionLocal
from app.models.user import User
from app.services.uin import allocate_uin


# A 30-row catalogue of nostalgia-soaked nicknames, light on the cliché. Mix of
# Cyrillic / Latin / 90s-2000s / modern. Tweak freely as the user discovers
# tone they want.
SEEDS: list[dict] = [
    {"nickname": "neon",        "city": "Saint Petersburg", "country": "RU", "age": 24, "status": "online",    "status_message": "Coding…",                       "about": "Junior at a startup, ICQ-curious."},
    {"nickname": "Ольга",       "city": "Moscow",           "country": "RU", "age": 27, "status": "online",    "status_message": "На связи",                      "about": "Маркетинг."},
    {"nickname": "DemoN_666",   "city": "Kyiv",             "country": "UA", "age": 31, "status": "away",      "status_message": "AFK",                           "about": "1999 forever."},
    {"nickname": "Маша99",      "city": "Minsk",            "country": "BY", "age": 25, "status": "online",    "status_message": "Listening to Linkin Park",     "about": ""},
    {"nickname": "trinity",     "city": "Berlin",           "country": "DE", "age": 29, "status": "dnd",       "status_message": "Deep work",                     "about": "Backend SRE."},
    {"nickname": "Дима_СПб",    "city": "Saint Petersburg", "country": "RU", "age": 22, "status": "online",    "status_message": "🍷 Friday night",               "about": ""},
    {"nickname": "ph03nIX",     "city": "Almaty",           "country": "KZ", "age": 33, "status": "online",    "status_message": "",                              "about": "Reborn from the ashes since 2003."},
    {"nickname": "alice.k",     "city": "London",           "country": "UK", "age": 26, "status": "away",      "status_message": "Walking the dog",               "about": "Designer, occasional poet."},
    {"nickname": "x_Killer_x",  "city": "Tashkent",         "country": "UZ", "age": 19, "status": "online",    "status_message": "Spam me, dare you",            "about": "School lunch chronicles."},
    {"nickname": "Натали",      "city": "Riga",             "country": "LV", "age": 30, "status": "invisible", "status_message": None,                            "about": "Quiet."},
    {"nickname": "Серёга",      "city": "Yekaterinburg",    "country": "RU", "age": 38, "status": "offline",   "status_message": "В отпуске",                    "about": "Старый ICQ-завсегдатай."},
    {"nickname": "matrix_keanu","city": "Los Angeles",      "country": "US", "age": 35, "status": "online",    "status_message": "Whoa.",                          "about": "There is no spoon."},
    {"nickname": "AzurE",       "city": "Tbilisi",          "country": "GE", "age": 28, "status": "online",    "status_message": "Coffee→code→repeat",            "about": "Indie gamedev."},
    {"nickname": "tager_beta",  "city": "Yerevan",          "country": "AM", "age": 23, "status": "online",    "status_message": "Тестирую RCQ",                 "about": "Beta tester #1."},
    {"nickname": "blink182",    "city": "New York",         "country": "US", "age": 32, "status": "away",      "status_message": "Out for lunch",                 "about": ""},
    {"nickname": "ReaPer",      "city": "Vilnius",          "country": "LT", "age": 21, "status": "online",    "status_message": "",                              "about": ""},
    {"nickname": "olya.dev",    "city": "Tallinn",          "country": "EE", "age": 26, "status": "dnd",       "status_message": "Pair programming",              "about": "Frontend, books, cats."},
    {"nickname": "Костя",       "city": "Sochi",            "country": "RU", "age": 41, "status": "online",    "status_message": "Море. Солнце. Ленивый.",      "about": ""},
    {"nickname": "DeadMau5",    "city": "Toronto",          "country": "CA", "age": 36, "status": "online",    "status_message": "Studio session",                "about": "Vibe."},
    {"nickname": "Вадим",       "city": "Kazan",            "country": "RU", "age": 29, "status": "offline",   "status_message": None,                            "about": "Иду спать."},
    {"nickname": "lana",        "city": "Bangkok",          "country": "TH", "age": 24, "status": "online",    "status_message": "🌴",                            "about": "Digital nomad."},
    {"nickname": "Ильнар",      "city": "Ufa",              "country": "RU", "age": 26, "status": "away",      "status_message": "Перерыв",                       "about": ""},
    {"nickname": "Cyber_Punk",  "city": "Tokyo",            "country": "JP", "age": 30, "status": "online",    "status_message": "Wake the f*** up",              "about": "2077 vibes."},
    {"nickname": "Анна_М",      "city": "Krasnodar",        "country": "RU", "age": 22, "status": "online",    "status_message": "Читаю",                         "about": "Студентка философии."},
    {"nickname": "SilenT",      "city": "Helsinki",         "country": "FI", "age": 34, "status": "invisible", "status_message": None,                            "about": "Less talk, more code."},
    {"nickname": "Эльдар",      "city": "Baku",             "country": "AZ", "age": 31, "status": "online",    "status_message": "На созвоне",                   "about": ""},
    {"nickname": "Sprite00",    "city": "Warsaw",           "country": "PL", "age": 20, "status": "online",    "status_message": "School's out",                  "about": "Linux fan, retro gaming."},
    {"nickname": "Юля_К",       "city": "Novosibirsk",      "country": "RU", "age": 28, "status": "dnd",       "status_message": "Не беспокоить",                "about": "Doctor."},
    {"nickname": "Mara",        "city": "Lisbon",           "country": "PT", "age": 27, "status": "online",    "status_message": "Surfing",                       "about": ""},
    {"nickname": "NotAFK",      "city": "Reykjavík",        "country": "IS", "age": 25, "status": "away",      "status_message": "Iceland walk",                  "about": "Stargazer."},
]


def _rand_b64(n: int) -> str:
    return base64.b64encode(secrets.token_bytes(n)).decode()


async def seed_fake_users() -> None:
    """Insert demo users if none exist yet. Idempotent — skips when fakes are
    already in the table. Called from the FastAPI lifespan after `init_db`."""
    async with SessionLocal() as db:  # type: AsyncSession
        existing = await db.scalar(
            select(func.count()).select_from(User).where(User.is_fake == True)  # noqa: E712
        )
        if (existing or 0) > 0:
            return

        for seed in SEEDS:
            uin = await allocate_uin(db)
            user = User(
                uin=uin,
                nickname=seed["nickname"],
                # Random base64 — fakes don't have real clients to decrypt
                # anything, so the column NOT NULL constraint is all that
                # matters. Real users send actual X25519 / Ed25519 pubkeys.
                identity_key=_rand_b64(32),
                signing_key=_rand_b64(32),
                city=seed.get("city"),
                country=seed.get("country"),
                age=seed.get("age"),
                about=seed.get("about") or None,
                status=seed["status"],
                status_message=seed.get("status_message"),
                is_fake=True,
            )
            db.add(user)
        await db.commit()
