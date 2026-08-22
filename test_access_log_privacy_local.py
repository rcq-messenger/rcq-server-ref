"""Local-only verification of the uvicorn access-log filter.

The one piece of privacy machinery in this codebase with no test, and the one
that has already taken production down. Worth writing out why both failures
were invisible to a smoke test:

  22.08, four minutes of prod   The first attempt rewrote the formatted message
                                and set `record.args = ()`. uvicorn's access
                                formatter unpacks those args itself, so an
                                empty tuple raised inside the formatter and
                                Python's logging answered every single request
                                with a traceback plus an `Arguments:` line
                                holding the untouched originals. The filter
                                "worked" on any logger that was not uvicorn's.
  22.08, still live afterwards  The fix only looked at `str` args. uvicorn's
                                HTTP line passes the client address as a
                                formatted string and its WEBSOCKET lines pass
                                `scope["client"]`, the raw `(host, port)`
                                TUPLE. So `/ws/<id>` came out with its path
                                masked and the full address beside it, ~1760
                                lines and 182 distinct addresses per half hour
                                on the flagship, and every HTTP line next to it
                                looked correct.

So the test drives real `logging.LogRecord`s through the real filter and then
through uvicorn's OWN `AccessFormatter`, because "does the filter return a
scrubbed string" is not the question. The question is what lands in journald.

No database and no Redis. Run: cd backend && PYTHONPATH=. .venv/bin/python test_access_log_privacy_local.py
"""
import logging
import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_access_log.db")
os.environ.setdefault("ENV", "dev")
os.environ.setdefault("JWT_SECRET", "access-log-test-secret")

from uvicorn.logging import AccessFormatter  # noqa: E402

from app.main import _RedactSecretsInLogs  # noqa: E402

FILTER = _RedactSecretsInLogs()
PASS = FAIL = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok   {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label}{(': ' + detail) if detail else ''}")


def render(name: str, msg: str, args: tuple) -> str:
    """One record through the filter, then through the formatter that would
    have written it. `AccessFormatter` is uvicorn's, so a record shape the
    filter mangles blows up here exactly as it did in production."""
    record = logging.LogRecord(name, logging.INFO, __file__, 1, msg, args, None)
    FILTER.filter(record)
    if name == "uvicorn.access":
        return AccessFormatter(fmt="%(message)s", use_colors=False).format(record)
    return record.getMessage()


print("\nHTTP access line (args are strings)")
out = render(
    "uvicorn.access",
    '%s - "%s %s HTTP/%s" %d',
    ("77.110.109.154:52344", "GET", "/users/695744503/info", "1.1", 200),
)
check("the client address is masked to /24", "77.110.109.0" in out, out)
check("the raw address is gone", "77.110.109.154" not in out, out)
check("the account number leaves the path", "695744503" not in out, out)
check("the endpoint is still readable", "/users/<id>/info" in out, out)
check("the formatter did not raise (args kept their arity)", "GET" in out, out)

print("\nWebSocket line (the client is a (host, port) TUPLE)")
out = render(
    "uvicorn.error",
    '%s - "WebSocket %s" [accepted]',
    (("77.110.109.154", 0), "/ws/695744503?token=eyJhbGciOiJIUzI1NiJ9.abc"),
)
check("⚠⚠ the address inside the tuple is masked too", "77.110.109.154" not in out, out)
check("...to the same /24 the HTTP line uses", "77.110.109.0" in out, out)
check("the tuple is still a tuple, so the line reads the same",
      out.startswith("('77.110.109.0', 0) - "), out)
check("the token is redacted", "eyJhbGciOiJIUzI1NiJ9" not in out and "token=<redacted>" in out, out)
check("the account number leaves the path", "695744503" not in out, out)
check("it is still recognisably a websocket accept", "[accepted]" in out, out)

print("\nWebSocket 403 and close lines take the same path")
for template, tail in (('%s - "WebSocket %s" 403', "403"), ('%s - "WebSocket %s" %d', "1000")):
    args: tuple = (("185.102.11.202", 0), "/ws/68650924?token=abc")
    if tail == "1000":
        args = args + (1000,)
    out = render("uvicorn.error", template, args)
    check(f"the {tail} line masks the address too", "185.102.11.202" not in out, out)

print("\nIPv6 and short segments")
out = render("uvicorn.access", '%s - "%s %s HTTP/%s" %d',
             ("10.0.0.7:1", "GET", "/keys/12/bundle", "1.1", 200))
check("a 2-digit path segment is NOT an account and survives", "/keys/12/bundle" in out, out)
out = render("uvicorn.access", '%s - "%s %s HTTP/%s" %d',
             ("10.0.0.7:1", "GET", "/v1/health", "1.1", 200))
check("an API version segment survives", "/v1/health" in out, out)

print("\nNon-uvicorn records are left structurally alone")
record = logging.LogRecord("rcq.messages", logging.WARNING, __file__, 1,
                           "[sealed] to=%s type=%s", ("-", "message"), None)
FILTER.filter(record)
check("an application record keeps its args", record.args == ("-", "message"), str(record.args))
check("...and formats", record.getMessage() == "[sealed] to=- type=message", record.getMessage())
out = render("rcq.federation", "peer replied ?token=%s", ("abc123",))
check("a secret in an application message is still redacted",
      "abc123" not in out and "token=<redacted>" in out, out)
check("an application path is NOT id-masked (that is the access log's job)",
      "/ws/12345" in render("rcq.x", "dialing /ws/12345", ()), "")

print("\nThe shape that broke prod")
record = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1,
                           '%s - "%s %s HTTP/%s" %d',
                           ("1.2.3.4:5", "GET", "/messages/queue", "1.1", 200), None)
FILTER.filter(record)
check("⚠⚠ the filter never blanks a uvicorn record's args",
      isinstance(record.args, tuple) and len(record.args) == 5, str(record.args))
try:
    AccessFormatter(fmt="%(message)s", use_colors=False).format(record)
    formatted_ok = True
except Exception as exc:  # noqa: BLE001
    formatted_ok = False
    print(f"       {type(exc).__name__}: {exc}")
check("...so uvicorn's own formatter still unpacks them", formatted_ok)

print(f"\n{PASS}/{PASS + FAIL} pass")
raise SystemExit(1 if FAIL else 0)
