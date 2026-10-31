"""Local-only verification of the media store's download ranges and upload
ceilings (report 1080, spec §9.1 to §9.3).

An interrupted download used to cost the whole file again: `GET /media/{id}`
answered every `Range` with a 200 and the blob from byte 0. And an oversize
upload was refused only after the island had received all of it, because
FastAPI spools a form body before the endpoint or any dependency runs.

Pins:
  * a plain GET is the blob verbatim with `Accept-Ranges: bytes`, a strong
    ETag, Last-Modified and the old Content-Disposition;
  * `bytes=S-`, `bytes=S-E` and `bytes=-N` answer 206 with the right bytes,
    Content-Range and Content-Length; a range past the end is clamped;
  * a range starting at or past the end is 416 `bytes */T`;
  * malformed ranges, a list of ranges, another unit and a last byte before
    the first are ignored: 200 and the whole blob;
  * `If-Range` with the current ETag honours the range; any other tag, and a
    date, get the whole blob;
  * the ETag is stable for one blob and differs between two blobs of the
    same size; a download resumed from any offset reassembles the blob;
  * an upload declaring a Content-Length over the ceiling is 413 before a
    single body byte is read, WITHOUT `Connection: close`: over a real socket
    a writer still sending the body reads the 413 and is not reset (closing
    there made a proxy built on Go's net/http answer 502 instead);
  * a chunked upload with no Content-Length is cut at the ceiling, not read
    to its end, with `Connection: close`, and leaves nothing in the store;
  * a blob of exactly the cap still goes in; one byte over is 413 and leaves
    neither a blob nor a temp file;
  * PUT is first write wins, also when the second deposit loses a race it
    has already passed the existence check for (the `os.link` branch), and
    an upload still works on a mount without hard links, where a copy that
    landed while a deposit streamed still stands.

Runs the real FastAPI stack in-process with Redis db 15 and a store under
./media/test_media_range. No database. NOT deployed.
Run: PYTHONPATH=. .venv/bin/python test_media_range_local.py
"""
import asyncio
import errno
import hashlib
import io
import os
from pathlib import Path

STORE = Path("./media/test_media_range")
os.environ["RCQ_MEDIA_DIR"] = str(STORE)
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_media_range.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
STORE.mkdir(parents=True, exist_ok=True)
for leftover in list(STORE.iterdir()):
    leftover.unlink()

import httpx  # noqa: E402
import uvicorn  # noqa: E402
from fastapi import FastAPI, UploadFile  # noqa: E402

import app.routers.media as media_mod  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.main import app  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def stored() -> list[str]:
    return sorted(p.name for p in STORE.iterdir())


async def clear_limits():
    redis = await get_redis()
    keys = [k async for k in redis.scan_iter(match="rl:*")]
    if keys:
        await redis.delete(*keys)


async def raw_call(asgi_app, method: str, path: str, headers: list[tuple[bytes, bytes]], receive):
    """One request straight through ASGI, so the test sees exactly which body
    messages the app asked for."""
    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": path, "raw_path": path.encode(),
        "root_path": "", "query_string": b"", "headers": headers,
        "client": ("10.9.8.7", 50000), "server": ("t", 80),
    }
    await asgi_app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    return start["status"], {k.decode().lower(): v.decode() for k, v in start["headers"]}


async def main() -> int:
    await (await get_redis()).flushdb()
    T = 3 * 1024 * 1024 + 4321
    data = os.urandom(T)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("10.9.8.7", 50000)),
                                 base_url="http://t") as c:

        async def upload(blob: bytes):
            await clear_limits()
            return await c.post("/media/upload", files={"blob": ("blob.bin", blob, "application/octet-stream")})

        async def get(mid, **headers):
            return await c.get(f"/media/{mid}", headers=headers)

        r = await upload(data)
        check(f"upload 201 ({r.status_code})", r.status_code == 201 and r.json().get("size") == T)
        mid = r.json()["media_id"]

        print("\nA plain GET:")
        r = await get(mid)
        etag = r.headers.get("etag", "")
        check("200 and the blob verbatim", r.status_code == 200 and r.content == data)
        check("Content-Length is the size", r.headers.get("content-length") == str(T))
        check("Accept-Ranges: bytes", r.headers.get("accept-ranges") == "bytes")
        check(f"a strong, quoted ETag ({etag})", etag.startswith('"') and etag.endswith('"') and len(etag) > 10)
        check("Last-Modified is there", bool(r.headers.get("last-modified")))
        check("the old Content-Disposition", r.headers.get("content-disposition") == f'attachment; filename="{mid}.bin"')
        check("octet-stream", r.headers.get("content-type") == "application/octet-stream")
        r2 = await get(mid)
        check("the ETag is stable", r2.headers.get("etag") == etag)

        print("\nRanges:")
        r = await get(mid, Range="bytes=1000-")
        check("bytes=S- is 206 from S to the end", r.status_code == 206 and r.content == data[1000:])
        check("with Content-Range", r.headers.get("content-range") == f"bytes 1000-{T - 1}/{T}")
        check("and Content-Length", r.headers.get("content-length") == str(T - 1000))
        check("and the same ETag and Accept-Ranges",
              r.headers.get("etag") == etag and r.headers.get("accept-ranges") == "bytes")
        r = await get(mid, Range="bytes=100-199")
        check("bytes=S-E is exactly those bytes", r.status_code == 206 and r.content == data[100:200])
        check("Content-Range 100-199", r.headers.get("content-range") == f"bytes 100-199/{T}")
        r = await get(mid, Range="bytes=-500")
        check("bytes=-N is the last N", r.status_code == 206 and r.content == data[-500:])
        check("Content-Range for a suffix", r.headers.get("content-range") == f"bytes {T - 500}-{T - 1}/{T}")
        r = await get(mid, Range=f"bytes=-{T * 2}")
        check("a suffix longer than the blob is the whole blob", r.status_code == 206 and r.content == data)
        r = await get(mid, Range=f"bytes=0-{T * 2}")
        check("a last byte past the end is clamped",
              r.status_code == 206 and r.content == data and r.headers.get("content-range") == f"bytes 0-{T - 1}/{T}")
        r = await get(mid, Range=f"bytes={T - 1}-")
        check("the very last byte", r.status_code == 206 and r.content == data[-1:])
        r = await get(mid, Range=f"bytes={64 * 1024 - 3}-{3 * 64 * 1024 + 5}")
        check("a range across several read chunks",
              r.status_code == 206 and r.content == data[64 * 1024 - 3:3 * 64 * 1024 + 6])
        r = await get(mid, Range="BYTES=10-19")
        check("the unit is case-insensitive", r.status_code == 206 and r.content == data[10:20])

        print("\nUnsatisfiable:")
        r = await get(mid, Range=f"bytes={T}-")
        check(f"a range starting at the end is 416 ({r.status_code})", r.status_code == 416)
        check("with Content-Range */T", r.headers.get("content-range") == f"bytes */{T}")
        check("and still the ETag", r.headers.get("etag") == etag and r.headers.get("accept-ranges") == "bytes")
        r = await get(mid, Range=f"bytes={T + 10}-{T + 20}")
        check("past the end entirely is 416", r.status_code == 416)
        r = await get(mid, Range="bytes=-0")
        check("an empty suffix is 416", r.status_code == 416)

        print("\nIgnored, the whole blob:")
        for bad in ("bytes=abc", "bytes=0-1,5-6", "items=0-9", "bytes=50-10", "bytes=-", "bytes=" + "9" * 25 + "-"):
            r = await get(mid, Range=bad)
            check(f"{bad[:30]!r} -> 200 whole ({r.status_code})", r.status_code == 200 and r.content == data)

        print("\nIf-Range:")
        r = await get(mid, Range="bytes=100-", **{"If-Range": etag})
        check("the current ETag honours the range", r.status_code == 206 and r.content == data[100:])
        r = await get(mid, Range="bytes=100-", **{"If-Range": '"not-this-one"'})
        check("another tag gets the whole blob", r.status_code == 200 and r.content == data)
        r = await get(mid, Range="bytes=100-", **{"If-Range": "W/" + etag})
        check("a weak tag never matches", r.status_code == 200 and r.content == data)
        lm = (await get(mid)).headers.get("last-modified", "")
        r = await get(mid, Range="bytes=100-", **{"If-Range": lm})
        check("a date gets the whole blob", r.status_code == 200 and r.content == data)
        r = await get(mid, **{"If-Range": '"not-this-one"'})
        check("If-Range without Range is a plain GET", r.status_code == 200 and r.content == data)

        print("\nResume:")
        cut = 1_234_567
        head = await get(mid, Range=f"bytes=0-{cut - 1}")
        tail = await get(mid, Range=f"bytes={cut}-", **{"If-Range": head.headers.get("etag", "")})
        joined = head.content + tail.content
        check("a download cut anywhere reassembles the blob",
              head.status_code == 206 and tail.status_code == 206
              and hashlib.sha256(joined).digest() == hashlib.sha256(data).digest())
        other = os.urandom(T)
        r = await upload(other)
        other_etag = (await get(r.json()["media_id"])).headers.get("etag")
        check("two blobs of the same size have different ETags", other_etag and other_etag != etag)

        print("\nUnchanged:")
        r = await get("0" * 32)
        check("an unknown id is 404", r.status_code == 404)
        r = await get("not-a-uuid")
        check("a malformed id is 404", r.status_code == 404)

        print("\nUpload ceilings:")
        saved_cap = media_mod.MAX_BLOB_SIZE
        media_mod.MAX_BLOB_SIZE = 256 * 1024
        ceiling = media_mod._body_ceiling()
        try:
            # The route class alone, without the app's middleware, so that every
            # body message the handler asks for is visible here.
            bare = FastAPI()
            bare.include_router(media_mod.router)
            pulled = {"n": 0}

            async def never_read():
                pulled["n"] += 1
                return {"type": "http.request", "body": b"x" * 65536, "more_body": True}

            await clear_limits()
            before = stored()
            status_code, headers = await raw_call(bare, "POST", "/media/upload", [
                (b"host", b"t"),
                (b"content-type", b"multipart/form-data; boundary=rcq"),
                (b"content-length", str(ceiling + 1024 * 1024).encode()),
            ], never_read)
            check(f"a declared length over the ceiling is 413 ({status_code})", status_code == 413)
            check(f"before a single body byte is read ({pulled['n']} reads)", pulled["n"] == 0)
            check("and the connection is kept, so a proxy reads the 413, not a reset",
                  "connection" not in headers)
            status_code, _ = await raw_call(bare, "PUT", f"/media/{'ab' * 16}", [
                (b"host", b"t"),
                (b"content-type", b"multipart/form-data; boundary=rcq"),
                (b"content-length", str(ceiling + 1).encode()),
            ], never_read)
            check(f"PUT the same ({status_code}, {pulled['n']} reads)", status_code == 413 and pulled["n"] == 0)
            check("nothing was stored", stored() == before)

            # The same over a real socket, the way a proxy sends it: the body
            # keeps coming while the answer goes back. A writer that is reset
            # here is a proxy that answers 502 instead of passing the 413 on.
            server = uvicorn.Server(uvicorn.Config(bare, host="127.0.0.1", port=0,
                                                   log_level="warning", lifespan="off"))
            serving = asyncio.create_task(server.serve())
            while not server.started:
                await asyncio.sleep(0.01)
            port = server.servers[0].sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(f"PUT /media/{'cd' * 16} HTTP/1.1\r\nHost: t\r\n"
                         "Content-Type: multipart/form-data; boundary=rcq\r\n"
                         f"Content-Length: {ceiling + 64 * 1024 * 1024}\r\n\r\n".encode())
            writer.write(b"z" * 65536)
            await writer.drain()
            status_line = await asyncio.wait_for(reader.readline(), 10)
            reset = None
            try:
                for _ in range(128):
                    writer.write(b"z" * 65536)
                    await writer.drain()
                    await asyncio.sleep(0)
            except (ConnectionError, OSError) as exc:
                reset = exc
            writer.close()
            server.should_exit = True
            await serving
            check(f"over a socket: 413 ({status_line.decode().strip()})", status_line.startswith(b"HTTP/1.1 413"))
            check(f"and 8 MB more of body after it are taken, not reset ({reset!r})", reset is None)

            # Chunked: no Content-Length, a body that would never end.
            sent_bytes = {"n": 0}

            async def endless():
                yield (b"--rcq\r\nContent-Disposition: form-data; name=\"blob\"; filename=\"blob.bin\"\r\n"
                       b"Content-Type: application/octet-stream\r\n\r\n")
                while sent_bytes["n"] < 64 * 1024 * 1024:
                    sent_bytes["n"] += 16 * 1024
                    yield b"y" * (16 * 1024)

            await clear_limits()
            r = await c.post("/media/upload", content=endless(),
                             headers={"content-type": "multipart/form-data; boundary=rcq"})
            check(f"a chunked body over the ceiling is 413 ({r.status_code})", r.status_code == 413)
            check(f"cut at the ceiling, not read to its end ({sent_bytes['n']} bytes pulled)",
                  sent_bytes["n"] <= ceiling + 64 * 1024)
            check("and the connection is closed after it", r.headers.get("connection") == "close")
            check("nothing stored, no temp file left", stored() == before)

            exact = os.urandom(media_mod.MAX_BLOB_SIZE)
            r = await upload(exact)
            check(f"a blob of exactly the cap goes in ({r.status_code})",
                  r.status_code == 201 and r.json().get("size") == len(exact))
            if r.status_code == 201:
                got = await get(r.json()["media_id"])
                check("and comes back whole", got.content == exact)
            before = stored()
            r = await upload(exact + b"!")
            check(f"one byte over the cap is 413 ({r.status_code})", r.status_code == 413)
            check("and leaves neither a blob nor a temp file", stored() == before)
        finally:
            media_mod.MAX_BLOB_SIZE = saved_cap

        print("\nFirst write wins:")
        dep_id = os.urandom(16).hex()
        a = os.urandom(200_000)
        b = os.urandom(200_000)
        await clear_limits()
        r = await c.put(f"/media/{dep_id}", files={"blob": ("blob.bin", a, "application/octet-stream")})
        check(f"a deposit lands ({r.status_code})", r.status_code == 201 and r.json().get("size") == len(a))
        await clear_limits()
        r = await c.put(f"/media/{dep_id}", files={"blob": ("blob.bin", b, "application/octet-stream")})
        check("a second deposit of the id is an idempotent success", r.status_code == 201)
        check("and the first copy stands", (await get(dep_id)).content == a)
        # The race: this deposit passed the existence check, then the other
        # one landed first. The link must refuse, not overwrite.
        target = media_mod.MEDIA_ROOT / f"{dep_id}.bin"
        size = await media_mod._stream_to(target, UploadFile(file=io.BytesIO(b + b"longer")))
        check("a deposit that loses the race leaves the winner's bytes", target.read_bytes() == a)
        check("and answers with the stored size", size == len(a))
        check("and leaves no temp file", not any(n.endswith(".part") for n in stored()))

        print("\nA mount without hard links:")
        real_link = os.link

        def no_links(src, dst, *args, **kwargs):
            raise OSError(errno.EPERM, "Operation not permitted")

        os.link = no_links
        try:
            blob = os.urandom(10_000)
            r = await upload(blob)
            ok = r.status_code == 201
            check(f"an upload still goes in ({r.status_code})", ok)
            if ok:
                check("and reads back", (await get(r.json()["media_id"])).content == blob)
            # A deposit that passed the existence check while another one
            # landed: the rename must look first, not replace the winner.
            size = await media_mod._stream_to(target, UploadFile(file=io.BytesIO(b"other")))
            check("a copy that landed meanwhile still stands", target.read_bytes() == a and size == len(a))
        finally:
            os.link = real_link
        check("no temp file left", not any(n.endswith(".part") for n in stored()))

    for leftover in list(STORE.iterdir()):
        leftover.unlink()
    await close_redis()
    print(f"\n{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
    return fails


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
